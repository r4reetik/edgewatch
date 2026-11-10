// S3: whether the account blocks public access, and buckets that are public
// through their policy or ACL once the bucket's and the account's blocks are
// taken into account.

import { defineChecks } from "./define.ts";
import { GLOBAL, type AwsBucket, type PublicAccessBlock } from "../types.ts";

const FLAGS: [keyof PublicAccessBlock, string][] = [
  ["blockPublicAcls", "Block public ACLs"],
  ["ignorePublicAcls", "Ignore public ACLs"],
  ["blockPublicPolicy", "Block public bucket policies"],
  ["restrictPublicBuckets", "Restrict public buckets"],
];
const off = (b: PublicAccessBlock | null): string[] => FLAGS.filter(([k]) => !b?.[k]).map(([, label]) => label);

/** How a bucket is open to the internet after both blocks apply, or [] when it isn't. */
export function publicThrough(b: AwsBucket, account: PublicAccessBlock | null): string[] {
  const on = (k: keyof PublicAccessBlock) => !!b.block?.[k] || !!account?.[k];
  return [
    b.policyPublic && !on("restrictPublicBuckets") ? "its bucket policy" : null,
    b.aclPublic?.length && !on("ignorePublicAcls") ? `an ACL that grants access to ${b.aclPublic.join(" and ")}` : null,
  ].flatMap((x) => x ?? []);
}

export default defineChecks(
  {
    "AS3-001": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-account.html",
      requires: ["s3Account", "s3Buckets"],
      title: "S3 Block Public Access is off for the account",
      why: "Without the account-wide block, any bucket can be made public by one policy or ACL change, now or later. With it on, a mistake on a single bucket can't expose data.",
      fix: "In the S3 console → Block Public Access settings for this account, turn on all four settings. Buckets that must be public (a static site, for example) are better served through CloudFront.",
    },
    "AS3-002": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
      requires: ["s3Account", "s3Buckets", "s3BucketAccess"],
      attackPath: true,
      title: "S3 bucket is public",
      why: "Anyone on the internet can read the bucket, and with some policies list or write to it. Public buckets are the most common source of leaked data on AWS.",
      fix: "1. If the bucket shouldn't be public, open it in S3 → Permissions and turn on Block Public Access. 2. Then remove the public statement from its policy and the public grants from its ACL. 3. If it serves a website through CloudFront, edit the distribution's origin to use origin access control, let CloudFront add the bucket policy it offers, and then turn on Block Public Access.",
    },
    "AS3-003": {
      category: "Attack surface",
      severity: "low",
      docs: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
      requires: ["s3Account", "s3Buckets", "s3BucketAccess"],
      title: "S3 bucket has no Block Public Access of its own",
      why: "The bucket is private today, but neither it nor the account blocks public access, so one policy or ACL change makes it public.",
      fix: "Open the bucket in S3 → Permissions → Block public access and turn on all four settings, or turn the block on for the whole account.",
    },
  },
  ({ inv, d }, report) => {
    if (inv.s3Block === undefined || !inv.buckets) return;
    const account = inv.s3Block;
    const accountOff = off(account);
    if (inv.buckets.length)
      report("AS3-001", {
        zone: GLOBAL,
        resource: "account",
        pass: !accountOff.length,
        detail: account ? `Off: ${accountOff.join(", ")}` : "Never configured",
        link: d.s3Settings,
      });

    for (const b of inv.buckets) {
      // A bucket whose settings couldn't be read is left out, not passed.
      if (b.block === undefined || b.policyPublic === undefined || b.aclPublic === undefined) continue;
      const through = publicThrough(b, account);
      // A public bucket that CloudFront serves is public on purpose, but it doesn't have to be: origin access control lets it be private.
      const served = (inv.distributions ?? []).filter((x) => x.enabled && x.origins.some((o) => o.s3 && !o.restricted && o.domain.startsWith(`${b.name}.`)));
      report("AS3-002", {
        zone: b.region,
        resource: b.name,
        pass: !through.length,
        severity: through.length && served.length ? "high" : undefined,
        detail: through.length
          ? `Public through ${through.join(" and ")}${
              served.length
                ? `. CloudFront distribution ${served.map((x) => x.aliases[0] ?? x.id).join(", ")} serves it, so visitors can also skip CloudFront and read the bucket directly`
                : ""
            }`
          : "",
        evidence: through.length
          ? {
              chain: [
                ...through.map((t) => ({ label: "Public access", value: t })),
                ...served.map((x) => ({ label: "Served by CloudFront", value: `${x.aliases[0] ?? x.domainName} (${x.id}), without origin access control` })),
                { label: "Bucket's Block Public Access", value: b.block ? (off(b.block).length ? `Off: ${off(b.block).join(", ")}` : "On") : "Not configured" },
                { label: "Account's Block Public Access", value: accountOff.length ? `Off: ${accountOff.join(", ")}` : "On" },
              ],
            }
          : null,
        link: d.bucket(b.name),
      });
      if (accountOff.length && !through.length)
        report("AS3-003", {
          zone: b.region,
          resource: b.name,
          pass: !off(b.block).length,
          detail: b.block ? `Off: ${off(b.block).join(", ")}` : "Not configured",
          link: d.bucket(b.name),
        });
    }
  },
);
