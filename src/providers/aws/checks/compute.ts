// EC2, EBS and Lambda: instances that still answer IMDSv1, volumes that aren't
// encrypted by default, snapshots and images shared with everyone, functions on
// runtimes AWS no longer patches, and function URLs without authentication. Then
// the paths that turn one bug into the whole account: an instance the internet
// reaches whose role is an administrator, and credentials left in start-up scripts.

import { defineChecks, roleOfProfile } from "./define.ts";

/**
 * Lambda runtimes past their deprecation date: AWS no longer applies security patches to them.
 * From https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html; add a runtime here when its date passes.
 */
export const DEPRECATED_RUNTIMES =
  /^(nodejs(\d\.\d+|(4|6|8|10|12|14|16|18|20)\.x)?|python(2\.7|3\.[6-9])|ruby(2\.[57]|3\.2)|java8|go1\.x|dotnetcore.*|dotnet[567](\.0)?|provided)$/;

export default defineChecks(
  {
    "AEC-001": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
      requires: ["instances"],
      title: "Instance still allows IMDSv1",
      why: "With IMDSv1, a single server-side request forgery bug in anything on the instance hands out the instance role's credentials. IMDSv2 requires a session token that such a bug can't obtain.",
      fix: "1. Check that the software on the instance uses a current AWS SDK. 2. In EC2 → the instance → Actions → Instance settings → Modify instance metadata options, set IMDSv2 to Required. 3. Set it in your launch templates too, so new instances start that way.",
    },
    "AEC-002": {
      category: "Platform",
      severity: "low",
      docs: "https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html",
      requires: ["ebs", "instances"],
      title: "EBS volumes aren't encrypted by default",
      why: "New volumes and snapshots in this region are unencrypted unless someone remembers to tick the box, and an unencrypted snapshot can be shared or copied out as it is.",
      fix: "In EC2 → Settings → Data protection and security for the region, turn on Always encrypt new EBS volumes. Existing volumes stay as they are.",
    },
    "AEC-003": {
      category: "Attack surface",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html",
      requires: ["ebs"],
      attackPath: true,
      title: "EBS snapshot is public",
      why: "Any AWS account can copy the snapshot and mount it: the whole disk, with whatever databases, keys and configuration were on it.",
      fix: "In EC2 → Snapshots, select the snapshot → Actions → Modify permissions, and set it to Private. Treat every secret that was on the disk as leaked and rotate it.",
    },
    "AEC-004": {
      category: "Attack surface",
      severity: "high",
      docs: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html",
      requires: ["ebs"],
      title: "Machine image (AMI) is public",
      why: "Any AWS account can launch the image and read what was baked into it: application code, configuration, and often credentials.",
      fix: "In EC2 → AMIs, select the image → Actions → Edit AMI permissions, and set it to Private. If it was meant to be shared, share it with specific accounts instead.",
    },
    "AEC-005": {
      category: "Platform",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
      requires: ["functions"],
      title: "Lambda function runs on a deprecated runtime",
      why: "AWS has stopped patching this runtime, so vulnerabilities in the language and its libraries stay open, and AWS will eventually block updates to the function.",
      fix: "Test the function on a supported runtime, then change it under Lambda → the function → Code → Runtime settings → Edit.",
    },
    "AEC-006": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html",
      requires: ["functions"],
      title: "Lambda function URL needs no authentication",
      why: "Anyone who finds the URL can invoke the function. Unless the function checks callers itself, they can use whatever it does and run up its bill.",
      fix: "If the function isn't a public endpoint, set its function URL's auth type to AWS_IAM under Lambda → the function → Configuration → Function URL. If it is public on purpose and checks requests itself, mark this as accepted.",
    },
    "AEC-007": {
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2.html",
      requires: ["instances", "securityGroups", "iamDetails"],
      attackPath: true,
      title: "Internet-facing instance runs with administrator access",
      why: "The instance has a public address and open ports, and the role attached to it can do anything in the account. One vulnerability in whatever listens there (a web app, an SSH daemon, an exposed admin tool) hands the attacker the role's credentials, and with them the account.",
      fix: "1. Give the instance a role with only the permissions its software uses. IAM Access Analyzer can generate one from the role's CloudTrail activity. 2. Require IMDSv2 on the instance. 3. Put it behind a load balancer and close its public ports, or remove its public address.",
    },
    "AEC-008": {
      category: "Secrets",
      severity: "high",
      docs: "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html",
      requires: ["userData", "instances"],
      title: "Credential in an instance's start-up script",
      why: "User data isn't a secret store: anyone who can describe the instance can read it, every process on the instance can fetch it from the metadata service, and it is copied into launch templates and images. A credential written there is readable far beyond the people who should have it.",
      fix: "1. Rotate the credential: treat it as leaked. 2. Move it to Secrets Manager or Systems Manager Parameter Store, and let the script read it at start-up with the instance's role. 3. Replace the instance (or its launch template) so the old script is gone.",
    },
  },
  ({ inv, d }, report) => {
    for (const r of inv.regions) {
      const zone = r.name;
      for (const i of (r.instances ?? []).filter((x) => x.running)) {
        if (i.imdsV2 == null) continue;
        // What IMDSv1 gives away is the instance's role: high when the internet reaches the instance, low when it has no role to steal.
        const runsAs = roleOfProfile(inv, i.profile);
        report("AEC-001", {
          zone,
          resource: i.name ? `${i.name} (${i.id})` : i.id,
          pass: i.imdsV2,
          severity: i.imdsV2 ? undefined : !i.profile ? "low" : i.publicIp ? "high" : undefined,
          detail: i.imdsV2
            ? ""
            : `IMDSv2 is optional${i.publicIp ? `, the instance has the public address ${i.publicIp}` : ""}${
                runsAs
                  ? `, and it runs as the role ${runsAs.name}${runsAs.admin ? ", which has administrator access" : ""}`
                  : i.profile
                    ? `, and it has the instance profile ${i.profile}`
                    : ". It has no role, so there are no credentials to take"
              }`,
          link: d.instance(zone, i.id),
        });
      }

      for (const i of (r.instances ?? []).filter((x) => x.running)) {
        const resource = i.name ? `${i.name} (${i.id})` : i.id;
        if (i.userDataSecret !== undefined)
          report("AEC-008", {
            zone,
            resource,
            pass: !i.userDataSecret,
            detail: i.userDataSecret ? `The user data contains ${i.userDataSecret}` : "",
            confidence: i.userDataSecret ? "likely" : undefined,
            link: d.instance(zone, i.id),
          });

        // Reachable: a public address, and a security group that lets the internet in on something.
        const open = (r.securityGroups ?? []).filter((g) => i.securityGroups.includes(g.id) && g.open.length);
        const role = roleOfProfile(inv, i.profile);
        if (!i.publicIp || !open.length || !role || !inv.roles || !r.securityGroups) continue;
        report("AEC-007", {
          zone,
          resource,
          pass: !role.admin,
          // With IMDSv1, a single forged request to the metadata service is enough to take the role's credentials.
          severity: role.admin && i.imdsV2 === false ? "critical" : undefined,
          detail: role.admin
            ? `Public at ${i.publicIp} through ${open.map((g) => g.name).join(", ")}, running as ${role.name}, which has administrator access${i.imdsV2 === false ? ". IMDSv1 is still allowed" : ""}`
            : "",
          evidence: role.admin
            ? {
                chain: [
                  { label: "Reachable from the internet", value: `${i.publicIp}, through ${open.map((g) => `${g.name} (${g.id})`).join(", ")}` },
                  { label: "Instance profile", value: `${i.profile} gives it the role ${role.name}` },
                  { label: "Role", value: `${role.name} has administrator access` },
                  { label: "Metadata service", value: i.imdsV2 === false ? "IMDSv1 allowed: one request forgery reads the credentials" : "IMDSv2 required" },
                ],
              }
            : null,
          link: d.instance(zone, i.id),
        });
      }

      // The setting only matters where volumes are created.
      if (r.ebsEncryptionByDefault != null && r.instances?.length)
        report("AEC-002", { zone, resource: zone, pass: r.ebsEncryptionByDefault, link: d.ebsSettings(zone) });

      if (r.publicSnapshots) {
        for (const id of r.publicSnapshots)
          report("AEC-003", { zone, resource: id, pass: false, detail: "Shared with all AWS accounts", link: d.snapshot(zone, id) });
        if (!r.publicSnapshots.length) report("AEC-003", { zone, resource: "snapshots", pass: true });
      }
      if (r.publicImages) {
        for (const i of r.publicImages)
          report("AEC-004", {
            zone,
            resource: i.name ? `${i.name} (${i.id})` : i.id,
            pass: false,
            detail: "Shared with all AWS accounts",
            link: d.image(zone, i.id),
          });
        if (!r.publicImages.length) report("AEC-004", { zone, resource: "images", pass: true });
      }

      for (const f of r.functions ?? []) {
        const link = d.lambda(zone, f.name);
        if (f.runtime) report("AEC-005", { zone, resource: f.name, pass: !DEPRECATED_RUNTIMES.test(f.runtime), detail: `Runtime ${f.runtime}`, link });
        if (f.urls?.length) {
          const open = f.urls.some((u) => u.authType === "NONE");
          // Anyone can run a public function; when its role is an administrator, a bug in it is a bug in the account.
          const admin = open && !!f.role && !!inv.roles?.find((x) => x.name === f.role)?.admin;
          report("AEC-006", {
            zone,
            resource: f.name,
            pass: !open,
            severity: admin ? "high" : undefined,
            detail: open ? `Auth type NONE${admin ? `, and its role ${f.role} has administrator access` : ""}` : "",
            confidence: open ? "likely" : undefined,
            link,
          });
        }
      }
    }
  },
);
