// Monitoring on Vercel: whether logs leave Vercel at all, and whether drains and
// webhooks send them somewhere safe.

import { defineChecks, plan } from "./define.ts";

const PUBLIC_ACL = /^public-/;

export default defineChecks(
  {
    "VMN-001": {
      category: "Monitoring",
      severity: "low",
      docs: "https://vercel.com/docs/drains",
      requires: ["drains"],
      title: "Logs aren't kept outside Vercel",
      why: "Vercel keeps runtime logs for a short time. Without a drain, there's nothing to search after an incident that's more than a few days old.",
      fix: "Add a log drain to your log platform or an S3 bucket under Team Settings → Drains.",
    },
    "VMN-002": {
      category: "Monitoring",
      severity: "critical",
      docs: "https://vercel.com/docs/drains",
      requires: ["drains"],
      attackPath: true,
      title: "Drain writes logs to S3 as public objects",
      why: "The drain sets a public ACL on every object it writes, so anyone with an object's URL can read request logs, which hold IP addresses, paths and sometimes tokens.",
      fix: "Change the drain's object ACL to private or bucket-owner-full-control, then remove public access from the objects already written.",
    },
    "VMN-003": {
      category: "Monitoring",
      severity: "high",
      docs: "https://vercel.com/docs/drains",
      requires: ["drains", "webhooks"],
      title: "Logs or webhooks are sent without encryption",
      why: "An http:// endpoint sends logs or event payloads in clear text, where anyone on the path can read or change them.",
      fix: "Change the endpoint to https:// under Team Settings → Drains or Webhooks.",
    },
    "VMN-004": {
      category: "Monitoring",
      severity: "medium",
      docs: "https://vercel.com/docs/drains",
      requires: ["drains"],
      title: "Drain is disabled or failing",
      why: "Logs stopped reaching their destination, so alerts and investigations that rely on them see nothing.",
      fix: "Open the drain under Team Settings → Drains, fix the endpoint or credentials, and turn it back on.",
    },
  },
  ({ inv, d }, report) => {
    if (inv.drains) {
      const working = inv.drains.filter((x) => !x.disabled);
      // Drains are a paid feature; on Hobby there's nothing to turn on.
      if (plan(inv) !== "hobby") report("VMN-001", { resource: inv.accountName ?? "team", pass: working.length > 0, link: d.drains });
      for (const x of inv.drains) {
        if (x.s3Acl) report("VMN-002", { resource: x.name, pass: !PUBLIC_ACL.test(x.s3Acl), detail: `Object ACL ${x.s3Acl}`, link: d.drains });
        if (x.endpoint) report("VMN-003", { resource: x.name, pass: !x.endpoint.startsWith("http://"), detail: `Drain to ${x.endpoint}`, link: d.drains });
        report("VMN-004", {
          resource: x.name,
          pass: !x.disabled && !x.erroring,
          detail: x.disabled ? "Disabled" : x.erroring ? "Delivery is failing" : "",
          link: d.drains,
        });
      }
    }
    for (const w of inv.webhooks ?? [])
      if (w.endpoint)
        report("VMN-003", {
          resource: w.endpoint,
          pass: !w.endpoint.startsWith("http://"),
          detail: `Webhook for ${w.events.length} event types`,
          link: d.webhooks,
        });
  },
);
