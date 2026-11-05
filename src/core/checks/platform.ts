// Developer platform: what Workers, Pages and R2 expose publicly, and secrets
// stored where anyone with read access can see them.

import { defineChecks } from "./define.ts";
import type { AccessApp } from "../cf-types.ts";

/** Variable names that usually hold a credential. */
const SECRET_NAME = /(secret|token|password|passwd|pwd|api[_-]?key|private[_-]?key|access[_-]?key|credential|auth|signing|webhook)/i;
const WRITE_METHODS = ["PUT", "POST", "DELETE", "PATCH"];

/** Does an Access application cover a hostname (wildcards included)? */
const accessCovers = (apps: AccessApp[] | null, host: string) =>
  (apps || []).some((a) =>
    [a.domain, ...(a.self_hosted_domains || []), ...(a.destinations || []).map((x) => x.uri)].filter(Boolean).some((dom) => {
      const h = String(dom).toLowerCase().split("/")[0];
      return h === host || (h.startsWith("*.") && host.endsWith(h.slice(1)));
    }),
  );

export default defineChecks(
  {
    "PLT-001": {
      category: "Platform",
      severity: "medium",
      docs: "https://developers.cloudflare.com/workers/configuration/routing/workers-dev/",
      requires: ["workers"],
      title: "Worker reachable on workers.dev",
      why: "The workers.dev URL bypasses the WAF, Access policies and rules on your custom domain.",
      fix: "Disable the workers.dev route for the Worker if it is only meant to be served on your domain.",
    },
    "PLT-002": {
      category: "Platform",
      severity: "medium",
      docs: "https://developers.cloudflare.com/r2/buckets/public-buckets/",
      requires: ["r2"],
      title: "R2 bucket is public on r2.dev",
      why: "Anyone with the URL can read every object; r2.dev is also rate-limited and not meant for production.",
      fix: "Disable the r2.dev URL and serve through a custom domain with access controls if needed.",
    },
    "PLT-003": {
      category: "Platform",
      severity: "high",
      docs: "https://developers.cloudflare.com/workers/configuration/secrets/",
      requires: ["workerSettings", "pages"],
      title: "Credential stored as a plain-text variable",
      why: "Plain-text variables are visible to anyone who can read the Worker or Pages project, in the dashboard and through the API. Secrets are encrypted and write-only.",
      fix: "1. Rotate the credential. 2. Store the new value as a secret (wrangler secret put, or Variables and Secrets → Encrypt). 3. Delete the plain-text variable.",
    },
    "PLT-004": {
      category: "Platform",
      severity: "low",
      docs: "https://developers.cloudflare.com/pages/configuration/preview-deployments/",
      requires: ["pages", "accessApps"],
      title: "Pages preview deployments are public",
      why: "Every branch push gets a public URL, so unreleased features, test data and debug builds are reachable by anyone who finds the hostname.",
      fix: "Turn on Access for the project's preview deployments under Settings → General → Enable access policy, or limit previews to chosen branches.",
    },
    "PLT-005": {
      category: "Platform",
      severity: "medium",
      docs: "https://developers.cloudflare.com/r2/buckets/cors/",
      requires: ["r2"],
      title: "R2 bucket lets any website write to it",
      why: "A CORS rule that allows any origin with PUT, POST or DELETE lets scripts on any site write to or delete from the bucket, wherever someone holds a presigned URL or token.",
      fix: "Under the bucket's Settings → CORS policy, list your own origins instead of *, and only allow the methods your app uses.",
    },
  },
  ({ inv, d }, report) => {
    if (inv.workersSubdomain?.subdomain) {
      for (const w of inv.workers) {
        if (!w.subdomain) continue;
        report("PLT-001", {
          resource: w.name,
          pass: !w.subdomain.enabled,
          link: d.worker(w.name),
          detail: `Reachable at https://${w.name}.${inv.workersSubdomain.subdomain}.workers.dev${w.subdomain.previews_enabled ? " (preview URLs also enabled)" : ""}.`,
        });
      }
    }
    for (const b of inv.r2) {
      if (b.managed)
        report("PLT-002", {
          resource: b.name,
          pass: !b.managed.enabled,
          detail: b.managed.enabled ? `Public at https://${b.managed.domain}.` : "",
          link: d.r2(b.name),
        });
      if (b.cors) {
        const open = b.cors.filter(
          (r) => (r.allowed?.origins || []).includes("*") && (r.allowed?.methods || []).some((m) => WRITE_METHODS.includes(m.toUpperCase())),
        );
        report("PLT-005", {
          resource: b.name,
          pass: !open.length,
          link: d.r2(b.name),
          detail: `Bucket ${b.name} accepts ${[...new Set(open.flatMap((r) => r.allowed?.methods || []))].join(", ")} from any origin.`,
        });
      }
    }

    // PLT-003: plain-text variables named like credentials. Only names are shown, never values.
    for (const w of inv.workers) {
      const plain = (w.bindings || []).filter((b) => b.type === "plain_text" && SECRET_NAME.test(b.name));
      if (w.bindings)
        report("PLT-003", {
          resource: `Worker ${w.name}`,
          pass: !plain.length,
          link: d.worker(w.name),
          detail: `Worker ${w.name} has ${plain.map((b) => b.name).join(", ")} as plain-text variables.`,
          evidence: plain.length ? { chain: plain.map((b) => ({ label: "Variable", value: `${b.name} (plain text, value not shown)` })) } : null,
        });
    }
    for (const p of inv.pages || []) {
      const plain = (["production", "preview"] as const).flatMap((env) =>
        Object.entries(p.deployment_configs?.[env]?.env_vars || {})
          .filter(([k, v]) => v && v.type !== "secret_text" && SECRET_NAME.test(k))
          .map(([k]) => `${k} (${env})`),
      );
      report("PLT-003", {
        resource: `Pages ${p.name}`,
        pass: !plain.length,
        link: d.pages(p.name),
        detail: `Pages project ${p.name} has ${plain.join(", ")} as plain-text environment variables.`,
        evidence: plain.length ? { chain: plain.map((v) => ({ label: "Variable", value: `${v}, value not shown` })) } : null,
      });

      // PLT-004: previews are public unless Access covers *.<project>.pages.dev.
      if (p.subdomain && p.source?.config?.preview_deployment_setting !== "none") {
        const host = `preview.${p.subdomain}`.toLowerCase();
        report("PLT-004", {
          resource: `Pages ${p.name}`,
          pass: accessCovers(inv.accessApps, host),
          link: d.pages(p.name),
          detail: `Preview deployments of ${p.name} are public at *.${p.subdomain}, with no Access application in front.`,
        });
      }
    }
  },
);
