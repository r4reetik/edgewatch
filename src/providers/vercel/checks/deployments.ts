// Deployments on Vercel: who can open preview and *.vercel.app URLs, what can
// trigger or skip that protection (bypass secrets, deploy hooks, cron jobs), and
// how long old deployments stay reachable.

import { defineChecks } from "./define.ts";
import type { DeploymentType, VercelProject } from "../types.ts";

/** Protection settings that also cover production deployment URLs (*.vercel.app). */
const COVERS_PRODUCTION_URLS = new Set<DeploymentType>(["all", "all_except_custom_domains", "prod_deployment_urls_and_all_previews"]);

const LABEL: Record<string, string> = {
  all: "all deployments",
  all_except_custom_domains: "all deployments except custom domains",
  prod_deployment_urls_and_all_previews: "previews and production deployment URLs",
  preview: "previews only",
  production: "production",
};

/** Which protections cover previews, by name. Every deployment type protects previews. */
export function previewProtection(p: VercelProject): string[] {
  const out: string[] = [];
  if (p.ssoProtection) out.push("Vercel Authentication");
  if (p.passwordProtection) out.push("Password");
  if (p.trustedIps && p.trustedIps !== "production") out.push("Trusted IPs");
  return out;
}

/** Whether *.vercel.app production URLs need a login or password. */
export const protectsProductionUrls = (p: VercelProject): boolean =>
  [p.ssoProtection, p.passwordProtection, p.trustedIps].some((t) => t != null && COVERS_PRODUCTION_URLS.has(t));

export default defineChecks(
  {
    "VDP-001": {
      category: "Deployments",
      severity: "high",
      docs: "https://vercel.com/docs/deployment-protection",
      requires: ["projects"],
      attackPath: true,
      title: "Preview deployments are open to anyone",
      why: "Every branch and pull request gets a public URL. Previews often run unreleased code against staging data, and their URLs are easy to find in Git comments and logs.",
      fix: "1. Open the project's Settings → Deployment Protection. 2. Turn on Vercel Authentication for Standard Protection (previews and deployment URLs).",
    },
    "VDP-002": {
      category: "Deployments",
      severity: "medium",
      docs: "https://vercel.com/docs/deployment-protection#understanding-deployment-protection-by-environment",
      requires: ["projects", "projectDomains"],
      title: "Production deployment URLs are open, bypassing the custom domain",
      why: "Each production deployment also answers on a *.vercel.app URL. If that URL is public, it serves the site without whatever sits in front of your custom domain, and old production builds stay reachable.",
      fix: "In Settings → Deployment Protection, choose Standard Protection, which covers every deployment except your custom domains.",
    },
    "VDP-003": {
      category: "Deployments",
      severity: "high",
      docs: "https://vercel.com/docs/git/vercel-for-github#git-fork-protection",
      requires: ["projects"],
      attackPath: true,
      title: "Pull requests from forks deploy without approval",
      why: "Anyone can open a pull request from a fork. Without Git Fork Protection it deploys straight away, with the project's environment variables, so code you never reviewed can read your secrets.",
      fix: "Turn on Settings → Git → Git Fork Protection.",
    },
    "VDP-004": {
      category: "Deployments",
      severity: "low",
      docs: "https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation",
      requires: ["projects"],
      title: "Deployment protection has a bypass secret",
      why: "A bypass secret opens every protected deployment to whoever holds it. It's meant for test automation, and it's easy to leave in a CI log or share too widely.",
      fix: "Check each secret under Settings → Deployment Protection → Protection Bypass for Automation is still used, and regenerate or remove the rest.",
    },
    "VDP-005": {
      category: "Deployments",
      severity: "low",
      docs: "https://vercel.com/docs/deploy-hooks",
      requires: ["projects"],
      title: "Project has deploy hooks",
      why: "A deploy hook URL needs no login: anyone who has it can start deployments, using build minutes and replacing what's live with the branch's latest build.",
      fix: "Under Settings → Git → Deploy Hooks, delete hooks nothing uses, and keep the rest out of client code and public repositories.",
    },
    "VDP-006": {
      category: "Deployments",
      severity: "low",
      docs: "https://vercel.com/docs/security/deployment-retention",
      requires: ["projects"],
      title: "Old preview deployments never expire",
      why: "Every preview stays reachable forever, including builds with since-fixed vulnerabilities or secrets that were later rotated out of code.",
      fix: "Set a retention period under Settings → Security → Deployment Retention Policy (for example 90 days for previews).",
    },
    "VDP-008": {
      category: "Deployments",
      severity: "medium",
      docs: "https://vercel.com/docs/cron-jobs/manage-cron-jobs#securing-cron-jobs",
      requires: ["projects", "env"],
      title: "Cron jobs can be triggered by anyone",
      why: "A cron job is an ordinary public URL. Vercel only proves a request came from its scheduler when the project sets CRON_SECRET and the route checks it, so without one anyone can run the job as often as they like.",
      fix: "1. Add a Sensitive CRON_SECRET environment variable (a random string of at least 16 characters). 2. In each cron route, reject requests whose Authorization header isn't `Bearer` followed by that secret.",
    },
    "VDP-007": {
      category: "Deployments",
      severity: "low",
      docs: "https://vercel.com/docs/deployment-protection#configuring-deployment-protection",
      requires: ["team"],
      title: "New projects start without deployment protection",
      why: "Each new project starts with public previews until someone remembers to change it.",
      fix: "Under Team Settings → Deployment Protection, turn on Vercel Authentication as the default for new projects.",
    },
  },
  ({ inv, d }, report) => {
    for (const p of inv.projects) {
      const preview = previewProtection(p);
      report("VDP-001", {
        zone: p.name,
        resource: p.name,
        pass: preview.length > 0,
        detail: preview.length ? `Protected by ${preview.join(", ")}` : "No Vercel Authentication, password or trusted IPs",
        link: d.project(p.name, "deployment-protection"),
      });

      const custom = (p.domains ?? []).filter((x) => !x.name.endsWith(".vercel.app") && !x.redirect && !x.gitBranch);
      if (p.domains && custom.length) {
        const prot = p.ssoProtection ?? p.passwordProtection;
        report("VDP-002", {
          zone: p.name,
          resource: p.name,
          pass: protectsProductionUrls(p),
          detail: prot ? `Protection covers ${LABEL[prot] ?? prot}` : "No protection",
          evidence: { customDomains: custom.map((x) => x.name) },
          link: d.project(p.name, "deployment-protection"),
        });
      }

      if (p.git && p.gitForkProtection != null)
        report("VDP-003", { zone: p.name, resource: p.name, pass: p.gitForkProtection, detail: `Connected to ${p.git.repo}`, link: d.project(p.name, "git") });

      const secrets = p.bypass.filter((b) => b.scope === "automation-bypass");
      report("VDP-004", {
        zone: p.name,
        resource: p.name,
        pass: secrets.length === 0,
        detail: `${secrets.length} bypass secret${secrets.length === 1 ? "" : "s"}`,
        evidence: secrets.length ? { created: secrets.map((s) => (s.createdAt ? new Date(s.createdAt).toISOString().slice(0, 10) : "unknown")) } : null,
        link: d.project(p.name, "deployment-protection"),
      });

      if (p.git)
        report("VDP-005", {
          zone: p.name,
          resource: p.name,
          pass: p.git.deployHooks === 0,
          detail: `${p.git.deployHooks} deploy hook${p.git.deployHooks === 1 ? "" : "s"}`,
          link: d.project(p.name, "git"),
        });

      report("VDP-006", {
        zone: p.name,
        resource: p.name,
        pass: p.previewRetentionDays != null,
        detail: p.previewRetentionDays != null ? `Previews expire after ${p.previewRetentionDays} days` : "No retention policy",
        link: d.project(p.name, "security"),
      });
    }

    for (const p of inv.projects) {
      if (!p.crons.length || !p.env) continue;
      const secret = p.env.some((e) => e.key === "CRON_SECRET" && e.targets.includes("production"));
      report("VDP-008", {
        zone: p.name,
        resource: p.name,
        pass: secret,
        detail: secret
          ? ""
          : `${p.crons.length} cron job${p.crons.length === 1 ? "" : "s"} (${p.crons.map((c) => c.path).join(", ")}) and no CRON_SECRET in Production`,
        confidence: secret ? undefined : "likely",
        link: d.project(p.name, "environment-variables"),
      });
    }

    if (inv.team) {
      const def = inv.team.defaultProtection;
      report("VDP-007", { resource: inv.team.name, pass: !!(def?.sso || def?.password), link: d.team("deployment-protection") });
    }
  },
);
