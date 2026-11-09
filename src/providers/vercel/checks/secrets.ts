// Secrets in Vercel environment variables (each project's and the team's shared
// ones) and in project commands. Edgewatch reads variable names, types and targets
// only, never values, so secrets are recognised by their names and by what Vercel
// itself flags. Commands are read to look for credentials written into them; only
// the kind found is reported, and the command is never stored.

import { defineChecks, looksSecret, PUBLIC_PREFIX, secretKindIn } from "./define.ts";
import type { VercelEnvVar } from "../types.ts";

const TARGETS = (t: string[]) => (t.length ? t.join(", ") : "no environment");

export default defineChecks(
  {
    "VEN-001": {
      category: "Secrets",
      severity: "high",
      docs: "https://vercel.com/docs/environment-variables/sensitive-environment-variables",
      requires: ["env"],
      title: "Vercel flags a secret that team members can read",
      why: "Vercel marked this variable as a readable secret: anyone on the team who can open the project, and any token with access, can read its value.",
      fix: "1. Rotate the secret with its issuer. 2. Delete the variable under Settings → Environment Variables. 3. Add the new value again with Sensitive turned on.",
    },
    "VEN-002": {
      category: "Secrets",
      severity: "high",
      docs: "https://vercel.com/docs/environment-variables#environment-variable-types",
      requires: ["env"],
      title: "Secret stored as a plain-text environment variable",
      why: "Plain-text variables are shown in the dashboard and returned by the API to anyone with access to the project. Its name suggests it holds a password, key or token.",
      fix: "Rotate the secret, delete the variable, and add the new value again with Sensitive turned on.",
    },
    "VEN-003": {
      category: "Secrets",
      severity: "high",
      docs: "https://vercel.com/docs/environment-variables/framework-environment-variables",
      requires: ["env"],
      attackPath: true,
      title: "Secret-looking variable is sent to browsers",
      why: "Frameworks copy variables with prefixes like NEXT_PUBLIC_ or VITE_ into the JavaScript every visitor downloads. A key or token there is public.",
      fix: "If the value really is secret, rotate it, rename the variable without the public prefix, and read it only in server code. If it's meant to be public (a publishable key), mark the finding as a false positive.",
    },
    "VEN-004": {
      category: "Secrets",
      severity: "medium",
      docs: "https://vercel.com/docs/environment-variables/sensitive-environment-variables",
      requires: ["env"],
      title: "Secret not marked Sensitive",
      why: "Without Sensitive, the value can be read back in the dashboard, the CLI and the API by anyone who can open the project. Sensitive values can only be used by deployments.",
      fix: "Delete the variable and add it again with Sensitive turned on. Vercel can't convert an existing variable.",
    },
    "VEN-005": {
      category: "Secrets",
      severity: "medium",
      docs: "https://vercel.com/docs/environment-variables#environments",
      requires: ["env"],
      title: "Production secret is also given to preview deployments",
      why: "Previews build any branch, often before review. A production secret there can be read by unreviewed code and ends up in more build logs.",
      fix: "Split the variable: keep the production value for Production only, and give Preview its own staging credential.",
    },
    "VEN-007": {
      category: "Secrets",
      severity: "medium",
      docs: "https://vercel.com/docs/environment-variables#development-environment-variables",
      requires: ["env"],
      title: "Production secret is downloaded to developer machines",
      why: "Variables for the Development environment are what `vercel env pull` writes into a local .env file. A production secret there ends up on every laptop that pulls it, in plain text.",
      fix: "Give Development its own non-production credential, and keep the production value for Production only. Sensitive variables can't be pulled at all.",
    },
    "VEN-008": {
      category: "Secrets",
      severity: "high",
      docs: "https://vercel.com/docs/builds/configure-a-build#build-command",
      requires: ["projects"],
      attackPath: true,
      title: "Credential written into a build or install command",
      why: "Project commands are shown in the dashboard and returned by the API to anyone with access to the project, and they appear in build logs. A token written into one is effectively public to the team.",
      fix: "1. Rotate the credential with its issuer. 2. Store the new one as a Sensitive environment variable. 3. Reference it from the command (for example `$NPM_TOKEN`) instead of writing it in.",
    },
    "VEN-006": {
      category: "Secrets",
      severity: "medium",
      docs: "https://vercel.com/docs/environment-variables/sensitive-environment-variables#environment-variables-policy",
      requires: ["team"],
      title: "Team doesn't require new secrets to be Sensitive",
      why: "Without the policy, every new production and preview variable is readable by default, and it's up to each person to remember the Sensitive switch.",
      fix: "Under Team Settings → Security & Privacy → Environment Variable Policy, turn on Enforce Sensitive Environment Variables.",
    },
  },
  ({ inv, d }, report) => {
    /** One set of variables: a project's, or the team's shared ones. */
    const judge = (zone: string, env: VercelEnvVar[], link: string) => {
      for (const e of env) {
        if (e.type === "system") continue;
        const resource = `${zone}: ${e.key}`;
        const secret = looksSecret(e.key.replace(PUBLIC_PREFIX, ""));
        const readable = e.issues.includes("readable-secret");
        report("VEN-001", { zone, resource, pass: !readable, detail: `Type ${e.type}, used in ${TARGETS(e.targets)}`, link });
        if (!secret) continue;
        // The browser-bound case is about where the value goes, not how it's stored.
        if (PUBLIC_PREFIX.test(e.key)) {
          report("VEN-003", { zone, resource, pass: false, detail: `Used in ${TARGETS(e.targets)}`, confidence: "likely", link });
          continue;
        }
        report("VEN-003", { zone, resource, pass: true });
        report("VEN-002", { zone, resource, pass: e.type !== "plain", detail: `Used in ${TARGETS(e.targets)}`, confidence: "likely", link });
        // Integration-managed values (databases, stores) are rotated by the integration; Vercel's own flag covers them.
        if (e.type === "encrypted" && !readable && !e.integration)
          report("VEN-004", { zone, resource, pass: false, detail: `Used in ${TARGETS(e.targets)}`, confidence: "likely", link });
        else if (e.type === "sensitive" || e.type === "secret") report("VEN-004", { zone, resource, pass: true });
        const prod = e.targets.includes("production");
        report("VEN-005", {
          zone,
          resource,
          pass: !(prod && e.targets.includes("preview")),
          detail: `One value for ${TARGETS(e.targets)}`,
          confidence: "likely",
          link,
        });
        // Sensitive values can't be pulled, so only readable ones reach laptops.
        if (prod && e.type !== "sensitive")
          report("VEN-007", {
            zone,
            resource,
            pass: !e.targets.includes("development"),
            detail: `One value for ${TARGETS(e.targets)}`,
            confidence: "likely",
            link,
          });
      }
    };
    for (const p of inv.projects) if (p.env) judge(p.name, p.env, d.project(p.name, "environment-variables"));
    if (inv.sharedEnv) judge("Shared variables", inv.sharedEnv, d.team("environment-variables"));

    for (const p of inv.projects) {
      for (const c of p.commands) {
        const kind = secretKindIn(c.command);
        report("VEN-008", {
          zone: p.name,
          resource: `${p.name}: ${COMMAND_LABEL[c.field] ?? c.field}`,
          pass: !kind,
          // The kind only: the command itself holds the secret.
          detail: kind ? `The ${COMMAND_LABEL[c.field]?.toLowerCase() ?? c.field} contains ${kind}` : "",
          link: d.project(p.name, "build-and-deployment"),
        });
      }
    }
    report.passIfNone("VEN-008", "commands");

    if (inv.team) {
      const on = inv.team.sensitiveEnvPolicy === "on";
      report("VEN-006", { resource: inv.team.name, pass: on, detail: on ? "" : "The policy is off", link: d.security });
    }
  },
);

const COMMAND_LABEL: Record<string, string> = {
  buildCommand: "Build command",
  installCommand: "Install command",
  devCommand: "Development command",
  commandForIgnoringBuildStep: "Ignored build step",
};
