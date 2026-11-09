// Platform settings on Vercel projects: runtimes past end of life, directory
// listings, public source maps, OIDC issuers, projects deployed outside Git, and
// production builds too old to carry recent fixes.

import { defineChecks } from "./define.ts";
import { DAY_MS } from "../../../shared/time.ts";

const STALE_PRODUCTION_DAYS = 365;

/** Node.js end-of-life dates (nodejs.org/en/about/previous-releases). Update when a line reaches end of life. */
const NODE_EOL: Record<string, string> = {
  "10": "2021-04-30",
  "12": "2022-04-30",
  "14": "2023-04-30",
  "16": "2023-09-11",
  "18": "2025-04-30",
  "20": "2026-04-30",
  "22": "2027-04-30",
  "24": "2028-04-30",
};

export default defineChecks(
  {
    "VPL-001": {
      category: "Platform",
      severity: "medium",
      docs: "https://vercel.com/docs/functions/runtimes/node-js/node-js-versions",
      requires: ["projects"],
      title: "Functions run on a Node.js version past end of life",
      why: "Node.js gets no security fixes after its end-of-life date, and Vercel stops building on old versions without much notice.",
      fix: "Choose a supported Node.js version under the project's Settings → Build and Deployment → Node.js Version, then redeploy and test.",
    },
    "VPL-002": {
      category: "Platform",
      severity: "medium",
      docs: "https://vercel.com/docs/directory-listing",
      requires: ["projects"],
      title: "Directory listing is on",
      why: "Visitors can browse every file in a folder without an index page, which can reveal backups, configuration and files that were never linked.",
      fix: "Turn off Settings → Advanced → Directory Listing.",
    },
    "VPL-003": {
      category: "Platform",
      severity: "low",
      docs: "https://vercel.com/docs/deployment-protection/protecting-sourcemaps",
      requires: ["projects"],
      title: "Source maps are public",
      why: "Public source maps hand anyone your original source code, comments included, which makes finding weaknesses much easier.",
      fix: "Turn on Protected Source Maps under Settings → Deployment Protection.",
    },
    "VPL-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://vercel.com/docs/oidc#issuer-mode",
      requires: ["projects"],
      title: "OIDC tokens use the global issuer",
      why: "With the global issuer, cloud roles that trust Vercel must check the team themselves; a trust policy that forgets lets other Vercel teams assume your role.",
      fix: "Switch Settings → Security → Secure Backend Access with OIDC Federation to Team issuer mode, then update the issuer URL in your cloud trust policies.",
    },
    "VPL-006": {
      category: "Platform",
      severity: "low",
      docs: "https://vercel.com/docs/deployments/managing-deployments#redeploy-a-project",
      requires: ["projects"],
      title: "Production hasn't been redeployed in over a year",
      why: "Dependency fixes, framework security releases and runtime patches only reach a site when it's rebuilt. A year-old production build carries every vulnerability found since.",
      fix: "Update the project's dependencies and redeploy, or, if the site is no longer needed, remove its domains and delete the project.",
    },
    "VPL-005": {
      category: "Change risk",
      severity: "low",
      docs: "https://vercel.com/docs/git",
      requires: ["projects"],
      title: "Project isn't connected to Git",
      why: "Deployments come from someone's machine through the CLI, so there's no review, no history of what was deployed and no easy rollback to a known commit.",
      fix: "Connect the repository under Settings → Git, and deploy through pull requests.",
    },
  },
  ({ inv, d }, report) => {
    const today = new Date(inv.now).toISOString().slice(0, 10);
    for (const p of inv.projects) {
      const major = p.nodeVersion?.split(".")[0];
      const eol = major ? NODE_EOL[major] : undefined;
      if (eol)
        report("VPL-001", {
          zone: p.name,
          resource: p.name,
          pass: eol > today,
          detail: `Node.js ${p.nodeVersion}, end of life ${eol}`,
          link: d.project(p.name, "build-and-deployment"),
        });
      if (p.directoryListing != null) report("VPL-002", { zone: p.name, resource: p.name, pass: !p.directoryListing, link: d.project(p.name, "advanced") });
      if (p.protectedSourcemaps != null)
        report("VPL-003", { zone: p.name, resource: p.name, pass: p.protectedSourcemaps, link: d.project(p.name, "deployment-protection") });
      if (p.oidcIssuerMode) report("VPL-004", { zone: p.name, resource: p.name, pass: p.oidcIssuerMode === "team", link: d.project(p.name, "security") });
      report("VPL-005", { zone: p.name, resource: p.name, pass: !!p.git, detail: p.git ? `${p.git.type}: ${p.git.repo}` : "", link: d.project(p.name, "git") });
      if (p.productionDeployedAt) {
        const age = Math.floor((inv.now - p.productionDeployedAt) / DAY_MS);
        report("VPL-006", {
          zone: p.name,
          resource: p.name,
          pass: age < STALE_PRODUCTION_DAYS,
          detail: `Production built ${new Date(p.productionDeployedAt).toISOString().slice(0, 10)} (${age} days ago)`,
          link: `${d.project(p.name).replace(/\/settings$/, "")}/deployments`,
        });
      }
    }
  },
);
