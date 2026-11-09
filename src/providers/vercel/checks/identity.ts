// Identity & access on Vercel: SSO, who holds the Owner role, people outside the
// company, stale invitations and access requests, team-wide two-factor
// authentication, integrations that reach every project, and the scanning user's
// own access tokens.

import { defineChecks, plan } from "./define.ts";
import { DAY_MS } from "../../../shared/time.ts";

const MAX_OWNERS = 3;
const INVITE_STALE_DAYS = 14;
const TOKEN_IDLE_DAYS = 90;
/** Roles that can change a team's projects or settings. */
const WRITE_ROLES = new Set(["OWNER", "MEMBER", "DEVELOPER", "SECURITY"]);
const domainOf = (email: string | null) => (email || "").toLowerCase().split("@")[1] || "";
const days = (from: number | null, now: number) => (from == null ? null : Math.floor((now - from) / DAY_MS));
const date = (t: number | null) => (t ? new Date(t).toISOString().slice(0, 10) : "unknown");

export default defineChecks(
  {
    "VID-001": {
      category: "Identity & access",
      severity: "high",
      docs: "https://vercel.com/docs/saml",
      requires: ["team"],
      title: "Team doesn't require SAML single sign-on",
      why: "Without SSO enforcement, members sign in with personal Vercel logins that your identity provider can't disable when someone leaves.",
      fix: "1. Open Team Settings → Security & Privacy → SAML Single Sign-On. 2. Connect your identity provider if it isn't. 3. Turn on Require Team Members to log in with SAML.",
    },
    "VID-002": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://vercel.com/docs/rbac/access-roles",
      requires: ["members"],
      title: "Too many team Owners",
      why: "Every Owner can delete projects, change billing, add members and read every secret. Each extra Owner widens the damage a stolen login can do.",
      fix: "Keep two Owners for break-glass access. Move everyone else to Member, Developer or Viewer under Team Settings → Members.",
    },
    "VID-003": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://vercel.com/docs/rbac/managing-team-members",
      requires: ["members"],
      title: "Team member outside company email domains can change projects",
      why: "Personal or third-party addresses sit outside your identity lifecycle, so offboarding won't remove them, and their role lets them deploy or change settings.",
      fix: "Replace the member with a company address, or give them the Viewer role or project-level access only. Add your company domains to the entity on the Accounts page if they're missing.",
    },
    "VID-004": {
      category: "Identity & access",
      severity: "low",
      docs: "https://vercel.com/docs/rbac/managing-team-members",
      requires: ["members"],
      title: "Team invitation or access request left open",
      why: "An invitation can still be accepted by whoever controls that inbox, and a request to join waits for anyone with the right role to approve it, long after either was needed.",
      fix: "Under Team Settings → Members, revoke invitations older than two weeks, and approve or decline requests to join.",
    },
    "VID-008": {
      category: "Identity & access",
      severity: "high",
      docs: "https://vercel.com/docs/two-factor-authentication",
      requires: ["team"],
      title: "Team doesn't require two-factor authentication",
      why: "Members can sign in with a password or email link alone. A phished or reused password then opens every project, secret and domain on the team.",
      fix: "Under Team Settings → Security & Privacy, turn on Require Two-Factor Authentication. Members without it are asked to set it up.",
    },
    "VID-009": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://vercel.com/docs/integrations/install-an-integration/manage-integrations-reference",
      requires: ["integrations"],
      title: "Integration can change every project",
      why: "The integration has write access and reaches all projects, including ones created later. If the vendor or its token is compromised, so is every project.",
      fix: "Under Team Settings → Integrations, open the integration's Manage page and limit it to the projects that need it, or remove it.",
    },
    "VID-005": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://vercel.com/docs/accounts/access-tokens",
      requires: ["tokens"],
      title: "Vercel access token was found leaked",
      why: "Vercel detected this token in a public place. Anyone who saw it can act as its user on this team.",
      fix: "1. Delete the token under Account Settings → Tokens now. 2. Create a replacement and update the system that used it. 3. Review the team's activity log for changes made since the leak.",
    },
    "VID-006": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://vercel.com/docs/accounts/access-tokens",
      requires: ["tokens"],
      title: "Vercel access token never expires",
      why: "A token without an end date keeps working long after the person or system that needed it is gone, and Vercel tokens can't be limited to reading.",
      fix: "Create a replacement with an expiration date under Account Settings → Tokens, switch the system over, then delete the old token.",
    },
    "VID-007": {
      category: "Identity & access",
      severity: "low",
      docs: "https://vercel.com/docs/accounts/access-tokens",
      requires: ["tokens"],
      title: "Vercel access token unused for 90 days",
      why: "An unused token is access nobody needs, waiting to leak.",
      fix: "Delete the token under Account Settings → Tokens.",
    },
  },
  ({ inv, d, org }, report) => {
    const p = plan(inv);
    const team = inv.team;

    // SSO is an Enterprise feature (and a Pro add-on): a Pro team only fails once it has SSO connected but not required.
    if (team?.saml && p !== "hobby") {
      const { connected, enforced } = team.saml;
      if (p === "enterprise" || connected)
        report("VID-001", {
          resource: team.name,
          pass: connected && enforced,
          detail: connected ? "SAML SSO is connected but not required." : "No identity provider is connected.",
          link: d.security,
        });
    }

    if (team && team.mfaEnforced != null)
      report("VID-008", {
        resource: team.name,
        pass: team.mfaEnforced,
        detail: team.mfaEnforced ? "" : "Two-factor authentication is optional",
        link: d.security,
      });

    if (inv.members) {
      // Members waiting for approval have no access yet: they're open requests, not members.
      const active = inv.members.filter((m) => m.confirmed);
      const owners = active.filter((m) => m.role === "OWNER");
      report("VID-002", {
        resource: team?.name ?? "team",
        pass: owners.length <= MAX_OWNERS,
        detail: `${owners.length} Owners`,
        evidence: { owners: owners.map((m) => m.email || m.username || m.uid) },
        link: d.members,
      });

      if (org.size) {
        for (const m of active) {
          if (!WRITE_ROLES.has(String(m.role))) continue;
          const dom = domainOf(m.email);
          report("VID-003", {
            resource: m.email || m.username || m.uid,
            pass: !dom || org.has(dom),
            detail: `${m.role.toLowerCase()} with an address at ${dom || "an unknown domain"}`,
            link: d.members,
          });
        }
      }

      for (const i of inv.invites ?? []) {
        const age = days(i.createdAt, inv.now);
        report("VID-004", {
          resource: i.email || "invitation",
          pass: !i.expired && (age == null || age < INVITE_STALE_DAYS),
          detail: `Invited as ${i.role.toLowerCase()} on ${date(i.createdAt)}${i.expired ? ", now expired" : ""}`,
          link: d.members,
        });
      }
      // Vercel lists an invited person both as an invitation and as an unconfirmed member; the invitation covers them.
      const invited = new Set((inv.invites ?? []).map((i) => (i.email || "").toLowerCase()));
      for (const m of inv.members.filter((x) => !x.confirmed && !invited.has((x.email || "").toLowerCase()))) {
        const age = days(m.createdAt, inv.now);
        const asked = m.joinedFrom === "nsnb-request-access";
        report("VID-004", {
          resource: m.email || m.username || m.uid,
          pass: age != null && age < INVITE_STALE_DAYS,
          detail: `${asked ? "Asked to join" : "Added"} as ${String(m.role).toLowerCase()} on ${date(m.createdAt)}, ${asked ? "not approved" : "not accepted yet"}`,
          link: d.members,
        });
      }
      report.passIfNone("VID-004", team?.name ?? "team");
    }

    for (const i of inv.integrations ?? []) {
      const writes = i.scopes.some((s) => s.startsWith("read-write:") && !s.endsWith(":integration-configuration"));
      report("VID-009", {
        resource: i.slug,
        pass: !(i.selection === "all" && writes),
        detail:
          i.selection === "all"
            ? `Reaches every project, with ${i.scopes.filter((s) => s.startsWith("read-write:")).join(", ") || "read"} access`
            : `Limited to ${i.projects} project${i.projects === 1 ? "" : "s"}`,
        link: d.team("integrations"),
      });
    }

    for (const t of inv.tokens ?? []) {
      const reach = t.fullAccount ? "every team and the personal account" : "this team";
      report("VID-005", {
        resource: t.name,
        pass: !t.leakedAt,
        detail: t.leakedAt ? `Leaked on ${date(t.leakedAt)}${t.leakedUrl ? ` at ${t.leakedUrl}` : ""}. It reaches ${reach}.` : "",
        confidence: t.leakedAt ? "confirmed" : undefined,
        link: d.tokens,
      });
      report("VID-006", { resource: t.name, pass: !!t.expiresAt, detail: `Created ${date(t.createdAt)}, reaches ${reach}`, link: d.tokens });
      const idle = days(t.activeAt ?? t.createdAt, inv.now);
      report("VID-007", {
        resource: t.name,
        pass: idle == null || idle < TOKEN_IDLE_DAYS,
        detail: t.activeAt ? `Last used ${date(t.activeAt)}` : `Never used since it was created on ${date(t.createdAt)}`,
        link: d.tokens,
      });
    }
  },
);
