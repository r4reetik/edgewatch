// Identity & access: who can sign in to the account, how, and with which API tokens.

import { defineChecks } from "./define.ts";
import { daysSince, emailDomain, parseDate, uniq } from "./helpers.ts";

const SUPER_ADMIN = /super administrator/i;
const MAX_SUPER_ADMINS = 3;
const TOKEN_IDLE_DAYS = 90;
/** Permission groups that can change things, as opposed to read them. */
const WRITES = /\b(write|edit|admin)\b/i;

export default defineChecks(
  {
    "IAM-001": {
      category: "Identity & access",
      severity: "high",
      docs: "https://developers.cloudflare.com/fundamentals/user-profiles/2fa/",
      requires: ["members"],
      title: "Member without two-factor authentication",
      why: "A stolen password alone gives full access to this Cloudflare account.",
      fix: "Ask the member to enable 2FA under My Profile → Authentication, or remove them. Members who sign in only through SSO can show as 2FA-off; confirm with them.",
    },
    "IAM-002": {
      category: "Identity & access",
      severity: "high",
      docs: "https://developers.cloudflare.com/fundamentals/manage-members/roles/",
      requires: ["members"],
      title: "Too many Super Administrators",
      why: "Every Super Administrator can delete zones, change billing and create API tokens. Each extra one widens the blast radius of a compromised login.",
      fix: "Keep two break-glass Super Administrators. Move everyone else to scoped roles (Administrator, DNS, Firewall, Zero Trust, Workers Admin).",
    },
    "IAM-003": {
      category: "Identity & access",
      severity: "low",
      docs: "https://developers.cloudflare.com/fundamentals/manage-members/manage/",
      requires: ["members"],
      title: "Pending member invitation",
      why: "Unaccepted invitations can be accepted later by whoever controls that inbox.",
      fix: "Revoke invitations that are no longer needed under Manage Account → Members.",
    },
    "IAM-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://developers.cloudflare.com/fundamentals/manage-members/manage/",
      requires: ["members"],
      title: "Member outside company email domains",
      why: "Personal or third-party addresses are outside your identity lifecycle: offboarding won't remove them.",
      fix: "Replace with a company address, or document why the external member needs access and scope their role.",
    },
    "IAM-005": {
      category: "Identity & access",
      severity: "high",
      docs: "https://developers.cloudflare.com/fundamentals/user-profiles/2fa/",
      requires: ["account"],
      title: "Account does not enforce two-factor authentication",
      why: "Without enforcement, any member can sign in with a password only.",
      fix: "Turn on Manage Account → Configurations → Enforce two-factor authentication.",
    },
    "IAM-006": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://developers.cloudflare.com/fundamentals/api/how-to/restrict-tokens/",
      requires: ["accountTokens"],
      title: "Account API token works from any IP address",
      why: "A leaked token without an IP restriction works for whoever has it, from anywhere.",
      fix: "1. Open Manage Account → Account API Tokens and edit the token. 2. Under Client IP Address Filtering, allow only the addresses your automation runs from.",
    },
    "IAM-007": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://developers.cloudflare.com/fundamentals/api/how-to/restrict-tokens/",
      requires: ["accountTokens"],
      title: "Account API token never expires",
      why: "Tokens without an end date keep working long after the person or system that needed them is gone.",
      fix: "1. Edit the token under Manage Account → Account API Tokens. 2. Set a TTL end date and roll the token before it lapses.",
    },
    "IAM-008": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/",
      requires: ["accountTokens"],
      title: "Account API token unused for 90 days or more",
      why: "An unused token is pure risk: nothing breaks if it's deleted, but it still works if it leaks.",
      fix: "1. Confirm nothing uses the token. 2. Delete it under Manage Account → Account API Tokens.",
    },
    "IAM-009": {
      category: "Identity & access",
      severity: "high",
      docs: "https://developers.cloudflare.com/fundamentals/api/reference/permissions/",
      requires: ["accountTokens"],
      title: "Account API token can change every zone",
      why: "A token with write permissions on all zones lets one leak rewrite DNS, turn off the WAF or redirect traffic everywhere at once.",
      fix: "1. Edit the token's Zone Resources to list only the zones it manages. 2. Keep write permissions to the groups the job needs, or split it into narrower tokens.",
    },
  },
  ({ inv, d, org }, report) => {
    if (inv.members) {
      const admins: string[] = [];
      for (const m of inv.members) {
        const email = m.user?.email || m.email || m.id || "unknown member";
        const roles = uniq([
          ...(m.roles || []).map((r) => String(r.name)),
          ...(m.policies || []).flatMap((p) => (p.permission_groups || []).map((g) => String(g.name))),
        ]);
        if (roles.some((r) => SUPER_ADMIN.test(r))) admins.push(email);
        const roleText = `Roles: ${roles.join(", ") || "none"}`;

        report("IAM-003", { resource: email, pass: m.status !== "pending", detail: `Invitation not yet accepted. ${roleText}`, link: d.members });
        if (m.status !== "pending")
          report("IAM-001", { resource: email, pass: !!m.user?.two_factor_authentication_enabled, detail: roleText, link: d.members });
        const dom = emailDomain(email);
        report("IAM-004", {
          resource: email,
          pass: !dom || org.has(dom),
          detail: `Email domain ${dom} is not one of: ${[...org].join(", ")}. ${roleText}`,
          link: d.members,
        });
      }
      report("IAM-002", {
        resource: "account",
        pass: admins.length <= MAX_SUPER_ADMINS,
        severity: admins.length >= inv.members.length && inv.members.length > MAX_SUPER_ADMINS ? "high" : "medium",
        detail: `${admins.length} of ${inv.members.length} members are Super Administrators (recommended: ${MAX_SUPER_ADMINS} or fewer).`,
        evidence: { superAdministrators: admins },
        link: d.members,
      });
    }

    if (inv.account?.settings) report("IAM-005", { resource: "account", pass: !!inv.account.settings.enforce_twofactor, link: d.accountConfig });

    for (const t of inv.accountTokens || []) {
      if (t.status !== "active") continue;
      const resource = t.name;
      const ipIn = t.condition?.request_ip?.in || [];
      report("IAM-006", { resource, pass: ipIn.length > 0, link: d.apiTokens, detail: `"${t.name}" has no client IP restriction.` });
      report("IAM-007", {
        resource,
        pass: !!t.expires_on,
        link: d.apiTokens,
        detail: `"${t.name}" was issued ${String(t.issued_on || "").slice(0, 10) || "at an unknown date"} and has no expiry.`,
      });
      const used = parseDate(t.last_used_on),
        issued = parseDate(t.issued_on);
      if (used != null || (issued != null && daysSince(issued, inv.now) > 30)) {
        const idle = used != null ? daysSince(used, inv.now) : null;
        report("IAM-008", {
          resource,
          pass: idle != null && idle < TOKEN_IDLE_DAYS,
          link: d.apiTokens,
          detail:
            idle == null
              ? `"${t.name}" has never been used since it was issued on ${String(t.issued_on).slice(0, 10)}.`
              : `"${t.name}" was last used ${idle} days ago.`,
        });
      }
      // Write permissions on resources that include every zone ("…zone.*" or the whole account).
      const broad = (t.policies || []).filter(
        (p) =>
          p.effect !== "deny" &&
          (p.permission_groups || []).some((g) => WRITES.test(String(g.name))) &&
          Object.entries(p.resources || {}).some(
            ([k, v]) => /zone\.\*$/.test(k) || (/\.account\.[0-9a-f]{32}$/.test(k) && typeof v === "object" && Object.keys(v).some((z) => /zone\.\*$/.test(z))),
          ),
      );
      if (broad.length) {
        const groups = uniq(broad.flatMap((p) => (p.permission_groups || []).map((g) => String(g.name)).filter((n) => WRITES.test(n))));
        report("IAM-009", {
          resource,
          pass: false,
          link: d.apiTokens,
          confidence: "likely",
          detail: `"${t.name}" has ${groups.slice(0, 4).join(", ")}${groups.length > 4 ? ` and ${groups.length - 4} more` : ""} on every zone.`,
          evidence: {
            chain: [
              { label: "Token", value: t.name },
              { label: "Write permissions", value: groups.join(", ") },
              { label: "Zones", value: "All zones in the account" },
            ],
          },
        });
      } else report("IAM-009", { resource, pass: true });
    }
  },
);
