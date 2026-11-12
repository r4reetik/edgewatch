// Identity & access on AWS: the root user, console users without MFA, access keys
// that are old or unused, the password policy, administrators who hold long-lived
// keys, roles anyone can assume, and policies that grant everything.

import { accountOf, date, days, defineChecks } from "./define.ts";
import { GLOBAL } from "../types.ts";

const KEY_MAX_AGE_DAYS = 90;
const IDLE_DAYS = 90;
const MIN_PASSWORD_LENGTH = 14;

export default defineChecks(
  {
    "AID-001": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/enable-mfa-for-root.html",
      requires: ["iamSummary"],
      title: "Root user has no MFA",
      why: "The root user can do anything in the account, including closing it, and no policy can restrict it. With a password alone, one phished or reused password gives all of that away.",
      fix: "1. Sign in as the root user. 2. Open the account menu → Security credentials. 3. Under Multi-factor authentication, assign a passkey or hardware key, and keep a second one somewhere safe.",
    },
    "AID-002": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html",
      requires: ["iamSummary"],
      title: "Root user has access keys",
      why: "A root access key is a permanent credential with full control of the account that MFA doesn't protect and no policy can limit. If it leaks from a laptop, a script or a repository, the account is gone.",
      fix: "1. Find what uses the key and move it to an IAM role or a user with only the permissions it needs. 2. Sign in as the root user → Security credentials → Access keys, and delete the key.",
    },
    "AID-003": {
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html",
      requires: ["iamUsers"],
      title: "IAM user can sign in to the console without MFA",
      why: "The user's password is all that stands between an attacker and everything the user can do in the console.",
      fix: "Open the user in IAM → Security credentials → Multi-factor authentication and assign a device. If the person signs in through IAM Identity Center instead, remove the console password.",
    },
    "AID-004": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id-credentials-access-keys-update.html",
      requires: ["iamUsers"],
      title: "Access key is older than 90 days",
      why: "Access keys never expire on their own. The longer one lives, the more places it has been copied to, and the more likely one of them leaks.",
      fix: "1. Create a second key for the user. 2. Switch the system that uses the old key over. 3. Deactivate the old key, and delete it once nothing breaks. Better: replace the user with an IAM role.",
    },
    "AID-005": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html",
      requires: ["iamUsers"],
      title: "Access key unused for 90 days",
      why: "A key nobody uses is access nobody needs, and nobody will notice when someone else starts using it.",
      fix: "Open the user in IAM → Security credentials, deactivate the key, and delete it after a few weeks without complaints.",
    },
    "AID-006": {
      category: "Identity & access",
      severity: "low",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html",
      requires: ["iamUsers"],
      title: "Console password unused for 90 days",
      why: "The person has left, changed role, or signs in another way, but their password still works.",
      fix: "Open the user in IAM → Security credentials → Console sign-in and remove console access, or delete the user if nothing else uses it.",
    },
    "AID-007": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
      requires: ["passwordPolicy", "iamUsers"],
      title: "Password policy is missing or weak",
      why: "IAM users with console passwords can pick short passwords and reuse old ones, which makes guessing and credential stuffing work.",
      fix: "In IAM → Account settings → Password policy, require at least 14 characters and prevent password reuse.",
    },
    "AID-008": {
      category: "Identity & access",
      severity: "high",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#bp-users-federation-idp",
      requires: ["iamUsers", "iamDetails"],
      attackPath: true,
      title: "Administrator has a long-lived access key",
      why: "The key gives full control of the account to whoever holds it, without MFA and without an expiry. Keys leak from laptops, CI logs and repositories far more often than passwords do.",
      fix: "1. Move the workload to an IAM role, or give its user only the permissions it needs. 2. For people, use IAM Identity Center or a role assumed with MFA. 3. Delete the administrator's access key.",
    },
    "AID-009": {
      category: "Identity & access",
      severity: "critical",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
      requires: ["iamDetails"],
      attackPath: true,
      title: "IAM role can be assumed by any AWS account",
      why: "The role's trust policy names every AWS principal, with no condition. Anyone with an AWS account can assume the role and use its permissions.",
      fix: "Open the role in IAM → Trust relationships and replace the wildcard principal with the specific account, role or service that needs it. For a third party, also require an external ID.",
    },
    "AID-010": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
      requires: ["iamDetails"],
      title: "Customer managed policy allows every action on every resource",
      why: "The policy is a second AdministratorAccess under another name. Whoever it is attached to is an administrator, which reviews that look for AdministratorAccess will miss.",
      fix: "Open the policy in IAM → Policies and narrow its actions and resources to what its users need, or detach it and use AdministratorAccess where full access is intended.",
    },
    "AID-011": {
      category: "Identity & access",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
      requires: ["iamDetails"],
      title: "IAM role trusts an AWS account outside the entity without an external ID",
      why: "Another company's AWS account can assume this role with nothing but its own permissions. If that account is a vendor's, any of the vendor's other customers may be able to make it act on your account (the confused deputy problem); if it is an old partner or a forgotten account, it still has the access.",
      fix: "1. Open the role in IAM → Trust relationships. 2. If the other account is one of yours, add it to this entity in Keelson. 3. If it is a vendor's, add a Condition that requires the external ID they gave you (sts:ExternalId). 4. If nobody uses the role any more, delete it.",
    },
  },
  ({ inv, d, related }, report) => {
    const g = { zone: GLOBAL };

    if (inv.root) {
      report("AID-001", { ...g, resource: "root user", pass: inv.root.mfa, link: d.rootCredentials });
      report("AID-002", { ...g, resource: "root user", pass: !inv.root.accessKeys, link: d.rootCredentials });
    }

    const admins = new Map((inv.admins ?? []).map((a) => [a.user, a.via]));
    for (const u of inv.users ?? []) {
      const link = d.user(u.name);
      if (u.console && u.mfa != null) {
        // An administrator behind a password alone is the whole account behind a password alone.
        const via = inv.admins && !u.mfa ? admins.get(u.name) : undefined;
        report("AID-003", {
          ...g,
          resource: u.name,
          pass: u.mfa,
          severity: via ? "critical" : undefined,
          detail: via ? `Administrator through ${via}, signing in with a password only` : "",
          evidence: via
            ? {
                chain: [
                  { label: "Console sign-in", value: `${u.name} has a password and no MFA device` },
                  { label: "Administrator access", value: `through ${via}` },
                ],
              }
            : null,
          link,
        });
      }
      if (u.console) {
        const idle = days(u.passwordLastUsedAt ?? u.createdAt, inv.now);
        report("AID-006", {
          ...g,
          resource: u.name,
          pass: idle == null || idle < IDLE_DAYS,
          detail: u.passwordLastUsedAt ? `Last signed in ${date(u.passwordLastUsedAt)}` : `Never signed in since ${date(u.createdAt)}`,
          link,
        });
      }
      const active = (u.keys ?? []).filter((k) => k.active);
      for (const k of active) {
        const resource = `${u.name} (key …${k.hint})`;
        const age = days(k.createdAt, inv.now);
        report("AID-004", { ...g, resource, pass: age == null || age <= KEY_MAX_AGE_DAYS, detail: `Created ${date(k.createdAt)}`, link });
        const idle = days(k.lastUsedAt ?? k.createdAt, inv.now);
        report("AID-005", {
          ...g,
          resource,
          pass: idle == null || idle < IDLE_DAYS,
          detail: k.lastUsedAt ? `Last used ${date(k.lastUsedAt)}` : `Never used since it was created on ${date(k.createdAt)}`,
          link,
        });
      }
      if (inv.admins && u.keys && admins.has(u.name))
        report("AID-008", {
          ...g,
          resource: u.name,
          pass: !active.length,
          detail: active.length ? `Administrator through ${admins.get(u.name)}, with ${active.length} active access key${active.length === 1 ? "" : "s"}` : "",
          evidence: active.length
            ? {
                chain: [
                  { label: "Administrator access", value: `${u.name} through ${admins.get(u.name)}` },
                  ...active.map((k) => ({
                    label: `Access key …${k.hint}`,
                    value: `created ${date(k.createdAt)}, ${k.lastUsedAt ? `last used ${date(k.lastUsedAt)}` : "never used"}`,
                  })),
                ],
              }
            : null,
          link,
        });
    }
    if (inv.admins && inv.users) report.passIfNone("AID-008", "account", GLOBAL);

    // The policy only governs IAM users who have a console password.
    if (inv.passwordPolicy !== undefined && inv.users?.some((u) => u.console)) {
      const p = inv.passwordPolicy;
      const weak = p
        ? [p.minLength < MIN_PASSWORD_LENGTH ? `minimum length ${p.minLength}` : null, p.reusePrevention ? null : "old passwords can be reused"].filter(Boolean)
        : [];
      report("AID-007", {
        ...g,
        resource: "password policy",
        pass: !!p && !weak.length,
        detail: p ? weak.join(", ") : "No password policy is set, so AWS's default applies: 8 characters, no reuse prevention",
        link: d.accountSettings,
      });
    }

    for (const r of inv.roles ?? []) {
      if (r.serviceLinked) continue;
      const anyone = r.trust.some((t) => t.kind === "anyone" && !t.conditional);
      report("AID-009", {
        ...g,
        resource: r.name,
        pass: !anyone,
        detail: anyone ? `The trust policy allows the principal "*" without a condition${r.admin ? ", and the role has administrator access" : ""}` : "",
        link: d.role(r.name),
      });
    }
    if (inv.roles) report.passIfNone("AID-009", "account", GLOBAL);

    // Which accounts belong to the entity is only known once every AWS account in it has been scanned.
    if (inv.roles && !related.unknown.includes("awsAccounts")) {
      const ours = new Set([inv.accountId, ...(related.awsAccounts ?? [])]);
      for (const r of inv.roles) {
        if (r.serviceLinked) continue;
        const outside = r.trust.filter((t) => t.kind === "account" && accountOf(t.principal) && !ours.has(accountOf(t.principal)!));
        if (!outside.length) continue;
        const open = outside.filter((t) => !t.conditional);
        const accounts = [...new Set(open.map((t) => accountOf(t.principal)))];
        const idle = days(r.lastUsedAt, inv.now);
        report("AID-011", {
          ...g,
          resource: r.name,
          pass: !open.length,
          severity: open.length && r.admin ? "high" : undefined,
          detail: open.length
            ? `Account${accounts.length === 1 ? "" : "s"} ${accounts.join(", ")} can assume it without a condition${r.admin ? ", and the role has administrator access" : ""}. ${
                r.lastUsedAt ? `Last used ${date(r.lastUsedAt)}${idle != null && idle > 90 ? `, ${idle} days ago` : ""}` : "Not used in the last 400 days"
              }`
            : "",
          link: d.role(r.name),
        });
      }
      report.passIfNone("AID-011", "account", GLOBAL);
    }

    for (const p of inv.policies ?? [])
      report("AID-010", {
        ...g,
        resource: p.name,
        // An unattached policy grants nothing yet.
        pass: !(p.fullAdmin && p.attachments > 0),
        detail: p.fullAdmin ? `Allows "*" on "*", attached to ${p.attachments} ${p.attachments === 1 ? "identity" : "identities"}` : "",
        link: d.policies,
      });
    if (inv.policies) report.passIfNone("AID-010", "account", GLOBAL);
  },
);
