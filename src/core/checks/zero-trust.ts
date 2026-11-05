// Zero Trust: Access applications and policies, identity providers, service
// tokens, tunnels, Gateway and WARP devices.

import { defineChecks } from "./define.ts";
import { daysSince, daysUntil, durationHours, emailDomain, FREE_MAIL, parseDate } from "./helpers.ts";
import { prefixLength } from "./expr.ts";
import { TUNNEL_CNAME } from "../cf-constants.ts";
import type { AccessGroup, AccessPolicy, AccessRule } from "../cf-types.ts";

const SSO_IDP_TYPES = new Set([
  "google-apps",
  "google",
  "okta",
  "azureAD",
  "saml",
  "oidc",
  "onelogin",
  "pingone",
  "centrify",
  "keycloak",
  "github",
  "linkedin",
  "facebook",
  "yandex",
  "auth0",
]);
const APP_TYPES = new Set(["self_hosted", "saas", "ssh", "vnc", "rdp", "infrastructure"]);
const MAX_SESSION_HOURS = 24;
const TOKEN_EXPIRY_WARN_DAYS = 30;
const TOKEN_IDLE_DAYS = 90;
const SEAT_IDLE_DAYS = 90;
const CLOUDFLARED_MAX_AGE_DAYS = 365;
/** Private routes this broad hand much of a network to anyone on WARP. */
const BROAD_ROUTE_PREFIX = 8;

const ZT_DOCS = "https://developers.cloudflare.com/cloudflare-one";

export default defineChecks(
  {
    "ZT-001": {
      category: "Zero Trust",
      severity: "medium",
      docs: "https://developers.cloudflare.com/cloudflare-one/policies/access/",
      requires: ["accessApps"],
      title: "Access policy allows an individual external email",
      why: "Individual addresses outside your domains bypass your IdP's offboarding and MFA policy.",
      fix: "Prefer a group from your identity provider, or a time-boxed policy. Remove addresses that no longer need access.",
    },
    "ZT-002": {
      category: "Zero Trust",
      severity: "low",
      docs: "https://developers.cloudflare.com/cloudflare-one/identity/users/session-management/",
      requires: ["accessApps"],
      title: "Access session lasts longer than 24 hours",
      why: "Long sessions let a stolen session cookie or an offboarded user keep access for days.",
      fix: "Set the application session duration to 24h or less (8h for admin tools).",
    },
    "ZT-003": {
      category: "Zero Trust",
      severity: "high",
      docs: "https://developers.cloudflare.com/cloudflare-one/policies/access/",
      requires: ["accessApps", "accessGroups"],
      title: "Access policy lets everyone in or bypasses Access",
      why: "An Allow-everyone or Bypass policy makes the application effectively public.",
      fix: "Restrict the policy to specific groups or email domains, or remove the application if it is meant to be public.",
    },
    "ZT-004": {
      category: "Zero Trust",
      severity: "medium",
      docs: "https://developers.cloudflare.com/cloudflare-one/identity/idp-integration/",
      requires: ["accessIdps"],
      title: "No single sign-on identity provider for Access",
      why: "One-time PIN by email is phishable and doesn't follow your IdP's MFA and offboarding.",
      fix: "Add your company identity provider (Google Workspace, Okta, Entra ID) under Zero Trust → Settings → Authentication and use it in policies.",
    },
    "ZT-005": {
      category: "Zero Trust",
      severity: "medium",
      docs: "https://developers.cloudflare.com/cloudflare-one/identity/service-tokens/",
      requires: ["accessServiceTokens"],
      title: "Service token expired or expiring within 30 days",
      why: "CI jobs and services using it will start failing authentication when it expires.",
      fix: "Rotate the token under Zero Trust → Access → Service auth and update its consumers before the expiry date.",
    },
    "ZT-006": {
      category: "Zero Trust",
      severity: "low",
      docs: "https://developers.cloudflare.com/cloudflare-one/identity/service-tokens/",
      requires: ["accessServiceTokens"],
      title: "Service token never expires",
      why: "A leaked non-expiring token works forever unless someone notices and revokes it.",
      fix: "Recreate the token with a duration (for example 1 year) and set an expiry alert.",
    },
    "ZT-007": {
      category: "Zero Trust",
      severity: "medium",
      docs: "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/monitor-tunnels/",
      requires: ["tunnels"],
      title: "Tunnel is not healthy",
      why: "Hostnames routed to a down tunnel return error 530 to users.",
      fix: "Check the cloudflared connector on the origin host, or delete the tunnel and its DNS routes if it was retired.",
    },
    "ZT-008": {
      category: "Zero Trust",
      severity: "low",
      docs: "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/routing-to-tunnel/",
      requires: ["tunnels", "dnsRecords", "privateRoutes"],
      title: "Tunnel has no public hostname or private route",
      why: "A healthy tunnel with no DNS route may be unused infrastructure that still holds credentials. (It may also serve private-network routes; confirm.)",
      fix: "Confirm whether the tunnel is still needed; delete it and its connector if not.",
    },
    "ZT-009": {
      category: "Zero Trust",
      severity: "medium",
      docs: "https://developers.cloudflare.com/cloudflare-one/identity/service-tokens/",
      requires: ["accessServiceTokens"],
      title: "Service token unused for 90 days or more",
      why: "An unused credential still opens the applications its policies allow, and nobody would notice it being used by someone else.",
      fix: "Revoke the token under Zero Trust → Access → Service auth, or confirm its owner still needs it.",
    },
    "ZT-010": {
      category: "Zero Trust",
      severity: "critical",
      docs: `${ZT_DOCS}/identity/service-tokens/`,
      requires: ["accessServiceTokens"],
      title: "Access service token was reported leaked",
      why: "A secret-scanning partner found this token's secret in public. Cloudflare disables it until it's rotated, so whatever uses it is broken, and the secret is out.",
      fix: "1. Open Access → Service auth and refresh the token's secret. 2. Update the systems that use it. 3. Find and remove the place it was published.",
    },
    "ZT-011": {
      category: "Zero Trust",
      severity: "low",
      docs: `${ZT_DOCS}/identity/service-tokens/`,
      requires: ["accessOrg", "accessServiceTokens"],
      title: "Idle service tokens aren't revoked automatically",
      why: "Service tokens nobody uses stay valid until someone remembers to delete them.",
      fix: "Turn on Settings → Authentication → Service token inactivity, so tokens unused for a set number of days stop working.",
    },
    "ZT-012": {
      category: "Zero Trust",
      severity: "high",
      docs: `${ZT_DOCS}/policies/access/groups/`,
      requires: ["accessGroups", "accessPolicies"],
      title: "Access group or policy admits everyone or a public email domain",
      why: "Every application that uses this group or policy is open to anyone on the internet, or anyone with a free webmail address.",
      fix: "1. Open Access → Access groups (or Policies). 2. Replace Everyone or the webmail domain with your company's domains, groups from your identity provider, or named emails.",
    },
    "ZT-013": {
      category: "Zero Trust",
      severity: "high",
      docs: `${ZT_DOCS}/identity/authorization-cookie/cors/`,
      requires: ["accessApps"],
      title: "Access application allows any origin with credentials",
      why: "Any website a signed-in user visits can make authenticated requests to the application and read the answers.",
      fix: "Under the application's Advanced settings → CORS, list the origins that may call it instead of allowing all origins.",
    },
    "ZT-014": {
      category: "Zero Trust",
      severity: "low",
      docs: `${ZT_DOCS}/identity/authorization-cookie/`,
      requires: ["accessApps"],
      title: "Access cookie is readable by scripts or sent cross-site",
      why: "Without HttpOnly, a cross-site scripting bug can steal the Access session; SameSite=None sends it with cross-site requests.",
      fix: "Under the application's Advanced settings → Cookie settings, turn on HTTP Only and set SameSite to Lax (or Strict).",
    },
    "ZT-015": {
      category: "Zero Trust",
      severity: "low",
      docs: `${ZT_DOCS}/identity/one-time-pin/`,
      requires: ["accessApps", "accessIdps"],
      title: "Application accepts one-time PIN logins alongside single sign-on",
      why: "One-time PIN skips your identity provider's MFA and offboarding: anyone who can read a matching mailbox can sign in.",
      fix: "Under the application's Authentication tab, choose only your single sign-on provider, or keep one-time PIN for named contractors only.",
    },
    "ZT-016": {
      category: "Zero Trust",
      severity: "high",
      docs: `${ZT_DOCS}/traffic-policies/http-policies/tls-decryption/`,
      requires: ["gatewayRules", "gatewayConfig"],
      title: "Gateway HTTP policies run without TLS inspection",
      why: "Almost all web traffic is HTTPS. Without TLS inspection, HTTP policies only see hostnames, so DLP, antivirus and path rules never match.",
      fix: "1. Install the Cloudflare root certificate on devices. 2. Turn on Traffic policies → Traffic settings → TLS decryption.",
    },
    "ZT-017": {
      category: "Zero Trust",
      severity: "medium",
      docs: `${ZT_DOCS}/insights/logs/gateway-logs/`,
      requires: ["gatewayRules", "gatewayConfig"],
      title: "Gateway activity logging is off",
      why: "Gateway enforces policies but keeps no record, so there's nothing to investigate after an incident.",
      fix: "Turn on Settings → Network → Activity logging (and Logpush, if you keep logs elsewhere).",
    },
    "ZT-018": {
      category: "Zero Trust",
      severity: "medium",
      docs: `${ZT_DOCS}/connections/connect-devices/warp/configure-warp/warp-settings/`,
      requires: ["deviceProfiles", "devices"],
      title: "WARP lets users turn it off or leave the organization",
      why: "Every Gateway and device-posture control stops applying as soon as a user switches WARP off.",
      fix: "In the device profile (Settings → WARP Client → Device settings), turn on Lock WARP switch and turn off Allow device to leave organization, with an auto-connect timeout.",
    },
    "ZT-019": {
      category: "Zero Trust",
      severity: "medium",
      docs: `${ZT_DOCS}/connections/connect-networks/private-net/cloudflared/`,
      requires: ["privateRoutes"],
      attackPath: true,
      title: "Tunnel routes a very broad private network",
      why: "A route this wide puts a whole network range in reach of every enrolled device; only Gateway network policies stand in the way.",
      fix: "Replace the route with the specific subnets or hosts users need, and add Gateway network policies that allow only named groups.",
    },
    "ZT-020": {
      category: "Zero Trust",
      severity: "low",
      docs: `${ZT_DOCS}/identity/devices/`,
      requires: ["devices", "devicePosture"],
      title: "Devices are enrolled but no posture checks exist",
      why: "Access and Gateway can't tell a managed, up-to-date laptop from any other device with WARP installed.",
      fix: "Add device posture checks (OS version, disk encryption, firewall, a managed-device certificate) and require them in Access policies for sensitive apps.",
    },
    "ZT-021": {
      category: "Zero Trust",
      severity: "medium",
      docs: `${ZT_DOCS}/connections/connect-networks/downloads/`,
      requires: ["tunnels"],
      title: "cloudflared is more than a year old",
      why: "Cloudflare supports cloudflared versions for one year; older connectors miss security fixes and can stop connecting.",
      fix: "Update cloudflared on the tunnel's hosts (or turn on automatic updates), then confirm the connector reconnects.",
    },
    "ZT-022": {
      category: "Zero Trust",
      severity: "low",
      docs: `${ZT_DOCS}/identity/users/seat-management/`,
      requires: ["accessUsers"],
      title: "Access seats held by users who haven't signed in for 90 days",
      why: "Former staff and contractors keep a seat, and their identity keeps working with Access until it's revoked.",
      fix: "1. Review the users under My team → Users. 2. Revoke and remove those who have left, or turn on automatic seat expiration.",
    },
  },
  ({ inv, d, org }, report) => {
    const groups = new Map((inv.accessGroups || []).map((g) => [g.id, g]));
    /** Why a set of include rules admits the public, resolving group references. */
    const openTo = (rules: AccessRule[] | undefined, seen = new Set<string>()): string | null => {
      for (const r of rules || []) {
        if (r.everyone) return "Everyone";
        const dom = r.email_domain?.domain?.toLowerCase();
        if (dom && FREE_MAIL.has(dom)) return `anyone with an @${dom} address`;
        const gid = r.group?.id;
        if (gid && !seen.has(gid)) {
          seen.add(gid);
          const g = groups.get(gid);
          const inner = g && openTo(g.include, seen);
          if (inner) return `${inner} (through group "${g!.name}")`;
        }
      }
      return null;
    };
    const policyOpen = (p: AccessPolicy) => (p.decision === "allow" && !(p.require || []).length ? openTo(p.include) : null);

    // Access applications and their policies.
    for (const app of inv.accessApps || []) {
      if (!APP_TYPES.has(app.type)) continue;
      const name = app.name || app.domain;
      const link = d.zt(`access/apps/edit/${app.id}`);
      const resource = `${name} (${app.domain || app.type})`;

      const hours = durationHours(app.session_duration);
      if (hours != null) report("ZT-002", { resource, pass: hours <= MAX_SESSION_HOURS, detail: `Session duration is ${app.session_duration}.`, link });

      const externals: { email: string; policy: string }[] = [];
      let open: string | null = null;
      for (const p of app.policies || []) {
        for (const r of p.include || []) {
          const e = r.email?.email;
          if (e && !org.has(emailDomain(e))) externals.push({ email: e, policy: p.name || "policy" });
        }
        if (p.decision === "bypass") open = `Policy "${p.name}" is a Bypass policy.`;
        else if (policyOpen(p)) open = `Policy "${p.name}" allows ${policyOpen(p)}.`;
      }
      report("ZT-003", { resource, pass: !open, detail: open || "", link });
      if (externals.length) {
        for (const x of externals)
          report("ZT-001", { resource: `${x.email} → ${name}`, pass: false, detail: `Allowed by policy "${x.policy}" on ${app.domain}.`, link });
      } else report("ZT-001", { resource, pass: true });

      if (app.cors_headers) {
        const c = app.cors_headers;
        report("ZT-013", {
          resource,
          pass: !(c.allow_all_origins && c.allow_credentials),
          link,
          detail: `CORS allows all origins and sends credentials for ${app.domain}.`,
        });
      }
      if (app.type === "self_hosted") {
        const weak = [
          app.http_only_cookie_attribute === false && "HttpOnly is off",
          String(app.same_site_cookie_attribute || "").toLowerCase() === "none" && "SameSite is None",
        ].filter(Boolean);
        report("ZT-014", { resource, pass: !weak.length, link, detail: `${weak.join(" and ")} on the Access cookie for ${app.domain}.` });
      }
    }

    // ZT-015: one-time PIN accepted next to SSO.
    const idps = inv.accessIdps || [];
    const otp = idps.find((i) => i.type === "onetimepin");
    if (otp && idps.some((i) => SSO_IDP_TYPES.has(i.type))) {
      for (const app of inv.accessApps || []) {
        if (app.type !== "self_hosted" && app.type !== "saas") continue;
        const allowsOtp = !app.allowed_idps?.length || app.allowed_idps.includes(otp.id);
        report("ZT-015", {
          resource: `${app.name || app.domain} (${app.domain || app.type})`,
          pass: !allowsOtp,
          link: d.zt(`access/apps/edit/${app.id}`),
          detail: `${app.name || app.domain} accepts one-time PIN as well as single sign-on${app.allowed_idps?.length ? "" : " (every login method is allowed)"}.`,
        });
      }
    }

    // ZT-012: groups and reusable policies open to the public. A group that admits everyone only
    // matters where an allow policy relies on it alone, with no require rules narrowing it down.
    const policiesLink = d.zt("access/policies");
    const allPolicies = [
      ...(inv.accessApps || []).flatMap((a) => (a.policies || []).map((p) => ({ p, app: a.name || a.domain || null }))),
      ...(inv.accessPolicies || []).map((p) => ({ p, app: null })),
    ];
    const checkGroup = (g: AccessGroup) => {
      const why = (g.require || []).length ? null : openTo(g.include);
      const relying = allPolicies.filter(({ p }) => p.decision === "allow" && !(p.require || []).length && (p.include || []).some((r) => r.group?.id === g.id));
      const where = [...new Set(relying.map((r) => r.app || r.p.name))].slice(0, 3).join(", ");
      report("ZT-012", {
        resource: `Group "${g.name}"`,
        pass: !why || !relying.length,
        link: d.zt("access/groups"),
        detail: `Access group "${g.name}" includes ${why}, and ${relying.length} polic${relying.length === 1 ? "y relies" : "ies rely"} on it alone (${where}).`,
      });
    };
    (inv.accessGroups || []).forEach(checkGroup);
    for (const p of inv.accessPolicies || []) {
      const why = policyOpen(p);
      report("ZT-012", {
        resource: `Policy "${p.name}"`,
        pass: !why,
        link: policiesLink,
        detail: `Reusable policy "${p.name}" allows ${why}${p.app_count ? `, and ${p.app_count} application${p.app_count === 1 ? " uses" : "s use"} it` : ""}.`,
      });
    }

    if (inv.accessIdps) {
      const types = inv.accessIdps.map((i) => String(i.type));
      report("ZT-004", {
        resource: "account",
        pass: types.some((t) => SSO_IDP_TYPES.has(t)),
        detail: `Configured login methods: ${types.join(", ") || "none"}.`,
        link: d.zt("settings/authentication"),
      });
    }

    const tokenLink = d.zt("access/service-auth");
    for (const t of inv.serviceTokens || []) {
      if (t.leak_reported_at !== undefined) {
        report("ZT-010", {
          resource: t.name,
          pass: !t.leak_reported_at,
          confidence: "confirmed",
          link: tokenLink,
          detail: `Reported leaked on ${String(t.leak_reported_at).slice(0, 10)}. Cloudflare has disabled it until it's rotated.`,
        });
      }
      const exp = parseDate(t.expires_at);
      const forever = t.duration === "forever" || (exp != null && daysUntil(exp, inv.now) > 50 * 365);
      const days = exp != null ? daysUntil(exp, inv.now) : null;
      report("ZT-006", { resource: t.name, pass: !forever, detail: `Duration: ${t.duration || "unknown"}.`, link: tokenLink });
      const created = parseDate(t.created_at) ?? 0;
      const seen = parseDate(t.last_seen_at);
      const idle = seen != null ? daysSince(seen, inv.now) : null;
      if (t.enabled !== false && (seen != null || daysSince(created, inv.now) > 30)) {
        report("ZT-009", {
          resource: t.name,
          pass: idle != null && idle < TOKEN_IDLE_DAYS,
          link: tokenLink,
          detail:
            idle == null
              ? `Never used since it was created on ${String(t.created_at).slice(0, 10)}.`
              : `Last used ${idle} days ago (${String(t.last_seen_at).slice(0, 10)}).`,
        });
      }
      if (!forever && days != null) {
        report("ZT-005", {
          resource: t.name,
          pass: days > TOKEN_EXPIRY_WARN_DAYS,
          severity: days < 0 ? "high" : "medium",
          link: tokenLink,
          detail:
            days < 0 ? `Expired ${-days} days ago (${String(t.expires_at).slice(0, 10)}).` : `Expires in ${days} days (${String(t.expires_at).slice(0, 10)}).`,
        });
      }
    }
    if (inv.accessOrg && (inv.serviceTokens || []).length) {
      const inactivity = inv.accessOrg.service_token_inactivity;
      report("ZT-011", {
        resource: "account",
        pass: !!inactivity?.enabled,
        link: d.zt("settings/authentication"),
        detail: `${(inv.serviceTokens || []).length} service tokens, and none is revoked automatically when it goes unused.`,
      });
    }

    // Tunnels: health, routes, connector age.
    if (inv.tunnels) {
      const routed = new Set<string>();
      for (const z of inv.zones)
        for (const r of z.dns) {
          const m = r.type === "CNAME" && r.content.match(TUNNEL_CNAME);
          if (m) routed.add(m[1].toLowerCase());
        }
      for (const t of inv.tunnels) {
        const link = d.zt(`networks/tunnels/cfd_tunnel/${t.id}/edit`);
        const healthy = t.status === "healthy";
        report("ZT-007", {
          resource: t.name,
          pass: healthy,
          severity: t.status === "inactive" ? "low" : "medium",
          link,
          detail: `Status: ${t.status}. Last connected: ${t.conns_active_at?.slice(0, 10) || "never"}.`,
        });
        const hasPrivateRoute = (inv.privateRoutes || []).some((r) => r.tunnel_id === t.id);
        if (healthy) report("ZT-008", { resource: t.name, pass: routed.has(t.id) || hasPrivateRoute, link });
        // Versions are YYYY.M.patch, so the year and month give the release date.
        const versions = (t.connections || []).map((c) => /^(\d{4})\.(\d{1,2})\./.exec(String(c.client_version || ""))).filter((m) => m != null);
        if (versions.length) {
          const oldest = versions.reduce((a, b) => (Number(a[1]) * 12 + Number(a[2]) <= Number(b[1]) * 12 + Number(b[2]) ? a : b));
          const released = Date.UTC(Number(oldest[1]), Number(oldest[2]) - 1, 1);
          report("ZT-021", {
            resource: t.name,
            pass: daysSince(released, inv.now) <= CLOUDFLARED_MAX_AGE_DAYS + 31,
            link,
            detail: `Tunnel "${t.name}" runs cloudflared ${oldest[0].slice(0, -1)}, released ${oldest[1]}-${oldest[2].padStart(2, "0")}.`,
          });
        }
      }
    }

    for (const r of inv.privateRoutes || []) {
      if (r.deleted_at) continue;
      const len = prefixLength(r.network);
      report("ZT-019", {
        resource: r.network,
        pass: len > BROAD_ROUTE_PREFIX,
        confidence: "likely",
        link: d.zt("networks/routes"),
        detail: `${r.network} is routed through tunnel ${r.tunnel_name || r.tunnel_id}${r.comment ? ` (${r.comment})` : ""}: ${len === 0 ? "every IPv4 address" : `${(2 ** (32 - len)).toLocaleString("en-US")} addresses`}.`,
        evidence: {
          chain: [
            { label: "Route", value: r.network },
            { label: "Tunnel", value: r.tunnel_name || r.tunnel_id || "unknown" },
            { label: "Prefix", value: `/${len}` },
          ],
        },
      });
    }

    // Gateway.
    const rules = (inv.gatewayRules || []).filter((r) => r.enabled !== false);
    const settings = inv.gatewayConfig?.settings;
    if (settings && rules.some((r) => (r.filters || []).includes("http"))) {
      report("ZT-016", {
        resource: "account",
        pass: !!settings.tls_decrypt?.enabled,
        link: d.zt("traffic-policies/traffic-settings"),
        detail: `${rules.filter((r) => (r.filters || []).includes("http")).length} HTTP policies are on, but TLS decryption is off.`,
      });
    }
    if (settings && rules.length) {
      report("ZT-017", {
        resource: "account",
        pass: settings.activity_log?.enabled !== false,
        link: d.zt("settings/network"),
        detail: "Gateway policies are enforced but activity isn't logged.",
      });
    }

    // Devices.
    const enrolled = (inv.devices || []).length;
    if (enrolled && inv.deviceProfiles) {
      for (const p of inv.deviceProfiles) {
        if (p.enabled === false) continue;
        const weak = [!p.switch_locked && "users can switch WARP off", p.allowed_to_leave && "users can leave the organization"].filter(Boolean);
        report("ZT-018", {
          resource: p.name || (p.default ? "Default profile" : "Device profile"),
          pass: !weak.length,
          link: d.zt("settings/devices"),
          detail: `In ${p.default ? "the default device profile" : `profile "${p.name}"`}, ${weak.join(" and ")}.`,
        });
      }
    }
    if (enrolled && inv.devicePosture) {
      report("ZT-020", {
        resource: "account",
        pass: inv.devicePosture.length > 0,
        link: d.zt("settings/devices/posture"),
        detail: `${enrolled} devices are enrolled and there are no posture checks.`,
      });
    }

    // ZT-022: one finding for all idle seats, not one per user.
    if (inv.accessUsers) {
      const idle = inv.accessUsers.filter(
        (u) =>
          u.access_seat &&
          (() => {
            const t = parseDate(u.last_successful_login);
            return t == null || daysSince(t, inv.now) > SEAT_IDLE_DAYS;
          })(),
      );
      const seats = inv.accessUsers.filter((u) => u.access_seat).length;
      if (seats) {
        report("ZT-022", {
          resource: "account",
          pass: idle.length === 0,
          link: d.zt("team/users"),
          detail: `${idle.length} of ${seats} users holding an Access seat haven't signed in for ${SEAT_IDLE_DAYS} days.`,
          evidence: { users: idle.slice(0, 50).map((u) => u.email || u.name || u.id) },
        });
      }
    }
  },
);
