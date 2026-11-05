// Monitoring: recommended notifications, broken alert and log delivery, and
// what Access sign-in analytics show.

import { defineChecks } from "./define.ts";
import { parseDate, proxiedZone } from "./helpers.ts";
import type { Inventory } from "../types.ts";

// Notifications worth having, with the condition under which they apply.
const RECOMMENDED_ALERTS: [string, string, (inv: Inventory) => boolean][] = [
  ["security_insights_alert", "Security Center finds a new issue", () => true],
  ["dos_attack_l7", "HTTP DDoS attack detected", (inv) => inv.zones.some(proxiedZone)],
  ["universal_ssl_event_type", "Edge certificate validation or renewal problems", (inv) => inv.zones.some(proxiedZone)],
  ["tunnel_health_event", "A Cloudflare Tunnel goes down", (inv) => (inv.tunnels || []).length > 0],
  ["expiring_service_token_alert", "An Access service token is about to expire", (inv) => (inv.serviceTokens || []).length > 0],
  ["real_origin_monitoring", "Origin becomes unreachable (Pro and above)", (inv) => inv.zones.some((z) => z.plan !== "free" && proxiedZone(z))],
  ["incident_alert", "Cloudflare incident affecting products you use", () => true],
];
/** Failed logins in a week, and how many times the successes, before an application is flagged. */
const LOGIN_FAILURES_MIN = 1000;
const LOGIN_FAILURE_RATIO = 5;

export default defineChecks(
  {
    "MON-001": {
      category: "Monitoring",
      severity: "medium",
      docs: "https://developers.cloudflare.com/notifications/",
      requires: ["notifications"],
      title: "Recommended notification not configured",
      why: "You won't hear about this class of problem until users report it.",
      fix: "Create the notification under Manage Account → Notifications.",
    },
    "MON-002": {
      category: "Monitoring",
      severity: "medium",
      docs: "https://developers.cloudflare.com/logs/logpush/logpush-health/",
      requires: ["logpushHealth"],
      title: "A Logpush job is failing to deliver logs",
      why: "Security logs your SIEM or storage depends on aren't arriving, so detections and investigations run on missing data.",
      fix: "Open Analytics & Logs → Logpush, check the job's last error (expired credentials and full buckets are common), and fix the destination.",
    },
    "MON-003": {
      category: "Monitoring",
      severity: "medium",
      docs: "https://developers.cloudflare.com/notifications/get-started/configure-webhooks/",
      requires: ["notifications"],
      title: "Notification webhook is insecure or failing",
      why: "Alerts sent over plain HTTP can be read or forged in transit, and a webhook that keeps failing means nobody sees the alerts at all.",
      fix: "Under Notifications → Destinations, switch the webhook to an https:// URL and fix whatever is rejecting deliveries.",
    },
    "MON-004": {
      category: "Monitoring",
      severity: "medium",
      docs: "https://developers.cloudflare.com/cloudflare-one/insights/logs/audit-logs/",
      requires: ["accessLogins", "accessApps"],
      title: "Access application rejects a high volume of logins",
      why: "Thousands of failed Access logins usually mean credential stuffing, a leaked or expired service token still in use, or a client misconfigured in a loop.",
      fix: "Open Logs → Access, filter by the application, and see who is failing: block abusive sources, rotate exposed tokens, or fix the client.",
    },
  },
  ({ inv, d }, report) => {
    if (inv.alertPolicies && inv.availableAlerts) {
      const available = new Set(
        Object.values(inv.availableAlerts)
          .flat()
          .map((a) => a.type),
      );
      const configured = new Set(inv.alertPolicies.filter((p) => p.enabled).map((p) => p.alert_type));
      for (const [type, label, applies] of RECOMMENDED_ALERTS) {
        if (!available.has(type) || !applies(inv)) continue;
        report("MON-001", { resource: label, pass: configured.has(type), detail: `Alert type: ${type}.`, link: d.notifications });
      }
    }

    for (const z of inv.zones) {
      const failures = z.analytics?.logpushFailures;
      if (!failures) continue;
      for (const f of failures) {
        report("MON-002", {
          zone: z.name,
          resource: `Logpush job ${f.jobId}`,
          pass: false,
          confidence: "confirmed",
          link: d.zone(z.name, "analytics/logs"),
          detail: `Job ${f.jobId} failed ${f.count.toLocaleString("en-US")} uploads in the last day${f.error ? `: ${f.error}` : ""}.`,
        });
      }
    }

    for (const w of inv.webhooks || []) {
      const insecure = String(w.url || "").startsWith("http://");
      const lastFail = parseDate(w.last_failure),
        lastOk = parseDate(w.last_success);
      const failing = lastFail != null && (lastOk == null || lastFail > lastOk);
      report("MON-003", {
        resource: w.name || w.url || w.id,
        pass: !insecure && !failing,
        link: `${d.notifications}/destinations`,
        detail: [
          insecure && "delivers over plain HTTP",
          failing && `last delivery failed on ${String(w.last_failure).slice(0, 10)}${lastOk ? ` (last success ${String(w.last_success).slice(0, 10)})` : ""}`,
        ]
          .filter(Boolean)
          .join(" and "),
      });
    }

    if (inv.accessLogins) {
      const names = new Map((inv.accessApps || []).map((a) => [a.id, a.name || a.domain || a.id]));
      for (const s of inv.accessLogins) {
        const noisy = s.failed >= LOGIN_FAILURES_MIN && s.failed > LOGIN_FAILURE_RATIO * s.success;
        if (!names.has(s.appId) && !noisy) continue;
        report("MON-004", {
          resource: names.get(s.appId) || `Access app ${s.appId}`,
          pass: !noisy,
          confidence: "likely",
          link: d.zt("logs/access"),
          detail: `${s.failed.toLocaleString("en-US")} failed and ${s.success.toLocaleString("en-US")} successful logins in the last 7 days${s.idps.length ? ` (login methods: ${s.idps.join(", ")})` : ""}.`,
          evidence: {
            chain: [
              { label: "Failed logins", value: s.failed.toLocaleString("en-US") },
              { label: "Successful logins", value: s.success.toLocaleString("en-US") },
              { label: "Countries with successful logins", value: s.countries.join(", ") || "none" },
            ],
          },
        });
      }
    }
  },
);
