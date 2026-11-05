// Post-scan notifications: Slack incoming webhooks (Block Kit) and a generic
// JSON webhook. Only https URLs are accepted, requests time out after 10s, and
// failures are logged without the URL (webhook URLs are secrets).

import { SEVERITY_WEIGHT } from "./core/catalog.ts";
import type { EntityNotifications } from "./store/repo.ts";
import type { Severity } from "./core/types.ts";

export interface ScanSummary {
  accountId: string;
  accountName: string;
  entityName: string;
  scanId: number;
  finishedAt: string;
  score: number | null;
  counts: Record<string, number>;
  newFindings: { fingerprint?: string; severity: Severity; title: string; resource: string; zone: string | null; reopened?: boolean }[];
}

export function validWebhookUrl(u: string): boolean {
  if (!u) return true;
  try {
    const url = new URL(u);
    return url.protocol === "https:" && !!url.hostname;
  } catch {
    return false;
  }
}

/** Sends a summary to the entity's destinations when there are new findings at or above its severity. */
export async function notifyScan(n: EntityNotifications, baseUrl: string, s: ScanSummary, log: (msg: string) => void): Promise<void> {
  if (!n.slackWebhookUrl && !n.webhookUrl) return;
  const min = SEVERITY_WEIGHT[n.minSeverity] ?? SEVERITY_WEIGHT.high;
  const relevant = s.newFindings.filter((f) => SEVERITY_WEIGHT[f.severity] >= min);
  if (!relevant.length) return;
  await send(n, baseUrl, { ...s, newFindings: relevant }, log);
}

export async function sendTest(n: EntityNotifications, baseUrl: string, entityName: string): Promise<{ slack?: string; webhook?: string }> {
  const sample: ScanSummary = {
    accountId: "",
    accountName: "Test account",
    entityName,
    scanId: 0,
    finishedAt: new Date().toISOString(),
    score: 72.5,
    counts: { critical: 0, high: 1, medium: 4, low: 9 },
    newFindings: [{ severity: "high", title: "This is a test notification from Edgewatch", resource: "example.com", zone: "example.com" }],
  };
  const out: { slack?: string; webhook?: string } = {};
  await send(
    n,
    baseUrl,
    sample,
    () => {},
    (kind, result) => {
      out[kind] = result;
    },
  );
  return out;
}

async function send(
  n: EntityNotifications,
  baseUrl: string,
  s: ScanSummary,
  log: (m: string) => void,
  report?: (kind: "slack" | "webhook", result: string) => void,
) {
  // Links open what's new in the scanned account, and each finding's own page.
  const base = baseUrl ? baseUrl.replace(/\/$/, "") : null;
  const link = base ? `${base}/findings${s.accountId ? `?scope=a:${s.accountId}&status=new` : ""}` : null;
  const findingUrl = (fp?: string) => (base && fp ? `${base}/findings/${fp}` : null);
  const jobs: Promise<void>[] = [];
  if (n.slackWebhookUrl)
    jobs.push(
      post(n.slackWebhookUrl, slackPayload(s, link, findingUrl)).then((r) => {
        report?.("slack", r);
        if (r !== "ok") log(`Slack notification failed: ${r}`);
      }),
    );
  if (n.webhookUrl)
    jobs.push(
      post(n.webhookUrl, {
        event: "scan.new_findings",
        account: s.accountName,
        accountId: s.accountId || null,
        entity: s.entityName,
        scanId: s.scanId,
        finishedAt: s.finishedAt,
        score: s.score,
        openCounts: s.counts,
        newFindings: s.newFindings.map((f) => ({ ...f, url: findingUrl(f.fingerprint) })),
        url: link,
      }).then((r) => {
        report?.("webhook", r);
        if (r !== "ok") log(`Webhook notification failed: ${r}`);
      }),
    );
  await Promise.all(jobs);
}

async function post(url: string, body: unknown): Promise<string> {
  if (!validWebhookUrl(url)) return "URL must be https";
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
      // A redirect could send the alert somewhere other than the https URL that was configured.
      redirect: "error",
    });
    return res.ok ? "ok" : `HTTP ${res.status}`;
  } catch (e) {
    return (e as Error).name === "TimeoutError" ? "timed out" : "request failed";
  }
}

const SEV_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

/** Slack rejects a section over 3000 characters, which would lose the whole alert. */
const SLACK_SECTION_MAX = 2900;
const SLACK_LINES_MAX = 15;
const clip = (t: string, n: number) => (t.length > n ? `${t.slice(0, n - 1)}…` : t);

function slackPayload(s: ScanSummary, link: string | null, findingUrl: (fp?: string) => string | null) {
  const lines: string[] = [];
  let size = 0;
  for (const f of s.newFindings.slice(0, SLACK_LINES_MAX)) {
    const url = findingUrl(f.fingerprint);
    const title = url ? `<${url}|${esc(f.title)}>` : esc(f.title);
    const line = `• *${SEV_LABEL[f.severity]}*${f.reopened ? " (came back)" : ""}: ${title} (${esc(clip(f.resource, 120))})`;
    if (size + line.length + 40 > SLACK_SECTION_MAX) break;
    lines.push(line);
    size += line.length + 1;
  }
  if (s.newFindings.length > lines.length) lines.push(`…and ${s.newFindings.length - lines.length} more`);
  const back = s.newFindings.filter((f) => f.reopened).length;
  const headline = `${s.newFindings.length} new finding${s.newFindings.length === 1 ? "" : "s"} in ${esc(s.accountName)}${back ? ` (${back} came back after being fixed)` : ""}`;
  return {
    text: headline,
    blocks: [
      { type: "header", text: { type: "plain_text", text: headline.slice(0, 150) } },
      { type: "section", text: { type: "mrkdwn", text: lines.join("\n") } },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `${esc(s.entityName)} · posture score ${s.score ?? "n/a"} · open: ${s.counts.critical || 0} critical, ${s.counts.high || 0} high · Edgewatch`,
          },
        ],
      },
      ...(link ? [{ type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "See what's new" }, url: link }] }] : []),
    ],
  };
}

const esc = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
