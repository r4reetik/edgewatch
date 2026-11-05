// What the browser sees of stored objects. Tokens and webhook URLs are secrets,
// so only hints leave the server.

import { displayName, type Account, type Entity } from "../store/repo.ts";
import type { TokenVault } from "../config.ts";
import type { EntityView, SessionAccount, SessionEntity } from "../shared/api.ts";

export const publicAccount = (vault: TokenVault, a: Account): SessionAccount => ({
  id: a.id,
  name: a.name,
  alias: a.alias,
  display: displayName(a),
  entityId: a.entityId,
  scheduled: a.scheduled,
  tokenHint: vault.hint(a.tokenId),
  tokenKind: a.tokenKind,
  tokenMissing: !vault.get(a.tokenId),
});

export const sessionEntity = (e: Entity): SessionEntity => ({ id: e.id, name: e.name, includeInAll: e.includeInAll });

const hint = (u: string) => (u ? `…${u.slice(-6)}` : "");

export function publicEntity(e: Entity): EntityView {
  const n = e.notifications;
  return {
    ...sessionEntity(e),
    orgDomains: e.orgDomains,
    position: e.position,
    notifications: {
      minSeverity: n.minSeverity,
      slackConfigured: !!n.slackWebhookUrl,
      slackHint: hint(n.slackWebhookUrl),
      webhookConfigured: !!n.webhookUrl,
      webhookHint: hint(n.webhookUrl),
    },
  };
}

export const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40) || "account";

export function csvCell(v: unknown): string {
  let s = v == null ? "" : String(v);
  // Neutralize spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}
