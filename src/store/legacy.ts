// One-time upgrade from Keelson 0.2, which scanned a single account: its
// config.json token becomes the first account in a new entity, and the global
// email domains and alert destinations move onto that entity.

import { readLegacyConfig, removeLegacyConfig, type TokenVault } from "../config.ts";
import { DEFAULT_NOTIFICATIONS, type Repo } from "./repo.ts";

export function importLegacy(dataDir: string, repo: Repo, vault: TokenVault, log: (m: string) => void): void {
  const legacy = readLegacyConfig(dataDir);
  const orgDomains = repo.settings.raw("orgDomains") as string[] | undefined;
  const n = repo.settings.raw("notifications") as Record<string, string> | undefined;
  if (legacy && !repo.accounts.list().length) {
    const entity = repo.entities.create(legacy.accountName || "My organization", {
      orgDomains: orgDomains || [],
      notifications: {
        slackWebhookUrl: n?.slackWebhookUrl || "",
        webhookUrl: n?.webhookUrl || "",
        minSeverity: (n?.minSeverity as typeof DEFAULT_NOTIFICATIONS.minSeverity) || DEFAULT_NOTIFICATIONS.minSeverity,
      },
    });
    const tokenId = vault.put(legacy.token, legacy.tokenKind);
    repo.accounts.add({ id: legacy.accountId, name: legacy.accountName, entityId: entity.id, tokenId, tokenKind: legacy.tokenKind });
    log(`Imported account ${legacy.accountName || legacy.accountId} from the previous version.`);
  }
  if (legacy) removeLegacyConfig(dataDir);
  if (n !== undefined || orgDomains !== undefined) {
    const settings = repo.settings.get();
    repo.settings.delete("notifications");
    repo.settings.delete("orgDomains");
    repo.settings.save(settings);
  }
}
