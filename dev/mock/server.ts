// Edgewatch against a mocked Cloudflare API: three accounts in two entities,
// in memory, scanned twice so trends and "new since last scan" have data.
// Run with `npm run dev -- --mock` (or `node dev/mock/server.ts`).

import "../../src/warnings.ts";
import { start } from "../../src/main.ts";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_ACCOUNT_2, MOCK_ACCOUNT_3, MOCK_TOKEN_2 } from "./cloudflare.ts";
import { seedAccount, seedTriageHistory } from "./accounts.ts";

installMockCloudflare();
const port = Number(process.env.EDGEWATCH_PORT || 4317);
const running = await start({
  host: "127.0.0.1",
  port,
  dataDir: null,
  password: null,
  insecureNoAuth: false,
  trustProxy: false,
  allowedHosts: [],
  schedule: false,
});
const { repo, vault, scanner } = running;
repo.settings.save({ ...repo.settings.get(), probes: { takeover: false } });
seedAccount(repo, vault, { entity: "Mock Group" });
seedAccount(repo, vault, { id: MOCK_ACCOUNT_3, name: "Mock Co Staging", entity: "Mock Group" });
const other = seedAccount(repo, vault, { id: MOCK_ACCOUNT_2, token: MOCK_TOKEN_2, name: "Other Ltd", entity: "Other Ltd" });
repo.entities.update(other.entityId, { ...repo.entities.get(other.entityId)!, orgDomains: ["other.example"], includeInAll: false });
await scanner.start("setup").done;
await scanner.start("manual").done;
seedTriageHistory(repo, MOCK_ACCOUNT);
console.log(`\n  Edgewatch (mock Cloudflare data)\n\n  Open:  ${running.url}\n`);
