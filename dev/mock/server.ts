// Edgewatch against mocked provider APIs (Cloudflare, Vercel and AWS), in memory:
// three Cloudflare accounts, a Vercel team and an AWS account in two entities,
// plus a Vercel-only entity with a personal account. Everything is scanned twice,
// so trends, "new since last scan" and the checks that span providers have data.
// Run with `npm run dev -- --mock` (or `node dev/mock/server.ts`).

import "../../src/warnings.ts";
import { start } from "../../src/main.ts";
import { installMockCloudflare, MOCK_ACCOUNT, MOCK_ACCOUNT_2, MOCK_ACCOUNT_3, MOCK_TOKEN_2 } from "./cloudflare.ts";
import { installMockVercel } from "./vercel.ts";
import { installMockAws, mockAws } from "./aws.ts";
import { seedAccount, seedAws, seedTriageHistory, seedVercel } from "./accounts.ts";
import { providerList } from "../../src/shared/providers.ts";

installMockCloudflare();
installMockVercel();
installMockAws();
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
  updateCheck: false,
});
const { repo, vault, scanner } = running;
repo.settings.save({ ...repo.settings.get(), probes: { takeover: false } });
seedAccount(repo, vault, { entity: "Mock Group" });
seedAccount(repo, vault, { id: MOCK_ACCOUNT_3, name: "Mock Co Staging", entity: "Mock Group" });
const other = seedAccount(repo, vault, { id: MOCK_ACCOUNT_2, token: MOCK_TOKEN_2, name: "Other Ltd", entity: "Other Ltd" });
repo.entities.update(other.entityId, { ...repo.entities.get(other.entityId)!, orgDomains: ["other.example"], includeInAll: false });
seedVercel(repo, vault, { entity: "Mock Group", personal: { entity: "Side Projects" } });
seedAws(repo, vault, { entity: "Mock Group" });
await scanner.start("setup").done;
// Between the scans the AWS account gives up an Elastic IP, so the second one finds the DNS records still pointing at it.
mockAws.released = true;
await scanner.start("manual").done;
// Once more for Cloudflare, which was scanned before AWS noticed the address was gone.
await scanner.start("manual", [MOCK_ACCOUNT]).done;
seedTriageHistory(repo, MOCK_ACCOUNT);
console.log(`\n  Edgewatch (mock ${providerList()} data)\n\n  Open:  ${running.url}\n`);
