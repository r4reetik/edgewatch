// What every provider gives the rest of Edgewatch. The scanner, the account routes
// and the setup screen only talk to providers through this interface, so adding a
// provider (AWS, Google Cloud, Google Workspace…) means implementing it once and
// listing it in ./index.ts. See "Adding a provider" in CONTRIBUTING.md.

import type { Evaluation } from "../core/engine.ts";
import type { EngineOptions, ProgressEvent } from "../core/types.ts";
import type { CheckMeta } from "../core/checks/define.ts";
import type { Coverage, PermissionProbe, ScanSnapshot, TokenInfo } from "../shared/api.ts";
import type { ProviderId, ProviderInfo } from "../shared/providers.ts";
import type { Account } from "../store/repo.ts";

export interface CheckDef extends CheckMeta<string> {
  id: string;
  provider: ProviderId;
}

export interface ScanInput {
  token: string;
  account: Account;
  engine: EngineOptions;
  /** Send probes to the account's own hostnames (Settings → Live checks). */
  probeTakeovers: boolean;
  onProgress: (p: ProgressEvent) => void;
}

export interface ScanOutput {
  /** The account's name at the provider, to keep Edgewatch's copy current. */
  accountName: string | null;
  evaluation: Evaluation;
  /** Provider-specific parts of the snapshot (zones, projects, links…). */
  snapshot: Omit<ScanSnapshot, "accountName" | "coverage" | "checks">;
  coverage: Coverage[];
  calls: number;
}

export interface Provider {
  info: ProviderInfo;
  checks: CheckDef[];
  /** Where to create a token, and a pre-filled template when the provider has one. */
  tokenHelp(accountId: string | null): { url: string; templateUrl: string | null };
  verify(token: string, accountIds: string[]): Promise<TokenInfo>;
  /** Accounts (or teams) the token can read, for the setup picker. */
  listAccounts(token: string): Promise<{ id: string; name: string }[]>;
  probe(token: string, accountId: string): Promise<PermissionProbe[]>;
  scan(input: ScanInput): Promise<ScanOutput>;
  /** Domains an account's latest snapshot shows it owns: they count as internal email domains for the entity's other accounts. */
  ownedDomains(snapshot: ScanSnapshot): string[];
}
