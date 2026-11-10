// Access key verification, the account the key belongs to, and the permission
// probe for the setup screen. An access key belongs to one AWS account, so the
// "accounts it can read" are that one.

import { AwsClient, parseCredentials, type AwsError } from "./client.ts";
import { AWS_SOURCES, AWS_SOURCE_KEYS, HOME_REGION } from "./sources.ts";
import { AWS_CHECKS } from "./catalog.ts";
import { find, text } from "./xml.ts";
import type { PermissionProbe, TokenInfo } from "../../shared/api.ts";

const BAD_FORMAT =
  "Enter the access key ID (it starts with AKIA) and its secret access key. Temporary keys (ASIA…) expire within hours and can't be used for daily scans.";

/** A client for the key, or the reason it can't be one. */
export function clientFor(token: string, accountId = ""): AwsClient {
  const creds = parseCredentials(token);
  if (!creds) throw new Error(BAD_FORMAT);
  return new AwsClient(creds, accountId);
}

async function identityOf(client: AwsClient): Promise<{ account: string; root: boolean }> {
  const doc = await client.query("sts", HOME_REGION, "GetCallerIdentity");
  return { account: text(find(doc, "Account")) ?? "", root: /:root$/.test(text(find(doc, "Arn")) ?? "") };
}

export async function verifyAwsKey(token: string): Promise<TokenInfo> {
  if (!parseCredentials(token)) return { valid: false, kind: null, message: BAD_FORMAT };
  try {
    const { root } = await identityOf(clientFor(token));
    // "account": the key is the root user's, which checks report on their own.
    return { valid: true, kind: root ? "account" : "user", status: "active", expiresOn: null };
  } catch (e) {
    const err = e as AwsError;
    return {
      valid: false,
      kind: null,
      message: err.denied ? "AWS didn't accept this access key. Check that it is active and that the secret was copied completely." : err.message,
    };
  }
}

/** The one account the key belongs to, named by its alias when it has one. */
export async function listAwsAccounts(token: string): Promise<{ id: string; name: string }[]> {
  const client = clientFor(token);
  const { account } = await identityOf(client);
  if (!account) return [];
  const alias = await client
    .query("iam", HOME_REGION, "ListAccountAliases")
    .then((d) => text(find(d, "AccountAliases"), "member"))
    .catch(() => null);
  return [{ id: account, name: alias ?? account }];
}

/** One request per source with a probe, and the checks each source powers. */
export async function probeAws(token: string, accountId: string): Promise<PermissionProbe[]> {
  const client = clientFor(token, accountId);
  return Promise.all(
    AWS_SOURCE_KEYS.filter((k) => AWS_SOURCES[k].probe).map(async (k): Promise<PermissionProbe> => {
      const s = AWS_SOURCES[k];
      const titles = [...new Set(AWS_CHECKS.filter((c) => c.requires?.includes(k)).map((c) => c.title))];
      const base = {
        source: s.label,
        permission: s.permission,
        powers: titles.length ? `${titles.length} check${titles.length === 1 ? "" : "s"}, e.g. ${titles.slice(0, 2).join("; ")}` : "Inventory",
      };
      try {
        await s.probe!(client);
        return { ...base, ok: true };
      } catch (e) {
        const err = e as AwsError;
        return { ...base, ok: false, status: err.status, message: err.message };
      }
    }),
  );
}
