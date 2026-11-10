// Choosing a provider, then entering its credential (a token, an access key),
// verification, account selection and permission check. Used by first-run setup
// and by Accounts → Add accounts. Each provider has its own steps for creating the
// credential (TokenHelp); the rest of the flow is shared and worded from
// PROVIDER_INFO, so it never branches on a provider's name.

import { useEffect, useMemo, useState } from "react";
import { Badge, Banner, Button, Input, Link, Radio, Select, SensitiveInput, Table, LayerCard } from "@cloudflare/kumo";
import { ArrowSquareOutIcon, CheckCircleIcon, WarningIcon, XCircleIcon } from "@phosphor-icons/react";
import {
  api,
  capitalize,
  CREDENTIAL_SEPARATOR,
  plural,
  PROVIDER_INFO,
  PROVIDERS,
  sameName,
  type ProviderId,
  type SessionEntity,
  type TemplateResponse,
} from "../lib.ts";
import { FormGrid, ProviderIcon } from "./ui.tsx";
import type { PermissionProbe, VisibleAccount, VerifyResponse, AddAccountsResponse } from "../lib.ts";
type Probe = PermissionProbe;
type Verify = VerifyResponse;
export type Connected = AddAccountsResponse;

const NEW = "new";

/** Which platform the accounts are on. Someone on one platform only ever sees that one's steps. */
export function ProviderPicker({ value, onChange }: { value: ProviderId; onChange: (p: ProviderId) => void }) {
  return (
    <Radio.Group legend="Platform" appearance="card" orientation="horizontal" value={value} onValueChange={(v) => onChange(v as ProviderId)}>
      {PROVIDERS.map((p) => (
        <Radio.Item
          key={p}
          value={p}
          label={
            <span className="inline-flex items-center gap-2">
              <ProviderIcon provider={p} className="h-4 w-4 text-kumo-default" />
              {PROVIDER_INFO[p].label}
            </span>
          }
          description={PROVIDER_INFO[p].blurb}
        />
      ))}
    </Radio.Group>
  );
}

/** How to create the credential, one set of steps per provider. A new provider doesn't compile until it has one. */
const TOKEN_HELP: Record<ProviderId, () => React.ReactNode> = { cloudflare: CloudflareTokenHelp, vercel: VercelTokenHelp, aws: AwsTokenHelp };

export function TokenHelp({ provider = "cloudflare" }: { provider?: ProviderId }) {
  const Help = TOKEN_HELP[provider];
  return <Help />;
}

/** The credential as it is sent and stored: one field as it is, several joined in order. */
export const joinCredential = (values: string[]) => (values.every((v) => v) ? values.join(CREDENTIAL_SEPARATOR) : "");

/**
 * The provider's credential inputs: one for a token, two for an AWS access key. Secret fields
 * are hidden while typing. The description sits under the last field.
 */
export function CredentialFields({
  provider,
  values,
  onChange,
  onEnter,
  description,
  error,
}: {
  provider: ProviderId;
  values: string[];
  onChange: (values: string[]) => void;
  onEnter?: () => void;
  description?: string;
  error?: string;
}) {
  const fields = PROVIDER_INFO[provider].fields;
  const inputs = fields.map((f, i) => {
    const last = i === fields.length - 1;
    const props = {
      className: "w-full",
      label: f.label,
      placeholder: f.placeholder,
      value: values[i] ?? "",
      onChange: (e: React.ChangeEvent<HTMLInputElement>) => onChange(fields.map((_, j) => (j === i ? e.target.value.trim() : (values[j] ?? "")))),
      // Enter submits a pasted credential, like a form.
      onKeyDown: (e: React.KeyboardEvent) => {
        if (e.key === "Enter") onEnter?.();
      },
      description: last ? description : undefined,
      variant: (last && error ? "error" : "default") as "error" | "default",
      error: last ? error || undefined : undefined,
    };
    return f.secret ? <SensitiveInput key={f.label} {...props} /> : <Input key={f.label} {...props} autoComplete="off" spellCheck={false} />;
  });
  return fields.length > 1 ? <FormGrid>{inputs}</FormGrid> : inputs[0];
}

function CloudflareTokenHelp() {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    api<TemplateResponse>("/api/accounts/template?provider=cloudflare")
      .then((r) => setUrl(r.url))
      .catch(() => {});
  }, []);
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li>
        In the Cloudflare dashboard, go to <span className="font-medium">My Profile → API Tokens → Create Token</span> and pick the{" "}
        <span className="font-medium">Read all resources</span> template. It covers every check and can only read.{" "}
        <Link href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
          Open API Tokens <ArrowSquareOutIcon />
        </Link>
      </li>
      <li>
        Prefer the smallest grant?{" "}
        {url ? (
          <Link href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
            Start from a pre-filled read-only token <ArrowSquareOutIcon />
          </Link>
        ) : (
          "Start from a pre-filled read-only token"
        )}{" "}
        and add the Security Center, Tunnel, Notifications and Access read permissions that the template link can't pre-fill.
      </li>
      <li>
        Include the accounts you want to scan. One token can cover several accounts; accounts that belong to another company usually need their own token,
        created by someone with access to them.
      </li>
    </ol>
  );
}

function VercelTokenHelp() {
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li>
        In Vercel, go to <span className="font-medium">Account Settings → Tokens</span> and create a token named Edgewatch.{" "}
        <Link href="https://vercel.com/account/settings/tokens" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
          Open Tokens <ArrowSquareOutIcon />
        </Link>
      </li>
      <li>
        Set <span className="font-medium">Scope</span> to the team you want to scan, or <span className="font-medium">Full Account</span> for every team you
        belong to and your personal projects. Choose an expiration date.
      </li>
      <li>Edgewatch only reads from Vercel. Teams that belong to another company usually need their own token, created by one of their members.</li>
    </ol>
  );
}

function AwsTokenHelp() {
  return (
    <ol className="ml-5 list-decimal space-y-2 text-base text-kumo-default marker:text-kumo-subtle">
      <li>
        In the AWS console, go to <span className="font-medium">IAM → Users → Create user</span>. Name it edgewatch and leave console access off.{" "}
        <Link href="https://console.aws.amazon.com/iam/home#/users/create" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
          Open IAM <ArrowSquareOutIcon />
        </Link>
      </li>
      <li>
        Choose <span className="font-medium">Attach policies directly</span> and attach AWS's managed <span className="font-medium">SecurityAudit</span> policy.
        It reads configuration only: it can't change anything, and it can't read what is stored in your buckets or databases.
      </li>
      <li>
        Open the user, go to <span className="font-medium">Security credentials → Create access key</span>, choose{" "}
        <span className="font-medium">Application running outside AWS</span>, and paste the key ID and the secret below. An access key belongs to one AWS
        account, so each account needs its own.
      </li>
    </ol>
  );
}

/** Remount it (key={provider}) when the provider changes: a credential belongs to one provider. */
export function ConnectForm({
  provider = "cloudflare",
  entities,
  defaultEntityId,
  onConnected,
  submitLabel,
}: {
  provider?: ProviderId;
  entities: SessionEntity[];
  defaultEntityId?: number;
  onConnected: (r: Connected) => void;
  submitLabel?: (n: number) => string;
}) {
  const info = PROVIDER_INFO[provider];
  const unit = info.account;
  const Unit = capitalize(unit);
  const cred = info.credential;
  const [values, setValues] = useState<string[]>(() => info.fields.map(() => ""));
  const token = joinCredential(values);
  const [result, setResult] = useState<Verify | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [probedKey, setProbedKey] = useState("");
  const [entity, setEntity] = useState(defaultEntityId != null ? String(defaultEntityId) : entities[0] ? String(entities[0].id) : NEW);
  const [entityName, setEntityName] = useState("");
  const [busy, setBusy] = useState<"verify" | "save" | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const ids = useMemo(() => [...selected].sort(), [selected]);
  // The server probes permissions on the first few accounts only; it says how many.
  const probeLimit = result?.probeLimit ?? ids.length;
  const key = ids.slice(0, probeLimit).join(",");

  const verify = async (accountIds: string[]) => {
    setBusy("verify");
    setErr(null);
    try {
      const r = await api<Verify>("/api/accounts/verify", { method: "POST", body: { provider, token, accountIds } });
      setResult(r);
      setProbedKey(accountIds.slice(0, r.probeLimit).join(","));
      // First check of a token: select every account it can see that isn't added yet, then check those.
      if (r.token.valid && !accountIds.length) {
        // A token that reaches an account already added most likely belongs to the same company.
        const sibling = r.accounts.find((a) => a.added && a.entityId != null);
        if (defaultEntityId == null && sibling) setEntity(String(sibling.entityId));
        const fresh = r.accounts
          .filter((a) => !a.added)
          .map((a) => a.id)
          .sort();
        setSelected(new Set(fresh));
        if (fresh.length) await verify(fresh);
      }
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const save = async () => {
    setBusy("save");
    setErr(null);
    try {
      const target = entity === NEW ? { entityName: entityName.trim() || suggestedName } : { entityId: Number(entity) };
      onConnected(await api<Connected>("/api/accounts", { method: "POST", body: { provider, token, accountIds: ids, ...target } }));
    } catch (e) {
      setErr((e as Error).message);
      setBusy(null);
    }
  };

  const valid = result?.token.valid;
  const accounts = result?.accounts || [];
  const suggestedName = accounts.find((a) => a.id === ids[0])?.name || "My organization";
  const probes = mergeProbes(result?.probes || {}, accounts);
  const gaps = probes.filter((p) => !p.ok);
  const stale = valid && ids.length > 0 && key !== probedKey;
  const toggle = (id: string, on: boolean) =>
    setSelected((s) => {
      const n = new Set(s);
      if (on) n.add(id);
      else n.delete(id);
      return n;
    });
  const entityOf = (id: number | null) => entities.find((e) => e.id === id)?.name;
  // Typing the name of an entity that already exists most likely means that entity, not a second one.
  const existing = entity === NEW ? entities.find((e) => sameName(e.name, entityName || suggestedName)) : undefined;

  return (
    <div className="flex flex-col gap-4">
      <CredentialFields
        provider={provider}
        values={values}
        onChange={(v) => {
          setValues(v);
          setResult(null);
          setSelected(new Set());
        }}
        onEnter={() => {
          if (token && !result && !busy) void verify([]);
        }}
        description={`Stored only on this machine, readable by your user only. It is never shown again or sent anywhere except ${info.apiHost}.`}
      />

      {err && <Banner variant="error" icon={<XCircleIcon weight="fill" />} title="Something went wrong" description={err} />}
      {result && !valid && (
        <Banner
          variant="error"
          icon={<XCircleIcon weight="fill" />}
          title={`${info.label} rejected this ${cred}`}
          description={result.token.message || "Check that it was copied completely and hasn't expired."}
        />
      )}
      {valid && !accounts.length && (
        <Banner variant="alert" icon={<WarningIcon weight="fill" />} title={`This ${cred} can't see any ${unit}`} description={info.noAccounts} />
      )}

      {valid && accounts.length > 0 && (
        <div className="flex flex-col gap-2">
          <div className="text-sm font-medium text-kumo-default">{Unit}s to scan</div>
          <LayerCard className="max-h-64 overflow-auto bg-kumo-base p-0">
            <Table layout="auto">
              <Table.Header variant="compact">
                <Table.Row>
                  <Table.CheckHead
                    aria-label="Select all"
                    checked={ids.length === accounts.length}
                    indeterminate={ids.length > 0 && ids.length < accounts.length}
                    onCheckedChange={() => setSelected(new Set(ids.length === accounts.length ? [] : accounts.map((a) => a.id)))}
                  />
                  <Table.Head>{Unit}</Table.Head>
                  <Table.Head>{Unit} ID</Table.Head>
                  <Table.Head>
                    <span className="sr-only">State</span>
                  </Table.Head>
                </Table.Row>
              </Table.Header>
              <Table.Body>
                {accounts.map((a) => (
                  <Table.Row
                    key={a.id}
                    variant={selected.has(a.id) ? "selected" : "default"}
                    className="cursor-pointer"
                    onClick={() => toggle(a.id, !selected.has(a.id))}
                  >
                    <Table.CheckCell
                      checked={selected.has(a.id)}
                      onCheckedChange={(v: boolean) => toggle(a.id, v)}
                      onClick={(e: React.MouseEvent) => e.stopPropagation()}
                      aria-label={`Scan ${a.name}`}
                    />
                    <Table.Cell className="max-w-64 truncate text-kumo-default">{a.name}</Table.Cell>
                    <Table.Cell className="font-mono text-xs text-kumo-subtle">{a.id}</Table.Cell>
                    <Table.Cell className="whitespace-nowrap text-right">
                      {a.added && (
                        <Badge variant="neutral">
                          {selected.has(a.id) ? `${capitalize(cred)} will be replaced` : `Added${entityOf(a.entityId) ? ` to ${entityOf(a.entityId)}` : ""}`}
                        </Badge>
                      )}
                    </Table.Cell>
                  </Table.Row>
                ))}
              </Table.Body>
            </Table>
          </LayerCard>
        </div>
      )}

      {valid && ids.length > 0 && (
        <FormGrid>
          {entities.length > 0 && (
            <Select
              className="w-full"
              label="Entity"
              hideLabel={false}
              value={entity}
              onValueChange={(v) => setEntity(String(v))}
              description={`The company or team that owns these ${info.accounts}. An entity can hold accounts from every platform. Ones already added stay where they are.`}
              items={{ ...Object.fromEntries(entities.map((e) => [String(e.id), e.name])), [NEW]: "New entity…" }}
            />
          )}
          {entity === NEW && (
            <Input
              className="w-full"
              label={entities.length ? "New entity name" : "Entity name"}
              placeholder={suggestedName}
              value={entityName}
              maxLength={80}
              onChange={(e) => setEntityName(e.target.value)}
              description={
                existing ? (
                  <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    {existing.name} already exists.
                    <Button type="button" size="sm" variant="secondary" onClick={() => setEntity(String(existing.id))}>
                      Add to {existing.name}
                    </Button>
                  </span>
                ) : entities.length ? undefined : (
                  `The company or team that owns these ${info.accounts}. Later you can add its accounts on other platforms to the same entity, and other companies as separate entities.`
                )
              }
            />
          )}
        </FormGrid>
      )}

      {valid &&
        !stale &&
        ids.length > 0 &&
        probes.length > 0 &&
        (gaps.length ? (
          <Banner
            variant="alert"
            icon={<WarningIcon weight="fill" />}
            title={`${plural(gaps.length, "data source")} not readable`}
            description={`You can add the ${info.accounts} now; the checks below are skipped until the ${cred} ${info.needsToRead}.`}
          />
        ) : (
          <Banner
            icon={<CheckCircleIcon weight="fill" />}
            title={`${capitalize(cred)} verified`}
            description={`The ${cred} can read everything Edgewatch checks${ids.length > probeLimit ? ` (checked on the first ${probeLimit} ${info.accounts})` : ""}.`}
          />
        ))}

      {valid && !stale && gaps.length > 0 && (
        <LayerCard className="max-h-72 overflow-auto bg-kumo-base p-0">
          <Table>
            <Table.Header variant="compact">
              <Table.Row>
                <Table.Head>Data</Table.Head>
                <Table.Head>Used for</Table.Head>
                <Table.Head>Access</Table.Head>
              </Table.Row>
            </Table.Header>
            <Table.Body>
              {[...probes]
                .sort((a, b) => Number(a.ok) - Number(b.ok))
                .map((p) => (
                  <Table.Row key={p.source}>
                    <Table.Cell>
                      <div className="text-kumo-default">{p.source}</div>
                      {!p.ok && <div className="text-xs text-kumo-subtle">Needs {p.permission}</div>}
                    </Table.Cell>
                    <Table.Cell className="text-xs text-kumo-subtle">{p.powers}</Table.Cell>
                    <Table.Cell>
                      {p.ok ? (
                        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
                          <CheckCircleIcon weight="fill" className="text-kumo-success" />
                          Readable
                        </span>
                      ) : (
                        <span className="inline-flex items-start gap-1.5">
                          <XCircleIcon weight="fill" className="mt-0.5 shrink-0 text-kumo-danger" />
                          {p.missing.length < ids.length ? `No access in ${p.missing.join(", ")}` : "No access"}
                        </span>
                      )}
                    </Table.Cell>
                  </Table.Row>
                ))}
            </Table.Body>
          </Table>
        </LayerCard>
      )}

      <div className="flex flex-wrap items-center justify-end gap-2">
        {valid && ids.length === 0 && accounts.length > 0 && <span className="mr-auto text-sm text-kumo-subtle">Select at least one {unit}.</span>}
        {(!valid || stale) && (
          <Button variant={valid ? "secondary" : "primary"} disabled={!token} loading={busy === "verify"} onClick={() => verify(valid ? ids : [])}>
            {valid ? "Check permissions" : `Verify ${cred}`}
          </Button>
        )}
        {valid && ids.length > 0 && (
          <Button variant="primary" loading={busy === "save"} disabled={busy === "verify"} onClick={save}>
            {submitLabel ? submitLabel(ids.length) : `Add ${plural(ids.length, unit)} and scan`}
          </Button>
        )}
      </div>
    </div>
  );
}

/** One row per data source; `missing` names the probed accounts that can't read it. */
function mergeProbes(byAccount: Record<string, Probe[]>, accounts: VisibleAccount[]) {
  const name = (id: string) => accounts.find((a) => a.id === id)?.name || id;
  const out = new Map<string, Probe & { missing: string[] }>();
  for (const [id, list] of Object.entries(byAccount)) {
    for (const p of list) {
      const cur = out.get(p.source) || out.set(p.source, { ...p, ok: true, missing: [] }).get(p.source)!;
      if (!p.ok) {
        cur.ok = false;
        cur.missing.push(name(id));
      }
    }
  }
  return [...out.values()];
}
