// Token entry, verification, account selection and permission check. Used by
// first-run setup and by Accounts → Add accounts.

import { useEffect, useMemo, useState } from "react";
import { Badge, Banner, Button, Input, Link, Select, SensitiveInput, Table, LayerCard } from "@cloudflare/kumo";
import { ArrowSquareOutIcon, CheckCircleIcon, WarningIcon, XCircleIcon } from "@phosphor-icons/react";
import { api, plural, type SessionEntity } from "../lib.ts";
import { FormGrid } from "./ui.tsx";
import type { PermissionProbe, VisibleAccount, VerifyResponse, AddAccountsResponse } from "../lib.ts";
type Probe = PermissionProbe;
type Verify = VerifyResponse;
export type Connected = AddAccountsResponse;

const NEW = "new";

export function TokenHelp() {
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    api<{ url: string }>("/api/accounts/template")
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

export function ConnectForm({
  entities,
  defaultEntityId,
  onConnected,
  submitLabel,
}: {
  entities: SessionEntity[];
  defaultEntityId?: number;
  onConnected: (r: Connected) => void;
  submitLabel?: (n: number) => string;
}) {
  const [token, setToken] = useState("");
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
      const r = await api<Verify>("/api/accounts/verify", { method: "POST", body: { token, accountIds } });
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
      onConnected(await api<Connected>("/api/accounts", { method: "POST", body: { token, accountIds: ids, ...target } }));
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

  return (
    <div className="flex flex-col gap-4">
      <SensitiveInput
        label="API token"
        value={token}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
          setToken(e.target.value.trim());
          setResult(null);
          setSelected(new Set());
        }}
        onKeyDown={(e: React.KeyboardEvent) => {
          // Enter verifies a pasted token, like submitting a form.
          if (e.key === "Enter" && token && !result && !busy) void verify([]);
        }}
        description="Stored only on this machine, readable by your user only. It is never shown again or sent anywhere except api.cloudflare.com."
      />

      {err && <Banner variant="error" icon={<XCircleIcon weight="fill" />} title="Something went wrong" description={err} />}
      {result && !valid && (
        <Banner
          variant="error"
          icon={<XCircleIcon weight="fill" />}
          title="Cloudflare rejected this token"
          description={result.token.message || "Check that it was copied completely and hasn't expired."}
        />
      )}
      {valid && !accounts.length && (
        <Banner
          variant="alert"
          icon={<WarningIcon weight="fill" />}
          title="This token can't see any account"
          description="Edit the token in Cloudflare and include at least one account."
        />
      )}

      {valid && accounts.length > 0 && (
        <div className="flex flex-col gap-2">
          <div className="text-sm font-medium text-kumo-default">Accounts to scan</div>
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
                  <Table.Head>Account</Table.Head>
                  <Table.Head>Account ID</Table.Head>
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
                          {selected.has(a.id) ? "Token will be replaced" : `Added${entityOf(a.entityId) ? ` to ${entityOf(a.entityId)}` : ""}`}
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
              description="The company or team that owns these accounts. Accounts already added stay where they are."
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
                entities.length
                  ? undefined
                  : "The company or team that owns these accounts. Later you can add accounts from other companies as separate entities, and keep them out of combined views."
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
            description="You can add the accounts now; the checks below are skipped until the token gets the permissions."
          />
        ) : (
          <Banner
            icon={<CheckCircleIcon weight="fill" />}
            title="Token verified"
            description={`A ${result!.token.kind}-owned token with read access to everything Edgewatch checks${ids.length > probeLimit ? ` (checked on the first ${probeLimit} accounts)` : ""}.`}
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
        {valid && ids.length === 0 && accounts.length > 0 && <span className="mr-auto text-sm text-kumo-subtle">Select at least one account.</span>}
        {(!valid || stale) && (
          <Button variant={valid ? "secondary" : "primary"} disabled={!token} loading={busy === "verify"} onClick={() => verify(valid ? ids : [])}>
            {valid ? "Check permissions" : "Verify token"}
          </Button>
        )}
        {valid && ids.length > 0 && (
          <Button variant="primary" loading={busy === "save"} disabled={busy === "verify"} onClick={save}>
            {submitLabel ? submitLabel(ids.length) : `Add ${plural(ids.length, "account")} and scan`}
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
