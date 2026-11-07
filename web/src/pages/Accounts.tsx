// Accounts and the entities (companies or teams) that own them. This is where
// people decide how accounts are grouped, named and shown: which entities appear
// in "All accounts", the order of entities and accounts, display names, and
// each entity's email domains and alert destinations.

import { useEffect, useState } from "react";
import { Badge, Button, Dialog, DropdownMenu, Input, Select, SensitiveInput, Switch, Table, Tooltip, useKumoToastManager } from "@cloudflare/kumo";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  ArrowsClockwiseIcon,
  ArrowsLeftRightIcon,
  DotsThreeIcon,
  EnvelopeSimpleIcon,
  EyeIcon,
  KeyIcon,
  PencilSimpleIcon,
  PlusIcon,
  TrashIcon,
} from "@phosphor-icons/react";
import { useShell } from "../shell.tsx";
import { api, ago, navigate, plural, sameName, score, useApi, type AccountRow, type AccountsResponse, type Severity } from "../lib.ts";
import { DialogHeader, ListCard, Page, PageState } from "../components/ui.tsx";
import { ConnectForm, TokenHelp } from "../components/connect.tsx";

type Account = AccountRow;
type Entity = AccountsResponse["entities"][number];

type Modal =
  | { kind: "add"; entityId?: number }
  | { kind: "new-entity" }
  | { kind: "rename-entity"; entity: Entity }
  | { kind: "entity-settings"; entity: Entity }
  | { kind: "rename-account"; account: Account }
  | { kind: "token"; account: Account }
  | { kind: "remove"; account: Account }
  | null;

const TITLE = "Accounts";
const DESCRIPTION =
  "Cloudflare accounts Edgewatch scans, grouped by the company or team that owns them. Each entity has its own email domains and alerts, and you choose which entities appear together in All accounts.";

export function AccountsPage() {
  const { dataVersion, status, refreshSession, setScope, startScan } = useShell();
  const { data, error, loading, reload } = useApi<{ entities: Entity[] }>("/api/accounts", [dataVersion, status?.running, status?.accountId]);
  const toasts = useKumoToastManager();
  const [modal, setModal] = useState<Modal>(null);

  if (error || !data) return <PageState title={TITLE} description={DESCRIPTION} error={error} loading={loading} empty={false} retry={reload} />;

  const entities = data.entities;
  const refresh = async () => {
    await Promise.all([reload(), refreshSession()]);
  };
  /** Runs a change, then refreshes this page and the session (the scope switcher reads it). */
  const act = async (fn: () => Promise<unknown>, done?: string) => {
    try {
      await fn();
      await refresh();
      if (done) toasts.add({ title: done, variant: "success" });
      return true;
    } catch (e) {
      toasts.add({ title: "Couldn't save", description: (e as Error).message, variant: "error" });
      return false;
    }
  };
  const patchEntity = (e: Entity, body: Record<string, unknown>, done?: string) => act(() => api(`/api/entities/${e.id}`, { method: "PATCH", body }), done);
  const patchAccount = (a: Account, body: Record<string, unknown>, done?: string) => act(() => api(`/api/accounts/${a.id}`, { method: "PATCH", body }), done);
  const close = () => setModal(null);

  const actions = (
    <>
      <Button variant="secondary" icon={<PlusIcon />} onClick={() => setModal({ kind: "new-entity" })}>
        New entity
      </Button>
      <Button variant="primary" icon={<PlusIcon />} onClick={() => setModal({ kind: "add" })}>
        Add accounts
      </Button>
    </>
  );

  return (
    <Page title={TITLE} description={DESCRIPTION} actions={actions}>
      {entities.map((e, i) => (
        <EntityCard
          key={e.id}
          entity={e}
          entities={entities}
          first={i === 0}
          last={i === entities.length - 1}
          onModal={setModal}
          patchEntity={patchEntity}
          patchAccount={patchAccount}
          onDeleteEntity={() => act(() => api(`/api/entities/${e.id}`, { method: "DELETE", body: {} }), `${e.name} deleted`)}
          onShow={(scope) => {
            setScope(scope);
            navigate("/");
          }}
          onScan={(a) => startScan(`a:${a.id}`)}
        />
      ))}

      {modal?.kind === "add" && (
        <Dialog.Root open onOpenChange={(o: boolean) => !o && close()}>
          <Dialog size="xl" className="max-h-[90vh] overflow-y-auto p-6">
            <DialogHeader title="Add accounts" description="Paste a read-only token, pick the accounts it should scan, and choose the entity they belong to." />
            <div className="mb-6">
              <TokenHelp />
            </div>
            <ConnectForm
              entities={entities}
              defaultEntityId={modal.entityId}
              onConnected={async (r) => {
                close();
                await refresh();
                toasts.add({
                  title: r.added.length ? `${plural(r.added.length, "account")} added` : "Token replaced",
                  description: "Scans have started.",
                  variant: "success",
                });
              }}
            />
          </Dialog>
        </Dialog.Root>
      )}
      {modal?.kind === "new-entity" && (
        <NameDialog
          title="New entity"
          label="Name"
          placeholder="Acme Ltd"
          submit="Create entity"
          taken={entities.map((e) => e.name)}
          description="An entity is a company, legal entity or team. Accounts in different entities can be kept apart: each entity has its own email domains and alerts, and can be left out of All accounts."
          onClose={close}
          onSave={(name) => act(() => api("/api/entities", { method: "POST", body: { name } }), `${name} created`)}
        />
      )}
      {modal?.kind === "rename-entity" && (
        <NameDialog
          title="Rename entity"
          label="Name"
          initial={modal.entity.name}
          submit="Save"
          taken={entities.filter((e) => e.id !== modal.entity.id).map((e) => e.name)}
          onClose={close}
          onSave={(name) => patchEntity(modal.entity, { name }, "Entity renamed")}
        />
      )}
      {modal?.kind === "rename-account" && (
        <NameDialog
          title="Rename account"
          label="Display name"
          initial={modal.account.alias || ""}
          placeholder={modal.account.name || modal.account.id}
          submit="Save"
          allowEmpty
          description={`Shown everywhere in Edgewatch instead of the Cloudflare name${modal.account.name ? ` (${modal.account.name})` : ""}. Leave empty to use the Cloudflare name. Nothing changes in Cloudflare.`}
          onClose={close}
          onSave={(alias) => patchAccount(modal.account, { alias: alias || null }, "Account renamed")}
        />
      )}
      {modal?.kind === "entity-settings" && (
        // The live entity, so the dialog reflects a removed webhook right after saving.
        <EntitySettingsDialog
          entity={data?.entities.find((e) => e.id === modal.entity.id) ?? modal.entity}
          onClose={close}
          onSave={(body) => patchEntity(modal.entity, body, `${modal.entity.name} saved`)}
        />
      )}
      {modal?.kind === "token" && (
        <TokenDialog
          account={modal.account}
          onClose={close}
          onSaved={async () => {
            close();
            await refresh();
            toasts.add({ title: "Token replaced", description: "A new scan has started.", variant: "success" });
          }}
        />
      )}
      {modal?.kind === "remove" && (
        <ConfirmDialog
          title={`Remove ${modal.account.display}?`}
          confirm="Remove account"
          onClose={close}
          description="Edgewatch stops scanning this account and deletes its scan history, findings and triage. Nothing changes in Cloudflare. A token no other account uses is deleted too."
          onConfirm={() => act(() => api(`/api/accounts/${modal.account.id}`, { method: "DELETE", body: {} }), `${modal.account.display} removed`)}
        />
      )}
    </Page>
  );
}

function EntityCard({
  entity: e,
  entities,
  first,
  last,
  onModal,
  patchEntity,
  patchAccount,
  onDeleteEntity,
  onShow,
  onScan,
}: {
  entity: Entity;
  entities: Entity[];
  first: boolean;
  last: boolean;
  onModal: (m: Modal) => void;
  patchEntity: (e: Entity, body: Record<string, unknown>, done?: string) => Promise<boolean>;
  patchAccount: (a: Account, body: Record<string, unknown>, done?: string) => Promise<boolean>;
  onDeleteEntity: () => void;
  onShow: (scope: string) => void;
  onScan: (a: Account) => void;
}) {
  const n = e.notifications;
  const alerts = [n.slackConfigured && "Slack", n.webhookConfigured && "webhook"].filter(Boolean).join(" and ");
  const others = entities.filter((x) => x.id !== e.id);

  const title = (
    <span className="flex min-w-0 items-center gap-2">
      <span className="truncate">{e.name}</span>
      {!e.includeInAll && <Badge variant="neutral">Kept separate</Badge>}
    </span>
  );
  const cardActions = (
    <>
      <span className="hidden items-center gap-2 text-sm font-normal text-kumo-subtle sm:flex">
        <span aria-hidden>Show in All accounts</span>
        <Switch
          aria-label={`Show ${e.name} in All accounts`}
          checked={e.includeInAll}
          onCheckedChange={(v: boolean) => void patchEntity(e, { includeInAll: v }, v ? `${e.name} is shown in All accounts` : `${e.name} is kept separate`)}
        />
      </span>
      <DropdownMenu>
        <DropdownMenu.Trigger
          render={<Button variant="ghost" size="sm" shape="square" icon={<DotsThreeIcon weight="bold" />} aria-label={`${e.name} options`} />}
        />
        <DropdownMenu.Content align="end">
          {e.accounts.length > 0 && (
            <DropdownMenu.Item icon={EyeIcon} onClick={() => onShow(`e:${e.id}`)}>
              Show on dashboard
            </DropdownMenu.Item>
          )}
          <DropdownMenu.Item icon={EnvelopeSimpleIcon} onClick={() => onModal({ kind: "entity-settings", entity: e })}>
            Email domains and alerts
          </DropdownMenu.Item>
          <DropdownMenu.Item icon={PencilSimpleIcon} onClick={() => onModal({ kind: "rename-entity", entity: e })}>
            Rename
          </DropdownMenu.Item>
          <DropdownMenu.Item className="sm:hidden" icon={EyeIcon} onClick={() => void patchEntity(e, { includeInAll: !e.includeInAll })}>
            {e.includeInAll ? "Keep out of All accounts" : "Show in All accounts"}
          </DropdownMenu.Item>
          <DropdownMenu.Item icon={ArrowUpIcon} disabled={first} onClick={() => void patchEntity(e, { move: "up" })}>
            Move up
          </DropdownMenu.Item>
          <DropdownMenu.Item icon={ArrowDownIcon} disabled={last} onClick={() => void patchEntity(e, { move: "down" })}>
            Move down
          </DropdownMenu.Item>
          <DropdownMenu.Separator />
          <DropdownMenu.Item icon={TrashIcon} variant="danger" disabled={e.accounts.length > 0} onClick={onDeleteEntity}>
            {e.accounts.length ? "Delete (move its accounts first)" : "Delete entity"}
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu>
    </>
  );

  return (
    <ListCard
      title={title}
      actions={cardActions}
      footer={
        <>
          <span className="min-w-0 truncate">
            {plural(e.accounts.length, "account")}
            {" · "}
            {e.orgDomains.length ? `Company domains ${e.orgDomains.join(", ")}` : "Company domains: zone names only"}
            {" · "}
            {alerts ? `Alerts to ${alerts}` : "No alerts"}
          </span>
          <Button size="sm" variant="ghost" icon={<PlusIcon />} onClick={() => onModal({ kind: "add", entityId: e.id })}>
            Add accounts
          </Button>
        </>
      }
    >
      {e.accounts.length ? (
        <Table layout="auto">
          <Table.Header variant="compact">
            <Table.Row>
              <Table.Head>Account</Table.Head>
              <Table.Head>Token</Table.Head>
              <Table.Head>Last scan</Table.Head>
              <Table.Head className="text-right">Score</Table.Head>
              <Table.Head className="whitespace-nowrap">Critical and high</Table.Head>
              <Table.Head className="whitespace-nowrap">Daily scan</Table.Head>
              <Table.Head className="w-12">
                <span className="sr-only">Actions</span>
              </Table.Head>
            </Table.Row>
          </Table.Header>
          <Table.Body>
            {e.accounts.map((a, i) => (
              <Table.Row key={a.id}>
                <Table.Cell className="max-w-72">
                  <div className="truncate text-kumo-default">{a.display}</div>
                  <div className="truncate text-sm text-kumo-subtle">
                    {a.alias && a.name ? `${a.name} · ` : ""}
                    <span className="font-mono text-xs">{a.id}</span>
                  </div>
                </Table.Cell>
                <Table.Cell className="whitespace-nowrap">
                  {a.tokenMissing ? (
                    <Badge variant="error">Missing</Badge>
                  ) : (
                    <>
                      <span className="font-mono text-sm">{a.tokenHint}</span>
                      {a.tokenKind && <span className="ml-2 text-sm text-kumo-subtle">{a.tokenKind === "user" ? "User token" : "Account token"}</span>}
                    </>
                  )}
                </Table.Cell>
                <Table.Cell className="whitespace-nowrap">
                  {a.busy ? (
                    <Badge variant="warning" appearance="dot">
                      Scanning
                    </Badge>
                  ) : a.lastFailed ? (
                    <Tooltip content={a.lastFailed.error}>
                      <span>
                        <Badge variant="error" appearance="dot">
                          Failed {ago(a.lastFailed.finishedAt)}
                        </Badge>
                      </span>
                    </Tooltip>
                  ) : a.lastScan ? (
                    <span className="text-kumo-subtle">{ago(a.lastScan.finishedAt)}</span>
                  ) : (
                    <span className="text-kumo-subtle">Not yet</span>
                  )}
                </Table.Cell>
                <Table.Cell className="text-right tabular-nums">{score(a.lastScan?.score)}</Table.Cell>
                <Table.Cell className="tabular-nums text-kumo-subtle">
                  {a.lastScan ? `${a.lastScan.counts.critical || 0} / ${a.lastScan.counts.high || 0}` : "—"}
                </Table.Cell>
                <Table.Cell>
                  <Switch
                    aria-label={`Include ${a.display} in the daily scan`}
                    checked={a.scheduled}
                    onCheckedChange={(v: boolean) =>
                      void patchAccount(a, { scheduled: v }, v ? `${a.display} is in the daily scan` : `${a.display} is left out of the daily scan`)
                    }
                  />
                </Table.Cell>
                <Table.Cell>
                  <DropdownMenu>
                    <DropdownMenu.Trigger
                      render={<Button variant="ghost" size="sm" shape="square" icon={<DotsThreeIcon weight="bold" />} aria-label={`${a.display} options`} />}
                    />
                    <DropdownMenu.Content align="end">
                      <DropdownMenu.Item icon={EyeIcon} onClick={() => onShow(`a:${a.id}`)}>
                        Show on dashboard
                      </DropdownMenu.Item>
                      <DropdownMenu.Item icon={ArrowsClockwiseIcon} disabled={a.busy} onClick={() => onScan(a)}>
                        Scan now
                      </DropdownMenu.Item>
                      <DropdownMenu.Item icon={PencilSimpleIcon} onClick={() => onModal({ kind: "rename-account", account: a })}>
                        Rename
                      </DropdownMenu.Item>
                      {others.length > 0 && (
                        <DropdownMenu.Sub>
                          <DropdownMenu.SubTrigger icon={ArrowsLeftRightIcon}>Move to entity</DropdownMenu.SubTrigger>
                          <DropdownMenu.SubContent>
                            {others.map((x) => (
                              <DropdownMenu.Item key={x.id} onClick={() => void patchAccount(a, { entityId: x.id }, `${a.display} moved to ${x.name}`)}>
                                {x.name}
                              </DropdownMenu.Item>
                            ))}
                          </DropdownMenu.SubContent>
                        </DropdownMenu.Sub>
                      )}
                      <DropdownMenu.Item icon={ArrowUpIcon} disabled={i === 0} onClick={() => void patchAccount(a, { move: "up" })}>
                        Move up
                      </DropdownMenu.Item>
                      <DropdownMenu.Item icon={ArrowDownIcon} disabled={i === e.accounts.length - 1} onClick={() => void patchAccount(a, { move: "down" })}>
                        Move down
                      </DropdownMenu.Item>
                      <DropdownMenu.Item icon={KeyIcon} onClick={() => onModal({ kind: "token", account: a })}>
                        Replace token
                      </DropdownMenu.Item>
                      <DropdownMenu.Separator />
                      <DropdownMenu.Item icon={TrashIcon} variant="danger" disabled={a.busy} onClick={() => onModal({ kind: "remove", account: a })}>
                        Remove account
                      </DropdownMenu.Item>
                    </DropdownMenu.Content>
                  </DropdownMenu>
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table>
      ) : (
        <div className="px-4 py-8 text-center text-sm text-kumo-subtle">
          No accounts yet. Add accounts to this entity, or move accounts here from another entity.
        </div>
      )}
    </ListCard>
  );
}

function NameDialog({
  title,
  label,
  description,
  initial = "",
  placeholder,
  submit,
  allowEmpty,
  taken = [],
  onClose,
  onSave,
}: {
  title: string;
  label: string;
  description?: string;
  initial?: string;
  placeholder?: string;
  submit: string;
  allowEmpty?: boolean;
  /** Names already in use: typing one is caught here instead of creating a look-alike. */
  taken?: string[];
  onClose: () => void;
  onSave: (name: string) => Promise<boolean>;
}) {
  const [name, setName] = useState(initial);
  const [busy, setBusy] = useState(false);
  const clash = name.trim() ? taken.find((t) => sameName(t, name)) : undefined;
  const ok = (allowEmpty || name.trim().length > 0) && !clash;
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="base" className="p-6">
        <DialogHeader title={title} description={description} />
        <form
          onSubmit={async (ev) => {
            ev.preventDefault();
            if (!ok) return;
            setBusy(true);
            if (await onSave(name.trim())) onClose();
            else setBusy(false);
          }}
        >
          <Input
            autoFocus
            className="w-full"
            label={label}
            placeholder={placeholder}
            value={name}
            maxLength={80}
            onChange={(ev) => setName(ev.target.value)}
            variant={clash ? "error" : "default"}
            error={clash ? `${clash} already exists. Pick another name.` : undefined}
          />
          <div className="mt-6 flex justify-end gap-2">
            <Dialog.Close
              render={(p) => (
                <Button {...p} variant="secondary">
                  Cancel
                </Button>
              )}
            />
            <Button type="submit" variant="primary" loading={busy} disabled={!ok}>
              {submit}
            </Button>
          </div>
        </form>
      </Dialog>
    </Dialog.Root>
  );
}

function ConfirmDialog({
  title,
  description,
  confirm,
  onClose,
  onConfirm,
}: {
  title: string;
  description: string;
  confirm: string;
  onClose: () => void;
  onConfirm: () => Promise<boolean>;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="base" className="p-6">
        <DialogHeader title={title} description={description} />
        <div className="mt-6 flex justify-end gap-2">
          <Dialog.Close
            render={(p) => (
              <Button {...p} variant="secondary">
                Cancel
              </Button>
            )}
          />
          <Button
            variant="destructive"
            loading={busy}
            onClick={async () => {
              setBusy(true);
              if (await onConfirm()) onClose();
              else setBusy(false);
            }}
          >
            {confirm}
          </Button>
        </div>
      </Dialog>
    </Dialog.Root>
  );
}

function TokenDialog({ account, onClose, onSaved }: { account: Account; onClose: () => void; onSaved: () => void }) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="lg" className="p-6">
        <DialogHeader
          title={`Replace token for ${account.display}`}
          description="The new token must be able to read this account. Other accounts keep their tokens."
        />
        <form
          onSubmit={async (ev) => {
            ev.preventDefault();
            setBusy(true);
            setErr(null);
            try {
              await api(`/api/accounts/${account.id}/token`, { method: "PUT", body: { token } });
              onSaved();
            } catch (e) {
              setErr((e as Error).message);
              setBusy(false);
            }
          }}
        >
          <SensitiveInput
            label="API token"
            value={token}
            onChange={(ev: React.ChangeEvent<HTMLInputElement>) => setToken(ev.target.value.trim())}
            variant={err ? "error" : "default"}
            error={err || undefined}
            description="Stored only on this machine, readable by your user only."
          />
          <div className="mt-6 flex justify-end gap-2">
            <Dialog.Close
              render={(p) => (
                <Button {...p} variant="secondary">
                  Cancel
                </Button>
              )}
            />
            <Button type="submit" variant="primary" loading={busy} disabled={!token}>
              Verify and replace
            </Button>
          </div>
        </form>
      </Dialog>
    </Dialog.Root>
  );
}

function EntitySettingsDialog({
  entity: e,
  onClose,
  onSave,
}: {
  entity: Entity;
  onClose: () => void;
  onSave: (body: Record<string, unknown>) => Promise<boolean>;
}) {
  const toasts = useKumoToastManager();
  const n = e.notifications;
  const [domains, setDomains] = useState(e.orgDomains.join(", "));
  const [slack, setSlack] = useState("");
  const [hook, setHook] = useState("");
  const [min, setMin] = useState<Severity>(n.minSeverity);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  // biome-ignore lint/correctness/useExhaustiveDependencies: a saved URL changes its hint; clear the inputs then
  useEffect(() => {
    setSlack("");
    setHook("");
  }, [n.slackHint, n.webhookHint]);

  const save = async (extra: Record<string, unknown> = {}) => {
    setBusy(true);
    const ok = await onSave({
      orgDomains: domains.split(/[\s,]+/).filter(Boolean),
      notifications: { ...(slack ? { slackWebhookUrl: slack } : {}), ...(hook ? { webhookUrl: hook } : {}), minSeverity: min, ...extra },
    });
    setBusy(false);
    return ok;
  };
  const test = async () => {
    setTesting(true);
    try {
      const r = await api<{ slack?: string; webhook?: string }>(`/api/entities/${e.id}/test-notification`, { method: "POST", body: {} });
      const parts = Object.entries(r).map(([k, v]) => `${k === "slack" ? "Slack" : "Webhook"}: ${v === "ok" ? "delivered" : v}`);
      const ok = Object.values(r).every((v) => v === "ok");
      toasts.add({ title: ok ? "Test sent" : "Test failed", description: parts.join(" · "), variant: ok ? "success" : "error" });
    } catch (err) {
      toasts.add({ title: "Test failed", description: (err as Error).message, variant: "error" });
    } finally {
      setTesting(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(o: boolean) => !o && onClose()}>
      <Dialog size="lg" className="max-h-[90vh] overflow-y-auto p-6">
        <DialogHeader title={`${e.name}: email domains and alerts`} description="These apply only to this entity's accounts." />
        <div className="flex flex-col gap-4">
          <Input
            className="w-full"
            label="Company email domains"
            placeholder="example.com, example.org"
            value={domains}
            onChange={(ev) => setDomains(ev.target.value)}
            description="Members and Access policies with addresses outside these domains are flagged. Zone names of this entity's accounts always count."
          />
          <SensitiveInput
            className="w-full"
            label="Slack incoming webhook"
            placeholder="https://hooks.slack.com/services/…"
            value={slack}
            onChange={(ev: React.ChangeEvent<HTMLInputElement>) => setSlack(ev.target.value)}
            description={
              n.slackConfigured ? `Configured (${n.slackHint}). Enter a new URL to replace it.` : "Post this entity's new findings to a Slack channel."
            }
          />
          <SensitiveInput
            className="w-full"
            label="Webhook"
            placeholder="https://example.com/hooks/edgewatch"
            value={hook}
            onChange={(ev: React.ChangeEvent<HTMLInputElement>) => setHook(ev.target.value)}
            description={
              n.webhookConfigured
                ? `Configured (${n.webhookHint}). It receives a JSON payload.`
                : "Send a JSON payload with the new findings to any https endpoint."
            }
          />
          <Select
            className="w-full"
            label="Notify on"
            hideLabel={false}
            value={min}
            onValueChange={(v) => setMin(v as Severity)}
            items={{ critical: "Critical only", high: "High and above", medium: "Medium and above", low: "All findings" }}
          />
          {(n.slackConfigured || n.webhookConfigured) && (
            <div className="flex flex-wrap gap-2">
              {n.slackConfigured && (
                <Button size="sm" variant="ghost" onClick={() => void save({ slackWebhookUrl: "" })}>
                  Remove Slack webhook
                </Button>
              )}
              {n.webhookConfigured && (
                <Button size="sm" variant="ghost" onClick={() => void save({ webhookUrl: "" })}>
                  Remove webhook
                </Button>
              )}
            </div>
          )}
        </div>
        <div className="mt-6 flex flex-wrap justify-end gap-2">
          <Button variant="secondary" loading={testing} disabled={!n.slackConfigured && !n.webhookConfigured} onClick={test}>
            Send test
          </Button>
          <Button
            variant="primary"
            loading={busy}
            onClick={async () => {
              if (await save()) onClose();
            }}
          >
            Save
          </Button>
        </div>
      </Dialog>
    </Dialog.Root>
  );
}
