// A finding's details and its triage: the body shared by the dialog and the
// finding page, the single-finding triage form, and bulk triage.

import { useEffect, useState, type ReactNode } from "react";
import { Button, Dialog, Input, InputArea, Link, Select, Tooltip, useKumoToastManager } from "@cloudflare/kumo";
import { ArrowSquareOutIcon, BookOpenIcon, CaretDownIcon, CaretUpIcon, LinkSimpleIcon, XIcon } from "@phosphor-icons/react";
import { api, dateOnly, dateTime, link, STATUS_LABEL, type Finding, type Triage, type TriageStatus } from "../lib.ts";
import { isoDate } from "../../../src/shared/time.ts";
import { ConfidenceBadge, FormGrid, ReopenedBadge, SeverityBadge, StatusBadge } from "./ui.tsx";
import { useShell } from "../shell.tsx";

type Editable = Pick<Triage, "status" | "owner" | "note" | "dueDate" | "acceptUntil">;
/** Statuses where a due date means nothing: the finding is out of the queue. */
const NO_DUE = new Set<TriageStatus>(["accepted", "false_positive"]);

export function permalink(fp: string) {
  return `${location.origin}/findings/${fp}`;
}

export function CopyLinkButton({ fingerprint }: { fingerprint: string }) {
  const toasts = useKumoToastManager();
  return (
    <Tooltip content="Copy a link to this finding">
      <Button
        variant="ghost"
        shape="square"
        aria-label="Copy link"
        icon={<LinkSimpleIcon />}
        onClick={async () => {
          try {
            await navigator.clipboard.writeText(permalink(fingerprint));
            toasts.add({ title: "Link copied", variant: "success" });
          } catch {
            toasts.add({ title: "Couldn't copy", description: permalink(fingerprint), variant: "error" });
          }
        }}
      />
    </Tooltip>
  );
}

/** Badges, title and where the finding is. */
/** `hideTitle` when the page heading already shows it. */
export function FindingHeader({ f, actions, hideTitle }: { f: Finding; actions?: ReactNode; hideTitle?: boolean }) {
  const { session } = useShell();
  return (
    <div className="flex flex-col-reverse gap-2 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
      <div className="min-w-0">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={f.severity} />
          <StatusBadge status={f.status} overdue={f.overdue} />
          <ConfidenceBadge confidence={f.confidence} />
          {f.reopened && <ReopenedBadge />}
          <span className="font-mono text-xs text-kumo-subtle">{f.source === "security_center" ? "Cloudflare Security Center" : f.checkId}</span>
        </div>
        {!hideTitle && <h2 className="text-lg font-semibold text-kumo-default">{f.title}</h2>}
        <p className="break-all text-sm text-kumo-subtle">
          {f.resource}
          {f.zone && f.zone !== f.resource ? ` · ${f.zone}` : ""}
        </p>
        {(session.accounts?.length || 0) > 1 && (
          <p className="mt-0.5 text-sm text-kumo-subtle">
            {f.account}
            {f.entity ? ` · ${f.entity}` : ""}
          </p>
        )}
      </div>
      {/* On phones the actions take their own row above, so the title keeps the full width. */}
      {actions && <div className="-mr-2 flex shrink-0 items-center justify-end gap-1 sm:mr-0">{actions}</div>}
    </div>
  );
}

/** What was found, why it matters, how to fix it, and the evidence. */
export function FindingBody({ f }: { f: Finding }) {
  const chain = f.evidence?.chain;
  const rest = f.evidence ? Object.fromEntries(Object.entries(f.evidence).filter(([k]) => k !== "securityCenter" && k !== "chain")) : {};
  const raw = Object.keys(rest).length ? JSON.stringify(rest, null, 2) : null;
  const sc = f.evidence?.securityCenter;
  return (
    <div className="flex flex-col gap-4 text-sm">
      {f.detail && <Section label="What we found">{f.detail}</Section>}
      {f.why && <Section label="Why it matters">{f.why}</Section>}
      {f.fix && (
        <Section label="How to fix">
          <FixSteps text={f.fix} />
        </Section>
      )}
      {sc && sc.length > 0 && <p className="text-kumo-subtle">Cloudflare Security Center reports this too ({sc.join(", ")}).</p>}
      {chain && chain.length > 0 && (
        <Section label="How we know">
          <ol className="flex flex-col gap-2">
            {chain.map((step, i) => (
              <li key={i} className="flex gap-3">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-kumo-recessed text-xs font-medium text-kumo-subtle">
                  {i + 1}
                </span>
                <div className="min-w-0">
                  <div className="text-xs text-kumo-subtle">{step.label}</div>
                  <div className="break-words text-kumo-default">{step.value}</div>
                </div>
              </li>
            ))}
          </ol>
        </Section>
      )}
      {raw && (
        <details>
          <summary className="cursor-pointer text-xs text-kumo-subtle select-none hover:text-kumo-default">Show raw evidence</summary>
          <pre className="mt-2 max-h-48 overflow-auto rounded-md bg-kumo-recessed p-3 font-mono text-xs whitespace-pre-wrap break-all">{raw}</pre>
        </details>
      )}
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs text-kumo-subtle">
        <dt>First seen</dt>
        <dd>{dateTime(f.firstSeen)}</dd>
        <dt>Due</dt>
        <dd className={f.overdue ? "text-kumo-danger" : undefined}>
          {f.due && !f.settled ? dateOnly(f.due) : "—"}
          {f.overdue ? " (overdue)" : ""}
        </dd>
        <dt>Category</dt>
        <dd>{f.category}</dd>
      </dl>
      <div className="flex flex-wrap gap-x-5 gap-y-1">
        {f.link && (
          <Link href={f.link} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
            Open in the Cloudflare dashboard <ArrowSquareOutIcon />
          </Link>
        )}
        {f.docs && (
          <Link href={f.docs} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1">
            <BookOpenIcon /> Cloudflare docs
          </Link>
        )}
      </div>
    </div>
  );
}

/** Fix text written as "1. … 2. …" renders as a numbered list. */
function FixSteps({ text }: { text: string }) {
  const steps = text
    .split(/\s*(?:^|\n|\s)(?=\d+\.\s)/)
    .map((s) => s.replace(/^\d+\.\s*/, "").trim())
    .filter(Boolean);
  if (steps.length < 2) return <>{text}</>;
  return (
    <ol className="list-decimal space-y-1 pl-5">
      {steps.map((s, i) => (
        <li key={i}>{s}</li>
      ))}
    </ol>
  );
}

function Section({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <div className="mb-1 text-xs font-medium uppercase tracking-wide text-kumo-subtle">{label}</div>
      <div className="text-kumo-default">{children}</div>
    </div>
  );
}

/** Saves triage for one finding; `onSaved` gets the new triage. */
export function TriagePanel({ f, onSaved, onSaveNext }: { f: Finding; onSaved: (t: Triage) => void; onSaveNext?: () => void }) {
  const toasts = useKumoToastManager();
  const [busy, setBusy] = useState(false);
  const save = async (t: Editable, next: boolean) => {
    setBusy(true);
    try {
      await api(`/api/triage/${f.fingerprint}`, { method: "PUT", body: t });
      onSaved({ ...t, updatedAt: new Date().toISOString() });
      toasts.add({ title: "Triage saved", variant: "success" });
      if (next) onSaveNext?.();
    } catch (e) {
      toasts.add({ title: "Couldn't save", description: (e as Error).message, variant: "error" });
    } finally {
      setBusy(false);
    }
  };
  return (
    // A container: the fields sit side by side only when the panel itself is wide enough.
    <div className="@container rounded-lg bg-kumo-elevated p-4 ring ring-kumo-line">
      <div className="mb-3 font-medium text-kumo-default">Triage</div>
      <TriageForm
        key={f.fingerprint}
        initial={f.triage}
        busy={busy}
        onSubmit={(t) => save(t, false)}
        onSubmitNext={onSaveNext ? (t) => save(t, true) : undefined}
      />
      {f.triage?.updatedAt && (
        <p className="mt-3 text-xs text-kumo-subtle">
          Updated {dateTime(f.triage.updatedAt)}
          {f.triage.updatedBy ? ` by ${f.triage.updatedBy}` : ""}
        </p>
      )}
    </div>
  );
}

function TriageForm({
  initial,
  onSubmit,
  onSubmitNext,
  busy,
}: {
  initial: Triage | null;
  onSubmit: (t: Editable) => void;
  onSubmitNext?: (t: Editable) => void;
  busy: boolean;
}) {
  const [status, setStatus] = useState<TriageStatus>(initial?.status || "open");
  const [owner, setOwner] = useState(initial?.owner || "");
  const [due, setDue] = useState(initial?.dueDate || "");
  const [until, setUntil] = useState(initial?.acceptUntil || "");
  const [note, setNote] = useState(initial?.note || "");
  const err = status === "accepted" && until && until < isoDate() ? "The expiry date is in the past." : null;
  const value = (): Editable => ({
    status,
    owner: owner || null,
    note: note || null,
    dueDate: NO_DUE.has(status) ? null : due || null,
    acceptUntil: status === "accepted" ? until || null : null,
  });
  return (
    <form
      className="flex flex-col gap-3"
      onSubmit={(e) => {
        e.preventDefault();
        if (!err) onSubmit(value());
      }}
    >
      <div className="grid grid-cols-1 items-start gap-4 @sm:grid-cols-2 [&>*]:min-w-0 [&_input]:min-w-0">
        <Select className="w-full" label="Status" hideLabel={false} value={status} onValueChange={(v) => setStatus(v as TriageStatus)} items={STATUS_LABEL} />
        <Input className="w-full" label="Owner" placeholder="name@company.com" value={owner} onChange={(e) => setOwner(e.target.value)} maxLength={120} />
        {!NO_DUE.has(status) && (
          <Input
            className="w-full"
            label="Due date"
            type="date"
            value={due}
            onChange={(e) => setDue(e.target.value)}
            description="Empty uses the SLA for this severity."
          />
        )}
        {status === "accepted" && (
          <Input
            className="w-full"
            label="Accept until"
            type="date"
            value={until}
            min={isoDate()}
            onChange={(e) => setUntil(e.target.value)}
            variant={err ? "error" : "default"}
            error={err || undefined}
            description="Reopens after this date. Empty accepts indefinitely."
          />
        )}
      </div>
      <InputArea
        label="Note"
        placeholder="Context, a ticket link, or why the risk is accepted"
        value={note}
        onValueChange={setNote}
        minRows={3}
        maxLength={4000}
      />
      <div className="flex flex-wrap justify-end gap-2">
        {onSubmitNext && (
          <Button
            type="button"
            loading={busy}
            onClick={() => {
              if (!err) onSubmitNext(value());
            }}
          >
            Save &amp; next
          </Button>
        )}
        <Button type="submit" variant="primary" loading={busy}>
          Save
        </Button>
      </div>
    </form>
  );
}

export interface DialogNav {
  onPrev?: () => void;
  onNext?: () => void;
  position?: string;
}

/** The finding in a dialog over the Findings list. J and K move to the next and previous finding. */
export function FindingDialog({ finding: f, onClose, onSaved, nav }: { finding: Finding; onClose: () => void; onSaved: (t: Triage) => void; nav?: DialogNav }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLElement && e.target.closest("input, textarea, select, [contenteditable], [role=combobox], [role=listbox]")) return;
      if (e.key === "j" && nav?.onNext) {
        e.preventDefault();
        nav.onNext();
      }
      if (e.key === "k" && nav?.onPrev) {
        e.preventDefault();
        nav.onPrev();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [nav]);
  return (
    <Dialog.Root
      open
      onOpenChange={(o: boolean) => {
        if (!o) onClose();
      }}
    >
      {/* Three quarters of the viewport from sm up; below that Kumo already fills the width less a 1rem gutter. */}
      <Dialog size="xl" className="max-h-[calc(100vh-6rem)] overflow-y-auto p-6 sm:w-[75vw]">
        <Dialog.Title className="sr-only">{f.title}</Dialog.Title>
        <FindingHeader
          f={f}
          actions={
            <>
              {nav?.position && <span className="mr-1 hidden text-xs text-kumo-subtle tabular-nums sm:inline">{nav.position}</span>}
              {nav && (
                <>
                  <Tooltip content="Previous (K)">
                    <Button variant="ghost" shape="square" aria-label="Previous finding" icon={<CaretUpIcon />} disabled={!nav.onPrev} onClick={nav.onPrev} />
                  </Tooltip>
                  <Tooltip content="Next (J)">
                    <Button variant="ghost" shape="square" aria-label="Next finding" icon={<CaretDownIcon />} disabled={!nav.onNext} onClick={nav.onNext} />
                  </Tooltip>
                </>
              )}
              <CopyLinkButton fingerprint={f.fingerprint} />
              <Tooltip content="Open as a page">
                <a
                  {...link(`/findings/${f.fingerprint}`)}
                  title="Open as a page"
                  className="inline-flex h-9 w-9 items-center justify-center rounded-md text-kumo-default hover:bg-kumo-tint focus-visible:ring-2 focus-visible:ring-kumo-brand focus-visible:outline-none"
                >
                  <ArrowSquareOutIcon />
                  <span className="sr-only">Open as a page</span>
                </a>
              </Tooltip>
              <Dialog.Close aria-label="Close" render={(p) => <Button {...p} variant="ghost" shape="square" icon={<XIcon />} aria-label="Close" />} />
            </>
          }
        />
        <div className="mt-4 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(20rem,26rem)]">
          <FindingBody f={f} />
          <TriagePanel f={f} onSaved={onSaved} onSaveNext={nav?.onNext} />
        </div>
      </Dialog>
    </Dialog.Root>
  );
}

const KEEP = "__keep";

/**
 * Triage for many findings at once. Each field starts as "Leave unchanged", so
 * assigning an owner doesn't wipe notes or due dates; the note can be appended
 * instead of replaced. The toast offers Undo, which restores each finding.
 */
export function BulkTriageDialog({ findings, onClose, onSaved }: { findings: Finding[]; onClose: () => void; onSaved: () => void }) {
  const toasts = useKumoToastManager();
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string>(KEEP);
  const [owner, setOwner] = useState<string | null>(null);
  const [due, setDue] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [noteMode, setNoteMode] = useState<"append" | "replace">("append");
  const count = findings.length;

  const undo = async () => {
    try {
      await Promise.all(
        findings.map((f) =>
          api(`/api/triage/${f.fingerprint}`, {
            method: "PUT",
            body: {
              status: f.triage?.status || "open",
              owner: f.triage?.owner ?? null,
              note: f.triage?.note ?? null,
              dueDate: f.triage?.dueDate ?? null,
              acceptUntil: f.triage?.acceptUntil ?? null,
            },
          }),
        ),
      );
      onSaved();
      toasts.add({ title: "Undone", variant: "success" });
    } catch (e) {
      toasts.add({ title: "Couldn't undo", description: (e as Error).message, variant: "error" });
    }
  };

  const save = async () => {
    const body: Record<string, unknown> = { fingerprints: findings.map((f) => f.fingerprint) };
    if (status !== KEEP) body.status = status;
    if (owner !== null) body.owner = owner;
    if (due !== null && !NO_DUE.has(status as TriageStatus)) body.dueDate = due;
    if (note.trim()) body[noteMode === "append" ? "appendNote" : "note"] = note.trim();
    if (Object.keys(body).length === 1) {
      onClose();
      return;
    }
    setBusy(true);
    try {
      await api("/api/triage", { method: "POST", body });
      onSaved();
      toasts.add({ title: `Updated ${count} findings`, variant: "success", actions: [{ children: "Undo", onClick: () => void undo() }] });
    } catch (e) {
      toasts.add({ title: "Couldn't save", description: (e as Error).message, variant: "error" });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root
      open
      onOpenChange={(o: boolean) => {
        if (!o) onClose();
      }}
    >
      <Dialog size="lg" className="p-6">
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <Dialog.Title className="text-lg font-semibold text-kumo-default">Triage {count} findings</Dialog.Title>
            <Dialog.Description className="text-sm text-kumo-subtle">
              Only the fields you change are applied. Everything else stays as it is on each finding.
            </Dialog.Description>
          </div>
          <Dialog.Close aria-label="Close" render={(p) => <Button {...p} variant="ghost" shape="square" icon={<XIcon />} aria-label="Close" />} />
        </div>
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            void save();
          }}
        >
          <FormGrid>
            <Select
              className="w-full"
              label="Status"
              hideLabel={false}
              value={status}
              onValueChange={(v) => setStatus(String(v))}
              items={{ [KEEP]: "Leave unchanged", ...STATUS_LABEL }}
            />
            <Input
              className="w-full"
              label="Owner"
              placeholder="Leave unchanged"
              value={owner ?? ""}
              onChange={(e) => setOwner(e.target.value)}
              maxLength={120}
              description={owner === "" ? "Clears the owner." : undefined}
            />
            {!NO_DUE.has(status as TriageStatus) && (
              <Input
                className="w-full"
                label="Due date"
                type="date"
                value={due ?? ""}
                onChange={(e) => setDue(e.target.value)}
                description={due === null ? "Leave empty to keep each finding's date." : undefined}
              />
            )}
          </FormGrid>
          <InputArea label="Note" placeholder="Leave empty to keep each finding's note" value={note} onValueChange={setNote} minRows={3} maxLength={4000} />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Select
              aria-label="Note mode"
              value={noteMode}
              onValueChange={(v) => setNoteMode(v as "append" | "replace")}
              items={{ append: "Add to each note", replace: "Replace each note" }}
              disabled={!note.trim()}
            />
            <Button type="submit" variant="primary" loading={busy}>
              Apply to {count}
            </Button>
          </div>
        </form>
      </Dialog>
    </Dialog.Root>
  );
}
