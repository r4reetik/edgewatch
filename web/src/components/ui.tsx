// Shared building blocks composed from Kumo components.
//
// Layout rules, taken from the Cloudflare dashboard (Kumo's ResourceListPage
// block). Every page goes through these components so spacing comes from one place:
//  - Page: max 1400px, p-6 / md:p-8 / lg:px-10 lg:py-9; sections stack with gap-6.
//  - Header: text-3xl semibold title, text-lg subtle description, actions top-right.
//  - Card: the header strip holds a title and actions only, so every strip has the
//    same height; descriptions and forms go in the body; actions go in the footer.
//  - ListCard: one card = toolbar, table (compact header), footer.
//  - Grids only hold peers of equal height (stat tiles, charts). Everything else
//    stacks full width.

import type { ReactNode } from "react";
import { Badge, Banner, Button, Dialog, Empty, LayerCard, Loader, Meter, Tooltip, cn } from "@cloudflare/kumo";
import {
  XIcon,
  CheckCircleIcon,
  InfoIcon,
  MinusCircleIcon,
  WarningCircleIcon,
  WarningDiamondIcon,
  WarningIcon,
  WarningOctagonIcon,
  XCircleIcon,
} from "@phosphor-icons/react";
import { SEVERITY_LABEL, STATUS_LABEL, type Severity, type TriageStatus } from "../lib.ts";

export function Page({ title, description, actions, children }: { title: string; description?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <div className="mx-auto flex w-full max-w-[1400px] flex-col gap-6 p-6 md:p-8 lg:px-10 lg:py-9">
      <header className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div className="min-w-0">
          <h1 className="m-0 text-3xl font-semibold text-kumo-default">{title}</h1>
          {description && <p className="mt-1.5 max-w-3xl text-lg leading-normal text-pretty text-kumo-subtle">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </header>
      {children}
    </div>
  );
}

/** Equal-height peers: stat tiles (4 across) or charts (2 across). */
export function Row({ cols = 4, children }: { cols?: 2 | 3 | 4; children: ReactNode }) {
  const grid = { 2: "lg:grid-cols-2", 3: "md:grid-cols-3", 4: "sm:grid-cols-2 xl:grid-cols-4" }[cols];
  return <div className={cn("grid grid-cols-1 gap-4", grid)}>{children}</div>;
}

export function Card({
  title,
  actions,
  description,
  footer,
  flush,
  className,
  children,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  description?: ReactNode;
  footer?: ReactNode;
  flush?: boolean;
  className?: string;
  children: ReactNode;
}) {
  return (
    <LayerCard className={cn("min-w-0", className)}>
      {(title || actions) && (
        <LayerCard.Secondary className="flex h-12 items-center justify-between gap-3 py-0">
          <span className="truncate">{title}</span>
          {actions && <div className="flex shrink-0 items-center gap-1">{actions}</div>}
        </LayerCard.Secondary>
      )}
      <LayerCard.Primary className={cn(flush && "overflow-hidden p-0")}>
        {description && <p className={cn("text-sm text-kumo-subtle", flush ? "px-4 pt-4" : "mb-4")}>{description}</p>}
        {children}
        {footer && (
          <div className={cn("flex flex-wrap items-center justify-end gap-2 border-t border-kumo-hairline px-4 py-3", !flush && "-mx-4 -mb-4 mt-4")}>
            {footer}
          </div>
        )}
      </LayerCard.Primary>
    </LayerCard>
  );
}

/**
 * A table's card: optional title strip (same as Card), toolbar row, table, footer row.
 * Without a title it is a single surface, as on list pages where the page title names it.
 */
export function ListCard({
  title,
  actions,
  toolbar,
  footer,
  children,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  toolbar?: ReactNode;
  footer?: ReactNode;
  children: ReactNode;
}) {
  const body = (
    <>
      {toolbar && <div className="flex flex-wrap items-center gap-2 border-b border-kumo-hairline bg-kumo-base p-3">{toolbar}</div>}
      <div className="overflow-x-auto bg-kumo-base">{children}</div>
      {footer && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-kumo-hairline bg-kumo-base px-4 py-2.5 text-sm text-kumo-subtle">
          {footer}
        </div>
      )}
    </>
  );
  if (!title) return <LayerCard className="min-w-0 overflow-hidden p-0">{body}</LayerCard>;
  return (
    <LayerCard className="min-w-0">
      <LayerCard.Secondary className="flex h-12 items-center justify-between gap-3 py-0">
        <span className="truncate">{title}</span>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </LayerCard.Secondary>
      <LayerCard.Primary className="overflow-hidden p-0">{body}</LayerCard.Primary>
    </LayerCard>
  );
}

/** Secondary text for the right side of a card's title strip; hidden on narrow screens so the title keeps its room. */
export function Aside({ children }: { children: ReactNode }) {
  return <span className="hidden truncate text-sm font-normal text-kumo-subtle md:inline">{children}</span>;
}

/**
 * Settings pattern: title and description on the left, the control on the right.
 * Fields fill the control column; toggles and read-only values sit at its end.
 */
export function SettingRow({ title, description, end, children }: { title: ReactNode; description?: ReactNode; end?: boolean; children: ReactNode }) {
  return (
    <div className="grid grid-cols-1 gap-3 py-4 first:pt-0 last:pb-0 md:grid-cols-[minmax(0,1fr)_minmax(0,24rem)] md:gap-8">
      <div className="min-w-0">
        <div className="text-base font-medium text-kumo-default">{title}</div>
        {description && <p className="mt-1 text-sm text-kumo-subtle">{description}</p>}
      </div>
      <div className={cn("min-w-0", end ? "flex items-start md:justify-end" : "grid content-start [&>*]:w-full")}>{children}</div>
    </div>
  );
}

/**
 * Form fields side by side. Fields align to the top of their row, so labels and
 * controls share one line and any description sits below it. Controls shrink to
 * their column (date inputs otherwise keep a wider intrinsic width and overflow).
 */
export function FormGrid({ cols = 2, children }: { cols?: 2 | 4; children: ReactNode }) {
  return (
    <div
      className={cn(
        "grid items-start gap-x-4 gap-y-4 [&>*]:min-w-0 [&_input]:min-w-0",
        cols === 4 ? "grid-cols-2 sm:grid-cols-4" : "grid-cols-1 sm:grid-cols-2",
      )}
    >
      {children}
    </div>
  );
}

export function SettingRows({ children }: { children: ReactNode }) {
  return <div className="divide-y divide-kumo-hairline">{children}</div>;
}

export function Stat({ label, value, note, onClick, hint }: { label: string; value: ReactNode; note?: ReactNode; onClick?: () => void; hint?: string }) {
  const body = (
    <LayerCard className={cn("flex h-full flex-col gap-1 p-4", onClick && "transition-shadow group-hover:ring-kumo-line")}>
      <div className="flex h-5 items-center gap-1.5 text-sm text-kumo-subtle">
        {label}
        {hint && (
          <Tooltip content={hint}>
            <InfoIcon className="text-kumo-subtle" />
          </Tooltip>
        )}
      </div>
      <div className="text-2xl font-semibold text-kumo-default tabular-nums">{value}</div>
      {note && <div className="text-sm text-kumo-subtle">{note}</div>}
    </LayerCard>
  );
  return onClick ? (
    <button type="button" onClick={onClick} className="group h-full rounded-lg text-left">
      {body}
    </button>
  ) : (
    body
  );
}

/** A 0-100 score as a meter, colored by band (the number is always shown, so color isn't the only signal). */
export function ScoreMeter({ label, value, note }: { label: string; value: number; note?: ReactNode }) {
  // Kumo draws the indicator as a gradient, so the stops are what change its color.
  const band =
    value < 50
      ? "from-kumo-danger via-kumo-danger to-kumo-danger"
      : value < 80
        ? "from-kumo-warning via-kumo-warning to-kumo-warning"
        : "from-kumo-success via-kumo-success to-kumo-success";
  return (
    <div className="flex flex-col gap-1">
      <Meter label={label} value={Math.max(value, 1)} customValue={`${Math.round(value)}`} indicatorClassName={band} />
      {note && <span className="text-sm text-kumo-subtle">{note}</span>}
    </div>
  );
}

/** Plain list of rows inside a card body (label left, value right). */
export function KeyValue({ items }: { items: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-8 gap-y-2 text-sm sm:grid-cols-[max-content_minmax(0,1fr)]">
      {items.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-kumo-subtle">{k}</dt>
          <dd className="min-w-0 text-kumo-default">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

// Strength follows severity: solid red, solid orange, yellow tint, outline.
const SEV_BADGE: Record<Severity, { variant: "red" | "orange" | "warning" | "outline" | "secondary"; icon: ReactNode }> = {
  critical: { variant: "red", icon: <WarningOctagonIcon weight="fill" /> },
  high: { variant: "orange", icon: <WarningDiamondIcon weight="fill" /> },
  medium: { variant: "warning", icon: <WarningIcon weight="fill" /> },
  low: { variant: "outline", icon: <InfoIcon /> },
  info: { variant: "secondary", icon: <InfoIcon /> },
};

/** Severity is always icon + label, never color alone. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEV_BADGE[severity] || SEV_BADGE.info;
  return (
    <Badge variant={s.variant} icon={s.icon}>
      {SEVERITY_LABEL[severity]}
    </Badge>
  );
}

export function StatusBadge({ status, overdue }: { status: TriageStatus; overdue?: boolean }) {
  if (overdue && (status === "open" || status === "in_progress"))
    return (
      <Badge variant="error" appearance="dot">
        Overdue
      </Badge>
    );
  const variant = status === "open" ? "neutral" : status === "in_progress" ? "warning" : "success";
  return (
    <Badge variant={variant} appearance="dot">
      {STATUS_LABEL[status]}
    </Badge>
  );
}

/**
 * Shown only when it adds information: "Confirmed" (a live probe confirmed it) or
 * "Likely" (a heuristic). Findings read straight from configuration carry no badge.
 */
export function ConfidenceBadge({ confidence }: { confidence: "confirmed" | "likely" | null | undefined }) {
  if (confidence === "confirmed")
    return (
      <Tooltip content="Confirmed by a live check of the hostname, or reported by Cloudflare">
        <Badge variant="teal-subtle" icon={<CheckCircleIcon weight="fill" />}>
          Confirmed
        </Badge>
      </Tooltip>
    );
  if (confidence === "likely")
    return (
      <Tooltip content="Based on a name pattern or sampled traffic. Confirm before acting.">
        <Badge variant="outline">Likely</Badge>
      </Tooltip>
    );
  return null;
}

export function ReopenedBadge() {
  return (
    <Tooltip content="This was fixed once and has come back">
      <Badge variant="purple">Reopened</Badge>
    </Tooltip>
  );
}

/** Small monospace tag for check IDs and sources. */
export function Tag({ children, info }: { children: ReactNode; info?: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 shrink-0 items-center rounded px-1.5 font-mono text-xs",
        info ? "bg-kumo-info-tint text-kumo-info" : "bg-kumo-recessed text-kumo-subtle",
      )}
    >
      {children}
    </span>
  );
}

/** Tri-state cell for settings grids: on, off, or not applicable. */
export function Flag({
  value,
  on = "On",
  off = "Off",
  na = "n/a",
  warn,
}: {
  value: boolean | null | undefined;
  on?: string;
  off?: string;
  na?: string;
  warn?: boolean;
}) {
  if (value == null)
    return (
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-kumo-inactive">
        <MinusCircleIcon />
        {na}
      </span>
    );
  if (value)
    return (
      <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-kumo-default">
        <CheckCircleIcon weight="fill" className="text-kumo-success" />
        {on}
      </span>
    );
  return warn ? (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-kumo-default">
      <WarningCircleIcon weight="fill" className="text-kumo-warning" />
      {off}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-kumo-default">
      <XCircleIcon weight="fill" className="text-kumo-danger" />
      {off}
    </span>
  );
}

/** Shown inside a card or table when it has no rows. */
export function NoRows({ children }: { children: ReactNode }) {
  return <p className="px-4 py-8 text-center text-sm text-kumo-subtle">{children}</p>;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-24 text-sm text-kumo-subtle">
      <Loader /> {label}…
    </div>
  );
}

export function ErrorState({ error, retry }: { error: Error; retry?: () => void }) {
  return (
    <Banner
      variant="error"
      icon={<WarningCircleIcon weight="fill" />}
      title="Couldn't load this page"
      description={error.message}
      action={retry && <Banner.Action onClick={retry}>Try again</Banner.Action>}
    />
  );
}

export function NoScan({ action }: { action?: ReactNode }) {
  return (
    <LayerCard className="py-10">
      <Empty
        icon={<WarningCircleIcon size={40} className="text-kumo-inactive" />}
        title="No scan yet"
        description="Run the first scan to see your account's posture. It reads configuration only and takes under a minute for most accounts."
        contents={action}
      />
    </LayerCard>
  );
}

/**
 * Why a page has no data although a scan exists: its source couldn't be read.
 * Names the permission to add, from the scan's coverage.
 */
export function unreadableText(
  coverage: { key?: string; label: string; permission?: string; ok: boolean; notReadableIn?: { name: string }[] }[] | undefined,
  key: string,
  what: string,
): string {
  const c = coverage?.find((x) => x.key === key && !x.ok);
  if (!c) return `No ${what} in the latest scan.`;
  return `The API token can't read ${c.label.toLowerCase()}${c.notReadableIn?.length ? ` for ${c.notReadableIn.map((a) => a.name).join(", ")}` : ""}. Add ${c.permission || "the matching read permission"} to the token on the Accounts page, then scan again.`;
}

/** Page wrapper for the loading, error and no-scan states so they sit in the same frame as the content. */
export function PageState({
  title,
  description,
  actions,
  error,
  loading,
  empty,
  retry,
  emptyAction,
  emptyText,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  error: Error | null;
  loading: boolean;
  empty: boolean;
  retry?: () => void;
  emptyAction?: ReactNode;
  /** Shown instead of "No scan yet" when the page is empty for another reason. */
  emptyText?: ReactNode;
}) {
  return (
    <Page title={title} description={description} actions={actions}>
      {error ? (
        <ErrorState error={error} retry={retry} />
      ) : loading ? (
        <Loading />
      ) : empty ? (
        emptyText ? (
          <NoRows>{emptyText}</NoRows>
        ) : (
          <NoScan action={emptyAction} />
        )
      ) : null}
    </Page>
  );
}

/** Title row of a dialog, with the close button. */
export function DialogHeader({ title, description }: { title: string; description?: ReactNode }) {
  return (
    <div className="mb-4 flex items-start justify-between gap-4">
      <div className="min-w-0">
        <Dialog.Title className="text-lg font-semibold text-kumo-default">{title}</Dialog.Title>
        {description && <Dialog.Description className="mt-1 text-sm text-kumo-subtle">{description}</Dialog.Description>}
      </div>
      <Dialog.Close aria-label="Close" render={(p) => <Button {...p} variant="ghost" size="sm" shape="square" icon={<XIcon />} aria-label="Close" />} />
    </div>
  );
}
