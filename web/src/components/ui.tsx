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
  ArrowsLeftRightIcon,
  BuildingsIcon,
  IdentificationCardIcon,
  ListChecksIcon,
  MapPinIcon,
  ShieldWarningIcon,
  StackIcon,
  InfoIcon,
  MinusCircleIcon,
  WarningCircleIcon,
  WarningDiamondIcon,
  WarningIcon,
  WarningOctagonIcon,
  XCircleIcon,
} from "@phosphor-icons/react";
import { PROVIDER_INFO, PROVIDERS, providerList, SEVERITY_LABEL, STATUS_LABEL, type ProviderId, type Severity, type TriageStatus } from "../lib.ts";
import { useShell } from "../shell.tsx";

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
        // px-3 matches the toolbar and Kumo's table cells, so the footer's text starts on the same line as the rows'.
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-kumo-hairline bg-kumo-base px-3 py-2.5 text-sm text-kumo-subtle">
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
      <Tooltip content="Confirmed by a live check of the hostname, or reported by the platform itself">
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

/**
 * Which platform an account is on: the platform's own monochrome mark (as published by Simple Icons, from each
 * platform's brand page), drawn in the text colour so it sits with the rest of the UI. Used only to say which
 * platform something is on; Keelson isn't affiliated with them. One per provider in src/shared/providers.ts.
 */
const PROVIDER_GLYPH: Record<ProviderId, string> = {
  cloudflare:
    "M16.5088 16.8447c.1475-.5068.0908-.9707-.1553-1.3154-.2246-.3164-.6045-.499-1.0615-.5205l-8.6592-.1123a.1559.1559 0 0 1-.1333-.0713c-.0283-.042-.0351-.0986-.021-.1553.0278-.084.1123-.1484.2036-.1562l8.7359-.1123c1.0351-.0489 2.1601-.8868 2.5537-1.9136l.499-1.3013c.0215-.0561.0293-.1128.0147-.168-.5625-2.5463-2.835-4.4453-5.5499-4.4453-2.5039 0-4.6284 1.6177-5.3876 3.8614-.4927-.3658-1.1187-.5625-1.794-.499-1.2026.119-2.1665 1.083-2.2861 2.2856-.0283.31-.0069.6128.0635.894C1.5683 13.171 0 14.7754 0 16.752c0 .1748.0142.3515.0352.5273.0141.083.0844.1475.1689.1475h15.9814c.0909 0 .1758-.0645.2032-.1553l.12-.4268zm2.7568-5.5634c-.0771 0-.1611 0-.2383.0112-.0566 0-.1054.0415-.127.0976l-.3378 1.1744c-.1475.5068-.0918.9707.1543 1.3164.2256.3164.6055.498 1.0625.5195l1.8437.1133c.0557 0 .1055.0263.1329.0703.0283.043.0351.1074.0214.1562-.0283.084-.1132.1485-.204.1553l-1.921.1123c-1.041.0488-2.1582.8867-2.5527 1.914l-.1406.3585c-.0283.0713.0215.1416.0986.1416h6.5977c.0771 0 .1474-.0489.169-.126.1122-.4082.1757-.837.1757-1.2803 0-2.6025-2.125-4.727-4.7344-4.727",
  vercel: "m12 1.608 12 20.784H0Z",
  aws: "M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.862.272a2.287 2.287 0 0 1-.28.104.488.488 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.416-.287-.807-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.175 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167zM21.698 16.207c-2.626 1.94-6.442 2.969-9.722 2.969-4.598 0-8.74-1.7-11.87-4.526-.247-.223-.024-.527.272-.351 3.384 1.963 7.559 3.153 11.877 3.153 2.914 0 6.114-.607 9.06-1.852.439-.2.814.287.383.607zM22.792 14.961c-.336-.43-2.22-.207-3.074-.103-.255.032-.295-.192-.063-.36 1.5-1.053 3.967-.75 4.254-.399.287.36-.08 2.826-1.485 4.007-.215.184-.423.088-.327-.151.32-.79 1.03-2.57.695-2.994z",
};

export function ProviderIcon({ provider, className = "h-4 w-4" }: { provider: ProviderId; className?: string }) {
  const label = PROVIDER_INFO[provider].label;
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" role="img" aria-label={label} className={`shrink-0 text-kumo-subtle ${className}`}>
      <path d={PROVIDER_GLYPH[provider]} />
    </svg>
  );
}

/**
 * The words Keelson uses for how things are grouped, widest first, each with the icon it carries elsewhere in
 * the app. Shown where accounts are managed, so the picker in the top bar and the columns in Findings make sense.
 */
export function Terms() {
  const each = (fn: (p: ProviderId) => string) => {
    const parts = PROVIDERS.map(fn);
    return parts.length < 2 ? parts.join("") : `${parts.slice(0, -1).join(", ")} or ${parts[parts.length - 1]}`;
  };
  const terms: [typeof StackIcon, string, string][] = [
    [BuildingsIcon, "Entity", "A company, legal entity or team. It owns accounts on any platform, and has its own email domains and alerts."],
    [StackIcon, "Platform", `Where accounts live: ${providerList()}. Each has its own icon, shown wherever platforms mix.`],
    [IdentificationCardIcon, "Account", `One ${each((p) => `${PROVIDER_INFO[p].label} ${PROVIDER_INFO[p].account}`)}, scanned with its own credential.`],
    [MapPinIcon, "Location", `Where in an account something is: a ${each((p) => `${PROVIDER_INFO[p].label} ${PROVIDER_INFO[p].resource}`)}.`],
    [ListChecksIcon, "Check", "A rule Keelson tests on every resource it applies to. A check that compares platforms shows both icons, joined by arrows."],
    [ShieldWarningIcon, "Finding", "One resource failing one check. Findings are what you triage: assign, fix, or accept."],
  ];
  return (
    <Card
      title="How things are grouped"
      description="An entity holds accounts; an account is on one platform and has locations; checks run on what is there, and each failure is a finding."
    >
      <dl className="grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 xl:grid-cols-3">
        {terms.map(([Icon, term, text]) => (
          <div key={term} className="flex gap-3">
            <Icon className="mt-0.5 h-4 w-4 shrink-0 text-kumo-subtle" aria-hidden />
            <div className="min-w-0">
              <dt className="text-sm font-medium text-kumo-default">{term}</dt>
              <dd className="m-0 text-sm text-kumo-subtle">{text}</dd>
            </div>
          </div>
        ))}
      </dl>
    </Card>
  );
}

/**
 * Which platform a finding, check or group of findings is from. A check that compares platforms shows both sides
 * joined by arrows ("AWS compared with Cloudflare"), so a correlation is recognisable at a glance.
 *
 * In a view with one platform a plain mark would repeat what the top bar already says, so it is left out;
 * a correlation is always shown. `always` keeps it anyway, and `label` writes the names next to the glyphs.
 */
export function PlatformMark({
  provider,
  spans = [],
  always,
  label,
  className = "h-3.5 w-3.5",
}: {
  provider: ProviderId | ProviderId[];
  spans?: ProviderId[];
  always?: boolean;
  label?: boolean;
  className?: string;
}) {
  const { view } = useShell();
  const from = Array.isArray(provider) ? provider : [provider];
  const mixed = new Set(view.accounts.map((a) => a.provider)).size > 1;
  if (!from.length || (!spans.length && !mixed && !always)) return null;
  const text = spans.length ? `${providerList(from)} compared with ${providerList(spans)}` : providerList(from);
  return (
    <span
      className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap text-kumo-subtle"
      title={spans.length ? `Compares platforms: ${text}` : `From ${text}`}
    >
      {from.map((p) => (
        <ProviderIcon key={p} provider={p} className={className} />
      ))}
      {spans.length > 0 && (
        <>
          <ArrowsLeftRightIcon className="h-3 w-3 text-kumo-inactive" aria-hidden />
          {spans.map((p) => (
            <ProviderIcon key={p} provider={p} className={className} />
          ))}
        </>
      )}
      {label && <span className="text-xs">{text}</span>}
    </span>
  );
}

/** An account name with its provider's glyph, for tables that mix providers. */
export function AccountName({ name, provider, showProvider = true }: { name: ReactNode; provider: ProviderId; showProvider?: boolean }) {
  if (!showProvider) return <>{name}</>;
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5" title={`${PROVIDER_INFO[provider].label} ${PROVIDER_INFO[provider].account}`}>
      <ProviderIcon provider={provider} className="h-3.5 w-3.5" />
      <span className="truncate">{name}</span>
    </span>
  );
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
  return `Keelson can't read ${c.label.toLowerCase()}${c.notReadableIn?.length ? ` for ${c.notReadableIn.map((a) => a.name).join(", ")}` : ""}. It needs ${c.permission || "the matching read permission"}: grant it, or replace the credential on the Accounts page, then scan again.`;
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
