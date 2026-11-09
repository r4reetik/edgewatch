// Every page in one table: the sidebar, breadcrumbs and router all read it.

import { lazy, type ComponentType } from "react";
import type { ProviderId } from "../../src/shared/providers.ts";
import {
  ArrowsClockwiseIcon,
  BuildingsIcon,
  ClipboardTextIcon,
  ClockCounterClockwiseIcon,
  GaugeIcon,
  GearIcon,
  GlobeIcon,
  ListChecksIcon,
  StackIcon,
  ShieldWarningIcon,
  WalletIcon,
} from "@phosphor-icons/react";

export type NavGroup = "Posture" | "Monitoring" | "Spend" | "Admin";
export const NAV_GROUPS: NavGroup[] = ["Posture", "Monitoring", "Spend", "Admin"];

export interface RouteDef {
  /** A path, or a pattern with `:param` segments. */
  path: string;
  label: string;
  group: NavGroup;
  icon: typeof GaugeIcon;
  page: ComponentType<{ params: Record<string, string> }>;
  /** Hidden from the sidebar (detail pages). */
  hidden?: boolean;
  /** The page applies to every account, so the header doesn't offer a scope. */
  global?: boolean;
  /** The sidebar item to highlight, when it isn't this route. */
  parent?: string;
  /** Only for these providers: hidden from the sidebar when no account in view is on one of them. */
  providers?: ProviderId[];
}

// Pages load on demand so the first paint doesn't wait for the chart library.
const page = <K extends string>(load: () => Promise<Record<K, ComponentType<{ params: Record<string, string> }>>>, name: K) =>
  lazy(() => load().then((m) => ({ default: m[name] })));

export const ROUTES: RouteDef[] = [
  { path: "/", label: "Overview", group: "Posture", icon: GaugeIcon, page: page(() => import("./pages/Overview.tsx"), "OverviewPage") },
  { path: "/findings", label: "Findings", group: "Posture", icon: ShieldWarningIcon, page: page(() => import("./pages/Findings.tsx"), "FindingsPage") },
  {
    path: "/findings/:fp",
    label: "Finding",
    group: "Posture",
    icon: ShieldWarningIcon,
    hidden: true,
    parent: "/findings",
    page: page(() => import("./pages/Finding.tsx"), "FindingPage"),
  },
  { path: "/triaged", label: "Triaged", group: "Posture", icon: ClipboardTextIcon, page: page(() => import("./pages/Triaged.tsx"), "TriagedPage") },
  {
    path: "/zones",
    label: "Zones",
    group: "Posture",
    icon: GlobeIcon,
    providers: ["cloudflare"],
    page: page(() => import("./pages/Zones.tsx"), "ZonesPage"),
  },
  {
    path: "/projects",
    label: "Projects",
    group: "Posture",
    icon: StackIcon,
    providers: ["vercel"],
    page: page(() => import("./pages/Projects.tsx"), "ProjectsPage"),
  },
  {
    path: "/activity",
    label: "Activity",
    group: "Monitoring",
    icon: ClockCounterClockwiseIcon,
    providers: ["cloudflare"],
    page: page(() => import("./pages/Activity.tsx"), "ActivityPage"),
  },
  {
    path: "/value",
    label: "Value",
    group: "Spend",
    icon: WalletIcon,
    providers: ["cloudflare"],
    page: page(() => import("./pages/Value.tsx"), "ValuePage"),
  },
  { path: "/accounts", label: "Accounts", group: "Admin", icon: BuildingsIcon, global: true, page: page(() => import("./pages/Accounts.tsx"), "AccountsPage") },
  { path: "/checks", label: "Checks", group: "Admin", icon: ListChecksIcon, page: page(() => import("./pages/Checks.tsx"), "ChecksPage") },
  { path: "/scans", label: "Scans", group: "Admin", icon: ArrowsClockwiseIcon, page: page(() => import("./pages/Scans.tsx"), "ScansPage") },
  { path: "/settings", label: "Settings", group: "Admin", icon: GearIcon, global: true, page: page(() => import("./pages/Settings.tsx"), "SettingsPage") },
];

export const ReportPage = page(() => import("./pages/Report.tsx"), "ReportPage");

/** The route for a path and its `:param` values. */
export function matchRoute(path: string): { route: RouteDef; params: Record<string, string> } | null {
  const parts = path.replace(/\/+$/, "").split("/");
  for (const route of ROUTES) {
    const pat = route.path.replace(/\/+$/, "").split("/");
    if (pat.length !== parts.length) continue;
    const params: Record<string, string> = {};
    if (pat.every((p, i) => (p.startsWith(":") ? (params[p.slice(1)] = decodeURIComponent(parts[i])) : p === parts[i]))) return { route, params };
  }
  return null;
}
