// Every page in one table: the sidebar, breadcrumbs and router all read it.

import { lazy, type ComponentType } from "react";
import type { ProviderId } from "../../src/shared/providers.ts";
import {
  ArrowsClockwiseIcon,
  MapPinIcon,
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

/**
 * The sidebar's sections, in order. Posture is what's wrong and what's being done about it, for every platform.
 * Inventory is what each platform has (one page per platform). Insights are what a platform reports besides
 * its configuration. Manage is Edgewatch itself: what it scans, with which checks, and when.
 */
export type NavGroup = "Posture" | "Inventory" | "Insights" | "Manage";
export const NAV_GROUPS: NavGroup[] = ["Posture", "Inventory", "Insights", "Manage"];

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
  /** Only for these providers: hidden from the sidebar when no account in view is on one of them, and marked with their icon. */
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
    group: "Inventory",
    icon: GlobeIcon,
    providers: ["cloudflare"],
    page: page(() => import("./pages/Zones.tsx"), "ZonesPage"),
  },
  {
    path: "/projects",
    label: "Projects",
    group: "Inventory",
    icon: StackIcon,
    providers: ["vercel"],
    page: page(() => import("./pages/Projects.tsx"), "ProjectsPage"),
  },
  {
    path: "/regions",
    label: "Regions",
    group: "Inventory",
    icon: MapPinIcon,
    providers: ["aws"],
    page: page(() => import("./pages/Regions.tsx"), "RegionsPage"),
  },
  {
    path: "/activity",
    label: "Activity",
    group: "Insights",
    icon: ClockCounterClockwiseIcon,
    providers: ["cloudflare"],
    page: page(() => import("./pages/Activity.tsx"), "ActivityPage"),
  },
  {
    path: "/value",
    label: "Value",
    group: "Insights",
    icon: WalletIcon,
    providers: ["cloudflare"],
    page: page(() => import("./pages/Value.tsx"), "ValuePage"),
  },
  {
    path: "/accounts",
    label: "Accounts",
    group: "Manage",
    icon: BuildingsIcon,
    global: true,
    page: page(() => import("./pages/Accounts.tsx"), "AccountsPage"),
  },
  { path: "/checks", label: "Checks", group: "Manage", icon: ListChecksIcon, page: page(() => import("./pages/Checks.tsx"), "ChecksPage") },
  { path: "/scans", label: "Scans", group: "Manage", icon: ArrowsClockwiseIcon, page: page(() => import("./pages/Scans.tsx"), "ScansPage") },
  { path: "/settings", label: "Settings", group: "Manage", icon: GearIcon, global: true, page: page(() => import("./pages/Settings.tsx"), "SettingsPage") },
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
