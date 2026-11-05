// Number, date and duration formatting. Relative times are short and uniform:
// "just now", "5 min ago", "3 h ago", "2 d ago".

import { DAY_MS } from "../../../src/shared/time.ts";

const nf = new Intl.NumberFormat("en-US");
export const num = (n: number | null | undefined) => (n == null ? "—" : nf.format(n));
export const compact = (n: number | null | undefined) =>
  n == null ? "—" : new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 }).format(n);
export const pct = (x: number | null | undefined) => (x == null ? "—" : x > 0 && x < 0.005 ? "<1%" : `${Math.round(x * 100)}%`);
/** Scores are shown as whole numbers everywhere. */
export const score = (n: number | null | undefined) => (n == null ? "—" : String(Math.round(n)));
export const dateTime = (s: string | null | undefined) => (s ? new Date(s).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—");
export const dateOnly = (s: string | null | undefined) =>
  s ? new Date(s.length === 10 ? `${s}T00:00:00` : s).toLocaleDateString(undefined, { dateStyle: "medium" }) : "—";

export function ago(s: string | null | undefined): string {
  if (!s) return "—";
  const mins = (Date.now() - Date.parse(s)) / 60_000;
  if (mins < 1) return "just now";
  if (mins < 60) return `${Math.floor(mins)} min ago`;
  if (mins < 1440) return `${Math.floor(mins / 60)} h ago`;
  return `${Math.floor(mins / 1440)} d ago`;
}

export function openFor(s: string | null | undefined): string {
  if (!s) return "—";
  const d = Math.floor((Date.now() - Date.parse(s)) / DAY_MS);
  return d < 1 ? "Today" : d === 1 ? "1 day" : `${d} days`;
}

export const plural = (n: number, one: string, many = `${one}s`) => `${num(n)} ${n === 1 ? one : many}`;
