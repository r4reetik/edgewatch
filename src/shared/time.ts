export const DAY_MS = 86_400_000;
export const HOUR_MS = 3_600_000;

/** YYYY-MM-DD in UTC. */
export const isoDate = (t: number | Date = Date.now()): string => new Date(t).toISOString().slice(0, 10);

/** ISO timestamp without milliseconds, as Cloudflare's APIs expect. */
export const isoSeconds = (t: number): string => new Date(t).toISOString().replace(/\.\d+Z$/, "Z");

export const daysBetween = (from: string | number, to: number = Date.now()): number =>
  Math.floor((to - (typeof from === "string" ? Date.parse(from) : from)) / DAY_MS);
