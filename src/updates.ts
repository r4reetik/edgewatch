// Tells the dashboard when a newer Keelson is out, and whether upgrading to it
// includes breaking changes. Once a day it reads the public list of GitHub
// releases: one unauthenticated GET with a generic User-Agent, and nothing about
// this install is sent. Turned off in Settings, or with KEELSON_UPDATE_CHECK=off.
//
// A release is breaking when its notes mark a change "**Breaking:**" (the
// CHANGELOG convention, see docs/releasing.md). By the versioning policy those
// only ship in a new minor (0.x) or major (1.x and later) version, so an
// installation pinned to its current line never receives one automatically.

import type { InstallKind, UpdateStatus } from "./shared/api.ts";

const DAY_MS = 86_400_000;
const FIRST_CHECK_MS = 30_000;
const TIMEOUT_MS = 10_000;
const BREAKING = /\*\*Breaking\b|^#{1,4}\s*Breaking\b/im;

interface Version {
  nums: [number, number, number];
  pre: string | null;
}

export function parseVersion(v: string): Version | null {
  const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(v.trim());
  return m ? { nums: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? null } : null;
}

/** Semver order: numbers first, then a prerelease sorts before its release. */
export function compareVersions(a: string, b: string): number {
  const x = parseVersion(a),
    y = parseVersion(b);
  if (!x || !y) return 0;
  for (let i = 0; i < 3; i++) if (x.nums[i] !== y.nums[i]) return x.nums[i] - y.nums[i];
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  return x.pre.localeCompare(y.pre, "en", { numeric: true });
}

/** The release line updates stay within without breaking changes: "0.4" before 1.0, "1" after. */
export function releaseLine(v: string): string {
  const p = parseVersion(v);
  if (!p) return v;
  return p.nums[0] === 0 ? `0.${p.nums[1]}` : String(p.nums[0]);
}

interface GithubRelease {
  tag_name: string;
  html_url: string;
  published_at: string | null;
  body: string | null;
  draft: boolean;
  prerelease: boolean;
}

/** What's newer than `current` among published, stable releases. */
export function evaluate(current: string, releases: GithubRelease[]): Pick<UpdateStatus, "latest" | "inLine" | "breaking" | "newerCount"> {
  const newer = releases
    .filter((r) => !r.draft && !r.prerelease && parseVersion(r.tag_name) && compareVersions(r.tag_name, current) > 0)
    .sort((a, b) => compareVersions(b.tag_name, a.tag_name));
  if (!newer.length) return { latest: null, inLine: null, breaking: false, newerCount: 0 };
  const version = (r: GithubRelease) => r.tag_name.replace(/^v/, "");
  const top = newer[0];
  // When the latest starts a new line, the newest compatible update is still worth taking.
  const line = newer.find((r) => releaseLine(version(r)) === releaseLine(current));
  return {
    latest: { version: version(top), url: top.html_url, publishedAt: top.published_at, sameLine: releaseLine(version(top)) === releaseLine(current) },
    inLine: line && line !== top ? { version: version(line), url: line.html_url } : null,
    breaking: newer.some((r) => BREAKING.test(r.body ?? "")),
    newerCount: newer.length,
  };
}

export interface UpdateCheckerOptions {
  version: string;
  /** "owner/name" on GitHub; null turns checking off (a fork without a repository). */
  repository: string | null;
  install: InstallKind;
  /** Read on every check, so the Settings switch applies without a restart. */
  enabled: () => boolean;
  /** Switched off by KEELSON_UPDATE_CHECK=off, whatever Settings says. */
  lockedOff?: boolean;
  fetch?: typeof fetch;
  log?: (msg: string) => void;
}

export class UpdateChecker {
  readonly #o: UpdateCheckerOptions;
  #status: UpdateStatus;

  constructor(o: UpdateCheckerOptions) {
    this.#o = o;
    this.#status = {
      enabled: this.#on(),
      lockedOff: !!o.lockedOff,
      current: o.version,
      install: o.install,
      line: releaseLine(o.version),
      latest: null,
      inLine: null,
      breaking: false,
      newerCount: 0,
      checkedAt: null,
      error: null,
    };
  }

  #on(): boolean {
    return !this.#o.lockedOff && !!this.#o.repository && this.#o.enabled();
  }

  status(): UpdateStatus {
    return { ...this.#status, enabled: this.#on() };
  }

  async check(): Promise<UpdateStatus> {
    const { repository, version } = this.#o;
    if (!repository || !this.#on()) return this.status();
    try {
      const res = await (this.#o.fetch ?? fetch)(`https://api.github.com/repos/${repository}/releases?per_page=30`, {
        headers: { accept: "application/vnd.github+json", "user-agent": "Keelson update check" },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(`GitHub answered ${res.status}`);
      this.#status = { ...this.#status, ...evaluate(version, (await res.json()) as GithubRelease[]), checkedAt: new Date().toISOString(), error: null };
      if (this.#status.latest)
        this.#o.log?.(
          `Keelson ${this.#status.latest.version} is available (running ${version})${this.#status.breaking ? ", with breaking changes" : ""}: ${this.#status.latest.url}`,
        );
    } catch (e) {
      // A failed check is never an error for the user: keep the last result and try again tomorrow.
      this.#status = { ...this.#status, checkedAt: new Date().toISOString(), error: (e as Error).message };
    }
    return this.status();
  }

  /** Checks shortly after start, then daily. Returns a function that stops it. */
  start(): () => void {
    const first = setTimeout(() => void this.check(), FIRST_CHECK_MS);
    const daily = setInterval(() => void this.check(), DAY_MS);
    first.unref();
    daily.unref();
    return () => {
      clearTimeout(first);
      clearInterval(daily);
    };
  }
}
