// Release helpers for .github/workflows/release.yml (see docs/releasing.md).
//
//   node scripts/release.ts bump <patch|minor|major|rc>   bump package.json and roll CHANGELOG.md
//   node scripts/release.ts notes <version>               print that version's release notes
//   node scripts/release.ts check                         released notes still match their tags
//
// The policy it enforces: a release needs notes under "## Unreleased"; notes
// that mark a change "**Breaking:**" need a new release line (a minor version
// before 1.0, a major one after), so nobody pinned to their current line ever
// receives a breaking change; and a database migration also needs a new line,
// so going back to an earlier version of the same line always works.

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export type Bump = "patch" | "minor" | "major" | "rc";
export const BUMPS: readonly Bump[] = ["patch", "minor", "major", "rc"];

const UNRELEASED = "## Unreleased";
const BREAKING = /\*\*Breaking\b|^#{1,4}\s*Breaking\b/im;

function parse(v: string) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?$/.exec(v);
  if (!m) throw new Error(`Unexpected version ${v}; expected X.Y.Z or X.Y.Z-rc.N`);
  return { major: +m[1], minor: +m[2], patch: +m[3], rc: m[4] == null ? null : +m[4] };
}

/**
 * The next version. Like npm's semver: releasing from a release candidate
 * finalises it (0.5.0-rc.2 + minor = 0.5.0). "rc" starts a candidate for the
 * next release line (0.4.1 → 0.5.0-rc.1, 1.2.0 → 2.0.0-rc.1) or moves to the
 * next candidate.
 */
export function nextVersion(current: string, bump: Bump): string {
  const v = parse(current);
  const pre = v.rc != null;
  switch (bump) {
    case "patch":
      return pre ? `${v.major}.${v.minor}.${v.patch}` : `${v.major}.${v.minor}.${v.patch + 1}`;
    case "minor":
      return pre && v.patch === 0 ? `${v.major}.${v.minor}.0` : `${v.major}.${v.minor + 1}.0`;
    case "major":
      return pre && v.minor === 0 && v.patch === 0 ? `${v.major}.0.0` : `${v.major + 1}.0.0`;
    case "rc":
      if (pre) return `${v.major}.${v.minor}.${v.patch}-rc.${(v.rc as number) + 1}`;
      return v.major === 0 ? `0.${v.minor + 1}.0-rc.1` : `${v.major + 1}.0.0-rc.1`;
  }
}

/** True when `next` starts a new release line after `current` (where breaking changes may go). */
export function newLine(current: string, next: string): boolean {
  const a = parse(current),
    b = parse(next);
  if (a.major !== b.major) return true;
  // Finalising a candidate (0.5.0-rc.1 → 0.5.0) is part of the line the candidate opened.
  if (a.rc != null && a.minor === b.minor && a.patch === b.patch) return b.major === 0 ? b.patch === 0 : b.minor === 0 && b.patch === 0;
  return b.major === 0 && a.minor !== b.minor;
}

/** The notes under a "## <heading>" line, up to the next "## ". */
export function section(changelog: string, heading: string): string | null {
  const lines = changelog.split("\n");
  const start = lines.findIndex((l) => l.trim() === heading);
  if (start < 0) return null;
  const end = lines.findIndex((l, i) => i > start && l.startsWith("## "));
  return lines
    .slice(start + 1, end < 0 ? undefined : end)
    .join("\n")
    .trim();
}

/** The release notes for a version: its own section, or "Unreleased" for a release candidate. */
export function releaseNotes(changelog: string, version: string): string {
  const notes = version.includes("-") ? section(changelog, UNRELEASED) : section(changelog, `## ${version}`);
  if (!notes) throw new Error(`CHANGELOG.md has no notes for ${version}`);
  return notes;
}

/**
 * Applies a bump to the CHANGELOG: a release renames "## Unreleased" to its
 * version and opens a new, empty "## Unreleased"; a release candidate leaves it
 * as is. Refuses a release with no notes, or a breaking change outside a new line.
 */
export function rollChangelog(changelog: string, current: string, next: string): string {
  const notes = section(changelog, UNRELEASED);
  if (!notes) throw new Error('Nothing to release: add notes under "## Unreleased" in CHANGELOG.md first.');
  if (BREAKING.test(notes) && !newLine(current, next)) {
    throw new Error(
      `The unreleased notes mark a breaking change, so ${next} can't be a compatible update to ${current}. Release a ${parse(current).major === 0 ? "minor" : "major"} version (or an rc) instead.`,
    );
  }
  if (next.includes("-")) return changelog;
  return changelog.replace(new RegExp(`^${UNRELEASED}$`, "m"), `${UNRELEASED}\n\n## ${next}`);
}

/**
 * Versions whose CHANGELOG notes differ from the notes at their release tag. Notes
 * written after a release belong under "## Unreleased", but a merge or rebase across
 * the workflow's "Release vX.Y.Z" commit can land them under that version instead,
 * which leaves "Unreleased" empty and describes the release wrongly.
 * `atTag(version)` returns CHANGELOG.md as tagged, or null when there's no such tag.
 */
export function releasedNotesChanged(changelog: string, atTag: (version: string) => string | null): string[] {
  const versions = [...changelog.matchAll(/^## (\d+\.\d+\.\d+)\s*$/gm)].map((m) => m[1]);
  return versions.filter((v) => {
    const tagged = atTag(v);
    return tagged != null && section(tagged, `## ${v}`) !== section(changelog, `## ${v}`);
  });
}

/** CHANGELOG.md at tag v<version>, or null when the tag isn't there (a shallow clone has none). */
export function changelogAtTag(version: string): string | null {
  try {
    return execFileSync("git", ["show", `v${version}:CHANGELOG.md`], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return null;
  }
}

function checkReleasedNotes(changelog: string) {
  const changed = releasedNotesChanged(changelog, changelogAtTag);
  if (changed.length) {
    throw new Error(
      `CHANGELOG.md has different notes for ${changed.join(", ")} than the release had. Notes added since belong under "## Unreleased" ` +
        "(a git pull that merged the Release commit can move them); compare with `git show v<version>:CHANGELOG.md`.",
    );
  }
}

/** Fingerprints added to the shipped-migrations list since a git ref (test/migrations.test.ts). */
export function migrationsAddedSince(diff: string): number {
  return (
    (diff.match(/^\+(?!\+).*"[0-9a-f]{16}"/gm) ?? []).reduce((n, line) => n + (line.match(/"[0-9a-f]{16}"/g) ?? []).length, 0) -
    (diff.match(/^-(?!-).*"[0-9a-f]{16}"/gm) ?? []).reduce((n, line) => n + (line.match(/"[0-9a-f]{16}"/g) ?? []).length, 0)
  );
}

/** Refuses a database migration in a release that stays on the current line. */
function checkMigrations(current: string, next: string) {
  if (newLine(current, next)) return;
  let diff: string;
  try {
    diff = execFileSync("git", ["diff", "--unified=0", `v${current}`, "--", "test/migrations.test.ts"], { encoding: "utf8" });
  } catch {
    console.warn(`release: can't compare with v${current} (no tag?); skipping the migration check`);
    return;
  }
  if (migrationsAddedSince(diff) > 0) {
    throw new Error(`There's a new database migration since v${current}, so ${next} can't be a compatible update: release a minor version (or an rc) instead.`);
  }
}

function bump(kind: string) {
  if (!BUMPS.includes(kind as Bump)) throw new Error(`Bump must be one of ${BUMPS.join(", ")}`);
  const read = (f: string) => readFileSync(f, "utf8");
  const pkg = JSON.parse(read("package.json"));
  const lock = JSON.parse(read("package-lock.json"));
  const next = nextVersion(pkg.version, kind as Bump);
  checkReleasedNotes(read("CHANGELOG.md"));
  checkMigrations(pkg.version, next);
  writeFileSync("CHANGELOG.md", rollChangelog(read("CHANGELOG.md"), pkg.version, next));
  pkg.version = lock.version = lock.packages[""].version = next;
  writeFileSync("package.json", `${JSON.stringify(pkg, null, 2)}\n`);
  writeFileSync("package-lock.json", `${JSON.stringify(lock, null, 2)}\n`);
  console.log(`${pkg.name} ${next}`);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `version=${next}\ntag=v${next}\n`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [cmd, arg] = process.argv.slice(2);
  try {
    if (cmd === "bump") bump(arg);
    else if (cmd === "check") checkReleasedNotes(readFileSync("CHANGELOG.md", "utf8"));
    else if (cmd === "notes") console.log(releaseNotes(readFileSync("CHANGELOG.md", "utf8"), String(arg).replace(/^v/, "")));
    else throw new Error("Usage: node scripts/release.ts bump <patch|minor|major|rc> | notes <version> | check");
  } catch (e) {
    console.error(`release: ${(e as Error).message}`);
    process.exit(1);
  }
}
