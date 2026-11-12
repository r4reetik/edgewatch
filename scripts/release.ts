// Releases (see docs/releasing.md). A release is cut on the maintainer's machine and
// published by .github/workflows/release.yml when its tag arrives:
//
//   npm run release -- <patch|minor|major|rc> [--dry-run]   sync, check, bump, commit, tag, push main and the tag together
//   npm run sync                                           catch up with origin/main and put moved notes back
//   node scripts/release.ts bump <bump>                    bump package.json and roll CHANGELOG.md (no git)
//   node scripts/release.ts notes <version>                print that version's release notes
//   node scripts/release.ts check                          released notes still match their tags
//
// Why on the maintainer's machine: when CI committed "Release vX.Y.Z" to origin/main,
// every release forked it from the local main. Unpushed local commits were left out of
// the release, and the next pull merged CHANGELOG.md across the rename of "Unreleased",
// moving new notes under the released version. Cutting the release locally and pushing
// main and the tag in one atomic push means there is only ever one main.
//
// The policy it enforces: a release needs notes under "## Unreleased"; notes
// that mark a change "**Breaking:**" need a new release line (a minor version
// before 1.0, a major one after), so nobody pinned to their current line ever
// receives a breaking change; and a database migration also needs a new line,
// so going back to an earlier version of the same line always works.

import { execFileSync } from "node:child_process";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { releaseLine } from "../src/updates.ts";

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

/**
 * Puts notes back where they belong: each released version's section becomes what its tag shipped, and any
 * line it gained since (a merge across the release commit lands new notes there) moves to the top of
 * "## Unreleased". Returns the repaired changelog and the lines it moved.
 */
export function repairReleasedNotes(changelog: string, atTag: (version: string) => string | null): { changelog: string; moved: string[] } {
  let out = changelog;
  const moved: string[] = [];
  for (const v of releasedNotesChanged(changelog, atTag)) {
    const shipped = section(atTag(v)!, `## ${v}`) ?? "";
    const now = section(out, `## ${v}`) ?? "";
    const shippedLines = new Set(shipped.split("\n").map((l) => l.trim()));
    moved.push(...now.split("\n").filter((l) => l.trim() && !shippedLines.has(l.trim())));
    out = replaceSection(out, `## ${v}`, shipped);
  }
  if (!moved.length) return { changelog: out, moved };
  const unreleased = section(out, UNRELEASED) ?? "";
  const kept = unreleased ? unreleased.split("\n") : [];
  const fresh = moved.filter((l) => !kept.some((k) => k.trim() === l.trim()));
  if (!out.includes(UNRELEASED)) out = out.replace(/^(# .*\n)/m, `$1\n${UNRELEASED}\n`);
  return { changelog: replaceSection(out, UNRELEASED, [...fresh, ...kept].join("\n")), moved };
}

/** Replaces the body under a "## <heading>" line, keeping one blank line around it. */
function replaceSection(changelog: string, heading: string, body: string): string {
  const lines = changelog.split("\n");
  const start = lines.findIndex((l) => l.trim() === heading);
  if (start < 0) return changelog;
  let end = lines.findIndex((l, i) => i > start && l.startsWith("## "));
  if (end < 0) end = lines.length;
  const middle = body.trim() ? ["", body.trim(), ""] : [""];
  return [...lines.slice(0, start + 1), ...middle, ...lines.slice(end)].join("\n").replace(/\n*$/, "\n");
}

/** CHANGELOG.md at tag v<version>, or null when the tag isn't there (a shallow clone has none). */
export function changelogAtTag(version: string, cwd = process.cwd()): string | null {
  try {
    return execFileSync("git", ["show", `v${version}:CHANGELOG.md`], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  } catch {
    return null;
  }
}

function checkReleasedNotes(changelog: string, atTag: (version: string) => string | null = changelogAtTag) {
  const changed = releasedNotesChanged(changelog, atTag);
  if (changed.length) {
    throw new Error(
      `CHANGELOG.md has different notes for ${changed.join(", ")} than the release had. Notes added since belong under "## Unreleased": ` +
        "`npm run sync` moves them back.",
    );
  }
}

/** Install instructions that name a release line, so new installs start on the newest one. */
export const LINE_DOCS = ["README.md", "docs/deployment.md"];

/**
 * Points install commands at release line `line`: the Docker tag (`keelson:0.5`, "Docker tag `:0.5`")
 * and the npm range (`keelson@0.5`). Exact versions (`keelson@0.5.1`) and `@latest` are left alone.
 */
export function pinLine(text: string, line: string): string {
  return text.replace(/(ghcr\.io\/[\w.-]+\/keelson:|\bkeelson@|Docker tag `:)(\d+(?:\.\d+)?)(?![\w.-])/g, (_m, prefix: string) => `${prefix}${line}`);
}

/** Fingerprints added to the shipped-migrations list since a git ref (test/migrations.test.ts). */
export function migrationsAddedSince(diff: string): number {
  return (
    (diff.match(/^\+(?!\+).*"[0-9a-f]{16}"/gm) ?? []).reduce((n, line) => n + (line.match(/"[0-9a-f]{16}"/g) ?? []).length, 0) -
    (diff.match(/^-(?!-).*"[0-9a-f]{16}"/gm) ?? []).reduce((n, line) => n + (line.match(/"[0-9a-f]{16}"/g) ?? []).length, 0)
  );
}

/** Refuses a database migration in a release that stays on the current line. */
function checkMigrations(current: string, next: string, cwd = process.cwd()) {
  if (newLine(current, next)) return;
  let diff: string;
  try {
    diff = execFileSync("git", ["diff", "--unified=0", `v${current}`, "--", "test/migrations.test.ts"], { cwd, encoding: "utf8" });
  } catch {
    console.warn(`release: can't compare with v${current} (no tag?); skipping the migration check`);
    return;
  }
  if (migrationsAddedSince(diff) > 0) {
    throw new Error(`There's a new database migration since v${current}, so ${next} can't be a compatible update: release a minor version (or an rc) instead.`);
  }
}

/** Applies a bump to the files in `dir`. Returns the versions and the files it changed. */
export function bump(kind: string, dir = process.cwd(), { write = true } = {}) {
  if (!BUMPS.includes(kind as Bump)) throw new Error(`Bump must be one of ${BUMPS.join(", ")}`);
  const path = (f: string) => join(dir, f);
  const read = (f: string) => readFileSync(path(f), "utf8");
  const pkg = JSON.parse(read("package.json"));
  const lock = JSON.parse(read("package-lock.json"));
  const current = pkg.version as string;
  const next = nextVersion(current, kind as Bump);
  checkReleasedNotes(read("CHANGELOG.md"), (v) => changelogAtTag(v, dir));
  checkMigrations(current, next, dir);
  const changelog = rollChangelog(read("CHANGELOG.md"), current, next);
  const touched = ["CHANGELOG.md", "package.json", "package-lock.json"];
  if (!write) return { current, next, touched };
  writeFileSync(path("CHANGELOG.md"), changelog);
  // A new stable line: install instructions move to it (release candidates never do).
  if (!next.includes("-") && newLine(current, next))
    for (const f of LINE_DOCS) {
      writeFileSync(path(f), pinLine(read(f), releaseLine(next)));
      touched.push(f);
    }
  pkg.version = lock.version = lock.packages[""].version = next;
  writeFileSync(path("package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
  writeFileSync(path("package-lock.json"), `${JSON.stringify(lock, null, 2)}\n`);
  return { current, next, touched };
}

/** Files a release commit changes: the only ones `sync` resolves conflicts in by itself. */
export const RELEASE_FILES = ["package.json", "package-lock.json", "CHANGELOG.md", ...LINE_DOCS];

/**
 * Resolves conflicts that are only adjacent, not overlapping, in a file merged with diff3 markers: when a hunk
 * has the same number of lines on both sides and in the base, each line takes whichever side changed it. A
 * release bumps `"version"` on one line while the branch edits the next (the description), and git reports that
 * as a conflict. Returns null when any line was changed differently on both sides: that's a real conflict.
 */
export function resolveAdjacent(text: string): string | null {
  const out: string[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].startsWith("<<<<<<< ")) {
      out.push(lines[i]);
      continue;
    }
    const ours: string[] = [],
      base: string[] = [],
      theirs: string[] = [];
    let part = ours;
    for (i++; i < lines.length && !lines[i].startsWith(">>>>>>> "); i++) {
      if (lines[i].startsWith("||||||| ")) part = base;
      else if (lines[i] === "=======") part = theirs;
      else part.push(lines[i]);
    }
    if (part !== theirs || ours.length !== base.length || theirs.length !== base.length) return null;
    for (let j = 0; j < base.length; j++) {
      if (ours[j] === base[j] || ours[j] === theirs[j]) out.push(theirs[j]);
      else if (theirs[j] === base[j]) out.push(ours[j]);
      else return null;
    }
  }
  return out.join("\n");
}

const gitIn =
  (cwd: string) =>
  (...args: string[]) =>
    execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

/** Stops unless `dir` is on main with nothing uncommitted: a release or sync must not mix with work in progress. */
function requireCleanMain(git: (...a: string[]) => string) {
  const branch = git("rev-parse", "--abbrev-ref", "HEAD");
  if (branch !== "main") throw new Error(`Releases come from main; you're on ${branch}. Switch with \`git switch main\`.`);
  const dirty = git("status", "--porcelain");
  if (dirty) throw new Error(`Commit or stash these first, so they aren't mixed into the release:\n${dirty}`);
}

/**
 * Brings main up to date with origin/main: fetches, merges what's new there (pull requests, Dependabot), and
 * moves notes a merge landed under a released version back to "## Unreleased", committing that repair.
 * Stops on a merge conflict, leaving main as it was.
 */
export function sync(dir = process.cwd(), log: (m: string) => void = console.log): { merged: number; moved: string[] } {
  const git = gitIn(dir);
  requireCleanMain(git);
  git("fetch", "--quiet", "--tags", "origin", "main");
  const behind = Number(git("rev-list", "--count", "HEAD..origin/main"));
  if (behind) {
    try {
      git("-c", "merge.conflictStyle=diff3", "merge", "--no-edit", "--quiet", "origin/main");
    } catch (e) {
      const conflicted = git("diff", "--name-only", "--diff-filter=U").split("\n").filter(Boolean);
      const resolved = conflicted.every((f) => {
        if (!RELEASE_FILES.includes(f)) return false;
        const merged = resolveAdjacent(readFileSync(join(dir, f), "utf8"));
        if (merged == null) return false;
        writeFileSync(join(dir, f), merged);
        return true;
      });
      if (!conflicted.length || !resolved) {
        git("merge", "--abort");
        throw new Error(
          `Merging origin/main conflicts${conflicted.length ? ` in ${conflicted.join(", ")}` : ""}, so nothing changed. Run \`git merge origin/main\`, resolve the conflicts, commit, then run this again.\n${(e as { stderr?: string }).stderr ?? ""}`,
        );
      }
      git("add", "--", ...conflicted);
      git("commit", "--quiet", "--no-edit");
      log(`Resolved the release's version change next to your edits in ${conflicted.join(", ")}.`);
    }
    log(`Merged ${behind} commit${behind === 1 ? "" : "s"} from origin/main.`);
  }
  const path = join(dir, "CHANGELOG.md");
  const { changelog, moved } = repairReleasedNotes(readFileSync(path, "utf8"), (v) => changelogAtTag(v, dir));
  if (moved.length) {
    writeFileSync(path, changelog);
    git("commit", "--quiet", "-m", "Keep notes written after the last release under Unreleased", "--", "CHANGELOG.md");
    log(`Moved ${moved.length} note${moved.length === 1 ? "" : "s"} back under "## Unreleased".`);
  }
  return { merged: behind, moved };
}

/**
 * Cuts a release: sync with origin, run the checks, bump, commit "Release vX.Y.Z", tag it, and push main and the
 * tag in one atomic push (both land or neither does). The tag starts the Release workflow, which publishes.
 */
export function release(kind: string, { dir = process.cwd(), dryRun = false, check = true, log = console.log } = {}) {
  const git = gitIn(dir);
  if (dryRun) {
    requireCleanMain(git);
    git("fetch", "--quiet", "--tags", "origin", "main");
    const behind = Number(git("rev-list", "--count", "HEAD..origin/main"));
    const ahead = Number(git("rev-list", "--count", "origin/main..HEAD"));
    const { current, next } = bump(kind, dir, { write: false });
    log(
      `Would release ${current} → ${next}${behind ? `, after merging ${behind} commit${behind === 1 ? "" : "s"} from origin/main` : ""}, and push ${ahead} local commit${ahead === 1 ? "" : "s"} with it.`,
    );
    log(`\nNotes:\n${section(readFileSync(join(dir, "CHANGELOG.md"), "utf8"), UNRELEASED)}`);
    return { next, pushed: false };
  }
  sync(dir, log);
  if (check) {
    log("Running npm run check…");
    execFileSync("npm", ["run", "check"], { cwd: dir, stdio: "inherit" });
  }
  const { next, touched } = bump(kind, dir);
  git("add", "--", ...touched);
  git("commit", "--quiet", "-m", `Release v${next}`);
  git("tag", "-a", `v${next}`, "-m", `Keelson v${next}`);
  git("push", "--atomic", "--quiet", "origin", "HEAD:main", `v${next}`);
  const repo = /github\.com[:/](.+?)(?:\.git)?$/.exec(git("remote", "get-url", "origin"))?.[1];
  log(`Released v${next}: main and the tag are on origin.${repo ? ` Publishing: https://github.com/${repo}/actions/workflows/release.yml` : ""}`);
  return { next, pushed: true };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const [cmd, arg] = process.argv.slice(2);
  try {
    if (cmd === "bump") {
      const { next } = bump(arg);
      console.log(`keelson ${next}`);
      if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `version=${next}\ntag=v${next}\n`);
    } else if (cmd === "release") release(arg, { dryRun: process.argv.includes("--dry-run"), check: !process.argv.includes("--skip-check") });
    else if (cmd === "sync") {
      const r = sync();
      if (!r.merged && !r.moved.length) console.log("main is up to date with origin/main.");
    } else if (cmd === "check") checkReleasedNotes(readFileSync("CHANGELOG.md", "utf8"));
    else if (cmd === "notes") console.log(releaseNotes(readFileSync("CHANGELOG.md", "utf8"), String(arg).replace(/^v/, "")));
    else
      throw new Error(
        "Usage: npm run release -- <patch|minor|major|rc> [--dry-run] | npm run sync | node scripts/release.ts bump <bump> | notes <version> | check",
      );
  } catch (e) {
    console.error(`release: ${(e as Error).message}`);
    process.exit(1);
  }
}
