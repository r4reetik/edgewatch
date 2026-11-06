// Which Node.js runs Edgewatch, and how to upgrade it. Loaded by bin.ts before
// anything else, so it imports nothing: it has to run on old Node.js versions
// too, to say what's wrong instead of failing on an import.

/** The Node.js line Edgewatch runs on. */
export const NODE_MAJOR = 26;
/** The first Node.js 26 LTS release, the oldest that runs Edgewatch (tested in CI). */
export const MIN_NODE = "26.13.0";

export interface NodeCheck {
  ok: boolean;
  message: string;
}

const parts = (v: string) =>
  v
    .replace(/^v/, "")
    .split(".")
    .map((n) => Number.parseInt(n, 10) || 0);

/** True when version `a` is older than `b`. */
export function older(a: string, b: string): boolean {
  const x = parts(a),
    y = parts(b);
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) < (y[i] ?? 0);
  return false;
}

/** The command that installs Node.js 26 LTS with whatever manages Node.js on this machine. */
export function upgradeCommand(env: Record<string, string | undefined>, execPath: string, platform: string): string {
  const n = NODE_MAJOR;
  if (env.NVM_DIR || /[\\/]\.nvm[\\/]/.test(execPath)) return `nvm install ${n} && nvm alias default ${n}`;
  if (env.FNM_DIR || env.FNM_MULTISHELL_PATH) return `fnm install ${n} && fnm default ${n}`;
  if (env.VOLTA_HOME) return `volta install node@${n}`;
  if (/[\\/](homebrew|Cellar|linuxbrew)[\\/]/.test(execPath)) return `brew install node@${n} && brew link --overwrite --force node@${n}`;
  if (platform === "win32") return "winget install OpenJS.NodeJS.LTS";
  return `Download Node.js ${n} LTS from https://nodejs.org/en/download`;
}

/** Whether this Node.js can run Edgewatch, and if not, how to upgrade. */
export function checkNode(version: string, env: Record<string, string | undefined>, execPath: string, platform: string): NodeCheck {
  if (!older(version, MIN_NODE)) return { ok: true, message: "" };
  const fix = upgradeCommand(env, execPath, platform);
  return {
    ok: false,
    message: [
      `edgewatch: this is Node.js ${version}; Edgewatch needs Node.js ${NODE_MAJOR} LTS (${MIN_NODE} or newer).`,
      "",
      fix.startsWith("Download") ? `  ${fix}` : `Upgrade with:\n  ${fix}`,
      "",
      "Then start the newest Edgewatch:",
      "  npx edgewatch@latest",
      "",
      "Or run it without Node.js, with Docker: see https://github.com/r4reetik/edgewatch#run-it-for-a-team-docker",
    ].join("\n"),
  };
}
