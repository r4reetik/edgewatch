// Which Node.js runs Edgewatch, and how to upgrade it. Loaded by bin.ts before
// anything else, so it imports nothing: it has to run on old Node.js versions
// too, to say what's wrong instead of failing on an import.

/** The oldest Node.js that runs Edgewatch (tested in CI). */
export const MIN_NODE = "24.22.1";
/** The Node.js line Edgewatch is built and tested on. */
export const RECOMMENDED_NODE_MAJOR = 26;

export interface NodeCheck {
  level: "ok" | "warn" | "error";
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

/** The command that installs Node.js 26 with whatever manages Node.js on this machine. */
export function upgradeCommand(env: Record<string, string | undefined>, execPath: string, platform: string): string {
  const n = RECOMMENDED_NODE_MAJOR;
  if (env.NVM_DIR || /[\\/]\.nvm[\\/]/.test(execPath)) return `nvm install ${n} && nvm alias default ${n}`;
  if (env.FNM_DIR || env.FNM_MULTISHELL_PATH) return `fnm install ${n} && fnm default ${n}`;
  if (env.VOLTA_HOME) return `volta install node@${n}`;
  if (/[\\/](homebrew|Cellar|linuxbrew)[\\/]/.test(execPath)) return `brew install node@${n} && brew link --overwrite --force node@${n}`;
  if (platform === "win32") return "winget install OpenJS.NodeJS.LTS";
  return `Download Node.js ${n} LTS from https://nodejs.org/en/download`;
}

/** Whether this Node.js can run Edgewatch, and what to tell the user if it's not the recommended one. */
export function checkNode(version: string, env: Record<string, string | undefined>, execPath: string, platform: string): NodeCheck {
  const n = RECOMMENDED_NODE_MAJOR;
  const fix = upgradeCommand(env, execPath, platform);
  const how = fix.startsWith("Download") ? `  ${fix}` : `Upgrade with:\n  ${fix}`;
  if (older(version, MIN_NODE)) {
    return {
      level: "error",
      message: [
        `edgewatch: this is Node.js ${version}; Edgewatch needs Node.js ${n} LTS (or at least ${MIN_NODE}).`,
        "",
        how,
        "",
        "Then start the newest Edgewatch:",
        "  npx edgewatch@latest",
        "",
        "Or run it without Node.js, with Docker: see https://github.com/r4reetik/edgewatch#run-it-for-a-team-docker",
      ].join("\n"),
    };
  }
  if (parts(version)[0] < n) {
    return {
      level: "warn",
      message: `edgewatch: Node.js ${n} LTS is recommended; this is Node.js ${version}. Edgewatch runs on it, but upgrade when you can. ${how.replace(/\n\s*/, " ")}`,
    };
  }
  return { level: "ok", message: "" };
}
