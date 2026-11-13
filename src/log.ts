// One logger for the server. Plain lines by default; KEELSON_LOG=json writes
// one JSON object per line (for Docker and log shippers). Errors go to stderr.

import { env } from "./env.ts";

type Level = "info" | "warn" | "error";
const json = env("LOG") === "json";

function write(level: Level, msg: string) {
  const line = json ? JSON.stringify({ time: new Date().toISOString(), level, msg }) : `[keelson] ${level === "info" ? "" : `${level}: `}${msg}`;
  (level === "info" ? process.stdout : process.stderr).write(line + "\n");
}

export const log = {
  info: (msg: string) => write("info", msg),
  warn: (msg: string) => write("warn", msg),
  error: (msg: string) => write("error", msg),
};

export type LogFn = (msg: string) => void;
