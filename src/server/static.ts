// Serves the built web app; unknown paths get index.html for client-side routes.

import type { Context } from "hono";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".json": "application/json",
  ".txt": "text/plain; charset=utf-8",
};

export async function serveWeb(c: Context, webDir: string | null): Promise<Response> {
  if (!webDir) return c.text("Web UI is not built. Run `npm run build:web`.", 503);
  const rel = normalize(decodeURIComponent(c.req.path)).replace(/^([/\\])+/, "");
  const file = join(webDir, rel);
  if (!file.startsWith(webDir + sep) && file !== webDir) return c.text("Not found", 404);
  let target = file;
  try {
    if (!(await stat(target)).isFile()) target = join(webDir, "index.html");
  } catch {
    // SPA fallback for client-side routes; real asset paths 404.
    if (rel.startsWith("assets/") || extname(rel)) return c.text("Not found", 404);
    target = join(webDir, "index.html");
  }
  const isAsset = target.includes(`${sep}assets${sep}`);
  return new Response(await readFile(target), {
    headers: {
      "content-type": MIME[extname(target)] || "application/octet-stream",
      "cache-control": isAsset ? "public, max-age=31536000, immutable" : "no-cache",
    },
  });
}
