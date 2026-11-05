// Handlers throw HttpError; the app turns it into `{ error, code? }` JSON.

import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { ApiError } from "../shared/api.ts";
import { log } from "../log.ts";

export class HttpError extends Error {
  readonly status: ContentfulStatusCode;
  readonly code?: ApiError["code"];
  constructor(status: ContentfulStatusCode, message: string, code?: ApiError["code"]) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const badRequest = (message: string) => new HttpError(400, message);
export const notFound = (message = "Not found") => new HttpError(404, message);
export const conflict = (message: string) => new HttpError(409, message);

export function onError(err: Error, c: Context) {
  if (err instanceof HttpError) return c.json({ error: err.message, ...(err.code ? { code: err.code } : {}) } satisfies ApiError, err.status);
  log.error(err.stack || String(err));
  return c.json({ error: "Internal error" } satisfies ApiError, 500);
}
