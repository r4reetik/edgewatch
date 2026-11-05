// Authentication and request hardening.
//
// - Loopback without a password: no login, but the Host header must be a
//   loopback name, which blocks DNS-rebinding attacks from web pages.
// - Password mode: scrypt-verified login, HttpOnly SameSite=Strict session
//   cookie, login rate limits per IP and overall.
// - Every state-changing request must be JSON and same-origin (CSRF).

import { randomBytes, scrypt, scryptSync, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import type { Context, MiddlewareHandler } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";

export interface AuthOptions {
  password: string | null;
  /** Explicitly run without a password on a non-loopback address (behind an authenticating proxy). */
  insecureNoAuth: boolean;
  loopback: boolean;
  trustProxy: boolean;
  allowedHosts: string[];
}

const SESSION_COOKIE = "edgewatch_session";
const SESSION_TTL_MS = 12 * 3600_000;
const LOGIN_WINDOW_MS = 15 * 60_000;
const LOGIN_MAX_ATTEMPTS = 10;
/** Failed logins from all addresses together, so many addresses can't guess (or burn CPU) in parallel. */
const LOGIN_MAX_FAILURES_TOTAL = 100;
/** Addresses remembered for rate limiting; the oldest are forgotten first. */
const LOGIN_TRACKED_IPS = 10_000;
/** A session's cookie is re-issued once it has slid this far, so active users stay signed in. */
const SESSION_REFRESH_MS = 3600_000;

const scryptAsync = promisify(scrypt) as (password: string, salt: Buffer, keylen: number) => Promise<Buffer>;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export class Auth {
  readonly required: boolean;
  readonly #opts: AuthOptions;
  readonly #hash: { salt: Buffer; key: Buffer } | null;
  readonly #sessions = new Map<string, number>();
  readonly #attempts = new Map<string, number[]>();
  #failures: number[] = [];

  constructor(opts: AuthOptions) {
    this.#opts = opts;
    this.required = !!opts.password;
    if (opts.password) {
      const salt = randomBytes(16);
      this.#hash = { salt, key: scryptSync(opts.password, salt, 64) };
    } else {
      this.#hash = null;
    }
  }

  isAuthenticated(c: Context): boolean {
    if (!this.required) return true;
    const id = getCookie(c, SESSION_COOKIE);
    if (!id) return false;
    const exp = this.#sessions.get(id);
    const now = Date.now();
    if (!exp || exp < now) {
      this.#sessions.delete(id);
      return false;
    }
    // Sliding expiry: the cookie is renewed with it, or the browser would drop it 12 hours after sign-in.
    if (exp - now < SESSION_TTL_MS - SESSION_REFRESH_MS) {
      this.#sessions.set(id, now + SESSION_TTL_MS);
      this.#setCookie(c, id);
    }
    return true;
  }

  #setCookie(c: Context, id: string): void {
    setCookie(c, SESSION_COOKIE, id, {
      httpOnly: true,
      sameSite: "Strict",
      path: "/",
      secure: isHttps(c, this.#opts.trustProxy),
      maxAge: SESSION_TTL_MS / 1000,
    });
  }

  /** Returns null on success, or an error message. Hashing runs off the event loop, so guesses can't stall the server. */
  async login(c: Context, password: string): Promise<string | null> {
    if (!this.#hash) return null;
    const ip = clientIp(c, this.#opts.trustProxy);
    const now = Date.now();
    const since = now - LOGIN_WINDOW_MS;
    const recent = (this.#attempts.get(ip) || []).filter((t) => t > since);
    this.#failures = this.#failures.filter((t) => t > since);
    if (recent.length >= LOGIN_MAX_ATTEMPTS || this.#failures.length >= LOGIN_MAX_FAILURES_TOTAL) return "Too many attempts. Try again in a few minutes.";
    const key = await scryptAsync(String(password || ""), this.#hash.salt, 64);
    if (!timingSafeEqual(key, this.#hash.key)) {
      this.#attempts.delete(ip); // re-insert, so the map stays in least-recent order
      this.#attempts.set(ip, [...recent, now]);
      if (this.#attempts.size > LOGIN_TRACKED_IPS) this.#attempts.delete(this.#attempts.keys().next().value as string);
      this.#failures.push(now);
      return "Incorrect password.";
    }
    this.#attempts.delete(ip);
    for (const [sid, exp] of this.#sessions) if (exp < now) this.#sessions.delete(sid);
    const id = randomBytes(32).toString("base64url");
    this.#sessions.set(id, now + SESSION_TTL_MS);
    this.#setCookie(c, id);
    return null;
  }

  logout(c: Context): void {
    const id = getCookie(c, SESSION_COOKIE);
    if (id) this.#sessions.delete(id);
    deleteCookie(c, SESSION_COOKIE, { path: "/" });
  }

  /** Host-header allowlist (loopback mode) and CSRF protection for state-changing requests. */
  guard(): MiddlewareHandler {
    return async (c, next) => {
      const host = (c.req.header("host") || "").toLowerCase();
      const hostname = host.replace(/:\d+$/, "");
      if (this.#opts.loopback && !this.required && !LOOPBACK_HOSTS.has(hostname) && !this.#opts.allowedHosts.includes(hostname)) {
        return c.text("Forbidden host", 403);
      }
      if (!["GET", "HEAD", "OPTIONS"].includes(c.req.method)) {
        if (!(c.req.header("content-type") || "").toLowerCase().startsWith("application/json")) return c.json({ error: "Expected application/json" }, 415);
        const site = c.req.header("sec-fetch-site");
        if (site && site !== "same-origin" && site !== "none") return c.json({ error: "Cross-site request blocked" }, 403);
        const origin = c.req.header("origin");
        if (origin) {
          let originHost = "";
          try {
            originHost = new URL(origin).host.toLowerCase();
          } catch {
            /* invalid */
          }
          const forwarded = this.#opts.trustProxy ? (c.req.header("x-forwarded-host") || "").toLowerCase() : "";
          if (originHost !== host && originHost !== forwarded) return c.json({ error: "Cross-origin request blocked" }, 403);
        }
      }
      await next();
    };
  }
}

export function securityHeaders(): MiddlewareHandler {
  return async (c, next) => {
    await next();
    c.header(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
    );
    c.header("X-Content-Type-Options", "nosniff");
    c.header("X-Frame-Options", "DENY");
    c.header("Referrer-Policy", "no-referrer");
    c.header("Cross-Origin-Opener-Policy", "same-origin");
    c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    if (c.req.path.startsWith("/api/")) c.header("Cache-Control", "no-store");
  };
}

/**
 * The address login limits apply to. Behind a trusted proxy that's the last X-Forwarded-For
 * entry: the one the proxy itself added. Earlier entries come from the client and can be forged.
 */
function clientIp(c: Context, trustProxy: boolean): string {
  if (trustProxy) {
    const xff = c.req.header("x-forwarded-for");
    if (xff) return xff.split(",").at(-1)?.trim() || "unknown";
  }
  const env = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
  return env?.incoming?.socket?.remoteAddress || "unknown";
}

function isHttps(c: Context, trustProxy: boolean): boolean {
  if (trustProxy && c.req.header("x-forwarded-proto") === "https") return true;
  return new URL(c.req.url).protocol === "https:";
}
