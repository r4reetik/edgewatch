// Read-only AWS client. Every request is a signed GET (test/aws.test.ts fails on
// anything else): the Query APIs (IAM, STS, EC2, RDS, load balancers) take their
// action in the query string, and the REST APIs (S3, CloudFront, Route 53, Lambda,
// GuardDuty) are read with GET by design. Services that only answer POST, such as
// CloudTrail, KMS and Config, are not read. Every call is recorded under a coverage
// label, like the other providers' clients.
//
// Limits: at most 8 requests in flight. Throttling answers and 5xx are retried
// with a growing pause; network errors are retried twice.

import { AWS_SOURCES, HOME_REGION, type AwsSourceKey } from "./sources.ts";
import { awsEncode, canonicalQuery, EMPTY_SHA256, signGet, type AwsCredentials } from "./sigv4.ts";
import { find, parseXml, text, type XmlNode } from "./xml.ts";
import { CREDENTIAL_SEPARATOR } from "../../shared/providers.ts";
import type { Coverage } from "../../shared/api.ts";

const MAX_IN_FLIGHT = 8;
const TIMEOUT_MS = 30_000;
/** A raw JSON payload from a REST-JSON API; inventory.ts turns it into the typed shapes in types.ts. */
export type Json = any;

/** The API version each Query service is asked for. */
const QUERY_VERSION: Record<string, string> = {
  iam: "2010-05-08",
  sts: "2011-06-15",
  ec2: "2016-11-15",
  rds: "2014-10-31",
  elasticloadbalancing: "2015-12-01",
};
/** Services with one endpoint for every region. */
const GLOBAL_HOST: Record<string, string> = { iam: "iam.amazonaws.com", sts: "sts.amazonaws.com" };
const THROTTLED = /^(Throttling|ThrottlingException|RequestLimitExceeded|TooManyRequestsException|SlowDown|RequestThrottled)$/;
const DENIED =
  /^(AccessDenied|AccessDeniedException|UnauthorizedOperation|AuthFailure|OptInRequired|InvalidClientTokenId|UnrecognizedClientException|SubscriptionRequiredException)$/;

export class AwsError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
  /** The thing asked for isn't set up: no password policy, no bucket policy. */
  get notFound(): boolean {
    return this.status === 404 || this.code.startsWith("NoSuch");
  }
  /** The access key isn't allowed to read it, or the region isn't open to it. */
  get denied(): boolean {
    return this.status === 401 || this.status === 403 || DENIED.test(this.code);
  }
}

/**
 * The access key as the vault stores it: "<access key ID>:<secret access key>". Null when it isn't
 * a long-lived key pair; temporary keys (ASIA…) need a session token and expire within hours.
 */
export function parseCredentials(token: string): AwsCredentials | null {
  const at = token.indexOf(CREDENTIAL_SEPARATOR);
  if (at < 0) return null;
  const accessKeyId = token.slice(0, at).trim();
  const secretAccessKey = token.slice(at + 1).trim();
  return /^AKIA[A-Z0-9]{12,28}$/.test(accessKeyId) && /^[A-Za-z0-9/+=]{30,80}$/.test(secretAccessKey) ? { accessKeyId, secretAccessKey } : null;
}

interface Request {
  service: string;
  region: string;
  host: string;
  path: string;
  query: Record<string, string>;
  headers?: Record<string, string>;
}

export class AwsClient {
  calls = 0;
  readonly coverage = new Map<AwsSourceKey, Coverage & { key: AwsSourceKey }>();
  /** The 12-digit account the key belongs to; S3's account-level settings are addressed by it. */
  accountId: string;
  readonly #creds: AwsCredentials;
  #inFlight = 0;
  #queue: (() => void)[] = [];

  constructor(creds: AwsCredentials, accountId = "") {
    this.#creds = creds;
    this.accountId = accountId;
  }

  /** A Query API action: IAM, STS, EC2, RDS and load balancers. GET, with the action in the query string. */
  query(service: string, region: string, action: string, params: Record<string, string> = {}): Promise<XmlNode> {
    const host = GLOBAL_HOST[service] ?? `${service}.${region}.amazonaws.com`;
    return this.xml(service, GLOBAL_HOST[service] ? HOME_REGION : region, host, "/", { Action: action, Version: QUERY_VERSION[service], ...params });
  }

  /** A REST-XML read: S3, CloudFront, Route 53. */
  async xml(
    service: string,
    region: string,
    host: string,
    path: string,
    query: Record<string, string> = {},
    headers?: Record<string, string>,
  ): Promise<XmlNode> {
    return parseXml(await this.#send({ service, region, host, path, query, headers }));
  }

  /** A REST-JSON read: Lambda, GuardDuty. */
  async json(service: string, region: string, path: string, query: Record<string, string> = {}): Promise<Json> {
    const body = await this.#send({ service, region, host: `${service}.${region}.amazonaws.com`, path, query });
    return body ? JSON.parse(body) : null;
  }

  /** S3, path-style, so bucket names with dots work. `query` holds the subresource: `{ acl: "" }`. */
  s3(region: string, path: string, query: Record<string, string>): Promise<XmlNode> {
    return this.xml("s3", region, region === HOME_REGION ? "s3.amazonaws.com" : `s3.${region}.amazonaws.com`, path, query);
  }

  /** S3's account-level API, which is addressed by account ID. */
  s3Control(path: string): Promise<XmlNode> {
    return this.xml("s3", HOME_REGION, `${this.accountId}.s3-control.${HOME_REGION}.amazonaws.com`, path, {}, { "x-amz-account-id": this.accountId });
  }

  /** Runs a read; null when the thing isn't set up (404, NoSuch…). Other errors are thrown. */
  async optional<T>(fn: () => Promise<T>): Promise<T | null> {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof AwsError && e.notFound) return null;
      throw e;
    }
  }

  /** Runs a read with coverage: null when the access key can't read it. */
  async read<T>(source: AwsSourceKey, fn: () => Promise<T>): Promise<T | null> {
    try {
      const out = await fn();
      this.note(source, true);
      return out;
    } catch (e) {
      this.note(source, false, e);
      return null;
    }
  }

  /** Like read(), but "not set up" is null and unreadable is undefined, and only the latter is a coverage gap. */
  async readOptional<T>(source: AwsSourceKey, fn: () => Promise<T>): Promise<T | null | undefined> {
    try {
      const out = await this.optional(fn);
      this.note(source, true);
      return out;
    } catch (e) {
      this.note(source, false, e);
      return undefined;
    }
  }

  /** Records whether a source was readable. The first failure sticks, as in the other clients. */
  note(source: AwsSourceKey, ok: boolean, err?: unknown): void {
    const prev = this.coverage.get(source);
    if (prev && !prev.ok) return;
    const { label, permission } = AWS_SOURCES[source];
    this.coverage.set(
      source,
      ok
        ? { key: source, label, permission, ok: true }
        : { key: source, label, permission, ok: false, status: (err as AwsError)?.status || 0, message: String((err as Error)?.message || err).slice(0, 200) },
    );
  }

  /** Sends one signed GET and returns the body. Throws AwsError. */
  async #send(req: Request): Promise<string> {
    await this.#acquire();
    try {
      for (let attempt = 0; ; attempt++) {
        this.calls++;
        const qs = canonicalQuery(req.query);
        const path = req.path.split("/").map(awsEncode).join("/");
        let res: Response;
        try {
          res = await fetch(`https://${req.host}${path}${qs ? `?${qs}` : ""}`, {
            method: "GET",
            signal: AbortSignal.timeout(TIMEOUT_MS),
            headers: signGet(this.#creds, { ...req, path, headers: { ...req.headers, "x-amz-content-sha256": EMPTY_SHA256 } }),
          });
        } catch (e) {
          if (attempt < 2) {
            await sleep(1000 * (attempt + 1));
            continue;
          }
          throw new AwsError(0, "NetworkError", `Network error: ${(e as Error).message}`);
        }
        const body = await res.text();
        if (res.ok) return body;
        const err = errorOf(res, body);
        if ((THROTTLED.test(err.code) || res.status === 429 || res.status >= 500) && attempt < 4) {
          await sleep(500 * 2 ** attempt);
          continue;
        }
        throw err;
      }
    } finally {
      this.#release();
    }
  }

  async #acquire(): Promise<void> {
    while (this.#inFlight >= MAX_IN_FLIGHT) await new Promise<void>((r) => this.#queue.push(r));
    this.#inFlight++;
  }

  #release(): void {
    this.#inFlight--;
    this.#queue.shift()?.();
  }
}

/** AWS reports errors as XML (Query, REST-XML) or JSON (REST-JSON), each with a code and a message. */
function errorOf(res: Response, body: string): AwsError {
  let code = "";
  let message = "";
  try {
    if (body.trimStart().startsWith("<")) {
      const doc = parseXml(body);
      const err = find(doc, "Error") ?? doc;
      code = text(err, "Code") ?? "";
      message = text(err, "Message") ?? "";
    } else if (body) {
      const j = JSON.parse(body);
      // "AccessDeniedException:http://…" in the header, "com.amazon.coral.service#AccessDeniedException" in the body.
      code =
        String(res.headers.get("x-amzn-errortype") || j.__type || j.code || "")
          .split(":")[0]
          .split("#")
          .pop() ?? "";
      message = String(j.message || j.Message || "");
    }
  } catch {
    /* an unparseable error body: fall back to the status */
  }
  return new AwsError(res.status, code || String(res.status), message || code || res.statusText || "Request failed");
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
