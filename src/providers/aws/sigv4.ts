// AWS Signature Version 4 for GET requests, with node:crypto and nothing else.
// Edgewatch only reads, so the body is always empty; there is no way to sign a
// request with a payload here. test/aws.test.ts checks it against AWS's published
// example signature.

import { createHash, createHmac } from "node:crypto";

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
}

export interface SignInput {
  host: string;
  /** The path as it is sent, already percent-encoded. */
  path: string;
  /** Query parameters, unencoded. A subresource such as S3's `?acl` is a key with an empty value. */
  query: Record<string, string>;
  /** Headers to sign besides Host and X-Amz-Date. */
  headers?: Record<string, string>;
  region: string;
  service: string;
  now?: Date;
}

const EMPTY_SHA256 = createHash("sha256").update("").digest("hex");
const hmac = (key: string | Buffer, data: string) => createHmac("sha256", key).update(data).digest();
const sha256 = (data: string) => createHash("sha256").update(data).digest("hex");

/** RFC 3986 encoding as AWS wants it: everything but letters, digits and -_.~ is escaped. */
export const awsEncode = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/** The query string in AWS's canonical form (sorted, strictly encoded), which is also how it is sent. */
export const canonicalQuery = (query: Record<string, string>) =>
  Object.keys(query)
    .sort()
    .map((k) => `${awsEncode(k)}=${awsEncode(query[k])}`)
    .join("&");

/** The headers of a signed GET, including Authorization. Host is implied by the URL. */
export function signGet(creds: AwsCredentials, input: SignInput): Record<string, string> {
  const amzDate = (input.now ?? new Date()).toISOString().replace(/[-:]|\.\d{3}/g, "");
  const date = amzDate.slice(0, 8);
  const headers: Record<string, string> = { host: input.host, "x-amz-date": amzDate };
  for (const [k, v] of Object.entries(input.headers ?? {})) headers[k.toLowerCase()] = v.trim();
  const names = Object.keys(headers).sort();
  const canonical = ["GET", input.path, canonicalQuery(input.query), ...names.map((n) => `${n}:${headers[n]}`), "", names.join(";"), EMPTY_SHA256].join("\n");
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${creds.secretAccessKey}`, date), input.region), input.service), "aws4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  const { host: _host, ...sent } = headers;
  return { ...sent, Authorization: `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${names.join(";")}, Signature=${signature}` };
}

export { EMPTY_SHA256 };
