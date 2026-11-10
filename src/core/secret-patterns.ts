// Patterns for credentials written straight into text that should only hold
// commands: a Vercel build command, an EC2 instance's start-up script. Providers
// share them, so a kind of secret found on one platform is found on the others.
// The text is only held while it is scanned; findings carry the kind, never the value.

/**
 * Credentials written straight into text (a build command, a start-up script), by kind. A reference to a variable (`$NPM_TOKEN`,
 * `${TOKEN}`) is fine and doesn't match. Only the kind is ever reported, never the value.
 */
const LITERAL = String.raw`(?!\$)`;
export const SECRET_IN_TEXT: [string, RegExp][] = [
  ["an npm auth token", new RegExp(String.raw`_authToken=${LITERAL}[^\s'"]{8,}`)],
  ["a GitHub token", /\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/],
  ["an AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["a Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ["a Stripe secret key", /\b[sr]k_live_[A-Za-z0-9]{16,}/],
  ["a password in a URL", new RegExp(String.raw`[a-z][a-z0-9+.-]*://[^/\s:@]+:${LITERAL}[^@\s/]{3,}@`, "i")],
  ["a bearer token", new RegExp(String.raw`Bearer\s+${LITERAL}[A-Za-z0-9._~+/-]{20,}`)],
  ["a private key", /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY/],
  ["a token passed on the command line", new RegExp(`--(token|password|api-key)[ =]${LITERAL}[A-Za-z0-9._-]{16,}`)],
];
export const secretKindIn = (text: string): string | null => SECRET_IN_TEXT.find(([, re]) => re.test(text))?.[0] ?? null;
