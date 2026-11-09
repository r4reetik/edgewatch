# Security policy

## Supported versions

Security fixes go into the latest minor release. Upgrade to it before reporting, if you can.

| Version | Supported |
|---|---|
| 0.4.x | Yes |
| < 0.4 | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[**Report a vulnerability**](https://github.com/r4reetik/edgewatch/security/advisories/new) form
(Security → Advisories) rather than in a public issue. Include the version,
how to reproduce it, and the impact. You'll get an acknowledgement within three working days,
and we'll agree a disclosure date with you once a fix is ready. Reporters are credited in the advisory unless they'd rather not be.

A false positive or missed finding in a check is not a vulnerability; use the
[false positive template](https://github.com/r4reetik/edgewatch/issues/new?template=false_positive.yml) for those.

## Threat model

Edgewatch holds Cloudflare API tokens and Vercel access tokens, and a database describing accounts'
configuration, including member email addresses. It is designed to:

- **Only read.** The scanner issues GET requests, plus Cloudflare GraphQL analytics queries (GraphQL is sent
  as POST, as Cloudflare requires, and only ever queries). Use a Cloudflare token with read permissions;
  Edgewatch never needs anything else. Vercel can't issue read-only tokens, so a Vercel token can do what its
  user's role allows: Edgewatch still only sends GET requests to Vercel, and tests fail on anything else.
- **Never read secret values.** Vercel environment variables are listed without their values; drain and
  webhook URLs are stored without their paths, query strings or headers.
- **Contact only what it needs.** Besides the Cloudflare and Vercel APIs and public DNS, the optional takeover check
  sends one GET to your own hostnames that point at known cloud providers, and the update check reads
  GitHub's public list of releases once a day, sending nothing about the installation. Both can be turned off in Settings.
  Secrets found in rules, such as hard-coded header values, and in plain-text Worker or Pages variables are
  never stored or shown; only their name (and, for headers, length) is.
- **Keep secrets local.**
  - Tokens are stored in `<data-dir>/credentials.json` with mode 0600, keyed by a random ID. The database
    only holds that ID. Each account is scanned only with the token it was added with, and a token no
    account uses any more is deleted.
  - Tokens are never returned by the API or written to logs.
  - Removing an account deletes its scans, findings and triage. Copies of the database made before
    upgrades (`<data-dir>/backups/`, the newest three) keep older data until they're replaced.
  - Webhook URLs are treated as secrets as well.
- **Resist browser-based attacks.**
  - Host-header allowlisting stops DNS rebinding in local mode.
  - Same-origin JSON is required for state changes (CSRF).
  - A strict Content-Security-Policy, framing denied.
  - CSV exports are protected against formula injection.
- **Require authentication when exposed.**
  - Binding to a non-loopback address requires an admin password, unless an authenticating proxy is explicitly declared with `EDGEWATCH_AUTH=none`.
  - Sessions are HttpOnly, SameSite=Strict cookies.
  - Login attempts are rate-limited per IP.

Out of scope: an attacker who can already read the data directory or run code as the same user.
