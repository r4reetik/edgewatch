# Deployment

Edgewatch is a single Node.js process with an embedded SQLite database. It needs Node.js 22.13 or newer,
outbound HTTPS to `api.cloudflare.com` and `cloudflare-dns.com`, and nothing else.

## On your own machine

```bash
npx edgewatch
```

It listens on `127.0.0.1:4317`, opens a browser tab, and keeps its data in `~/.edgewatch`. No password is
needed, because only your machine can reach it, and Host-header checks stop other websites from reaching it
through your browser (DNS rebinding).

To keep it installed and up to date yourself:

```bash
npm install -g edgewatch
edgewatch
```

## For a team, with Docker

```yaml
# compose.yaml
services:
  edgewatch:
    image: ghcr.io/r4reetik/edgewatch:latest
    restart: unless-stopped
    ports:
      - "4317:4317"
    environment:
      EDGEWATCH_PASSWORD: ${EDGEWATCH_PASSWORD:?set a password of at least 12 characters}
    volumes:
      - edgewatch-data:/data

volumes:
  edgewatch-data:
```

```bash
EDGEWATCH_PASSWORD='a-long-admin-password' docker compose up -d
```

The image runs as an unprivileged user, stores everything in `/data`, and has a health check on `/api/health`.
It listens on all interfaces, so it refuses to start without a password unless you declare an authenticating
proxy (below).

## Behind Cloudflare Access

If you already use Cloudflare Zero Trust, put Edgewatch behind a Cloudflare Tunnel and an Access application,
and let Access do the sign-in:

1. Run Edgewatch with `EDGEWATCH_AUTH=none` and `EDGEWATCH_TRUST_PROXY=1`, reachable only from the tunnel
   (for example `ports: ["127.0.0.1:4317:4317"]`, or no published port and `cloudflared` on the same network).
2. Create a public hostname on the tunnel pointing at `http://edgewatch:4317`.
3. Create an Access application for that hostname, with a policy that allows only the people who should see
   your security findings.

`EDGEWATCH_AUTH=none` turns off Edgewatch's own password, so never expose the port anywhere else.

## Behind another reverse proxy

Terminate TLS at the proxy, keep the password on, and set `EDGEWATCH_TRUST_PROXY=1` so session cookies are
marked `Secure` and client IPs (used for login rate limiting) come from `X-Forwarded-For`. With Caddy:

```
edgewatch.example.com {
  reverse_proxy 127.0.0.1:4317
}
```

## As a service (without Docker)

```ini
# /etc/systemd/system/edgewatch.service
[Unit]
Description=Edgewatch
After=network-online.target

[Service]
User=edgewatch
Environment=EDGEWATCH_DATA_DIR=/var/lib/edgewatch
Environment=EDGEWATCH_HOST=127.0.0.1
ExecStart=/usr/bin/edgewatch --no-open
Restart=on-failure
StateDirectory=edgewatch
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

## Configuration

| Flag | Environment | Default | |
|---|---|---|---|
| `--port` | `EDGEWATCH_PORT` | `4317` | Port to listen on |
| `--host` | `EDGEWATCH_HOST` | `127.0.0.1` | Address to bind. Anything but loopback requires a password |
| `--data-dir` | `EDGEWATCH_DATA_DIR` | `~/.edgewatch` | Database and stored tokens |
| `--password-file` | `EDGEWATCH_PASSWORD` | none | Admin password, at least 12 characters |
| `--trust-proxy` | `EDGEWATCH_TRUST_PROXY=1` | off | Trust `X-Forwarded-*` from your reverse proxy |
| `--no-open` | | | Don't open a browser |
| | `EDGEWATCH_AUTH=none` | | Allow no password on a network address (only behind an authenticating proxy) |
| | `EDGEWATCH_ALLOWED_HOSTS` | | Extra hostnames accepted in local mode, comma-separated |
| | `EDGEWATCH_LOG=json` | text | Log one JSON object per line, for log collectors |

Everything else (scan schedule, retention, SLAs, the takeover probe, accounts, entities and alert destinations)
is set in the web app and stored in the database.

## Data, backups and upgrades

The data directory holds two files, both readable by the owning user only:

- `edgewatch.db`: accounts, scans, findings, triage and settings (SQLite).
- `credentials.json`: the API tokens. The database only holds a reference to each.

Back up both together; a copy of the directory taken while Edgewatch is stopped is a complete backup. Treat it
like the tokens themselves. Scans older than the retention period (Settings → Scans) are pruned automatically;
triage is kept.

Upgrading is replacing the binary or image and restarting. Database migrations run on start and are
forward-only, so back up before upgrading across minor versions. See the [changelog](../CHANGELOG.md) for
breaking changes.
