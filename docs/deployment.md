# Deployment

Edgewatch is a single Node.js process with an embedded SQLite database. It needs Node.js 26 LTS (26.13.0 or newer), and
outbound HTTPS to `api.cloudflare.com` and `cloudflare-dns.com`. It also contacts, unless turned off in
Settings: your own hostnames that point at cloud providers (the takeover check, over HTTPS then HTTP),
`api.github.com` (the update check), and any Slack or webhook URL you configure for alerts.

## On your own machine

```bash
npx edgewatch@latest
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
    # The release line: compatible updates only. See upgrading.md.
    image: ghcr.io/r4reetik/edgewatch:0.7
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

If Edgewatch itself listens on `127.0.0.1` (the systemd setup below, or `cloudflared` on the same host) and
has no password, it only answers requests addressed to `localhost`, which blocks DNS-rebinding attacks. Add the
public hostname with `EDGEWATCH_ALLOWED_HOSTS=edgewatch.example.com`, or set a password.

## Behind another reverse proxy

Terminate TLS at the proxy, keep the password on, and set `EDGEWATCH_TRUST_PROXY=1` so session cookies are
marked `Secure` and login rate limits apply to the client's address. Edgewatch takes that address from the last
`X-Forwarded-For` entry, the one your proxy adds, so the proxy must append to the header (Caddy, nginx's
`$proxy_add_x_forwarded_for` and most others do). With Caddy:

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
| | `EDGEWATCH_UPDATE_CHECK=off` | on | Never check GitHub for new releases, whatever Settings say |

Everything else (scan schedule, retention, SLAs, the takeover probe, accounts, entities and alert destinations)
is set in the web app and stored in the database.

## Data, backups and upgrades

The data directory holds:

- `edgewatch.db`, with `edgewatch.db-wal` and `edgewatch.db-shm` next to it while it runs: accounts, scans,
  findings, triage and settings (SQLite).
- `credentials.json`: the API tokens. The database only holds a reference to each.
- `backups/`: copies of the database from before each upgrade that changed it, the newest three.

All of them are readable by the owning user only. Back up the whole directory; a copy taken while Edgewatch
is stopped is complete. Treat it like the tokens themselves. Scans older than the retention period (Settings →
Scans) are pruned automatically, along with the triage of findings no scan reports any more.

Upgrading is replacing the package or image and restarting; Edgewatch copies the database to `backups/` before
migrating it. Release lines, automatic updates and rolling back are covered in [upgrading.md](upgrading.md).

## Operating it

- **Logs** go to standard output (warnings and errors to standard error): `docker logs edgewatch`,
  `journalctl -u edgewatch`, or the terminal. `EDGEWATCH_LOG=json` writes one JSON object per line.
- **Changing the password:** Edgewatch doesn't store it. Change `EDGEWATCH_PASSWORD` (or the password file)
  and restart. Sessions are kept in memory, so a restart signs everyone out.
- **Removing an account** (Accounts → the account's menu → Remove) deletes its scans, findings and triage.
  Older copies remain in `backups/` until newer upgrades replace them.
- **Uninstalling:** stop Edgewatch and delete the data directory (`~/.edgewatch` by default) or the Docker
  volume. Nothing is stored anywhere else. Revoke the API tokens in Cloudflare too.
- `PORT` is read when `EDGEWATCH_PORT` isn't set, for platforms that assign one.
