# Deployment

Keelson is a single Node.js process with an embedded SQLite database. It needs Node.js 26 LTS (26.13.0 or newer), and
outbound HTTPS to `api.cloudflare.com` and `cloudflare-dns.com`. It also contacts, unless turned off in
Settings: your own hostnames that point at cloud providers (the takeover check, over HTTPS then HTTP),
`api.github.com` (the update check), and any Slack or webhook URL you configure for alerts.

## On your own machine

```bash
npx keelson@latest
```

It listens on `127.0.0.1:4317`, opens a browser tab, and keeps its data in `~/.keelson`. No password is
needed, because only your machine can reach it, and Host-header checks stop other websites from reaching it
through your browser (DNS rebinding).

To keep it installed and up to date yourself:

```bash
npm install -g keelson
keelson
```

## For a team, with Docker

```yaml
# compose.yaml
services:
  keelson:
    # The release line: compatible updates only. See upgrading.md.
    image: ghcr.io/r4reetik/keelson:0.9
    restart: unless-stopped
    ports:
      - "4317:4317"
    environment:
      KEELSON_PASSWORD: ${KEELSON_PASSWORD:?set a password of at least 12 characters}
    volumes:
      - keelson-data:/data

volumes:
  keelson-data:
```

```bash
KEELSON_PASSWORD='a-long-admin-password' docker compose up -d
```

The image runs as an unprivileged user, stores everything in `/data`, and has a health check on `/api/health`.
It listens on all interfaces, so it refuses to start without a password unless you declare an authenticating
proxy (below).

## Behind Cloudflare Access

If you already use Cloudflare Zero Trust, put Keelson behind a Cloudflare Tunnel and an Access application,
and let Access do the sign-in:

1. Run Keelson with `KEELSON_AUTH=none` and `KEELSON_TRUST_PROXY=1`, reachable only from the tunnel
   (for example `ports: ["127.0.0.1:4317:4317"]`, or no published port and `cloudflared` on the same network).
2. Create a public hostname on the tunnel pointing at `http://keelson:4317`.
3. Create an Access application for that hostname, with a policy that allows only the people who should see
   your security findings.

`KEELSON_AUTH=none` turns off Keelson's own password, so never expose the port anywhere else.

If Keelson itself listens on `127.0.0.1` (the systemd setup below, or `cloudflared` on the same host) and
has no password, it only answers requests addressed to `localhost`, which blocks DNS-rebinding attacks. Add the
public hostname with `KEELSON_ALLOWED_HOSTS=keelson.example.com`, or set a password.

## Behind another reverse proxy

Terminate TLS at the proxy, keep the password on, and set `KEELSON_TRUST_PROXY=1` so session cookies are
marked `Secure` and login rate limits apply to the client's address. Keelson takes that address from the last
`X-Forwarded-For` entry, the one your proxy adds, so the proxy must append to the header (Caddy, nginx's
`$proxy_add_x_forwarded_for` and most others do). With Caddy:

```
keelson.example.com {
  reverse_proxy 127.0.0.1:4317
}
```

## As a service (without Docker)

```ini
# /etc/systemd/system/keelson.service
[Unit]
Description=Keelson
After=network-online.target

[Service]
User=keelson
Environment=KEELSON_DATA_DIR=/var/lib/keelson
Environment=KEELSON_HOST=127.0.0.1
ExecStart=/usr/bin/keelson --no-open
Restart=on-failure
StateDirectory=keelson
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

## Configuration

| Flag | Environment | Default | |
|---|---|---|---|
| `--port` | `KEELSON_PORT` | `4317` | Port to listen on |
| `--host` | `KEELSON_HOST` | `127.0.0.1` (`0.0.0.0` in the Docker image) | Address to bind. Anything but loopback requires a password |
| `--data-dir` | `KEELSON_DATA_DIR` | `~/.keelson` (`/data` in the Docker image) | Database and stored tokens |
| `--password-file` | `KEELSON_PASSWORD` | none | Admin password, at least 12 characters |
| `--trust-proxy` | `KEELSON_TRUST_PROXY=1` | off | Trust `X-Forwarded-*` from your reverse proxy |
| `--no-open` | | | Don't open a browser |
| | `KEELSON_AUTH=none` | | Allow no password on a network address (only behind an authenticating proxy) |
| | `KEELSON_ALLOWED_HOSTS` | | Extra hostnames accepted in local mode, comma-separated |
| | `KEELSON_LOG=json` | text | Log one JSON object per line, for log collectors |
| | `KEELSON_UPDATE_CHECK=off` | on | Never check GitHub for new releases, whatever Settings say |

Keelson was called Edgewatch before 0.10, and still reads every variable by its old name (`EDGEWATCH_PORT` and
so on) when the new one isn't set. See [upgrading from Edgewatch](upgrading.md#upgrading-from-edgewatch).

Everything else (scan schedule, retention, SLAs, the takeover probe, accounts, entities and alert destinations)
is set in the web app and stored in the database.

## Data, backups and upgrades

The data directory holds:

- `keelson.db`, with `keelson.db-wal` and `keelson.db-shm` next to it while it runs: accounts, scans,
  findings, triage and settings (SQLite).
- `credentials.json`: the tokens and access keys. The database only holds a reference to each.
- `backups/`: copies of the database from before each upgrade that changed it, the newest three.

All of them are readable by the owning user only. Back up the whole directory; a copy taken while Keelson
is stopped is complete. Treat it like the tokens themselves. Scans older than the retention period (Settings →
Scans) are pruned automatically, along with the triage of findings no scan reports any more.

Upgrading is replacing the package or image and restarting; Keelson copies the database to `backups/` before
migrating it. Release lines, automatic updates and rolling back are covered in [upgrading.md](upgrading.md).

## Operating it

- **Logs** go to standard output (warnings and errors to standard error): `docker logs keelson`,
  `journalctl -u keelson`, or the terminal. `KEELSON_LOG=json` writes one JSON object per line.
- **Changing the password:** Keelson doesn't store it. Change `KEELSON_PASSWORD` (or the password file)
  and restart. Sessions are kept in memory, so a restart signs everyone out.
- **Removing an account** (Accounts → the account's menu → Remove) deletes its scans, findings and triage.
  Older copies remain in `backups/` until newer upgrades replace them.
- **Uninstalling:** stop Keelson and delete the data directory (`~/.keelson` by default) or the Docker
  volume. Nothing is stored anywhere else. Revoke the tokens and access keys at each provider too.
- `PORT` is read when `KEELSON_PORT` isn't set, for platforms that assign one.
