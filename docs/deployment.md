# Deployment

Keelson ships as one container image, `ghcr.io/r4reetik/keelson`, for `linux/amd64` and `linux/arm64`. Inside is a
single Node.js process with an embedded SQLite database, on Alpine Linux. It needs Docker (or any OCI runtime:
Podman, containerd, ECS, Kubernetes), and outbound HTTPS to `api.cloudflare.com` and `cloudflare-dns.com`. It also contacts, unless turned off in
Settings: your own hostnames that point at cloud providers (the takeover check, over HTTPS then HTTP),
`api.github.com` (the update check), and any Slack or webhook URL you configure for alerts.

## On your own machine

```bash
docker run -d --name keelson -p 127.0.0.1:4317:4317 \
  -v keelson-data:/data \
  -e KEELSON_PASSWORD='a-long-admin-password' \
  ghcr.io/r4reetik/keelson:0.10
```

Open http://localhost:4317 and sign in with the password. Publishing the port on `127.0.0.1` keeps Keelson
reachable from this machine only. It still asks for a password, because inside the container it listens on every
interface and can't tell how the port was published.

To keep your data in a folder rather than a Docker volume, mount the folder and run as your own user, so the files
stay yours: `--user "$(id -u):$(id -g)" -v ~/.keelson:/data`.

## For a team, with Docker

```yaml
# compose.yaml
services:
  keelson:
    # The release line: compatible updates only. See upgrading.md.
    image: ghcr.io/r4reetik/keelson:0.10
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

If Keelson itself listens on `127.0.0.1` (`KEELSON_HOST=127.0.0.1` with host networking, or running from a clone) and
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

## Configuration

| Flag | Environment | Default | |
|---|---|---|---|
| `--port` | `KEELSON_PORT` | `4317` | Port to listen on |
| `--host` | `KEELSON_HOST` | `0.0.0.0` (`127.0.0.1` from a clone) | Address to bind. Anything but loopback requires a password |
| `--data-dir` | `KEELSON_DATA_DIR` | `/data` (`~/.keelson` from a clone) | Database and stored tokens |
| `--password-file` | `KEELSON_PASSWORD` | none | Admin password, at least 12 characters |
| `--trust-proxy` | `KEELSON_TRUST_PROXY=1` | off | Trust `X-Forwarded-*` from your reverse proxy |
| `--no-open` | | | Don't open a browser (the image always passes it) |
| | `KEELSON_AUTH=none` | | Allow no password on a network address (only behind an authenticating proxy) |
| | `KEELSON_ALLOWED_HOSTS` | | Extra hostnames accepted in local mode, comma-separated |
| | `KEELSON_LOG=json` | text | Log one JSON object per line, for log collectors |
| | `KEELSON_UPDATE_CHECK=off` | on | Never check GitHub for new releases, whatever Settings say |

Flags are for the command, so in a container they mean replacing it: for a password kept in a Docker secret, run
the image with the command `node dist/bin.js --no-open --password-file /run/secrets/keelson_password`.

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

Upgrading is pulling the new image and recreating the container; Keelson copies the database to `backups/` before
migrating it. Release lines, automatic updates and rolling back are covered in [upgrading.md](upgrading.md).

## Operating it

- **Logs** go to standard output (warnings and errors to standard error): `docker logs keelson`. `KEELSON_LOG=json` writes one JSON object per line.
- **Changing the password:** Keelson doesn't store it. Change `KEELSON_PASSWORD` (or the password file)
  and restart. Sessions are kept in memory, so a restart signs everyone out.
- **Removing an account** (Accounts → the account's menu → Remove) deletes its scans, findings and triage.
  Older copies remain in `backups/` until newer upgrades replace them.
- **Uninstalling:** remove the container and its volume (`docker rm -f keelson && docker volume rm
  keelson-data`), or the folder you mounted at `/data`. Nothing is stored anywhere else. Revoke the tokens and access keys at each provider too.
- `PORT` is read when `KEELSON_PORT` isn't set, for platforms that assign one.

## Running from a clone

For working on Keelson itself, see [CONTRIBUTING.md](../CONTRIBUTING.md). `npm ci && npm run build && npm start` runs the
same server on Node.js 26 LTS, listening on `127.0.0.1` with its data in `~/.keelson`, and on loopback it needs no
password. That is for development; the image is the supported way to run Keelson, and the only one released.
