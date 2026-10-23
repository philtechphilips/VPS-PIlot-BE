# Self-hosting VPSPilot

The control plane (API, dashboard and PostgreSQL) runs in Docker on one
Ubuntu or Debian server. HTTPS is handled by `vpspilot-proxy` (Caddy), the
same proxy the agent uses for your apps' domains, so a server can host the
control plane and your apps at the same time.

## Requirements

- Ubuntu 22.04+ or Debian 12+, 2 GB RAM (building the dashboard needs it)
- Ports 80 and 443 free
- A DNS record pointing your chosen hostname at the server

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/philtechphilips/VPS-PIlot-BE/main/deploy/install.sh \
  | sudo bash -s -- --domain pilot.example.com --email you@example.com
```

The installer:

1. installs Docker if it's missing,
2. clones the code into `/opt/vpspilot/{api,web}`,
3. generates the database password, `SECRET_KEY` and `ENCRYPTION_KEY` into
   `/opt/vpspilot/api/deploy/.env` (mode 600),
4. builds and starts `vpspilot-db`, `vpspilot-api` and `vpspilot-web`,
5. starts `vpspilot-proxy` and gets a certificate for your domain.

Then open `https://pilot.example.com/setup` to create the owner account.
To manage this same server, go to Servers → Enroll Server and run the
command it shows.

Add `--resend-key re_...` to send email (sign-in codes, alerts). Without it,
sign-in codes are written to the API log: `vpspilot logs api`.

Running the installer again is safe. It keeps the existing secrets and data.

## Day to day

| Command | What it does |
| --- | --- |
| `vpspilot status` | Container state and API health |
| `vpspilot logs [api\|web\|db\|proxy]` | Follow a component's logs |
| `sudo vpspilot upgrade` | Back up, pull the latest code, rebuild and restart. Migrations run on start. |
| `sudo vpspilot backup [DIR]` | Write the database and `.env` to `DIR` (default `/var/backups/vpspilot`) |
| `sudo vpspilot restore FILE` | Restore a file made by `vpspilot backup` |
| `sudo vpspilot restart` | Apply edits to `.env` (recreates the API and dashboard) |
| `sudo vpspilot admin EMAIL` | Add another admin, or promote an existing user |
| `sudo vpspilot viewer EMAIL` | Add a view-only user: sees everything except secrets, changes nothing |

`vpspilot upgrade` also upgrades the agent on the same server, if one is enrolled there. Upgrade the agents on your other servers from their pages in the dashboard.

## Keep the keys safe

`ENCRYPTION_KEY` decrypts every stored secret: environment variables, GitHub
tokens, database passwords and backup keys. If you lose it, those secrets
can't be recovered. `vpspilot backup` includes it. Keep a copy off the
server.

To rotate it, set the new value as `ENCRYPTION_KEY`, move the old one to
`ENCRYPTION_KEYS_PREVIOUS`, restart, then run:

```bash
docker exec vpspilot-api python -m app.encryption rotate
```

## Layout

| Path | Contents |
| --- | --- |
| `/opt/vpspilot/api/deploy/.env` | Secrets and settings |
| `/var/lib/vpspilot-proxy/Caddyfile` | Written by the agent (app domains) |
| `/var/lib/vpspilot-proxy/extra/control-plane.caddy` | The dashboard's own site |
| Docker volume `vpspilot_vpspilot-db` | The control-plane database |

The dashboard won't stop VPSPilot's own containers (`vpspilot-*`).
