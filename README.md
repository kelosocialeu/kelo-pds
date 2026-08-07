# Kelo PDS

Production-oriented AT Protocol Personal Data Server configuration for Kelo Social, designed for deployment on Render.

## Goals

- Run the official Bluesky/AT Protocol PDS image.
- Keep the PDS fully interoperable with Bluesky and other AT Protocol clients.
- Serve the PDS on `pds.kelosocial.eu` while allowing account handles such as `name.kelosocial.eu` through `PDS_SERVICE_HANDLE_DOMAINS`.
- Require hCaptcha for account creation using the PDS native hCaptcha configuration.
- Keep Kelo ID verification enforcement in Kelo Social only, never in the PDS.
- Persist repositories, SQLite databases and blobs on a Render persistent disk.
- Enable SMTP, federation crawling, rate limiting, Redis/Valkey scratch storage, health checks and production logging.

## Important architecture note about age assurance

AT Protocol account creation does not store a date of birth in `com.atproto.server.createAccount`. Bluesky's current age-assurance system is implemented at the Bluesky/AppView product layer. This repository therefore does **not** invent a non-standard PDS field that would break client compatibility.

Kelo's own registration UI may collect a declared date of birth / age category before calling the standard PDS account-creation endpoint. Bluesky and other clients remain free to apply their own age-assurance rules when the same account is used there.

## Render layout

The repository contains a Render Blueprint (`render.yaml`) for:

1. `kelo-pds` — public Docker web service running the official PDS.
2. `kelo-pds-cache` — Render Key Value (Valkey/Redis compatible) for shared PDS scratch/rate-limit state.
3. A persistent disk mounted at `/pds` on the PDS web service.

The PDS listens on Render's `PORT` through `docker-entrypoint.sh`.

## Files

- `Dockerfile` — pins the official PDS container image.
- `docker-entrypoint.sh` — maps Render's `PORT` to `PDS_PORT`, validates required variables and creates persistent directories.
- `render.yaml` — Render Blueprint.
- `.env.example` — all variables to configure in Render.
- `docs/RENDER_SETUP.md` — exact Render setup sequence.
- `docs/DNS.md` — DNS requirements for PDS + `*.kelosocial.eu` handles.
- `docs/SECURITY.md` — secrets, backups and production considerations.
- `docs/AGE_AND_CAPTCHA.md` — compatibility rules for age declaration and hCaptcha.

## PDS image

The deployment is pinned to `ghcr.io/bluesky-social/pds:0.4.219` so a deploy cannot unexpectedly upgrade the database format. Upgrade deliberately after reviewing upstream release notes.

## Persistent data

Everything important is written under `/pds`:

- SQLite account/sequencer/cache databases
- actor repositories
- uploaded blobs
- temporary blob files

Never run this deployment without the Render persistent disk attached to `/pds`.

## Federation defaults

The production defaults are the public AT Protocol network:

```env
PDS_DID_PLC_URL=https://plc.directory
PDS_BSKY_APP_VIEW_URL=https://api.bsky.app
PDS_BSKY_APP_VIEW_DID=did:web:api.bsky.app
PDS_CRAWLERS=https://bsky.network
PDS_REPORT_SERVICE_URL=https://mod.bsky.app
PDS_REPORT_SERVICE_DID=did:plc:ar7c4by46qjdydhdevvrndac
```

## Health check

Render should use:

```text
/xrpc/_health
```

A healthy PDS returns JSON containing its version.

## Before first production account

Treat these variables as permanent secrets once accounts exist:

- `PDS_JWT_SECRET`
- `PDS_ADMIN_PASSWORD`
- `PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX`
- `PDS_DPOP_SECRET`

Back them up securely. In particular, do not casually replace the PLC rotation key after identities have been created.
