# Configuration

DockGo is configured mainly through environment variables.

## Authentication

DockGo provides two main methods of authentication:

1. **User Authentication** (`AUTH_USERNAME` / `AUTH_PASSWORD_HASH`): Recommended for humans accessing the Web UI. It provisions secure, session-based cookies.
2. **API Token** (`API_TOKEN`): A traditional, stateless Bearer token designed for scripts, webhooks, and headless automation.

### User Authentication

Recommended:

- `AUTH_USERNAME`
- `AUTH_PASSWORD_HASH`
- `AUTH_SECRET`

Convenience for testing:

- `AUTH_PASSWORD`

Production recommendation:

- prefer `AUTH_PASSWORD_HASH` over plaintext `AUTH_PASSWORD`
- set a strong `AUTH_SECRET`
- do not expose DockGo publicly without additional protection

### API Token

You can run `API_TOKEN` and User Authentication concurrently; they do not conflict.

```yaml
services:
  dockgo:
    image: dockgo/dockgo:latest
    environment:
      - API_TOKEN=your_secure_random_string_here
```

When `API_TOKEN` is configured, pass the token in the HTTP `Authorization` header as a `Bearer` token:

```bash
curl -X POST \
  -H "Authorization: Bearer your_secure_random_string_here" \
  http://localhost:3131/api/update/my-container-name
```

```bash
curl -X GET \
  -H "Authorization: Bearer your_secure_random_string_here" \
  http://localhost:3131/api/containers
```

Security best practices:

- treat the API Token like a password; use a long, randomly generated string (e.g., `openssl rand -hex 32`)
- never commit the token; inject it via environment variables or a `.env` file ignored by Git
- when exposing DockGo publicly, put it behind a reverse proxy (Nginx, Traefik, Caddy) with TLS, since Bearer tokens travel in plaintext over HTTP

## Logging

Useful variables:

- `LOG_LEVEL`
- `LOG_FORMAT`
- `LOG_FILE_PATH`
- `LOG_MAX_SIZE`
- `LOG_MAX_BACKUPS`
- `LOG_MAX_AGE`
- `LOG_COMPRESS`

Use persistent log files if you want a useful audit trail outside the container logs.

## Compose Path Handling

This is one of the most important setup differences between Linux and Windows.

### Linux

Preferred:

- mount the compose root into DockGo at the same absolute host path
- use `Host Native`
- do not set `COMPOSE_PATH_MAPPING`

Example:

```yaml
- /home/johan/docker:/home/johan/docker
```

### Windows

Typical:

- mount host compose root to an internal path like `/compose`
- set `COMPOSE_PATH_MAPPING`
- use `Mapped`

Example:

```yaml
- D:\Docker:/compose
```

```env
COMPOSE_PATH_MAPPING=D:\Docker:/compose
```

## Security-Sensitive Settings

- `ALLOWED_COMPOSE_PATHS`
- `CORS_ORIGIN`
- `DOCKGO_DEBUG`

Recommended:

- set `ALLOWED_COMPOSE_PATHS` to the roots you actually want DockGo to manage
- leave `DOCKGO_DEBUG=false` unless actively debugging
- do not set permissive CORS unless you really need it

## Notifications

Useful variables:

- `APPRISE_URL`
- `APPRISE_API_HOST`
- `APPRISE_QUEUE_SIZE`
- `SCAN_INTERVAL`

See [Notifications](./notifications.md) for examples.

## Session and State Files

By default DockGo stores state inside `/app/data`.

Relevant paths:

- sessions
- stack definitions
- stack history
- optional persistent logs

Back up that directory if you want to preserve DockGo state. See [Backup and Restore](./backup-and-restore.md).

## Compose File Conventions

The tracked `docker-compose.yml.example` and `docker-compose.agent.yml.example` files are the canonical templates.

For local runs, copy them without the `.example` suffix and edit to taste:

- the server uses `docker-compose.yml` at the repo root
- agents use `docker-compose-agent.yml` (copy of `docker-compose.agent.yml.example`)

Both local compose files are gitignored; they are machine-local and should not be committed.
