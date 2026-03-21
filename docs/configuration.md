# Configuration

DockGo is configured mainly through environment variables.

## Authentication

Recommended:

- `AUTH_USERNAME`
- `AUTH_PASSWORD_HASH`
- `AUTH_SECRET`

Convenience for testing:

- `AUTH_PASSWORD`

Legacy/API use:

- `API_TOKEN`

Production recommendation:

- prefer `AUTH_PASSWORD_HASH` over plaintext `AUTH_PASSWORD`
- set a strong `AUTH_SECRET`
- do not expose DockGo publicly without additional protection

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
