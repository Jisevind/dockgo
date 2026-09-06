# Notifications

DockGo can send notifications through [Apprise](https://github.com/caronc/apprise), which supports over 100+ services including Gotify, Ntfy, Discord, Slack, Telegram, and email.

## What Notifications Are Useful For

- new updates detected
- update success
- update failure
- connection to the Docker daemon lost
- operational visibility without watching the UI

## Basic Setup

Set:

```env
APPRISE_URL=gotify://host/token
```

or another supported Apprise target. You can specify multiple URLs separated by commas; DockGo sends each notification to every URL.

Optional:

```env
APPRISE_API_HOST=http://apprise:8000
APPRISE_QUEUE_SIZE=100
SCAN_INTERVAL=6h
```

- `APPRISE_API_HOST` is the base URL of the Apprise API container (default: `http://apprise:8000`). Use it if you rename the Apprise sidecar container.
- `APPRISE_QUEUE_SIZE` is the buffer size for outbound notification events (default: `100`).

If `APPRISE_URL` is not set or is empty, the notification system is gracefully disabled. DockGo integrates directly with Apprise's stateless `/notify` API, so you do not need an external `apprise.yml` volume mapping.

### Example Compose Snippet

```yaml
services:
  dockgo:
    image: ghcr.io/jisevind/dockgo:latest
    environment:
      - APPRISE_URL=gotify://192.168.1.204/token

  apprise:
    image: caronc/apprise
    container_name: apprise
    restart: unless-stopped
    ports:
      - "4747:8000"
```

## Example Targets

- Gotify: `gotify://192.168.1.50/token`
- ntfy (self-hosted): `ntfys://user:password@ntfy.example.com/mytopic`
- ntfy (public): `ntfy://mytopic`
- ntfy (token auth): `ntfy://tk_your32charactertoken@ntfy.example.com/mytopic` *(no colon before `tk_`)*
- Discord
- Slack
- Telegram

The exact URL format depends on the provider supported by Apprise.

## How It Works

Notifications are processed by a dedicated background worker goroutine so they never slow down the main server operations. Notifications are placed in a buffered channel; if the queue is full, new notifications are dropped with a warning logged to prevent memory exhaustion.

Notification events map to standard Apprise message types:

- `info`: informational events
- `success`: successful operations (e.g., a successful container update)
- `warning`: warning events (e.g., transient issues)
- `failure`: error events (e.g., connection to the Docker daemon lost or an update failed)

### Retry Semantics

- Requests are sent with a **10-second timeout**.
- If a request fails (network error or HTTP status code >= 300), DockGo **retries once** after a 2-second delay.

### Example Payload

```json
{
  "title": "DockGo: Update Available",
  "body": "An update is available for container 'my-app'.",
  "type": "info"
}
```

Apprise translates this standard payload into the format required by each configured service.

## Testing

Use the built-in test notification flow in the UI after configuration.

## Troubleshooting

Check:

- the Apprise URL format
- reachability of the Apprise API host
- DockGo logs for notification errors

If notifications matter operationally, also persist DockGo logs to disk.
