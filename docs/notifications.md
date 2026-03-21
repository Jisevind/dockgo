# Notifications

DockGo can send notifications through Apprise.

## What Notifications Are Useful For

- new updates detected
- update success
- update failure
- operational visibility without watching the UI

## Basic Setup

Set:

```env
APPRISE_URL=gotify://host/token
```

or another supported Apprise target.

Optional:

```env
APPRISE_API_HOST=http://apprise:8000
APPRISE_QUEUE_SIZE=200
SCAN_INTERVAL=6h
```

## Example Targets

- Gotify
- ntfy
- Discord
- Slack
- Telegram

The exact URL format depends on the provider supported by Apprise.

## Testing

Use the built-in test notification flow in the UI after configuration.

## Troubleshooting

Check:

- the Apprise URL format
- reachability of the Apprise API host
- DockGo logs for notification errors

If notifications matter operationally, also persist DockGo logs to disk.
