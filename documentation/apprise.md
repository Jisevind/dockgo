# Apprise Notifications in DockGo

DockGo supports sending notifications to a wide variety of services via [Apprise](https://github.com/caronc/apprise). This allows you to receive real-time alerts about container updates, connection status, and application health on platforms like Discord, Slack, Telegram, Email, and many more.

## Configuration

To enable Apprise notifications, you need to configure the `APPRISE_URL` environment variable properly to point to an Apprise API container.

### Environment Variable

*   **`APPRISE_URL`**: Your notification URL(s). Apprise natively supports over 100+ services including Gotify, Ntfy, Discord, and Telegram.

**Examples:**
*   Gotify: `gotify://192.168.1.50/token`
*   Ntfy (Self-hosted): `ntfys://user:password@ntfy.example.com/mytopic`
*   Ntfy (Public): `ntfy://mytopic`
*   Ntfy (Token Auth): `ntfy://tk_your32charactertoken@ntfy.example.com/mytopic` *(Note: No colon before tk_)*
*   Multiple (Comma-separated): `gotify://192.168.1.50/token,ntfys://ntfy.example.com/mytopic`

**Example `docker-compose.yml` snippet:**

```yaml
services:
  dockgo:
    image: jisevind/dockgo:latest
    environment:
      - APPRISE_URL=gotify://192.168.1.204/Aon5xAnYo-hTn70

  apprise:
    image: caronc/apprise
    container_name: apprise
    restart: unless-stopped
    ports:
      - "4747:8000"
```

If the `APPRISE_URL` environment variable is not set or is empty, the notification system is gracefully disabled. DockGo natively integrates directly with Apprise's stateless `/notify` API, meaning you do not need to configure an external `apprise.yml` volume mapping. All URLs provided to the environment variable are safely wrapped in JSON and securely fired to your local Apprise container.

## How it Works

The notification system in DockGo is designed to be robust and non-blocking:

1.  **Asynchronous Execution**: Notifications are processed by a dedicated background worker goroutine. This ensures that sending notifications does not slow down the main server operations or API endpoints.
2.  **Buffered Queue**: Notifications are placed in a buffered channel (queue size of 100). If the queue is full, new notifications are dropped with a warning logged to prevent memory exhaustion and goroutine flooding.
3.  **Multiple URLs**: You can specify multiple Apprise URLs separated by commas. DockGo will format and send the notification payload to each URL sequentially.
4.  **Resilience & Retries**:
    *   Requests are sent with a **10-second timeout**.
    *   If a request fails (e.g., due to a network error or an HTTP status code >= 300), the system will automatically **retry once** after a 2-second delay.

## Notification Types

DockGo maps its internal notification events to the standard Apprise message types:

*   `info`: Informational events.
*   `success`: Successful operations (e.g., a successful container update).
*   `warning`: Warning events (e.g., transient issues).
*   `failure`: Error events (e.g., connection to the Docker daemon lost or an update failed).

## Example Playload

When DockGo sends a notification to your configured Apprise URL(s), it sends a JSON payload similar to the following:

```json
{
  "title": "DockGo: Update Available",
  "body": "An update is available for container 'my-app'.",
  "type": "info"
}
```

Apprise then translates this standard payload into the specific format required by the service(s) you have configured in your Apprise URLs.
