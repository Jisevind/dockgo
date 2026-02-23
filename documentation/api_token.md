# API Token Authentication

DockGo provides two main methods of authentication:
1.  **User Authentication** (`AUTH_USERNAME` / `AUTH_PASSWORD_HASH`): Recommended for humans accessing the Web UI. It provisions secure, session-based cookies.
2.  **API Token** (`API_TOKEN`): A traditional, stateless Bearer token designed for scripts, webhooks, and headless automation.

This document covers the **API Token**.

## Configuration

To enable API Token authentication, define the `API_TOKEN` variable in your `.env` file or `docker-compose.yml`:

```yaml
services:
  dockgo:
    image: dockgo/dockgo:latest
    environment:
      - API_TOKEN=your_secure_random_string_here
```

*Note: You can run both `API_TOKEN` and User Authentication concurrently. They do not conflict.*

## Usage

When `API_TOKEN` is configured, you can perform authorized actions against the DockGo API by passing the token in the HTTP `Authorization` header as a `Bearer` token.

### Example: Triggering a Container Update

If you want to trigger a container update programmatically from a bash script or cronjob:

```bash
curl -X POST \
  -H "Authorization: Bearer your_secure_random_string_here" \
  http://localhost:3131/api/update/my-container-name
```

### Example: Fetching Container Status

If you want to pull the raw JSON state of your containers from an external monitoring tool:

```bash
curl -X GET \
  -H "Authorization: Bearer your_secure_random_string_here" \
  http://localhost:3131/api/containers
```

## Security Best Practices

*   **Make it complex:** Treat your API Token like a password. Use a long, randomly generated string (e.g., `openssl rand -hex 32`).
*   **Keep it secret:** Never commit your API Token in source control. Always inject it via environment variables or a `.env` file that is ignored by Git (`.gitignore`).
*   **HTTPS:** If you are exposing DockGo to the public internet, always map it behind a reverse proxy (like Nginx, Traefik, or Caddy) with an SSL/TLS certificate. Bearer tokens are sent in plaintext over HTTP, meaning anyone on your network could intercept the token if it's not encrypted via HTTPS.
