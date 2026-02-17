# DockGo 🐳

> **A lightweight, secure Docker update agent — single binary, no fuss.**

![DockGo dashboard showing container updates](screenshot.png)

## What is DockGo?

DockGo is a simple, single-binary application that monitors your Docker containers for updates. It focuses on visibility and control rather than automatic unattended updates and it provides:
1.  A **Web Dashboard** to see container status and available updates at a glance.
2.  A **CLI** for scripting and manual checks.
3.  **Smart Updates** that handle standard containers, private registries, and Docker Compose services.

## Why DockGo?

Most Docker update tools (like Watchtower or Ouroboros) are great, but can be:
*   **Heavy**: Running complex logical loops or requiring root.
*   **Insecure**: Often demanding full root access to the socket without dropping privileges or providing authentication.
*   **Opaque**: Updating things silently without a clear UI to see *what* is happening.

**DockGo is different:**
*   **Security-focused by default**: Runs as a non-root user (`dockgo`).
*   **Transparent**: You decide when to update (via UI or CLI), or automate it with scripts.
*   **Lightweight**: Written in Go, typically very low memory footprint (~10–30MB).

---

## Quick Start

The fastest way to run DockGo is via Docker:

```bash
docker run -d \
  --name dockgo \
  -p 3131:3131 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e LOG_LEVEL=info \
  dockgo/dockgo
```

Visit **http://localhost:3131** to see your dashboard!

---

## Security Model

DockGo takes security seriously.

1.  **Non-Root Execution**: Inside the container, the process runs as the `dockgo` user (UID 1000), not root.
2.  **Socket Permissions**: The entrypoint script creates a `docker` group matching the host's socket GID, allowing the `dockgo` user to talk to the engine without being root.
3.  **Authentication**:
    *   **User Login (Recommended)**: Set `AUTH_USERNAME` and `AUTH_PASSWORD` to enable a secure login flow with HttpOnly cookies.
    *   **Legacy Token**: Set `API_TOKEN` for simple script integrations.
    *   **CORS**: Disabled by default. Only enabled if you specifically set `CORS_ORIGIN`.
4.  **Log Redaction**: Sensitive errors and login failures are redacted in logs.

> **⚠️ Security Warning**: Mounting /var/run/docker.sock effectively grants root-level control of Docker. While DockGo minimizes risk by running non-root, DockGo is intended for trusted networks or behind a reverse proxy (like Nginx or Traefik) and authentication.

---

## Features

*   **Web Dashboard**: Real-time status, "Update" buttons, and progress tracking.
*   **Smart Discovery**:
    *   Checks standard Docker Hub images.
    *   Supports **Private Registries** (using your host's credentials).
    *   Works for most standard **Docker Compose** setups.
*   **Safe Mode**: Use `--safe` (or Safe Mode in UI if implemented) to pull images without restarting running containers.
*   **Network Preservation**: Keeps static IPs and MAC addresses when recreating containers.
*   **Registry Caching**: Caches registry digests for 10 minutes to prevent rate-limiting.
*   **Log Level Control**: adjustable verbosity via `LOG_LEVEL`.

---

## Configuration

Configure DockGo using environment variables:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Web server port | `3131` |
| `LOG_LEVEL` | Log verbosity (`debug`, `info`, `warn`, `error`) | `info` |
| `AUTH_USERNAME` | Username for web login | *(empty)* |
| `AUTH_PASSWORD` | Password for web login | *(empty)* |
| `AUTH_SECRET` | Secret for signing session cookies | *(random)* |
| `API_TOKEN` | Legacy token for API updates | *(empty)* |
| `CORS_ORIGIN` | Allowed Origin for CORS (e.g. `https://mydomain.com`) | *(disabled)* |

**Example `docker-compose.yml`:**

```yaml
services:
  dockgo:
    image: dockgo/dockgo
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - "3131:3131"
    environment:
      - LOG_LEVEL=info
      - AUTH_USERNAME=admin
      - AUTH_PASSWORD=secret
```

---

## CLI Usage

You can use the `dockgo` binary directly for scripting or manual checks.

```bash
# Check all containers
dockgo check

# Check with JSON output (great for scripts)
dockgo check -json

# Update a specific container
dockgo update -y my-container

# Update ALL containers
dockgo update -a

# Safe Mode: Pull only, don't restart running containers
dockgo update -safe -a

# Force Mode: Restart even if running
dockgo update -force -y my-container
```

```bash
# Typical workflow:
dockgo check
dockgo update -a
```

### Flags

*   `-y <name>`: Target specific container.
*   `-a`: Target all containers with updates.
*   `-json`: Output standard JSON.
*   `-stream`: Output SSE-compatible line-delimited JSON.
*   `-preserve-network`: Preserve network settings (IP/MAC) during recreation.

---

### Building from Source

```bash
git clone https://github.com/yourusername/dockgo.git
cd dockgo
go build -o dockgo ./cmd/dockgo
```

### Building for Windows


### Troubleshooting

#### Windows Connection Issues

If you see an error like `failed to connect to Docker`, ensure Docker Desktop is running. You may need to set the `DOCKER_HOST` environment variable if the default connection fails:

```powershell
$env:DOCKER_HOST = "npipe:////./pipe/docker_engine"
```

#### Docker Container "no such file or directory"

If the container crashes with `exec ./entrypoint.sh: no such file or directory`, it likely has Windows line endings (CRLF). Ensure `entrypoint.sh` uses Unix line endings (LF). The build process should handle this, but if you are mounting the file locally, you may need to convert it.

