# DockGo

A lightweight Go application to check for Docker container updates, providing a web dashboard and a CLI.

## Features
- **Dashboard**: Web interface to view container status and available updates.
- **Smart Checks**: Handles local vs remote digests, supports private registries, and is platform-aware (multi-arch).
- **Safe Updates**: `--update-safe` mode to pull updates without restarting running containers.
- **Network Preservation**: `--preserve-network` to keep static IPs and MAC addresses during recreation.
- **Compose Support**: Detects Compose services and attempts to update them via `docker compose`.
- **SSE Updates**: Real-time progress streaming for the dashboard.

## ⚠️ Security Notice

> **Access to the Docker Socket (`/var/run/docker.sock`) is effectively root access to the host.**

DockGo requires this access to inspect and update containers. While the container runs as a non-root user (`dockgo`) to minimize attack surface, the socket access itself grants broad privileges.
- **Do not expose DockGo to the public internet** without a secure reverse proxy and authentication (which is enabled by default).
- **Review your network security**: Ensure only trusted networks can access the DockGo interface.

## Build

### Prerequisites
- Go 1.21+

### Steps
1. Navigate to the project directory:
   ```bash
   cd dockgo
   ```
2. Build the binary:
   go build -o dockgo ./cmd/dockgo
   ```

### Windows Build
1. Navigate to the `dockgo` directory:
   ```powershell
   cd dockgo
   ```
2. Build the binary:
   ```powershell
   go build -o dockgo.exe ./cmd/dockgo
   ```

## Deployment

### Docker Build
To build the Docker image manually from the root directory:
```bash
docker build -t dockgo . --no-cache
```

### Docker Compose
A `docker-compose.yml` is provided in the root directory.

```bash
docker compose up -d --force-recreate
```

### Docker Run

The easiest way to run DockGo is as a Docker container.

```bash
docker run -d \
  --name dockgo \
  -p 3131:3131 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e API_TOKEN=mysecrettoken \
  dockgo
```

**Environment Variables:**
- `PORT`: Server port (default: `3131`).
- `PORT`: Server port (default: `3131`).
- `API_TOKEN`: Secret token for API updates (Legacy/Token mode).
- `AUTH_USERNAME`: Username for login (User mode).
- `AUTH_PASSWORD`: Password for login (User mode).
- `AUTH_SECRET`: Secret key for signing session cookies (User mode).

## Authentication

DockGo supports two authentication modes which can be used separately or together.

### 1. Token Mode (Legacy)
- **Config**: Set `API_TOKEN`.
- **Behavior**: The UI is read-only. When you click "Update", the browser prompts you to enter the token. The token is stored in `sessionStorage`.
- **Best for**: Simple setups where you just want to protect the update action with a shared secret.

### 2. User Login Mode (Recommended)
- **Config**: Set `AUTH_USERNAME` and `AUTH_PASSWORD`.
- **Behavior**: The UI is read-only. When you click "Update":
    - If you are **logged in**, the update proceeds automatically.
    - If you are **not logged in**, you are prompted to log in via a modal.
- **Session**: Login creates a secure, HttpOnly session cookie valid for 24 hours.

### 3. Hybrid Mode
- **Config**: Set `API_TOKEN` AND `AUTH_USERNAME`/`PASSWORD`.
- **Behavior**: You can log in as a user to perform updates without constant prompts. Scripts or other tools can still use the `API_TOKEN` (via `Authorization: Bearer <token>` header) to trigger updates programmatically.

## Usage (CLI)

You can also run the binary directly to check or update containers.

```bash
# Check all containers and print status
./dockgo

# Update a specific container
./dockgo -y my-container

# Safe update (pull only, do not restart if running)
./dockgo --update-safe -y my-container

# Force update (restart even if running)
./dockgo --update-force -y my-container

# Preserve network settings (static IP/MAC)
./dockgo --preserve-network -y my-container
```

### Flags
- `-n`: Check only (dry-run).
- `-y <name>`: Target specific container.
- `-a`: Update all available.
- `--update-safe`: Pull image but don't restart running containers.
- `--update-force`: Force update and restart.
- `--preserve-network`: Preserve IP/MAC address during recreation.
- `-json`: Output results as JSON.
- `-stream`: Output as SSE-compatible JSON stream.
