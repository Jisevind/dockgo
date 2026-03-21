# Installation

This page covers the recommended DockGo installation patterns for Linux and Windows.

## Supported Setup Models

DockGo can be used in two main ways:

- as a Docker container, which is the primary documented setup
- as a native binary for CLI usage and advanced scenarios

For most users, the Docker container setup is the right starting point.

## Docker Requirements

- Docker engine available on the host
- Docker Compose v2 preferred
- access to the Docker socket

## Linux Installation

Recommended Compose file:

```yaml
services:
  dockgo:
    image: ghcr.io/jisevind/dockgo:latest
    container_name: dockgo
    restart: unless-stopped
    ports:
      - "3131:3131"
    env_file:
      - .env
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/app/data
      - /home/your-user/docker:/home/your-user/docker
```

Why mount the compose root to the same path:

- DockGo can see the same path as the host
- Linux stacks can use `Host Native`
- relative bind mounts in your Compose projects behave more reliably

For Linux, avoid `COMPOSE_PATH_MAPPING` unless DockGo sees the project at a different internal path than the host.

Start:

```bash
docker compose up -d
```

## Windows Installation

Recommended Compose file:

```yaml
services:
  dockgo:
    image: ghcr.io/jisevind/dockgo:latest
    container_name: dockgo
    restart: unless-stopped
    ports:
      - "3131:3131"
    env_file:
      - .env
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/app/data
      - D:\Docker:/compose
```

Example `.env`:

```env
COMPOSE_PATH_MAPPING=D:\Docker:/compose
```

Why this is different from Linux:

- DockGo runs as a Linux container
- Windows host paths like `D:\Docker\app` are not valid Linux paths inside the container
- `Mapped` stacks translate host paths into container-visible paths

Start:

```powershell
docker compose up -d
```

Older Compose command:

```powershell
docker-compose up -d
```

## Native CLI Build

Linux or macOS:

```bash
git clone https://github.com/Jisevind/dockgo.git
cd dockgo
go build -o dockgo ./cmd/dockgo
```

Windows:

```powershell
git clone https://github.com/Jisevind/dockgo.git
cd dockgo
$env:GOOS="windows"
$env:GOARCH="amd64"
go build -o dockgo.exe ./cmd/dockgo
```

## After Installation

- Read [Configuration](./configuration.md)
- Learn the main UI in [Dashboard and Updates](./dashboard-and-updates.md)
- If you use Compose apps, read [Stacks](./stacks.md)
