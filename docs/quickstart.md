# Quickstart

This page is the fastest path from zero to a working DockGo installation.

## What You Need

- Docker running on the host
- A Docker Compose v2 setup
- A browser that can reach the DockGo UI

Older `docker-compose` commands are still common in existing setups, but this documentation targets Docker Compose v2 (`docker compose`) first.

## Quickstart: Linux

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

Example `.env`:

```env
PORT=3131
AUTH_USERNAME=admin
AUTH_PASSWORD=changeme
AUTH_SECRET=replace-this-with-a-long-random-secret
```

Start DockGo:

```bash
docker compose up -d
```

Open:

```text
http://localhost:3131
```

## Quickstart: Windows

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
PORT=3131
AUTH_USERNAME=admin
AUTH_PASSWORD=changeme
AUTH_SECRET=replace-this-with-a-long-random-secret
COMPOSE_PATH_MAPPING=D:\Docker:/compose
```

Start DockGo:

```powershell
docker compose up -d
```

Open:

```text
http://localhost:3131
```

## First Things To Do

1. Log in.
2. Confirm DockGo can see your containers on the dashboard.
3. Open the `Stacks` view if you manage Compose apps and register the stacks you care about.
4. Test one update on a non-critical container first.
5. Configure notifications if you want update alerts.

## Next Steps

- [Installation](./installation.md)
- [Configuration](./configuration.md)
- [Stacks](./stacks.md)
