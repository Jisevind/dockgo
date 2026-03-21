# Troubleshooting

This page covers the most common DockGo issues.

## Cannot Reach the UI

Check:

- container is running
- port mapping is correct
- browser is pointing to the right host and port

## Login Problems

Check:

- `AUTH_USERNAME`
- `AUTH_PASSWORD_HASH` or `AUTH_PASSWORD`
- `AUTH_SECRET`

If you changed auth settings, restart DockGo.

## Docker Connection Problems

Check:

- Docker is running
- `/var/run/docker.sock` is mounted correctly

Windows native CLI users may also need:

```powershell
$env:DOCKER_HOST = "npipe:////./pipe/docker_engine"
```

## Stack Is Unbound

Meaning:

- DockGo knows the stack definition
- but does not yet own runtime container IDs for it

Fix:

- `Reconcile` if the current runtime containers are correct
- `Deploy` if you want DockGo to recreate and own them

## Stack Is Drifted

Meaning:

- DockGo owns container IDs
- but the current runtime no longer matches them

Fix:

- `Reconcile` if the current containers are the right ones
- `Deploy` if you want the registered stack to reassert desired state

## Validation Fails on Linux

If you use Linux and containerized DockGo:

- prefer mounting your compose root at the same absolute path as the host
- use `Host Native`
- avoid `COMPOSE_PATH_MAPPING` unless you actually need different internal paths

## Validation Fails on Windows

Check:

- `COMPOSE_PATH_MAPPING`
- the stack path mode is `Mapped`
- host path and mapped container path match your DockGo volume mount

## Compose Project Shows Old `/compose/...` Paths

This usually means the running containers still have old Compose labels from a previous mapped setup.

Recreate the app from the host side once:

Linux:

```bash
docker compose down
docker compose up -d
```

Windows PowerShell:

```powershell
docker compose down
docker compose up -d
```

## Deploy Fails But Reconcile Works

This usually means:

- the runtime containers are already correct
- but the deploy path failed during Compose execution

Check:

- stack history
- container logs
- DockGo logs

If the runtime is already correct, `Reconcile` may be the right recovery action.

## Need More Detail

Read:

- [Stacks](./stacks.md)
- [Internals](./internals.md)
