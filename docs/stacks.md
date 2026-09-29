# Stacks

![DockGo dashboard showing container updates](../screenshots/screenshot-stacks-tab.png)

In DockGo, a stack is a registered Docker Compose project.

If you run Compose apps regularly, stacks should be part of your normal workflow.

## Why Register Stacks

Registered stacks give DockGo:

- an explicit compose file
- a known working directory
- validation rules
- deploy history
- ownership of the runtime containers

This is safer than trying to operate only from runtime Docker labels.

## Typical Stack Workflow

1. Discover a Compose project in the `Stacks` view
2. Register it
3. Validate it
4. Deploy it when needed
5. Use the main dashboard for one-click updates afterward

Once a Compose app is stack-managed, dashboard updates use the registered stack behind the scenes.

## Linux: Host Native

Use `Host Native` (`"host_native"`) when DockGo sees the Compose project at the same absolute path as the host.

Example:

- host path: `/home/johan/docker/audiobookshelf`
- DockGo path: `/home/johan/docker/audiobookshelf`

Recommended on Linux.

## Windows: Mapped

Use `Mapped` (`"mapped"`) when DockGo sees the Compose project at a different internal path.

Example:

- host path: `D:\Docker\audiobookshelf`
- DockGo path: `/compose/audiobookshelf`

Typical on Windows with a Linux DockGo container.

## Important Stack States

DockGo tracks two aspects of a stack: its **ownership mode** and its **operational state**.

**Ownership mode** (`ownership_mode`):
- `unbound` — the stack definition exists, but DockGo does not yet own any container IDs for it
- `managed` — the stack owns runtime container IDs

**Operational state** (`state`):

### Unbound

Meaning:

- the stack definition exists
- but DockGo does not yet own any container IDs for it

Common fix:

- `Reconcile` if the containers are already running and correct
- `Deploy` if you want DockGo to recreate and own them

### Running

All stack containers are running (and healthy, if healthchecks exist).

### Starting

Containers are starting or waiting for healthchecks to pass.

### Degraded

Some stack containers are stopped or unhealthy, but at least one is still running.

### Down

All stack containers are stopped.

### Drifted

Meaning:

- DockGo owns container IDs for the stack
- but the currently running containers do not match that ownership anymore

This usually means containers were recreated or changed outside the last known DockGo ownership state.

Common fix:

- `Reconcile` if the currently running containers are the correct ones
- `Deploy` if you want DockGo to reassert the stack definition

## Reconcile

`Reconcile` tells DockGo to adopt the currently running containers for that stack.

Use it when:

- you imported or restored DockGo state
- you registered stacks after a clean install
- containers were recreated outside DockGo and you want DockGo to adopt them

Do not use it blindly if the runtime state is wrong. In that case, fix the stack and deploy instead.

## Validation

Validation checks:

- working directory
- compose file
- env file
- path resolution
- runtime drift warnings

Use `Validate` after editing stack paths or changing mount strategy.

## Editing Compose And Env Files

DockGo can edit the compose and env files of a registered stack directly.

- Content is checked for syntax first (YAML for compose files, `KEY=VALUE` for
  env files) and rejected if it does not parse.
- Saves are then validated with `docker compose config`. A save that fails
  triggers a rollback to the previous content, so a broken stack cannot be
  saved; if the rollback write itself fails, the save returns an error.
- Only files already registered to the stack can be edited, and only within
  `ALLOWED_COMPOSE_PATHS` when that is configured.
- For `git_repo` stacks, saving edits the checked-out working copy; a later
  pull may overwrite those edits.
- Files are addressed with `kind` (`compose` or `env`) and a 0-based `index`
  within that kind; compose files come first, then env files.
- Both `validate` and `PUT` take a JSON body of `{"content": "<draft text>"}`.
- Agent-hosted stacks cannot be edited yet — saving one returns
  `501 Not Implemented`.

## Deploy

`Deploy` runs the registered Compose stack definition and then binds runtime ownership.

If deploy succeeds but ownership cannot be bound, DockGo now treats that as an error instead of silently leaving the stack in a misleading success state.

## API Reference

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/api/stacks` | List all registered stacks |
| `POST` | `/api/stacks` | Register a new stack |
| `GET` | `/api/stacks/:id` | Get stack details, validation, status, and history |
| `PUT` | `/api/stacks/:id` | Update a stack definition |
| `DELETE` | `/api/stacks/:id` | Unregister a stack |
| `POST` | `/api/stacks/:id/validate` | Validate stack files and paths |
| `POST` | `/api/stacks/:id/deploy` | Deploy the stack (SSE stream) |
| `POST` | `/api/stacks/:id/pull` | Pull stack images (SSE stream) |
| `POST` | `/api/stacks/:id/restart` | Restart stack services (SSE stream) |
| `POST` | `/api/stacks/:id/stop` | Stop stack services, leaving containers in place (SSE stream) |
| `POST` | `/api/stacks/:id/start` | Start previously stopped stack services (SSE stream) |
| `POST` | `/api/stacks/:id/down` | Stop and remove stack services (SSE stream) |
| `GET` | `/api/stacks/:id/files` | List a stack's editable compose and env files |
| `GET` | `/api/stacks/:id/file?kind=&index=` | Read one compose or env file |
| `POST` | `/api/stacks/:id/file/validate?kind=&index=` | Validate draft content without saving |
| `PUT` | `/api/stacks/:id/file?kind=&index=` | Save a file (validated, rolled back on failure) |
| `POST` | `/api/stacks/:id/reconcile` | Adopt currently running containers |
| `GET` | `/api/stacks/:id/history` | Get stack action history (supports `?limit=`, `?action=`, `?status=`, `?source=` filters) |
| `GET` | `/api/stacks/discover` | Discover unregistered Compose projects |

## Troubleshooting Stack Problems

Read [Troubleshooting](./troubleshooting.md) if you see:

- `Unbound`
- `Drifted`
- validation failures
- path mapping issues
- deploy failures
