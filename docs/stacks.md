# Stacks

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

Use `Host Native` when DockGo sees the Compose project at the same absolute path as the host.

Example:

- host path: `/home/johan/docker/audiobookshelf`
- DockGo path: `/home/johan/docker/audiobookshelf`

Recommended on Linux.

## Windows: Mapped

Use `Mapped` when DockGo sees the Compose project at a different internal path.

Example:

- host path: `D:\Docker\audiobookshelf`
- DockGo path: `/compose/audiobookshelf`

Typical on Windows with a Linux DockGo container.

## Important Stack States

### Unbound

Meaning:

- the stack definition exists
- but DockGo does not yet own any container IDs for it

Common fix:

- `Reconcile` if the containers are already running and correct
- `Deploy` if you want DockGo to recreate and own them

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

## Deploy

`Deploy` runs the registered Compose stack definition and then binds runtime ownership.

If deploy succeeds but ownership cannot be bound, DockGo now treats that as an error instead of silently leaving the stack in a misleading success state.

## Troubleshooting Stack Problems

Read [Troubleshooting](./troubleshooting.md) if you see:

- `Unbound`
- `Drifted`
- validation failures
- path mapping issues
- deploy failures
