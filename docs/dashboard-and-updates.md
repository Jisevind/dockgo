# Dashboard and Updates

The main dashboard is intended to stay simple:

- see what is running
- see which containers have updates
- update with one click

## Main Dashboard

Each container card shows:

- name
- image
- tag
- state
- update availability

Primary action:

- `Update Now`

Secondary actions in the menu:

- start
- stop
- restart
- view logs
- view stack, when the container is managed by a registered stack

## Updating Containers

For standalone containers:

- `Update Now` updates that container directly

For stack-managed containers:

- `Update Now` routes through the registered stack
- the dashboard stays simple, but the backend uses the stack definition

## Logs

Use `View Logs` from the menu to inspect a container directly.

This is useful when:

- an update fails
- a container starts but does not become healthy
- you want to confirm an app migrated correctly after an update

## Reading Common States

- `running`: container is up
- `exited`: container is stopped
- `Update Available`: a newer image is available

Stack-specific operational states such as `Unbound` or `Drifted` appear in the `Stacks` view, not the main dashboard workflow.

## Safe Usage Tips

- update one or two non-critical apps first
- verify logs after updating stateful apps
- prefer registered stacks for Compose projects
- keep backups for app data before major updates

See [Stacks](./stacks.md) for Compose-specific day-to-day use.
