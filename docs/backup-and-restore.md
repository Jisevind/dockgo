# Backup and Restore

There are two different things to think about:

- DockGo state
- managed app data

You should back up both.

## Back Up DockGo State

DockGo state is usually stored in its data directory, for example:

```text
./data
```

That state can include:

- sessions
- stack definitions
- stack history
- persistent logs, if enabled

If you want to preserve DockGo configuration and stack management state, back up that directory regularly.

## Back Up Managed App Data

DockGo does not replace app-level backups.

You should still back up the data for the applications DockGo manages, such as:

- databases
- app config directories
- media libraries
- uploaded files
- backup folders used by the apps themselves

## Restore DockGo

Typical restore flow:

1. Restore the DockGo data directory
2. Start DockGo again
3. Verify sessions, stacks, and logs are present
4. Open the `Stacks` view and confirm stack states

If state was lost and you re-register stacks manually:

- use `Reconcile` to adopt already-running containers

## Restore Managed Apps

The exact process depends on the app.

Typical examples:

- restore bind-mounted app data
- restore named volumes from backup
- restore databases from database-native backups

For stateful apps, test restore procedures before you need them.

## Recommended Strategy

- back up DockGo state regularly
- back up managed app data separately
- document where each app stores its real data
- test both restore paths
