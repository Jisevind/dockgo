# Internals

This page is for technical readers who want a clearer mental model of how DockGo works without diving straight into the codebase.

## High-Level Model

DockGo now separates three concerns:

- discovery
- ownership
- runtime execution

### Discovery

Discovery uses Docker runtime information, including Compose labels, to find containers and suggest stack registrations.

### Ownership

Ownership is not the same as discovery.

For registered stacks, DockGo stores owned container IDs. That ownership is what makes a stack authoritative for the containers it manages.

### Runtime Execution

When a registered stack is used for updates, DockGo executes the saved stack definition and then binds runtime containers back to stack ownership.

## Why Discovery and Ownership Are Separate

If DockGo relied only on Docker labels as truth, stacks could drift silently when:

- containers are recreated elsewhere
- project names are reused
- labels no longer match the intended stack definition

By separating discovery from ownership:

- Docker labels help DockGo find candidates
- stored ownership tells DockGo what it actually manages

## Stack States

### Unbound

The stack exists, but DockGo has not yet established owned container IDs.

### Managed

The stack owns runtime container IDs and can safely associate those containers back to the stack.

### Drifted

DockGo has recorded ownership, but the current runtime no longer matches it.

This is surfaced explicitly so the UI and API do not silently guess.

## Reconcile

`Reconcile` updates ownership from the currently running runtime containers for the stack.

This is useful after:

- fresh DockGo installs
- state restore
- manual runtime changes outside DockGo

## Why Path Handling Differs Between Linux and Windows

### Linux

Best case:

- same host path inside DockGo
- `Host Native`

This keeps Compose path resolution straightforward.

### Windows

Common case:

- Windows host path
- Linux DockGo container path
- `Mapped` translation

This is why Windows stacks usually need explicit path mappings.

## Dashboard vs Stacks

The main dashboard is intentionally simple and container-first.

The `Stacks` view is the advanced operational surface for Compose projects.

That split exists so DockGo can support:

- one-click updates for normal usage
- stronger stack correctness for Compose users

without forcing every user to think in stack internals all the time.
