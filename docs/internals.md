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

## Stack Status Model

The stack status API returns two separate concepts:

### Ownership Mode (`ownership_mode`)

- `unbound` — the stack has no managed container IDs yet
- `managed` — the stack owns runtime container IDs and can associate those containers back to the stack

### Operational State (`state`)

- `unbound` — no managed containers recorded; deploy or reconcile to establish ownership
- `running` — all stack containers are running (and healthy, if healthchecks exist)
- `starting` — containers are starting or waiting for healthchecks
- `degraded` — some containers are stopped or unhealthy
- `down` — all stack containers are stopped
- `drifted` — ownership drift detected; currently running containers don't match recorded ownership
- `unknown` — runtime inspection failed

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

## Registered Stacks Design

DockGo adopts a **registered-stack architecture** for Compose support. The label-driven Compose updater is treated as a legacy discovery convenience, not the future deployment model.

### Problem Statement

DockGo detects Compose-managed containers from Docker labels and runs `docker compose` from inside the DockGo container using the Compose project working directory. That approach is fragile because:

- running `docker compose` inside a container does not guarantee the same filesystem view as the host
- relative bind mounts such as `./app_data:/config` may resolve differently inside DockGo than on the host
- translating only the project working directory is not enough to make bind mount source paths safe
- Compose updates succeed if `docker compose up -d` exits cleanly, even if the stack is still starting incorrectly

### Design Goals

- keep DockGo containerized
- support Compose projects on both Linux and Windows
- make Compose updates explicit and predictable
- avoid relying on runtime labels as the deployment source of truth
- support health-aware stack deployments
- preserve the current simple workflow for standalone containers
- provide a migration path from the current Compose implementation

### Path Strategies

Each stack must declare one of two path strategies:

- `host_native`: DockGo may execute Compose directly using the registered paths
- `mapped`: DockGo must validate that deployment still produces host-valid bind mount sources; if that cannot be guaranteed, validation fails before any update is attempted

The old global `COMPOSE_PATH_MAPPING` should be considered legacy behavior; path handling moves into stack configuration and validation.

### Deployment Engine

DockGo uses the Docker Compose CLI as the deployment backend, through a dedicated stack executor rather than generic label-driven shelling. The executor:

- resolves the stack source into concrete Compose inputs
- validates files and environment
- enforces stack path mode rules
- constructs exact Compose CLI arguments
- streams logs back as structured events
- performs post-deploy verification
- returns structured success or failure

Deployment is a staged workflow: **Resolve → Preflight Validation → Pull and Build → Deploy → Verification → Result**. If preflight validation fails, deployment stops before any container changes occur. Verification inspects the resulting services and containers (`docker compose ps`, Docker inspect, healthcheck state, startup grace windows) — success is not defined as "the command exited zero".

### Discovery and Association

When DockGo scans containers:

- standalone containers remain managed as they are today
- containers with Compose labels are checked for a matching registered stack (via `com.docker.compose.project`, known service names, known working directory, and known compose files)

If matched, the container is annotated as belonging to a registered stack; if unmatched, it shows as an unregistered Compose project.

### Tradeoffs

Costs include more configuration, more implementation complexity, more UI surface area, and a stronger need for migration and documentation — justified because the current architecture cannot make Compose updates safe and predictable across Linux and Windows without explicit stack registration.

## GitHub Actions Release Flow

Pushing code to the `main` or `master` branch triggers `.github/workflows/release.yml`. The workflow automates versioning and release:

### 1. Semantic Version Analysis

The workflow runs **Semantic Release**, which analyzes commit messages since the last release using the Conventional Commits specification.

- commit prefixes (`feat:`, `fix:`, `BREAKING CHANGE`) determine the next version number
- if commits do not warrant a release (e.g., only `chore:` or `docs:` commits), the workflow stops safely

### 2. GitHub Release Creation

If a release is warranted, Semantic Release:

- generates a formatted Changelog from recent commit messages
- pushes a new git tag (e.g., `v1.2.0`)
- publishes an official GitHub Release with the Changelog

### 3. Docker Image Build & Publish (GHCR)

Only if a new version was published:

- sets up Docker Buildx and logs into the GitHub Container Registry (`ghcr.io`) using the repository's `GITHUB_TOKEN`
- builds the image from the `Dockerfile`, passing the version as the `VERSION` build argument
- pushes the image twice: tagged with the specific version (e.g., `ghcr.io/your-username/dockgo:1.2.0`) and as `latest`

In short: no manual versioning or publishing is needed — merging conventional commits to `main` automatically tags, changelogs, builds, and publishes the Docker image.

## Dashboard vs Stacks

The main dashboard is intentionally simple and container-first.

The `Stacks` view is the advanced operational surface for Compose projects.

That split exists so DockGo can support:

- one-click updates for normal usage
- stronger stack correctness for Compose users

without forcing every user to think in stack internals all the time.
