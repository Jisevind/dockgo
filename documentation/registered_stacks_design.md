# Registered Stacks Design

## Purpose

This document proposes a registered-stack architecture for Docker Compose support in DockGo.

The goal is to replace the current label-driven Compose update flow with an explicit stack model that works reliably for both Linux and Windows while allowing DockGo to remain containerized.

## Problem Statement

DockGo currently detects Compose-managed containers from Docker labels and runs `docker compose` from inside the DockGo container using the Compose project working directory.

That approach is fragile because:

- running `docker compose` inside a container does not guarantee the same filesystem view as the host
- relative bind mounts such as `./app_data:/config` may resolve differently inside DockGo than they do on the host
- translating only the project working directory is not enough to make bind mount source paths safe
- Compose updates currently succeed if `docker compose up -d` exits cleanly, even if the stack is still starting incorrectly

This is the root architectural weakness behind stateful apps appearing to boot as fresh installations after a DockGo-triggered update.

## Design Goals

- Keep DockGo containerized
- Support Compose projects on both Linux and Windows
- Make Compose updates explicit and predictable
- Avoid relying on runtime labels as the deployment source of truth
- Support health-aware stack deployments
- Preserve the current simple workflow for standalone containers
- Provide a migration path from the current Compose implementation

## Non-Goals

- Replacing the Docker Compose CLI entirely
- Reconstructing arbitrary host Compose projects only from running container metadata
- Solving every host-specific bind mount portability issue automatically on day one

## High-Level Model

DockGo should manage two distinct resource types:

- `container`
- `stack`

A `container` remains the current standalone Docker container workflow.

A `stack` is a first-class managed resource representing a Compose project with an explicit deployment definition.

DockGo may still discover Compose-managed containers from labels, but those labels should only help with association and onboarding. They should not be used as the source of truth for future deployments.

## Why Registered Stacks

Registered stacks solve the core problem by making the deployment context explicit.

Instead of inferring a project from a running container, DockGo stores:

- where the Compose definition lives
- which Compose files are used
- which env files are used
- which project name is expected
- how paths should be interpreted
- how updates should be executed
- how success should be verified

This is closer to how tools such as Portainer manage stacks. It is also more suitable for cross-platform support than the current label-driven model.

## Stack Data Model

Each stack should be represented by a persistent record.

Suggested fields:

```json
{
  "id": "stack_123",
  "name": "audiobookshelf",
  "project_name": "audiobookshelf",
  "kind": "compose_files",
  "compose_files": [
    "/home/johan/docker/audiobookshelf/docker-compose.yml"
  ],
  "env_files": [
    "/home/johan/docker/audiobookshelf/.env"
  ],
  "working_dir": "/home/johan/docker/audiobookshelf",
  "profiles": [],
  "project_env": {},
  "path_mode": "host_native",
  "path_mappings": [],
  "update_policy": {
    "pull": true,
    "build": false,
    "down_before_up": false,
    "force_recreate": false,
    "remove_orphans": true
  },
  "health_policy": {
    "use_compose_wait": true,
    "require_healthy": true,
    "wait_timeout_seconds": 120,
    "startup_grace_seconds": 20
  },
  "discovery_selector": {
    "compose_project": "audiobookshelf",
    "service_names": [
      "audiobookshelf"
    ]
  },
  "git_source": null,
  "labels": {},
  "last_deploy_status": "success",
  "last_deploy_at": "2026-03-19T10:00:00Z",
  "created_at": "2026-03-19T09:00:00Z",
  "updated_at": "2026-03-19T09:30:00Z"
}
```

## Stack Source Types

The stack model should support multiple source types.

### 1. Compose File

Single Compose file stored on disk.

Use when a stack is defined by one `docker-compose.yml` or `compose.yml`.

### 2. Compose Files

Ordered list of Compose files.

Use when a stack relies on multiple files such as:

- `compose.yml`
- `compose.override.yml`
- `compose.prod.yml`

### 3. Git Repo

Stack definition is pulled from a Git repository.

Use when deployment should be based on version-controlled stack definitions rather than local host files.

### 4. Inline Compose

Optional later feature where DockGo stores the Compose content directly.

This is useful for small stacks or direct UI-managed definitions, but it is not required for the initial design.

## Execution Modes

Registered stacks need an explicit path strategy.

### Host Native Mode

`host_native` means DockGo sees the stack files at the same absolute paths as the host.

This is the preferred mode on Linux.

Example:

- host path: `/home/johan/docker/audiobookshelf`
- DockGo volume: `/home/johan/docker:/home/johan/docker`
- stack working dir: `/home/johan/docker/audiobookshelf`

Benefits:

- relative bind mounts behave like host-run Compose
- minimal path translation logic
- easiest to reason about

### Mapped Mode

`mapped` means DockGo sees the project under a different path than the host.

Example:

- host path: `D:\Docker\audiobookshelf`
- container path: `/compose/audiobookshelf`

This mode is necessary for Windows when DockGo runs as a Linux container, but it is more complex because translating the project directory alone is not enough. Bind mount source paths must also be handled explicitly.

Because of that, mapped mode should be treated as an advanced execution mode with stronger validation requirements.

## Path Handling

Path handling must become stack-scoped rather than relying on a single global `COMPOSE_PATH_MAPPING`.

### Current Problem

Today, DockGo translates the Compose project working directory and then runs `docker compose` in that translated directory.

That solves:

- locating the Compose project from inside DockGo

It does not solve:

- making relative bind mounts resolve to the correct host filesystem paths

### Proposed Rule

Each stack must declare one of these path strategies:

- `host_native`
- `mapped`

For `host_native`, DockGo may execute Compose directly using the registered paths.

For `mapped`, DockGo must validate that deployment can still produce host-valid bind mount sources. If that cannot be guaranteed, validation must fail before any update is attempted.

### Implication

The old global `COMPOSE_PATH_MAPPING` should be considered legacy behavior. A registered-stack design should move path handling into stack configuration and validation.

## Deployment Engine

DockGo should continue using the Docker Compose CLI as the deployment backend, but it should do so through a dedicated stack executor rather than generic label-driven shelling.

### Executor Inputs

- stack definition
- requested action
- runtime options

Supported actions:

- `validate`
- `pull`
- `build`
- `deploy`
- `restart`
- `down`
- `logs`
- `status`

Runtime options may include:

- target services
- safe mode
- force recreate
- remove orphans
- wait
- timeout

### Executor Responsibilities

- resolve stack source into concrete Compose inputs
- validate files and environment
- enforce stack path mode rules
- construct exact Compose CLI arguments
- stream logs back as structured events
- perform post-deploy verification
- return structured success or failure

## Deployment Workflow

Stack deployment should be a staged workflow.

### 1. Resolve

Load the registered stack and determine:

- compose files
- env files
- working directory
- profiles
- project name
- path mode

### 2. Preflight Validation

Before any deployment begins, verify:

- compose files exist
- env files exist
- working directory exists
- Compose config renders successfully
- project name is valid and stable
- bind mount sources are valid for the selected path mode

If validation fails, deployment must stop before any container changes occur.

### 3. Pull and Build

Execute pull and optional build according to stack policy.

### 4. Deploy

Run the stack deploy command using the resolved Compose inputs.

Default behavior should likely be:

- `docker compose pull`
- optional `docker compose build`
- `docker compose up -d --remove-orphans`

Per-stack options should control:

- `down_before_up`
- `force_recreate`
- `remove_orphans`
- `build_before_up`

### 5. Verification

Success cannot be defined as "the command exited zero".

Stack verification should inspect the resulting services and containers using:

- `docker compose ps`
- Docker inspect
- healthcheck state
- startup grace windows for services without healthchecks

Optional support for Compose `--wait` should be enabled when available.

### 6. Result

Record:

- success or failure
- timestamps
- verification outcome
- relevant log summary

## Health and Verification Policy

The current standalone updater includes stability verification and rollback logic. Stack deployment needs equivalent health awareness, even if rollback is introduced later.

Each stack should define a health policy:

- whether healthy services are required
- whether Compose `--wait` should be used
- wait timeout in seconds
- startup grace window for services without healthchecks

### Recommended Default

- use Compose wait when supported
- require healthy state when healthchecks exist
- for services without healthchecks, require them to remain running during a grace window

### Future Extension

Support optional rollback strategies:

- no rollback
- restart previous containers if possible
- restore previous Git ref or known good definition

Rollback should not be in the first delivery if it delays getting reliable stack deployment in place.

## Discovery and Association

Container discovery should remain, but Compose labels should be used only for association and onboarding.

### New Behavior

When DockGo scans containers:

- standalone containers remain managed as they are today
- containers with Compose labels are checked for a matching registered stack

Matching signals:

- `com.docker.compose.project`
- known service names
- known working directory
- known compose files if available

### Outcomes

- if matched, annotate the container as belonging to a registered stack
- if unmatched, show it as an unregistered Compose project

This preserves discovery while preventing runtime labels from controlling update execution.

## UI Design

DockGo needs a dedicated stack management surface.

### New Stacks View

Add a top-level Stacks section showing:

- stack name
- project name
- source type
- working directory
- execution mode
- services
- current status
- update availability
- last deploy result

### Stack Detail View

A stack detail page should show:

- Compose files
- env files
- profiles
- update policy
- health policy
- associated running containers
- deployment logs
- last validation result

### Stack Actions

- validate
- check updates
- pull
- deploy
- restart
- down
- inspect logs
- edit stack settings

### Unregistered Compose Projects

For Compose-managed containers found during discovery but not yet registered:

- show "Compose project detected"
- offer "Register stack"
- prefill project name, working dir, and service names from labels
- require the user to confirm or correct stack source information

## API Design

Add stack-specific API routes rather than overloading the container endpoints.

Suggested routes:

- `GET /api/stacks`
- `POST /api/stacks`
- `GET /api/stacks/{id}`
- `PUT /api/stacks/{id}`
- `DELETE /api/stacks/{id}`
- `POST /api/stacks/{id}/validate`
- `POST /api/stacks/{id}/deploy`
- `POST /api/stacks/{id}/pull`
- `POST /api/stacks/{id}/restart`
- `POST /api/stacks/{id}/down`
- `GET /api/stacks/{id}/status`
- `GET /api/stacks/{id}/logs`
- `POST /api/stacks/discover`

The existing container routes should remain focused on standalone or direct container operations:

- `GET /api/containers`
- `POST /api/update/{container}`
- `POST /api/container/{container}/action`

## Validation Rules

Registration must include strong validation.

Minimum checks:

- Compose file paths exist
- env file paths exist
- working directory exists
- `docker compose config` succeeds
- project name is valid
- path mode is supported
- bind mount sources can be resolved safely

For `mapped` stacks, validation must be stricter because translated working directories can hide bind mount resolution problems.

If DockGo cannot prove a stack is deployable in mapped mode, it should reject the registration or mark it unsupported rather than allowing a risky deploy.

## Storage Design

Introduce persistent stack storage under `/app/data`.

Suggested files:

- `/app/data/stacks.json`
- `/app/data/stack_history.json`

Possible later evolution:

- `/app/data/stacks/*.json`
- `/app/data/stack-history/*.json`

### Storage Concerns

- avoid storing plaintext Git credentials directly in stack records
- prefer references to secrets or external auth config
- separate operational history from desired stack state

## Migration Strategy

Migration should happen in phases.

### Phase 1: Introduce Stack Model

- add stack types and storage
- add registration and validation APIs
- add stack UI
- keep current label-driven Compose updates as legacy behavior

### Phase 2: Deploy Registered Stacks

- implement stack executor
- implement validation and verification
- route registered Compose projects through the new stack path

### Phase 3: Shift Compose UX

- show warnings when users attempt to update an unregistered Compose project
- encourage stack registration
- keep labels for discovery and association only

### Phase 4: Deprecate Legacy Compose Update Path

- stop using runtime label-derived working directories as the deployment source of truth
- keep discovery intact
- make registered stacks the supported Compose update mechanism

### Phase 5: Advanced Sources

- add Git-backed stacks
- add stack history and richer auditing
- add drift detection between desired stack definition and running containers

## Codebase Impact

The current codebase is container-centric, so stacks should become a separate subsystem rather than being forced into `ContainerUpdate`.

### New Packages

Suggested package layout:

- `dockgo/stacks/types.go`
- `dockgo/stacks/store.go`
- `dockgo/stacks/validator.go`
- `dockgo/stacks/executor.go`
- `dockgo/stacks/discovery.go`
- `dockgo/stacks/history.go`

### Existing Areas Likely to Change

- `dockgo/engine/compose.go`
- `dockgo/engine/updater.go`
- `dockgo/engine/planner.go`
- `dockgo/server/http.go`
- `dockgo/server/web/*`

### Recommended Refactor Direction

- keep `engine` focused on standalone Docker operations
- move Compose stack deployment into a dedicated `stacks` subsystem
- keep container scanning, but layer stack association on top
- add stack-aware UI and API flows separately from direct container updates

## Recommended Product Stance

DockGo should treat Compose support as explicit infrastructure management, not as a best-effort extension of container updates.

Recommended positioning:

- standalone containers: zero-registration, discover and update
- Compose stacks: discoverable, but registration required for reliable updates

This preserves the simplicity of the current standalone workflow while addressing the structural limitations of Compose management from inside a container.

## Tradeoffs

### Benefits

- reliable cross-platform Compose updates
- better validation before deployment
- clearer operational model
- safer handling of stateful applications
- cleaner UI and API semantics

### Costs

- more configuration than label-driven inference
- more implementation complexity
- more UI surface area
- stronger need for migration and documentation

These tradeoffs are justified because the current architecture cannot make Compose updates safe and predictable across Linux and Windows without explicit stack registration.

## Recommendation

DockGo should adopt a registered-stack architecture for Compose support.

This is the strongest long-term solution if the product must:

- remain containerized
- support Linux and Windows
- manage stateful Compose projects reliably

The current label-driven Compose updater should be treated as a legacy discovery convenience, not as the future deployment model.
