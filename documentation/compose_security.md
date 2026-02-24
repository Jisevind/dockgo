# Compose Security

## Overview

DockGo can update containers managed by Docker Compose by reading the `com.docker.compose.project.working_dir` label from containers and executing `docker compose` commands in that directory.

## Security Concern

Since the working directory comes from container labels (which are user-controlled), there's a potential security risk if a malicious container is launched with a crafted working directory. While this is unlikely in practice, it's important to mitigate this risk.

## Security Measures Implemented

### 1. Path Validation

All Compose working directories now go through a `validateWorkingDir()` function that performs the following checks:

#### Path Sanitization
- **Cleans paths**: Removes `.` and `..` components using `filepath.Clean()`
- **Resolves symlinks**: Uses `filepath.EvalSymlinks()` to get the real path, preventing symlink-based attacks
- **Absolute path requirement**: Ensures the path is absolute, preventing relative path tricks
- **Directory verification**: Confirms the path exists and is actually a directory

#### Path Restriction (Optional)
When `ALLOWED_COMPOSE_PATHS` is configured:
- Only directories within the specified base paths are allowed
- Each allowed path is also cleaned and symlink-resolved for comparison
- This provides defense-in-depth by limiting where Compose commands can run

### 2. Configuration

Set the `ALLOWED_COMPOSE_PATHS` environment variable to restrict Compose working directories:

```bash
# Single allowed path
ALLOWED_COMPOSE_PATHS=/opt/docker

# Multiple allowed paths (comma-separated)
ALLOWED_COMPOSE_PATHS=/opt/docker,/home/user/docker,/data/compose

# Empty value (default): Any valid directory is allowed (backward compatible)
ALLOWED_COMPOSE_PATHS=
```

### 3. Logging

When path restrictions are enabled, DockGo logs:

```
Security: Compose working directory restrictions enabled for paths: [/opt/docker /home/user/docker]
```

And when validating a directory:

```
✅ Validated working directory: /opt/docker/myproject
```

## Risk Assessment

### Before Mitigation
- **Risk Level**: Minor
- **Scenario**: A malicious container with crafted `com.docker.compose.project.working_dir` label could potentially cause DockGo to execute `docker compose` commands in unintended directories
- **Impact**: Limited - would require malicious container access and DockGo scanning that container

### After Mitigation
- **Risk Level**: Very Low
- **Scenario**: Same as above, but now mitigated by:
  1. Path sanitization (prevents path traversal)
  2. Symlink resolution (prevents symlink-based attacks)
  3. Optional path restrictions (limits where commands can run)
  4. Directory existence verification

## Recommendations

1. **For production environments**: Set `ALLOWED_COMPOSE_PATHS` to your actual Compose project directories
2. **For development**: Can leave empty for convenience, but be aware of the minor risk
3. **Audit**: Review your container labels to ensure they contain legitimate working directories

## Example Configuration

```bash
# .env file for production
PORT=3131
API_TOKEN=your-secure-token-here
CORS_ORIGIN=https://your-domain.com

# Restrict Compose to these base directories
ALLOWED_COMPOSE_PATHS=/opt/docker-compose-projects,/data/compose
```

## How It Works

When updating a Compose-managed container:

1. DockGo reads the `com.docker.compose.project.working_dir` label
2. Passes it through `validateWorkingDir()` with the allowed paths
3. If validation passes, executes `docker compose` commands in the validated directory
4. If validation fails, the update is aborted with a clear error message

### Error Examples

```bash
# Path traversal attempt
Error: working directory must be an absolute path: ../../../etc

# Path not in allowed list
Error: working directory '/tmp/malicious' is not within allowed paths: [/opt/docker]

# Symlink outside allowed path
Error: working directory '/opt/docker/project' is not within allowed paths: [/opt/docker]
# (because the symlink points elsewhere)
```

## Backward Compatibility

If `ALLOWED_COMPOSE_PATHS` is not set or empty, the behavior remains the same as before (any valid directory is allowed). This ensures backward compatibility with existing deployments.