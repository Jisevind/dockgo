# Project Context

This is a javascript project using go-net-http.

The API has 20 routes. See .codesight/routes.md for the full route map with methods, paths, and tags.

High-impact files (most imported, changes here affect many other files):
- encoding/json (imported by 22 files)
- path/filepath (imported by 13 files)
- dockgo/logger (imported by 12 files)
- net/http (imported by 10 files)
- dockgo/stacks (imported by 9 files)
- dockgo/api (imported by 8 files)
- dockgo/agent (imported by 8 files)
- dockgo/agentstore (imported by 6 files)

Required environment variables (no defaults):
- AGENT_JWT_TTL (dockgo\server\http.go)
- AGENT_MAX_CONCURRENT (dockgo\server\http.go)
- APPRISE_QUEUE_SIZE (dockgo\notify\apprise.go)
- AUTH_BCRYPT_COST (dockgo\cmd\dockgo\main.go)
- AUTH_PASSWORD (dockgo\server\http.go)
- DOCKGO_DEBUG (dockgo\server\http.go)
- DOCKGO_HEALTH_TIMEOUT (dockgo\engine\recreate.go)
- DOCKGO_HELPER_PROCESS (dockgo\stacks\executor_test.go)
- DOCKGO_INITIAL_RUNTIME_CHECK (dockgo\engine\recreate.go)
- DOCKGO_SERVER_URL (dockgo\cmd\dockgo-agent\main.go)
- DOCKGO_STABILITY_WINDOW (dockgo\engine\recreate.go)
- DOCKGO_STOP_TIMEOUT (dockgo\engine\recreate.go)
- LOG_COMPRESS (dockgo\logger\logger.go)
- LOG_FORMAT (dockgo\logger\logger.go)
- LOG_MAX_AGE (dockgo\logger\logger.go)

See .codesight/cicd.md for additional cicd context.

Read .codesight/wiki/index.md for orientation (WHERE things live). Then read actual source files before implementing. Wiki articles are navigation aids, not implementation guides.
Read .codesight/CODESIGHT.md for the complete AI context map including all routes, schema, components, libraries, config, middleware, and dependency graph.
