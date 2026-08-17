# Web Orchestrator Upgrade

## Existing scanner preservation

No Python scanner engine was rewritten. The web orchestrator calls the existing four launchers in their existing order.

One launcher portability correction was applied:

- `run-max-v8.5.1-recursive.cmd` now uses its own folder (`%~dp0`) instead of the old hardcoded V8 project path.
- All scan arguments and scanner behavior remain unchanged.
- The exact previous launcher is retained as `run-max-v8.5.1-recursive.original.cmd` for rollback/comparison.

## Added

- `WEBAPP_README.md`
- `webapp/start-webapp.cmd`
- `webapp/run-web-tests.cmd`
- `webapp/backend/`
  - FastAPI REST API
  - WebSocket event stream
  - SQLite orchestration database
  - Safe Windows `.cmd` subprocess execution
  - scan cancellation
  - report/evidence/screenshot indexing and serving
  - backend tests
- `webapp/frontend/`
  - Next.js App Router frontend
  - modern responsive dashboard
  - four-stage progress visualization
  - real-time logs with polling fallback
  - report/evidence preview
  - screenshot gallery
  - scan history

## Validation

- 96 original scanner tests passed.
- 4 new backend tests passed.
- Mock four-stage API lifecycle passed.
- WebSocket lifecycle passed.
- Existing `hiapp.pk` artifacts indexed successfully: four reports, screenshots, and structured evidence.
- Frontend TypeScript/JSX syntax validation passed.

The full external-tool scan was not executed in the build environment because it requires the user's Windows toolchain, API credentials, Docker images, and authorized target access.
