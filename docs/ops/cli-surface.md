# CLI Surface

## Stable CLI Surface

The following root modules under `backend.tools.ops` are the stable public CLI surface for crawler and maintenance entrypoints:

- `python -m backend.tools.ops.run_incremental`
- `python -m backend.tools.ops.scheduler_loop`
- `python -m backend.tools.ops.db_retention`
- `python -m backend.tools.ops.list_publications`
- `python -m backend.tools.ops.publish_publication`
- `python -m backend.tools.ops.set_publication_pointer`

These wrappers are intentionally thin and preserve the existing CLI behavior, arguments, and stdout/stderr summary shape by delegating to the existing inner modules.

## Deprecated Aliases

The following root modules remain available as deprecated compatibility aliases:

- `python -m backend.tools.ops.t10_run_incremental`
- `python -m backend.tools.ops.t10_scheduler_loop`
- `python -m backend.tools.ops.t9_db_retention`
- `python -m backend.tools.ops.t9_list_publications`
- `python -m backend.tools.ops.t9_publish_publication`
- `python -m backend.tools.ops.t9_set_publication_pointer`

These aliases should continue to behave exactly the same as the stable CLI surface until they are explicitly removed in a later cleanup round.

## Preconditions For Removing Deprecated Aliases

Deprecated aliases should not be removed until all of the following are true:

- `docker-compose.yml` no longer invokes any `backend.tools.ops.t9_*` or `backend.tools.ops.t10_*` module path.
- Repo docs, shell scripts, and other text surfaces no longer reference the deprecated module paths.
- Any in-repo Python imports that still depend on the deprecated aliases have been updated or intentionally kept for compatibility.
- The replacement descriptive module path has been frozen as the long-term public CLI surface.

## Chat Wrappers

The root `chat_*` wrappers under `backend.tools.ops` are long-term public surface and are out of scope for this change.

- Do not rename them as part of crawler / maintenance CLI cleanup.
- Do not treat them as deprecated aliases in this round.
