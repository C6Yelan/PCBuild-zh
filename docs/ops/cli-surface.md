# CLI Surface

## Canonical Implementation Trees

- crawler parse：`backend.tools.crawler.parse.*`
  - stable public wrapper：`python -m backend.tools.crawler.crawl_parse_snapshot`
- stage-from-snapshot / staging ingest：`backend.tools.db.stage_from_snapshot.*`、`backend.tools.db.staging_capture_support.*`、`backend.tools.db.staging_ingest_support.*`
  - stable public CLIs：`python -m backend.tools.db.stage_from_snapshot_cli`、`python -m backend.tools.db.stage_ingest_json_cli`
- chat ops：`backend.tools.ops.chat.*`
  - stable public wrappers：`python -m backend.tools.ops.chat_provider_healthcheck`、`python -m backend.tools.ops.chat_regression_report`、`python -m backend.tools.ops.chat_snapshot_inspect`、`python -m backend.tools.ops.chat_staging_inspect`、`python -m backend.tools.ops.chat_release_check --mode p10`
- crawler ops：`backend.tools.ops.crawler.*`
  - stable public wrappers：`python -m backend.tools.ops.run_incremental`、`python -m backend.tools.ops.scheduler_loop`、`python -m backend.tools.ops.list_publications`、`python -m backend.tools.ops.publish_publication`、`python -m backend.tools.ops.set_publication_pointer`
- maintenance ops：`backend.tools.ops.maintenance.*`
  - stable public wrapper：`python -m backend.tools.ops.db_retention`

## Stable Public CLI Surface

The following module paths are the stable public CLI surface:

- `python -m backend.tools.crawler.crawl_parse_snapshot`
- `python -m backend.tools.db.stage_from_snapshot_cli`
- `python -m backend.tools.db.stage_ingest_json_cli`
- `python -m backend.tools.ops.run_incremental`
- `python -m backend.tools.ops.scheduler_loop`
- `python -m backend.tools.ops.db_retention`
- `python -m backend.tools.ops.list_publications`
- `python -m backend.tools.ops.publish_publication`
- `python -m backend.tools.ops.set_publication_pointer`
- `python -m backend.tools.ops.chat_provider_healthcheck`
- `python -m backend.tools.ops.chat_regression_report`
- `python -m backend.tools.ops.chat_snapshot_inspect`
- `python -m backend.tools.ops.chat_staging_inspect`
- `python -m backend.tools.ops.chat_release_check --mode p10`

These wrappers are intentionally thin and preserve the existing CLI behavior, arguments, and stdout/stderr summary shape by delegating to the existing inner modules.

## Legacy / Compat Surface

The following root modules remain available as deprecated compatibility aliases:

- `python -m backend.tools.ops.t10_run_incremental`
- `python -m backend.tools.ops.t10_scheduler_loop`
- `python -m backend.tools.ops.t9_db_retention`
- `python -m backend.tools.ops.t9_list_publications`
- `python -m backend.tools.ops.t9_publish_publication`
- `python -m backend.tools.ops.t9_set_publication_pointer`

These aliases should continue to behave exactly the same as the stable CLI surface until they are explicitly removed in a later cleanup round.
- `--mode p10`、`t9_*` / `t10_*` module names、event key、artifact path（例如 `temp/t7/...`、`temp/t10/...`）目前屬穩定 compat / contract，不是 canonical 名稱。

## Preconditions For Removing Deprecated Aliases

Deprecated aliases should not be removed until all of the following are true:

- `docker-compose.yml` no longer invokes any `backend.tools.ops.t9_*` or `backend.tools.ops.t10_*` module path.
- Repo docs, shell scripts, and other text surfaces no longer reference the deprecated module paths.
- Any in-repo Python imports that still depend on the deprecated aliases have been updated or intentionally kept for compatibility.
- The replacement descriptive module path has been frozen as the long-term public CLI surface.

## Internal Import Guidance

- Internal crawler parse helper imports should use `backend.tools.crawler.parse.*`.
- Internal stage-from-snapshot helper imports should use `backend.tools.db.stage_from_snapshot.*`、`backend.tools.db.staging_capture_support.*`、`backend.tools.db.staging_ingest_support.*`。
- Internal crawler ops helper imports should use `backend.tools.ops.crawler.*`.
- Internal chat ops helper imports should use `backend.tools.ops.chat.*`.
