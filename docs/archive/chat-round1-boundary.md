> Archive Notice
>
> 這是歷史 / 整理期文件，用來保留早期 boundary 與 compat 決策。
> 它不作為目前維護期正式 SOP。
> 正式入口請回 [README](../../README.md) 與 `docs/ops/chat-ops-index.md`。

# Chat Round 1 Boundary Status

> 角色：歷史 / 過渡治理文件。這份文件保存 chat round 1 架構整理時的 boundary 與 compat 決策，不作為當前 chat ops 的唯一操作入口。
>
> 目前正式入口請先看 `docs/ops/chat-ops-index.md`，再依主題進入 `chat-provider-health.md`、`chat-snapshot-audit.md`、`ai-baseline-freeze.md`。
>
> 歷史路徑註記：本文若出現早期 flat file 寫法，請以目前 repo 為準：
> `backend/services/chat/service.py` → `backend/services/chat/service/__init__.py`
> `backend/services/chat/staging.py` → `backend/services/chat/staging/__init__.py`

## 目的
- 記錄 chat round 1 目前已凍結的 public boundary 與 compat 點。
- 這份文件反映 Step 1、Step 2A、Step 2B 的現況，不改 `generate_chat_reply` 簽名，不改 `/api/chat` contract，不改 CLI stdout JSON shape / exit code。
- 持續原則：不要新增新的跨模組 `_...` import / patch。
- 下列 CLI / module 清單只作 frozen boundary inventory；目前日常營運說明請回到 `docs/ops/chat-ops-index.md` 與其指向的正式文件。

## 已凍結的不變項
- 正式業務入口維持 `backend.services.chat.generate_chat_reply`。
- `backend.services.chat.service.generate_chat_reply` 保留為 compat import path。
- 下列 CLI 名稱不得直接消失：
  - `python -m backend.tools.ops.chat_provider_healthcheck`
  - `python -m backend.tools.ops.chat_regression_report`
  - `python -m backend.tools.ops.chat_snapshot_inspect`
  - `python -m backend.tools.ops.chat_staging_inspect`
  - `python -m backend.tools.ops.chat_release_check --mode p10`
- 不改 `/api/chat` contract，不改 `backend/schemas/chat.py`。
- 不在 round 1 內觸碰 auth、crawler、alembic、`backend/app.py`、`backend/db.py`、`backend/security.py`。

## Public Boundary

### 正式業務入口
- `backend.services.chat.generate_chat_reply`
- `backend.services.chat.service.generate_chat_reply`

### 正式 ops 入口
- `python -m backend.tools.ops.chat_provider_healthcheck`
- `python -m backend.tools.ops.chat_regression_report`
- `python -m backend.tools.ops.chat_snapshot_inspect --request-id <REQUEST_ID>`
- `python -m backend.tools.ops.chat_staging_inspect --request-id <REQUEST_ID>`
- `python -m backend.tools.ops.chat_staging_inspect --list-quarantine --limit <N>`

### Test Harness / Acceptance 入口
- `python -m backend.tools.ops.chat_release_check --mode p10`
- `backend/tests/chat/harness/test_release_check.py`
- `backend/tests/chat/service/*.py`
- `backend/tests/chat/context_pack/*.py`
- `backend/tests/chat/provider/*.py`
- `backend/tests/chat/inference/*.py`
- `backend/tests/chat/contracts/*.py`

## 測試命名規則
- chat 測試統一放在 `backend/tests/chat/<group>/`。
- 檔名以責任或行為命名，例如 `test_service_snapshot.py`、`test_retrieval_ordering.py`。
- 階段代號僅保留在歷史文件、CLI mode、migration 與治理語彙，不再作為測試主檔名。

## Step 2 現況

### 已完成的 provider caller seam
- `backend/services/chat/provider_caller.py`
  - `build_provider_messages`
  - `generate_provider_result`
  - `ProviderCallResult`
  - `ProviderDispatchError`
- `backend/tools/ops/chat_release_check.py` 已改 patch `backend.services.chat.provider_caller.generate_provider_result`。
- provider-facing service tests 已改用 `ProviderCallResult` / `generate_provider_result`，不再直接依賴 `service.py` 的 provider 私有 helper。

### 已完成的 snapshot / staging seam
- `backend/services/chat/snapshot_store.py`
  - `snapshot_root`
  - `snapshot_dir`
  - `read_json_file`
  - `persist_ai_snapshot`
  - `update_snapshot_meta`
  - `build_candidate_lineage_categories`
- `backend/services/chat/staging/__init__.py`
  - `ChatStagingRecord`
  - `persist_chat_staging_record`
  - `persist_chat_quarantine_entry`
  - `build_chat_staging_record`
  - `persist_chat_stage_or_quarantine`
- `chat_snapshot_inspect.py` / `chat_staging_inspect.py` 已共用 `snapshot_store` 的 snapshot root / JSON loading helper，不改 CLI contract。

## Import / CLI Mapping

### Service 與 Support Modules

| 檔案 | 目前對外可見名稱 | 目前被誰引用 | round 1 狀態 | private helper 外溢 |
| --- | --- | --- | --- | --- |
| `backend/services/chat/__init__.py` | `generate_chat_reply` | `backend/api/routes/chat.py` | 保留正式 package public entrypoint | 否 |
| `backend/services/chat/service/__init__.py` | `generate_chat_reply` | `backend/services/chat/__init__.py`、`backend/services/chat/health.py`、`backend/tests/chat/service/*.py` | 保留路徑；現在以 orchestration 為主，provider 與 snapshot/staging 寫檔邏輯已直接接到 seam | 否；不再提供跨模組可見的 provider / snapshot private patch 點 |
| `backend/services/chat/provider_caller.py` | `build_provider_messages`、`generate_provider_result`、`ProviderCallResult`、`ProviderDispatchError` | `service.py`、`chat_release_check.py`、`backend/tests/chat/provider/*.py`、`backend/tests/chat/service/*.py` | 已成 round-1 provider seam；先保留 path，不做 rename | 否 |
| `backend/services/chat/snapshot_store.py` | `persist_ai_snapshot`、`update_snapshot_meta`、`snapshot_root`、`snapshot_dir`、`read_json_file`、`build_candidate_lineage_categories` | `service.py`、`staging.py`、inspect CLIs | 已成 round-1 snapshot persistence seam；保留 path | 否 |
| `backend/services/chat/staging/__init__.py` | `ChatStagingRecord`、`persist_chat_staging_record`、`persist_chat_quarantine_entry`、`build_chat_staging_record`、`persist_chat_stage_or_quarantine` | `service/__init__.py` | 已成 round-1 staging/quarantine seam；保留 path | 否 |
| `backend/services/chat/health.py` | `run_provider_health_check` | `backend/tools/ops/chat_provider_healthcheck.py`、`backend/tools/ops/chat_regression_report.py`、`backend/tests/chat/provider/test_provider_health.py` | 保留 official ops 的 service-side support | 否 |
| `backend/services/chat/context_pack/retrieval.py` | `P1Demand`、`CandidatePart`、`P1RetrievalResult`、`retrieve_topk_candidates`、`build_category_retrieval_stmt` | `service.py`、`backend/tests/chat/context_pack/test_retrieval_contracts.py`、`backend/tests/chat/context_pack/test_retrieval_ordering.py` | 路徑先保留；`build_category_retrieval_stmt` 作為 SQL ordering contract seam | 否 |
| `backend/services/chat/context_pack/compress.py` | `compress_candidates` | `service.py`、`backend/tests/chat/context_pack/test_compress_candidates.py`、`backend/tests/chat/service/test_service_compress_logging.py` | 保留 | 否 |
| `backend/services/chat/context_pack/render.py` | `build_context_pack`、`canonicalize_text_for_hash`、`hash_context_pack` | `service.py`、`backend/tests/chat/context_pack/test_context_pack_render.py` | 保留 | 否 |
| `backend/services/chat/clients/openai_compat_client.py` | `generate_openai_compat_completion`、`generate_openai_compat_text`、`OpenAICompatError`、`OpenAICompatResult` | provider seam、tests | 保留 path | 否 |
| `backend/services/chat/demand_inference.py` | `infer_chat_demand` | `service.py`、`backend/tests/chat/inference/test_demand_inference.py`、`backend/tests/chat/service/test_service_demand_resolution.py` | 保留 | 否 |
| `backend/services/chat/prompt.py` | `build_prompt` | `provider_caller.py` | internal-only module | 否 |
| `backend/services/chat/gate.py` | `validate_text_response`、`TextValidationReport` | `service.py`、gate tests | internal-only module | 否 |
| `backend/services/chat/dq.py` | `evaluate_text_dq`、`DQReport` | `service.py`、DQ tests | internal-only module | 否 |
| `backend/services/chat/normalize.py` | `normalize_provider_success`、`NormalizedAIResponse` | `service.py`、normalize tests | internal-only module | 否 |
| `backend/services/chat/retry_policy.py` | `RETRY_BACKOFF_SECONDS`、`should_retry_chat_error` | `openai_compat_client.py`、retry tests | internal-only module | 否 |

### Ops / Harness Modules

| 檔案 | 目前對外可見名稱 | 目前被誰引用 | round 1 狀態 | private helper 外溢 |
| --- | --- | --- | --- | --- |
| `backend/tools/ops/chat_provider_healthcheck.py` | CLI `python -m backend.tools.ops.chat_provider_healthcheck`、`main()` | `docs/ops/chat-provider-health.md`、`docs/ops/ai-baseline-freeze.md` | official ops | 否 |
| `backend/tools/ops/chat_regression_report.py` | CLI `python -m backend.tools.ops.chat_regression_report`、`main()` | `docs/ops/ai-baseline-freeze.md`、`backend/tests/chat/ops/test_regression_report.py` | official ops | 否 |
| `backend/tools/ops/chat_snapshot_inspect.py` | CLI `python -m backend.tools.ops.chat_snapshot_inspect`、`main()` | `docs/ops/chat-snapshot-audit.md`、`backend/tests/chat/ops/test_snapshot_inspect.py` | official ops；已共用 `snapshot_store` loader | 否 |
| `backend/tools/ops/chat_staging_inspect.py` | CLI `python -m backend.tools.ops.chat_staging_inspect`、`main()` | `backend/tests/chat/ops/test_staging_inspect.py` | official ops；已共用 `snapshot_store` loader | 否 |
| `backend/tools/ops/chat_release_check.py` | CLI `python -m backend.tools.ops.chat_release_check --mode p10`、`run_p10_release_check()`、`main()` | `docs/ops/chat-snapshot-audit.md`、`docs/ops/ai-baseline-freeze.md`、`backend/tests/chat/harness/test_release_check.py` | test harness / acceptance surface；保留 CLI 名稱與 summary shape | 否；已改 patch provider seam |

## 目前文件定位
- 正式 chat ops 導覽與當前 CLI 入口：`docs/ops/chat-ops-index.md`
- snapshot / staging / quarantine 稽核：`docs/ops/chat-snapshot-audit.md`
- provider smoke / health：`docs/ops/chat-provider-health.md`
- baseline freeze / regression / release acceptance：`docs/ops/ai-baseline-freeze.md`
- 本文件只保留 round 1 的 boundary / compat 決策與歷史 import/CLI mapping，不再重複維護日常 SOP 清單。

## 目前剩餘的 private helper debt
- chat round 1 既知的 private-helper test dependency 已清零。
- `backend/tests/chat/context_pack/test_retrieval_ordering.py` 已改走 `build_category_retrieval_stmt`。
- `backend/tests/chat/service/test_service_demand_resolution.py` 已改 patch `backend.services.chat.snapshot_store.persist_ai_snapshot`。
- `backend/services/chat/service/__init__.py` 仍有 internal-only `_...` orchestration helpers，但它們不再作為跨模組 patch / import 點。

## 必須保留的 compat 點
- import path 不能直接消失：
  - `backend.services.chat.generate_chat_reply`
  - `backend.services.chat.service.generate_chat_reply`
  - `backend.services.chat.health.run_provider_health_check`
  - `backend.services.chat.contracts.ChatRequest`
  - `backend.services.chat.contracts.ChatResponse`
  - `backend.services.chat.clients.openai_compat_client.generate_openai_compat_text`
  - `backend.services.chat.clients.openai_compat_client.generate_openai_compat_completion`
- CLI 名稱不能直接改：
  - `backend.tools.ops.chat_provider_healthcheck`
  - `backend.tools.ops.chat_regression_report`
  - `backend.tools.ops.chat_snapshot_inspect`
  - `backend.tools.ops.chat_staging_inspect`
  - `backend.tools.ops.chat_release_check`

## Compat 狀態
- `service.py` 仍必須保留的 compat 只有正式 import path：`backend.services.chat.service.generate_chat_reply`。
- 已移除且目前無外部依賴的 service-level wrapper：
  - `_generate_provider_result`
  - `_build_provider_messages`
  - `_persist_ai_snapshot`
  - `_persist_chat_stage_or_quarantine`
- provider / snapshot / staging 的穩定 seam 現在分別在：
  - `backend.services.chat.provider_caller`
  - `backend.services.chat.snapshot_store`
  - `backend.services.chat.staging`

## Round 1 結論
- chat round 1 architecture cleanup complete。
- chat 測試已完成責任式命名與 `backend/tests/chat/*` 歸位整理。
- 後續正式 chat ops / baseline / 稽核入口已移到 `docs/ops/chat-ops-index.md`。
