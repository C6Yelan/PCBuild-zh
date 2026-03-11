# Chat Round 1 Boundary Status

## 目的
- 記錄 chat round 1 目前已凍結的 public boundary 與 compat 點。
- 這份文件反映 Step 1、Step 2A、Step 2B 的現況，不改 `generate_chat_reply` 簽名，不改 `/api/chat` contract，不改 CLI stdout JSON shape / exit code。
- 持續原則：不要新增新的跨模組 `_...` import / patch。

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
- `backend/tests/test_chat_release_check.py`
- `backend/tests/test_chat_service_*.py`
- `backend/tests/test_chat_p1_retrieval_ordering.py`
- `backend/tests/test_chat_p2_compress_candidates.py`
- `backend/tests/test_chat_p3_context_pack_render.py`
- `backend/tests/test_chat_demand_inference.py`
- `backend/tests/test_chat_p0_contracts.py`
- `backend/tests/test_chat_a1_provider_config.py`

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
- `backend/services/chat/staging.py`
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
| `backend/services/chat/service.py` | `generate_chat_reply` | `backend/services/chat/__init__.py`、`backend/services/chat/health.py`、多數 `test_chat_service_*` | 保留路徑；現在以 orchestration 為主，provider 與 snapshot/staging 寫檔邏輯已直接接到 seam | 否；不再提供跨模組可見的 provider / snapshot private patch 點 |
| `backend/services/chat/provider_caller.py` | `build_provider_messages`、`generate_provider_result`、`ProviderCallResult`、`ProviderDispatchError` | `service.py`、`chat_release_check.py`、多個 service tests | 已成 round-1 provider seam；先保留 path，不做 rename | 否 |
| `backend/services/chat/snapshot_store.py` | `persist_ai_snapshot`、`update_snapshot_meta`、`snapshot_root`、`snapshot_dir`、`read_json_file`、`build_candidate_lineage_categories` | `service.py`、`staging.py`、inspect CLIs | 已成 round-1 snapshot persistence seam；保留 path | 否 |
| `backend/services/chat/staging.py` | `ChatStagingRecord`、`persist_chat_staging_record`、`persist_chat_quarantine_entry`、`build_chat_staging_record`、`persist_chat_stage_or_quarantine` | `service.py` | 已成 round-1 staging/quarantine seam；保留 path | 否 |
| `backend/services/chat/health.py` | `run_provider_health_check` | `backend/tools/ops/chat_provider_healthcheck.py`、`backend/tools/ops/chat_regression_report.py`、`test_chat_service_p4_health.py` | 保留 official ops 的 service-side support | 否 |
| `backend/services/chat/context_pack/retrieval.py` | `P1Demand`、`CandidatePart`、`P1RetrievalResult`、`retrieve_topk_candidates`、`build_category_retrieval_stmt` | `service.py`、`test_chat_p1_contracts.py`、`test_chat_p1_retrieval_ordering.py` | 路徑先保留；`build_category_retrieval_stmt` 作為 SQL ordering contract seam | 否 |
| `backend/services/chat/context_pack/compress.py` | `compress_candidates` | `service.py`、`test_chat_p2_compress_candidates.py` | 保留 | 否 |
| `backend/services/chat/context_pack/render.py` | `build_context_pack`、`canonicalize_text_for_hash`、`hash_context_pack` | `service.py`、`test_chat_p3_context_pack_render.py` | 保留 | 否 |
| `backend/services/chat/clients/openai_compat_client.py` | `generate_openai_compat_completion`、`generate_openai_compat_text`、`OpenAICompatError`、`OpenAICompatResult` | provider seam、tests | 保留 path | 否 |
| `backend/services/chat/demand_inference.py` | `infer_chat_demand` | `service.py`、`test_chat_demand_inference.py` | 保留 | 否 |
| `backend/services/chat/prompt.py` | `build_prompt` | `provider_caller.py` | internal-only module | 否 |
| `backend/services/chat/gate.py` | `validate_text_response`、`TextValidationReport` | `service.py`、gate tests | internal-only module | 否 |
| `backend/services/chat/dq.py` | `evaluate_text_dq`、`DQReport` | `service.py`、DQ tests | internal-only module | 否 |
| `backend/services/chat/normalize.py` | `normalize_provider_success`、`NormalizedAIResponse` | `service.py`、normalize tests | internal-only module | 否 |
| `backend/services/chat/retry_policy.py` | `RETRY_BACKOFF_SECONDS`、`should_retry_chat_error` | `openai_compat_client.py`、retry tests | internal-only module | 否 |

### Ops / Harness Modules

| 檔案 | 目前對外可見名稱 | 目前被誰引用 | round 1 狀態 | private helper 外溢 |
| --- | --- | --- | --- | --- |
| `backend/tools/ops/chat_provider_healthcheck.py` | CLI `python -m backend.tools.ops.chat_provider_healthcheck`、`main()` | `docs/ops/chat-provider-health.md`、`docs/ops/ai-baseline-freeze.md` | official ops | 否 |
| `backend/tools/ops/chat_regression_report.py` | CLI `python -m backend.tools.ops.chat_regression_report`、`main()` | `docs/ops/ai-baseline-freeze.md`、`test_chat_service_p10_publish.py` | official ops | 否 |
| `backend/tools/ops/chat_snapshot_inspect.py` | CLI `python -m backend.tools.ops.chat_snapshot_inspect`、`main()` | `docs/ops/chat-snapshot-audit.md`、snapshot/gate/dq tests | official ops；已共用 `snapshot_store` loader | 否 |
| `backend/tools/ops/chat_staging_inspect.py` | CLI `python -m backend.tools.ops.chat_staging_inspect`、`main()` | `test_chat_service_p9_staging.py` | official ops；已共用 `snapshot_store` loader | 否 |
| `backend/tools/ops/chat_release_check.py` | CLI `python -m backend.tools.ops.chat_release_check --mode p10`、`run_p10_release_check()`、`main()` | `docs/ops/chat-snapshot-audit.md`、`docs/ops/ai-baseline-freeze.md`、`test_chat_release_check.py` | test harness / acceptance surface；保留 CLI 名稱與 summary shape | 否；已改 patch provider seam |

## 檔案分類

### Official Ops
- `backend/tools/ops/chat_provider_healthcheck.py`
- `backend/tools/ops/chat_regression_report.py`
- `backend/tools/ops/chat_snapshot_inspect.py`
- `backend/tools/ops/chat_staging_inspect.py`
- `docs/ops/chat-provider-health.md`
- `docs/ops/chat-snapshot-audit.md`

### Test Harness
- `backend/tools/ops/chat_release_check.py`
- `backend/tests/test_chat_release_check.py`
- `backend/tests/test_chat_service_p5_snapshot.py` 內的 snapshot inspect CLI contract 測試
- `backend/tests/test_chat_service_p9_staging.py` 內的 staging inspect CLI contract 測試
- `backend/tests/test_chat_service_p10_publish.py` 內的 release-like publish / retry 驗證

### Internal Support Seams
- `backend/services/chat/provider_caller.py`
- `backend/services/chat/snapshot_store.py`
- `backend/services/chat/staging.py`

### Internal-Only Modules
- `backend/services/chat/service.py` 的所有 `_...`
- `backend/services/chat/context_pack/retrieval.py` 的所有 `_...`
- `backend/services/chat/prompt.py`
- `backend/services/chat/gate.py`
- `backend/services/chat/dq.py`
- `backend/services/chat/normalize.py`
- `backend/services/chat/retry_policy.py`

## 目前剩餘的 private helper debt
- chat round 1 既知的 private-helper test dependency 已清零。
- `backend/tests/test_chat_p1_retrieval_ordering.py` 已改走 `build_category_retrieval_stmt`。
- `backend/tests/test_chat_service_demand_resolution.py` 已改 patch `backend.services.chat.snapshot_store.persist_ai_snapshot`。
- `backend/services/chat/service.py` 仍有 internal-only `_...` orchestration helpers，但它們不再作為跨模組 patch / import 點。

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
- 下一步建議進入第 2 階段：AI log contract / Loki / Grafana dashboard。
