# Chat Round 1 Boundary Freeze

## 目的
- 凍結 chat round 1 的 public boundary、import path、CLI 名稱與檔案歸屬。
- 這是施工前準備文件，不改功能、不改 `generate_chat_reply` 簽名、不改 CLI stdout JSON shape 與 exit code。
- Step 1 起點原則：不要新增任何跨模組依賴 `_` 開頭成員的地方。

## 本輪凍結的不變項
- 正式業務入口維持 `backend.services.chat.generate_chat_reply`。
- `backend.services.chat.service.generate_chat_reply` 暫時保留為 compat import path。
- 下列 CLI 名稱不得直接消失：
  - `python -m backend.tools.ops.chat_provider_healthcheck`
  - `python -m backend.tools.ops.chat_regression_report`
  - `python -m backend.tools.ops.chat_snapshot_inspect`
  - `python -m backend.tools.ops.chat_staging_inspect`
  - `python -m backend.tools.ops.chat_release_check --mode p10`
- 不改 `/api/chat` contract，不改 `backend/schemas/chat.py`。
- 不在 round 1 內觸碰 auth、crawler、alembic、`backend/app.py`、`backend/db.py`、`backend/security.py`。

## Public Boundary 最終清單

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

### Internal Helper
- `backend/services/chat/service.py` 內所有 `_...`
- `backend/services/chat/context_pack/retrieval.py` 內所有 `_...`
- `backend/tools/ops/chat_release_check.py` 內為 deterministic harness 而寫的 `_...`
- `backend/tools/ops/chat_snapshot_inspect.py`、`backend/tools/ops/chat_staging_inspect.py` 內的 `_load_json` / `_tail_jsonl`

## Import / CLI Mapping

### Service 與 Support Modules

| 檔案 | 目前對外可見名稱 | 目前被誰引用 | round 1 建議 | private helper 外溢 |
| --- | --- | --- | --- | --- |
| `backend/services/chat/__init__.py` | `generate_chat_reply` | `backend/api/routes/chat.py` | 保留為正式 package public entrypoint | 否 |
| `backend/services/chat/service.py` | `generate_chat_reply` | `backend/services/chat/__init__.py`、`backend/services/chat/health.py`、多數 `test_chat_service_*` | 保留路徑；未來拆分時若實作搬走，這裡要留 compat wrapper | 是；`_ProviderCallResult`、`_generate_provider_result`、`_build_provider_messages`、`_ProviderDispatchError` 被 tests / harness 觸碰 |
| `backend/services/chat/health.py` | `run_provider_health_check` | `backend/tools/ops/chat_provider_healthcheck.py`、`backend/tools/ops/chat_regression_report.py`、`test_chat_service_p4_health.py` | 保留 callable path，視為 official ops 的 service-side support | 否 |
| `backend/services/chat/context_pack/retrieval.py` | `P1Demand`、`CandidatePart`、`P1RetrievalResult`、`retrieve_topk_candidates` | `backend/services/chat/service.py`、`test_chat_p1_contracts.py`、`test_chat_p1_retrieval_ordering.py` | 路徑先保留；未來若改職責式命名，先加 compat alias 再搬 | 是；`_build_category_stmt` 被 `test_chat_p1_retrieval_ordering.py` 直接 import |
| `backend/services/chat/context_pack/compress.py` | `compress_candidates` | `backend/services/chat/service.py`、`test_chat_p2_compress_candidates.py` | 保留；可作為日後 service 下沉點 | 否 |
| `backend/services/chat/context_pack/render.py` | `build_context_pack`、`canonicalize_text_for_hash`、`hash_context_pack` | `backend/services/chat/service.py`、`test_chat_p3_context_pack_render.py` | 保留；可作為日後 service 下沉點 | 否 |
| `backend/services/chat/config.py` | `AISettings`、`get_ai_settings`、`SYSTEM_PROMPT`、`OPENAI_COMPAT_PROVIDERS` | service、ops CLIs、tests | 保留；本輪不改 env-facing names | 否 |
| `backend/services/chat/contracts/__init__.py` | `ChatMessage`、`ChatRequest`、`ChatResponse`、`ContextPack`、`ContextPackItem`、`P3ContextPack` | service、tests、API schema 轉接層 | 保留；本輪不碰 API schema coupling | 否 |
| `backend/services/chat/contracts/types.py` | 同上實際定義 | `backend/services/chat/contracts/__init__.py`、tests | 保留；本輪不改 contract shape | 否 |
| `backend/services/chat/clients/openai_compat_client.py` | `generate_openai_compat_completion`、`generate_openai_compat_text`、`OpenAICompatError`、`OpenAICompatResult` | service、tests | 保留 path；若未來收斂 provider result 型別，先做 compat | 否 |
| `backend/services/chat/demand_inference.py` | `infer_chat_demand` | service、`test_chat_demand_inference.py` | 保留；internal-only callable | 否 |
| `backend/services/chat/prompt.py` | `build_prompt` | service | internal-only module；不要新增新 consumers | 否 |
| `backend/services/chat/gate.py` | `validate_text_response`、`TextValidationReport` | service、gate tests | internal-only module | 否 |
| `backend/services/chat/dq.py` | `evaluate_text_dq`、`DQReport` | service、DQ tests | internal-only module | 否 |
| `backend/services/chat/normalize.py` | `normalize_provider_success`、`NormalizedAIResponse` | service、normalize tests | internal-only module | 否 |
| `backend/services/chat/staging.py` | `ChatStagingRecord`、`persist_chat_staging_record`、`persist_chat_quarantine_entry` | service | internal-only module | 否 |
| `backend/services/chat/retry_policy.py` | `RETRY_BACKOFF_SECONDS`、`should_retry_chat_error` | `openai_compat_client.py`、retry tests | internal-only module | 否 |

### Ops / Harness Modules

| 檔案 | 目前對外可見名稱 | 目前被誰引用 | round 1 建議 | private helper 外溢 |
| --- | --- | --- | --- | --- |
| `backend/tools/ops/chat_provider_healthcheck.py` | CLI `python -m backend.tools.ops.chat_provider_healthcheck`、`main()` | `docs/ops/chat-provider-health.md`、`docs/ops/ai-baseline-freeze.md` | 列為 official ops；保留 CLI 名稱、stdout JSON shape、exit code | 否 |
| `backend/tools/ops/chat_regression_report.py` | CLI `python -m backend.tools.ops.chat_regression_report`、`main()` | `docs/ops/ai-baseline-freeze.md`、`test_chat_service_p10_publish.py` | 列為 official ops；保留 CLI 名稱、stdout JSON shape、exit code | 否 |
| `backend/tools/ops/chat_snapshot_inspect.py` | CLI `python -m backend.tools.ops.chat_snapshot_inspect`、`main()` | `docs/ops/chat-snapshot-audit.md`、`test_chat_service_p5_snapshot.py`、`test_chat_service_p7_gate.py`、`test_chat_service_p8_dq.py` | 列為 official ops；保留 CLI 名稱、payload shape、exit code | 否 |
| `backend/tools/ops/chat_staging_inspect.py` | CLI `python -m backend.tools.ops.chat_staging_inspect`、`main()` | `test_chat_service_p9_staging.py` | 列為 official ops；保留 CLI 名稱、payload shape、exit code | 否 |
| `backend/tools/ops/chat_release_check.py` | CLI `python -m backend.tools.ops.chat_release_check --mode p10`、`run_p10_release_check()`、`main()` | `docs/ops/chat-snapshot-audit.md`、`docs/ops/ai-baseline-freeze.md`、`test_chat_release_check.py` | 列為 test harness / acceptance surface；若日後實作搬動，這裡應留 compat wrapper | 是；直接 patch `chat_service._generate_provider_result` |

### Docs / Test Entry Groups

| 檔案或檔群 | 分類 | 目前用途 | round 1 建議 | private helper 外溢 |
| --- | --- | --- | --- | --- |
| `docs/ops/chat-provider-health.md` | official ops doc | provider smoke/health runbook | 保留，並視為 `chat_provider_healthcheck` 的文件入口 | 否 |
| `docs/ops/chat-snapshot-audit.md` | official ops doc + harness reference | snapshot/staging audit runbook，並引用 `chat_release_check` | 保留，但明確把 `chat_release_check` 視為 harness | 否 |
| `backend/tests/test_chat_service_*.py` | stable verification group | service 主線回歸網 | 暫不大量 rename；後續重組前先保留 file group 可選取性 | 是；多檔直接使用 service `_...` |
| `backend/tests/test_chat_release_check.py` | harness verification | 驗證 acceptance CLI summary/exit code | 保留 file path 與 summary shape | 否 |
| `backend/tests/test_chat_p1_retrieval_ordering.py` | stable verification group | 驗證 retrieval SQL 排序穩定 | 暫保留；未來要用 public wrapper 或黑箱 SQL 測試取代 `_build_category_stmt` 直連 | 是 |
| `backend/tests/test_chat_p2_compress_candidates.py` | stable verification group | 驗證 P2 壓縮輸出 | 暫保留；本輪不改語意 | 否 |
| `backend/tests/test_chat_p3_context_pack_render.py` | stable verification group | 驗證 context pack render/hash | 暫保留；本輪不改語意 | 否 |
| `backend/tests/test_chat_demand_inference.py` | stable verification group | 驗證 demand inference | 暫保留；本輪不改語意 | 否 |
| `backend/tests/test_chat_p0_contracts.py`、`backend/tests/test_chat_a1_provider_config.py` | stable verification group | contracts / provider config | 暫保留；本輪不動 `backend/schemas/chat.py` | 否 |

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

### Internal-Only Module
- `backend/services/chat/service.py` 的所有 `_...`
- `backend/services/chat/context_pack/retrieval.py` 的所有 `_...`
- `backend/services/chat/prompt.py`
- `backend/services/chat/gate.py`
- `backend/services/chat/dq.py`
- `backend/services/chat/normalize.py`
- `backend/services/chat/staging.py`
- `backend/services/chat/retry_policy.py`

## 現有 private helper 外溢點
- `backend/tests/test_chat_p1_retrieval_ordering.py` 直接 import `_build_category_stmt`
- `backend/tests/test_chat_service_p4_health.py` 直接呼叫 `_build_provider_messages`
- `backend/tests/test_chat_service_p5_snapshot.py`
- `backend/tests/test_chat_service_p6_normalize.py`
- `backend/tests/test_chat_service_p7_gate.py`
- `backend/tests/test_chat_service_p8_dq.py`
- `backend/tests/test_chat_service_p9_staging.py`
- `backend/tests/test_chat_service_p10_publish.py`
  - 以上多檔直接依賴 `_ProviderCallResult` 與 `_generate_provider_result`
- `backend/tests/test_chat_service_p9_staging.py` 額外直接依賴 `_ProviderDispatchError`
- `backend/tools/ops/chat_release_check.py` 直接 patch `_generate_provider_result`

## 拆 service.py 前一定要保留的 compat 點
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
- legacy tests / harness 之後若要消除 private helper 依賴，至少要先提供下列 compat seam 其一：
  - service-level provider caller seam，取代 `_generate_provider_result`
  - 測試專用 provider result fixture builder，取代 `_ProviderCallResult`
  - 狹義的 provider message builder seam，取代 `_build_provider_messages` 白箱測試
  - retrieval SQL assertion seam 或改成 black-box query output 驗證，取代 `_build_category_stmt`

## Step 1 完成定義
- 可以進入 Step 2 的條件：
  - 上述 import path / CLI path 已視為 frozen boundary
  - 新增程式碼不得再依賴新的 `_...` 跨模組 import / patch
  - service.py 之後可拆，但先從 compat 點保留開始
