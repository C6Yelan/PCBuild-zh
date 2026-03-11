# Chat Snapshot Audit

> 角色：正式操作文件。這份文件負責 snapshot / staging / quarantine artifact 稽核與 inspect 流程。

## 目的
- 這是 P5 的原始 AI 呼叫保存與稽核說明，用來追 request_id 對應的 snapshot artifact。
- 這不是 provider health check；provider smoke/health 仍看 `docs/ops/chat-provider-health.md`。
- chat 文件入口與角色分工見 `docs/ops/chat-ops-index.md`。

## Snapshot 目錄結構範例

```text
<AI_RAW_SNAPSHOT_DIR>/<request_id>/
  raw_request.json
  raw_response.json
  meta.json
  request_context.json
  validation_report.json
  dq_report.json
  staging_record.json
  quarantine_entry.json
  context_pack.txt
  compressed_candidates.json
  drop_log.json
  lineage.json

<AI_RAW_SNAPSHOT_DIR>/_staging/
  <request_id>.staging.json

<AI_RAW_SNAPSHOT_DIR>/_quarantine/
  <request_id>.quarantine.json
  quarantine_index.jsonl
```

## 檔案用途

### raw_request.json
- 保存當次送往 provider 的請求摘要。
- 包含 provider / model / endpoint / messages / request_headers / request_json。
- 已做 redact，不應出現 Authorization 原值或 API key。

### raw_response.json
- 保存當次 provider 回應摘要。
- 包含 status_code / response_headers / response_json / raw_response_text / upstream_request_id。

### meta.json
- 保存最上層 trace 摘要。
- 包含 request_id / provider / model / context_pack_hash / latency_ms / ok / error_type / snapshot_id。
- 也會包含 gate 結果：
  - `gate_status`（`pass` / `fail`）
  - `gate_reasons`
- 也會包含 DQ 結果：
  - `dq_status`（`pass` / `fail` / `skipped`）
  - `dq_reasons`
- 也會包含 P9 暫存/隔離結果：
  - `staging_status`（`staged` / `skipped`）
  - `quarantine_status`（`not_quarantined` / `quarantined` / `not_applicable`）
- 也會列出本次實際寫出的 artifact 檔名。

### request_context.json
- 保存這次進入 chat service 時的請求上下文摘要。
- 包含：
  - request_mode（messages 或 user_text）
  - demand_source（explicit / inferred / none）
  - triggered_retrieval
  - categories / top_k / env
  - warnings
  - has_context_pack
  - message_chars / history_turns
- `warnings` 也可能包含 normalize / truncation / gate warning，例如 `usage_unavailable`、`output_truncated`、`control_chars_removed`。

### validation_report.json
- 保存 P7 文字版輕量 Gate 結果。
- 包含：
  - `passed`
  - `reasons`
  - `warnings`
  - `removed_chars_count`
  - `max_chars`
  - `original_length`
  - `sanitized_length`
- 若本次為較舊 snapshot 或未經 gate 路徑，則可能不存在。

### dq_report.json
- 保存 P8 文字版 DQ Gate 結果。
- 包含：
  - `passed`
  - `reasons`
  - `warnings`
  - `metrics`
  - `quarantine`
- 若本次 gate 已失敗、或為較舊 snapshot，則可能不存在。

### staging_record.json
- 保存 P9 staged 成功的摘要記錄。
- 只有 gate 與 DQ 都通過時才會寫出。
- 也會同步複製到 `<AI_RAW_SNAPSHOT_DIR>/_staging/<request_id>.staging.json`。
- 會包含：
  - `data_versions`：直接 materialize 的候選資料版本（`snapshot_id/run_id`）
  - `published`
  - `publish_reason`（目前 staged 成功時為 `staged_pass`）

### quarantine_entry.json
- 保存 P9 quarantined 的摘要記錄。
- 若 gate fail 或 DQ fail，則不寫 staging，而改寫 quarantine。
- 也會同步複製到 `<AI_RAW_SNAPSHOT_DIR>/_quarantine/<request_id>.quarantine.json`。
- 會包含：
  - `publish_blocked`
  - `publish_reason`（例如 `validation_failed` / `dq_failed`）

### _quarantine/quarantine_index.jsonl
- append-only 的 quarantine 索引。
- 方便快速查看最近被 quarantine 的 request，而不必逐筆進 snapshot 目錄。
- 每行至少包含：
  - `request_id`
  - `snapshot_id`
  - `provider`
  - `model`
  - `error_type`
  - `gate_status`
  - `dq_status`
  - `reasons`
  - `created_at`

### context_pack.txt
- 保存當次實際注入模型的 context pack 純文字。
- 若本次沒有 retrieval / context pack，則可能不存在。

### compressed_candidates.json
- 保存 P2 壓縮後候選資料。
- 供稽核與回放使用，不提供前端直接使用。

### drop_log.json
- 保存 P2 壓縮階段被丟棄欄位與裁切摘要。

### lineage.json
- 由 `compressed_candidates.json` 推導出的 lineage 摘要。
- 用來快速查看每個 category 下實際餵給 AI 的零件來源與 `snapshot_id/run_id`。

## 容器內 inspect 指令

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_snapshot_inspect --request-id <REQUEST_ID>
```

## P10 營運驗收工具
- `chat_release_check.py` 用於 P10 release / acceptance check。
- 它會以可重跑、deterministic 的方式驗證：
  - staged success
  - validation_failed
  - dq_failed
  - provider error
  - retry/backoff
- 這是營運驗收工具，不是正式服務路徑。
- 若要保存 release 驗收與 regression 結果，正式治理入口請看 `docs/ops/ai-baseline-freeze.md`。

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10
```

## 如何從 request_id 追到 snapshot
1. 從 `ai_call` log 或 API response 取得 `request_id`
2. 用 inspect 指令找到對應 snapshot 目錄
3. 先看 `meta.json` 與 `request_context.json`
4. 若 `context_pack_hash` 不是 `-`，再看：
   - `context_pack.txt`
   - `compressed_candidates.json`
   - `lineage.json`
5. 若要查 provider 原始回應，再看：
   - `raw_request.json`
   - `raw_response.json`
6. 若要確認是否已 staged / quarantined，再看：
   - `meta.json`
   - `staging_record.json`
   - `quarantine_entry.json`
   - `_quarantine/quarantine_index.jsonl`

## 重要說明
- 這些檔案僅供後端稽核、除錯、交叉測試與回放，不提供前端直接使用。
- snapshot 仍是檔案型 artifact，不會寫入資料庫。
