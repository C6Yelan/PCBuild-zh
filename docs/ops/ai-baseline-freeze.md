# AI 基線凍結紀錄模板

## 1. 目的
- 用於在第 0 階段凍結目前 AI 行為基線，建立後續比對與回退依據。
- 本文件只記錄營運驗收與環境指紋，不修改 backend 主邏輯，不涉及 API 契約變更。
- 填寫時禁止寫入 API key、Authorization header、完整 `AI_OAI_BASE_URL` 明文。

## 2. 基線日期
- 日期：`<YYYY-MM-DD>`
- 時區：`<UTC 或 UTC+08:00>`
- 凍結執行人：`<name>`

## 3. git commit SHA
- `git rev-parse HEAD`：`<40-char sha>`
- 如需對照部署版本，可補充 `APP_GIT_SHA`：`<sha or tag>`

## 4. AI 設定指紋
只記錄可公開比對的指紋，不記錄 secrets 與完整 upstream URL。

| 欄位 | 值 |
| --- | --- |
| `AI_PROVIDER` | `<value>` |
| `AI_MODEL` | `<value>` |
| `AI_TIMEOUT_SECONDS` | `<value>` |
| `AI_MAX_OUTPUT_CHARS` | `<value>` |
| `AI_OAI_BASE_URL_SHA12` | `<12-char sha256 prefix 或 ->` |

備註：
- `AI_OAI_BASE_URL_SHA12` 來源為 `sha256(AI_OAI_BASE_URL)` 前 12 碼。
- 若目前 provider 不使用 OpenAI-compatible base URL，可填 `-`。

## 5. 基線驗收結果
| 檢查項目 | 結果 | 補充 |
| --- | --- | --- |
| provider health check | `<pass/fail>` | `report_path=<path>` |
| regression report path | `<path>` | 建議直接貼 tool 輸出的 `report_path` |
| release check result | `<pass/fail>` | `mode=p10`, `snapshot_root=<path>` |

建議同步保存：
- 基線檢查輸出目錄：`/tmp/ai-baseline-freeze-<UTC timestamp>/`
- `provider_healthcheck.stdout.json`
- `chat_regression_report.stdout.json`
- `chat_release_check_p10.stdout.json`
- `baseline_summary.txt`

## 6. 真實 request 樣本
在完成固定驗收指令後，請手動打一筆真實 chat request，再補以下欄位：

| 欄位 | 值 |
| --- | --- |
| `request_id` | `<request_id>` |
| `snapshot_dir` | `<AI_RAW_SNAPSHOT_DIR>/<request_id>` |
| `staging_status` | `<staged/skipped>` |
| `quarantine_status` | `<not_quarantined/quarantined/not_applicable>` |
| `context_pack_hash` | `<hash or ->` |

補充紀錄建議：
- request 摘要：`<一句話描述，不貼完整敏感內容>`
- 實際觀察：`<是否符合目前線上預期>`

## 7. 固定驗收指令
先在 repo root 執行基線檢查腳本：

```bash
scripts/ops/freeze_ai_baseline.sh
```

若需要逐項重跑，固定指令如下：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
docker compose exec -T fastapi python -m backend.tools.ops.chat_regression_report
docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10
```

手動打一筆真實 request 後，可再用下列指令追蹤 snapshot：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_snapshot_inspect --request-id <REQUEST_ID>
```

## 8. 回退 SOP
1. 先找出上一份已確認可接受的基線紀錄，確認其 `git commit SHA` 與 AI 設定指紋。
2. 將部署環境回退到前一版 commit，並把 `.env` 內 `AI_PROVIDER`、`AI_MODEL`、`AI_TIMEOUT_SECONDS`、`AI_MAX_OUTPUT_CHARS`、`AI_OAI_BASE_URL` 恢復到上一份基線值。
3. 重新啟動 `fastapi` 服務，確認容器內環境與回退目標一致。
4. 重新執行第 0 階段固定驗收指令，確認：
   - provider health check 回到預期結果
   - regression report 與前一份基線一致或差異可解釋
   - `chat_release_check --mode p10` 回到 `pass`
5. 再手動打一筆真實 chat request，確認新的 `request_id`、`snapshot_dir`、`staging_status`、`quarantine_status` 與 `context_pack_hash` 皆符合回退後預期。
