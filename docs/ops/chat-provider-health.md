# Chat Provider Health Check

> 角色：正式操作文件。這份文件負責 provider smoke / health check 的日常操作與判讀。

## 目的
- 這是 AI provider smoke/health check，用來確認目前後端環境變數指定的 provider/model 是否可正常走完既有 chat service 主流程。
- 目前收尾版本的正式 AI 主線是 `openai_compat` + env-only 切換；本文件以這條主線為準。
- 這不是 crawler smoke；crawler 相關檢查仍看 `docs/SMOKE_TEST.md` 與 `docs/ops/crawler-health.md`。
- chat 文件入口與角色分工見 `docs/ops/chat-ops-index.md`。

## 路徑 / 定位
- canonical implementation 在 `backend.tools.ops.chat.chat_provider_healthcheck` 與 `backend.services.chat.health`。
- stable public CLI wrapper 仍是 `python -m backend.tools.ops.chat_provider_healthcheck`。
- `/api/chat` 對外 contract 未變；這份文件只描述 provider health flow 的維運檢查。

## 前置條件
- `.env` 內的 `AI_PROVIDER`、`AI_MODEL`、`AI_TIMEOUT_SECONDS`、`AI_MAX_OUTPUT_CHARS` 已正確設定。
- 收尾版本預期 `AI_PROVIDER=openai_compat`。
- `AI_OAI_BASE_URL` 與 `AI_OAI_API_KEY` 必須對應目前上游。
- `fastapi` 容器已使用最新 `.env` 啟動完成。

## 容器內執行命令

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
```

## 如何判讀
- `pass=true`：
  - 代表固定 5 題 smoke cases 都取得非空文字，且 `error_type` 全部為 `null`。
- `pass=false`：
  - 代表至少一題失敗。
  - 先看 `failed_cases`、`error_type_counts`、各 case 的 `request_id`。
  - 再用 `request_id` 去查既有 `ai_call` log 與 raw snapshot。
- 若目前 `.env` 不是 `openai_compat`，這代表執行環境偏離目前收尾主線；先回到既定 `.env` 再做基線驗收。

## Loki / Log Lookup 注意事項
- 建議用 `provider`、`model`、`env`、`component` 這類低基數欄位做 label / filter。
- `request_id`、`snapshot_id`、`context_pack_hash` 只用來做 structured metadata 或 log body 查詢，不應作為 label。

## Report 寫入位置
- 報告會寫到：

```text
<AI_RAW_SNAPSHOT_DIR>/provider_health_reports/<UTC timestamp>__<provider>__<model>.json
```

- 例如當 `AI_RAW_SNAPSHOT_DIR=/app/data/ai_raw_snapshots` 時，報告會落在：

```text
/app/data/ai_raw_snapshots/provider_health_reports/
```

## 切換 `.env` 後的 SOP
1. 修改 `.env`
   只切 `AI_PROVIDER`、`AI_MODEL`、`AI_TIMEOUT_SECONDS`、`AI_MAX_OUTPUT_CHARS`、`AI_OAI_BASE_URL`、`AI_OAI_API_KEY`
2. 重新啟動 `fastapi`

```bash
docker compose up -d --build fastapi
```

3. 執行 provider health check

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
```

4. 觀察 `pass`、`failed_cases`、`error_type_counts`
5. 若失敗：
   - 先查 report 檔與 `request_id`
   - 確認是 provider 連線、429、timeout、network error，或 `.env` 偏離主線
   - 回退 `.env`
   - 重新啟動 `fastapi`
   - 再重跑一次 health check

## 本階段明確不做
- 不新增 provider
- 不把 Gemini、本地模型、多平台比較拉回主線
- 不處理前端模型選擇
- 不處理 Grafana / Loki / dashboard

## 相關文件
- 若要追單筆 request 的 snapshot artifact：看 `docs/ops/chat-snapshot-audit.md`
- 若要做基線凍結 / regression / release acceptance：看 `docs/ops/ai-baseline-freeze.md`
