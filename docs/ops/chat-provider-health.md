# Chat Provider Health Check

## 目的
- 這是 P4 的 AI provider smoke/health check，用來確認目前後端環境變數指定的 provider/model 是否可正常走完既有 chat service 主流程。
- 這不是 crawler smoke；crawler 相關檢查仍看 `docs/SMOKE_TEST.md` 與 `docs/ops/crawler-health.md`。
- Chat round 1 的邊界凍結與 CLI 分類見 `docs/ops/chat-round1-boundary.md`。

## 前置條件
- `.env` 內的 `AI_PROVIDER`、`AI_MODEL`、`AI_TIMEOUT_SECONDS`、`AI_MAX_OUTPUT_CHARS` 已正確設定。
- 若目前 provider 為 OpenAI-compatible，`AI_OAI_BASE_URL` 與 `AI_OAI_API_KEY` 也必須對應目前上游。
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
- 若目前 `AI_PROVIDER=gemini`，在尚未做正式 adapter 前，health check 會忠實回報 `provider_not_ready`；這是預期行為，不會偷偷改走 OpenAI-compatible client。

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
   - 確認是 provider 連線、429、timeout、或 `provider_not_ready`
   - 回退 `.env`
   - 重新啟動 `fastapi`
   - 再重跑一次 health check
