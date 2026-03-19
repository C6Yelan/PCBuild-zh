# PCBuild-zh

目前收尾範圍只保留三件事：推薦品質、既有外部免費開源 AI 主線、最小必要操作文件。

目前正式 AI 主線：
- 後端 `.env` 決定 `AI_PROVIDER` / `AI_MODEL` / `AI_OAI_BASE_URL`
- 正式支援與驗收基線以 `openai_compat` 為主
- 前端不負責選模型，也不接受 provider / base_url 覆寫

最小必要文件入口：
- [Chat Ops Index](/home/ayaya/projects/PCBuild-zh/docs/ops/chat-ops-index.md)
- [Chat Provider Health Check](/home/ayaya/projects/PCBuild-zh/docs/ops/chat-provider-health.md)
- [AI Baseline Freeze Template](/home/ayaya/projects/PCBuild-zh/docs/ops/ai-baseline-freeze.md)

## Typesense 最小整合

- 商品搜尋層新增 Typesense；PostgreSQL 仍是 source of truth，chat/context pack 下游資料契約不變。
- Typesense 是部署端服務，由 `TYPESENSE_ENABLED` 控制是否啟用；本機 Windows + WSL 開發端不負責啟動 Docker 容器。
- `TYPESENSE_ENABLED=false` 時，retrieval 會直接走既有 PostgreSQL 路徑。
- `TYPESENSE_ENABLED=true` 但 Typesense 未就緒或缺設定時，後端會記錄明確 fallback event，並退回 PostgreSQL retrieval。

必要 env：
- `TYPESENSE_ENABLED`
- `TYPESENSE_HOST`
- `TYPESENSE_PORT`
- `TYPESENSE_PROTOCOL`
- `TYPESENSE_API_KEY`
- `TYPESENSE_COLLECTION_PARTS`
- `TYPESENSE_TIMEOUT_SECONDS`

本機（Windows + WSL）：
- 只做程式碼修改、本機純 Python / 靜態檢查 / 單元測試、`git add` / `git commit` / `git push`。
- 不在本機 WSL 執行 `docker compose up`、`docker compose exec`、Typesense sync、provider health、regression、release check。

伺服器主機：
- 才執行部署與驗收。
- `fastapi` 透過 `depends_on` 帶起 `typesense`；Typesense 資料持久化在 `./data/typesense`。

伺服器主機啟動：

```bash
docker compose up -d --build fastapi
```

伺服器主機建 collection / 全量同步：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.typesense_parts_sync ensure-collection
docker compose exec -T fastapi python -m backend.tools.ops.typesense_parts_sync sync --env prod
```

伺服器主機全量重建索引：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.typesense_parts_sync rebuild --env prod
```

回退 / fallback SOP：
- 若 Typesense service 未啟動、collection 不存在、sync 失敗或查詢失敗，retrieval 會記錄明確 fallback event，並回退到 PostgreSQL retrieval。
- 若伺服器驗收不過，最快停用方式是把 `TYPESENSE_ENABLED=false`，再於伺服器主機重新部署 `fastapi`。
- 若需要整版回退，可在伺服器主機 `git pull` 回上一個已驗證版本後，再重啟 `fastapi`。

伺服器主機快速停用 Typesense：

```bash
TYPESENSE_ENABLED=false
docker compose up -d --build fastapi
```

伺服器主機最終驗收順序：
- 本機先完成 `git add`、`git commit`、`git push`
- 伺服器主機再依序執行 `git pull`
- 伺服器主機執行 `docker compose up -d --build fastapi`
- 伺服器主機執行 `docker compose exec -T fastapi python -m backend.tools.ops.typesense_parts_sync ensure-collection`
- 伺服器主機執行 `docker compose exec -T fastapi python -m backend.tools.ops.typesense_parts_sync sync --env prod`
- 伺服器主機執行 `docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck`
- 伺服器主機執行 `docker compose exec -T fastapi python -m backend.tools.ops.chat_regression_report`
- 伺服器主機執行 `docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10`
- 伺服器主機人工 smoke 至少驗 3 題：
- `幫我找 2 萬左右的 RTX 5070 顯卡`
- `最近有推薦的 Ryzen 9700X CPU 嗎？`
- `幫我配一台 4 萬內遊戲機，想要 AMD CPU + NVIDIA 顯卡`
