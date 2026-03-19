# 從零開始架設整體環境

這份文件只描述目前 repo 真正可用的作業方式，並明確區分兩種環境：

- Windows + WSL：只做開發、閱讀、純 Python 驗證
- 伺服器主機：才做 Docker / Compose 啟動、ops CLI、完整驗收

不要把伺服器操作搬到 WSL，也不要把 WSL 當成 Docker deployment 環境。

## A. 本機 Windows + WSL（非 Docker）

### 1. 你需要先安裝什麼

- Git
- WSL2
- Python 3.12
- Python `venv`
- VS Code 與 WSL extension（建議，但非必需）

Ubuntu / Debian 類 WSL 可參考：

```bash
sudo apt update
sudo apt install -y git python3.12 python3.12-venv
```

### 2. clone repo

```bash
git clone https://github.com/C6Yelan/PCBuild-zh.git PCBuild-zh
cd PCBuild-zh
```

### 3. 建立與啟用 venv

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### 4. 安裝 backend 依賴

```bash
pip install -r backend/requirements.txt
```

目前 repo 沒有額外 frontend build step；`web/` 是靜態檔案，不需要另外安裝 Node 套件才能閱讀與修改。

### 5. 準備 `.env`

如果你要在本機做設定檔閱讀、局部工具測試，先複製範例檔：

```bash
cp .env.example .env
```

說明：

- 若你只是改文件、跑 `compileall`、跑多數純 Python 測試，`.env` 可先保留 placeholder。
- 若你打算在本機直接啟動 app 或跑依賴 `DATABASE_URL` / AI 設定的程式，再補齊對應欄位。
- 本機 WSL 不負責 Docker deployment，因此不要在 WSL 內把 `.env` 當成 server compose 的正式部署設定。

### 6. 本機可做的事情

- 修改程式與文件
- 閱讀架構與 ops 文件
- 跑純 Python 驗證
- 做 git 操作

建議最小驗證：

```bash
PYTHONPATH=. .venv/bin/pytest -q backend/tests/chat
PYTHONPATH=. .venv/bin/python -m compileall backend/services/chat backend/tests/chat backend/schemas
```

需要多補一層 crawler 純 Python 測試時，可跑：

```bash
PYTHONPATH=. .venv/bin/pytest -q backend/tests/crawler/link_consistency_gate
```

### 7. 本機 WSL 明確不負責的事情

以下不要在 WSL 執行：

- `docker compose up`
- `docker compose exec`
- 啟動 PostgreSQL / Redis / Typesense / FastAPI 容器
- provider healthcheck
- regression report
- release check
- Typesense collection / sync
- server 端 publish / scheduler / retention

這些都只在伺服器主機執行。

## B. 伺服器主機（Docker / Compose）

### 1. 前置條件

- 已安裝 Docker 與 Docker Compose
- repo 已 clone 到伺服器
- `.env` 已配置完成
- 準備好 `APP_GIT_SHA`
- 不在主機上額外安裝 Python 來跑專案 CLI

說明：

- `docker-compose.yml` 會要求 `APP_GIT_SHA` 存在，否則 `fastapi` 與 `pcbuild-scheduler` build 會失敗。
- 專案已提供 `scripts/compose_with_git_sha.sh` 可自動注入目前 git sha。

### 2. 準備 `.env`

先從範例檔建立：

```bash
cp .env.example .env
```

重要：

- 伺服器 Docker 並不是把整份 host `.env` 自動掛進容器。
- 目前只有 `docker-compose.yml` 明確引用或映射的欄位，才會在 compose / 容器內真正生效。
- 其餘欄位主要用於本機非 Docker Python 執行，或未來若你自行擴充 compose 時才會用到。

至少要確認這幾類欄位已填好：

- Database：`POSTGRES_PASSWORD`
- Redis：`REDIS_PASSWORD`
- AI：`AI_PROVIDER`、`AI_MODEL`、`AI_TIMEOUT_SECONDS`、`AI_MAX_OUTPUT_CHARS`
- OpenAI-compatible 主線：`AI_OAI_BASE_URL`、`AI_OAI_API_KEY`
- Typesense：若要啟用 `TYPESENSE_ENABLED=true`，需補 `TYPESENSE_API_KEY`
- Auth / Email：若要使用註冊、驗證信、忘記密碼流程，需補 `RESEND_*`
- Observability：若要啟用 Grafana SMTP / 管理者密碼，需補 `GRAFANA_*` 與 `RESEND_SMTP_API_KEY`

### 3. 真正的啟動順序

先更新程式碼：

```bash
git pull
```

再準備 `APP_GIT_SHA`：

```bash
export APP_GIT_SHA="$(git rev-parse --short=12 HEAD)"
```

接著啟動最小服務：

```bash
docker compose up -d --build fastapi
```

這個命令會連帶處理 `fastapi` 的依賴：

- `pcbuild-db`
- `pcbuild-redis`
- `typesense`
- `migrate`

補充：

- 若你偏好一次把 git sha 注入 compose，可改用：

```bash
./scripts/compose_with_git_sha.sh up -d --build fastapi
```

- 若這台主機同時負責背景抓取與資料清理，再另外啟動：

```bash
docker compose up -d pcbuild-scheduler pcbuild-retention
```

- `cloudflared`、`loki`、`grafana`、`alloy` 為部署選配服務，不是最小啟動必要條件。

### 4. migration / tools / ops 如何執行

原則只有一個：

- 一律透過 `docker compose exec -T fastapi ...`

不要在主機上自己裝 Python 後直接跑 `python -m ...`。

範例：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
docker compose exec -T fastapi python -m backend.tools.ops.chat_regression_report
docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10
docker compose exec -T fastapi python -m backend.tools.ops.run_incremental --source coolpc --parts all --publish --max-items 2000 --t5-limit 50
docker compose exec -T fastapi python -m backend.tools.ops.list_publications --limit 10 --env prod
```

### 5. 最小驗收方式

chat 主線最小驗收：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
docker compose exec -T fastapi python -m backend.tools.ops.chat_regression_report
docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10
```

若要追 request artifact：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_snapshot_inspect --request-id <REQUEST_ID>
docker compose exec -T fastapi python -m backend.tools.ops.chat_staging_inspect --request-id <REQUEST_ID>
```

crawler / catalog 驗收入口：

- `docs/SMOKE_TEST.md`
- `docs/ops/crawler-health.md`

常用命令：

```bash
scripts/ops/check_crawler_health.sh
docker compose exec -T fastapi python -m backend.tools.ops.run_incremental --source coolpc --parts cpu --no-publish --max-items 2000 --t5-limit 50
docker compose exec -T fastapi python -m backend.tools.ops.list_publications --limit 10 --env prod
```

### 6. AI / crawler / Typesense 額外初始化步驟

#### 6.1 AI / chat

- 正式基線建議先用 `AI_PROVIDER=openai_compat`
- 切換 provider / model 後，至少重跑：
  - provider healthcheck
  - regression report
  - release check

#### 6.2 crawler / catalog

如果是全新資料庫、還沒有 publication pointer，至少先跑一次可 publish 的增量流程：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.run_incremental --source coolpc --parts all --publish --max-items 2000 --t5-limit 50
```

之後可確認 publication：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.list_publications --limit 10 --env prod
```

#### 6.3 Typesense

Typesense 是選配但目前 repo 內有實際整合。

若你不打算使用 Typesense：

```bash
TYPESENSE_ENABLED=false
```

若要啟用 Typesense：

1. 先確保已有 `prod` publication pointer
2. 再建立 collection 與同步資料

```bash
docker compose exec -T fastapi python -m backend.tools.ops.typesense_parts_sync ensure-collection
docker compose exec -T fastapi python -m backend.tools.ops.typesense_parts_sync sync --env prod
```

需要全量重建索引時：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.typesense_parts_sync rebuild --env prod
```

#### 6.4 scheduler / retention

這兩個是 server 常駐服務：

- `pcbuild-scheduler`
  週期性跑增量抓取與 publish
- `pcbuild-retention`
  週期性做 retention 清理

若這台主機只負責手動驗收，可先不啟動；若是正式運行主機，建議一起啟動。

## C. 常見問題排除

### 1. `.env` 缺欄位

現象：

- app 啟動失敗
- compose interpolation 失敗
- AI 設定 fail fast

處理方式：

1. 先對照 `.env.example`
2. 確認 `POSTGRES_PASSWORD`、`REDIS_PASSWORD`、`AI_PROVIDER`、`AI_MODEL`、`AI_TIMEOUT_SECONDS`、`AI_MAX_OUTPUT_CHARS` 已填
3. 若走 OpenAI-compatible 主線，再確認 `AI_OAI_BASE_URL`、`AI_OAI_API_KEY`
4. 若啟用 Typesense，再確認 `TYPESENSE_API_KEY`
5. 若用 auth 郵件功能，再確認 `RESEND_*`

### 2. compose interpolation / env 問題

最常見的是 `APP_GIT_SHA` 沒有提供。

先做：

```bash
export APP_GIT_SHA="$(git rev-parse --short=12 HEAD)"
```

再重跑：

```bash
docker compose up -d --build fastapi
```

若不想手動 export，就用：

```bash
./scripts/compose_with_git_sha.sh up -d --build fastapi
```

也要確認：

- `.env` 位於 repo root
- 不是在錯誤目錄執行 compose
- `.env` 中沒有把必填欄位留成空字串

### 3. provider healthcheck fail

處理順序：

1. 先看 `docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck`
2. 找輸出的 `report_path`
3. 看失敗 case 的 `request_id`
4. 用 `chat_snapshot_inspect` 追 artifact

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_snapshot_inspect --request-id <REQUEST_ID>
```

優先檢查：

- `AI_PROVIDER` 是否偏離目前正式基線
- `AI_OAI_BASE_URL` / `AI_OAI_API_KEY` 是否正確
- timeout / 429 / network error
- provider upstream 是否回空字串或非預期格式

### 4. regression / release check fail

先不要急著重新部署更多東西，先看輸出摘要與 snapshot。

建議順序：

1. 看 `chat_regression_report` 的 `report_path`
2. 看 `chat_release_check --mode p10` 的 `snapshot_root`
3. 比對最近 baseline freeze
4. 用 `request_id` / `context_pack_hash` 查是否是 retrieval、gate、DQ 或 provider 行為漂移

相關文件：

- `docs/ops/ai-baseline-freeze.md`
- `docs/ops/chat-snapshot-audit.md`

### 5. 伺服器主機沒有 pytest

這是正常情況。

- `pytest` 與本機純 Python 驗證在 Windows + WSL 做
- 伺服器主機只做 Docker 驗收與 ops CLI
- 若真的要在容器內補跑測試，請明確知道這是額外操作，不是目前正式 server SOP

### 6. 何時該看 `request_id` / snapshot artifact

以下情況優先查 artifact，而不是只看前端輸出：

- provider healthcheck 失敗
- release check fail
- regression 漂移
- 使用者回報某題回答明顯不合理
- 想知道這次推薦用的是哪一批候選與哪個 publication run
- 想確認答案是 staged、quarantined，還是因 gate / DQ 被阻擋

常用命令：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_snapshot_inspect --request-id <REQUEST_ID>
docker compose exec -T fastapi python -m backend.tools.ops.chat_staging_inspect --request-id <REQUEST_ID>
```

## 相關文件

- `README.md`
- `docs/project-architecture.md`
- `docs/ops/chat-ops-index.md`
- `docs/ops/chat-provider-health.md`
- `docs/ops/chat-snapshot-audit.md`
- `docs/ops/ai-baseline-freeze.md`
- `docs/ops/crawler-health.md`
- `docs/SMOKE_TEST.md`
