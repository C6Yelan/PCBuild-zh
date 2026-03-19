# 專案架構說明

這份文件用來說明目前 repo 的正式結構、資料流與設計邊界。它比 README 詳細，但仍以「導覽與接手」為主，不逐檔解說歷史細節。

## 專案總覽圖

```text
使用者 / 營運人員
├─ Browser
│  └─ web/ 靜態頁面（chat / login / register / verify）
├─ API / Chat
│  └─ FastAPI
│     ├─ backend/api/               HTTP route / auth / dependencies
│     ├─ backend/core/              settings / middleware / logging / security
│     ├─ backend/services/chat/     demand -> retrieval -> context pack -> provider -> gate/DQ
│     └─ backend/services/auth/     session / email verification / password reset
├─ Data Pipeline
│  └─ backend/services/crawler/ + backend/tools/
│     ├─ fetch raw snapshot
│     ├─ parse / schema gate / DQ / link consistency
│     ├─ staging tables
│     ├─ merge into catalog
│     └─ publication pointer 切換有效版本
└─ Runtime Dependencies
   ├─ PostgreSQL         source of truth / staging / catalog / publication
   ├─ Redis              rate limit storage
   ├─ Typesense          optional retrieval accelerator with PostgreSQL fallback
   ├─ AI provider        env-only 切換，OpenAI-compatible 為主線
   └─ Loki / Grafana     結構化 log 與觀測
```

## 分層說明

### 1. web 靜態前端

- 目錄：`web/`
- 目前是靜態站點，由 FastAPI 直接掛載到 `/`。
- 主要頁面包含 chat、註冊、登入、驗證成功 / 失敗、忘記密碼等流程。
- 前端只負責送出 chat request 與 auth 操作，不負責選擇 AI provider / model。

### 2. FastAPI API layer

- 目錄：`backend/api/`
- 由 `backend/core/app_factory.py` 建立 app，並在 `backend/api/router.py` 掛載 route。
- 現行主要 API surface：
  - `/api/chat`
  - `/api/auth/...`
  - debug route（受 `DEBUG_ROUTES_ENABLED` 控制）
- `/api/chat` 會強制拒絕前端傳入 `provider`、`model`、`base_url`、`api_key` 等覆寫欄位。

### 3. core / settings / middleware / logging

- 目錄：`backend/core/`
- `settings.py`
  - 專案設定單一入口，從 `.env` / 環境變數讀取。
  - 負責 DB、rate limit、CSRF、logging、Typesense 等共用設定。
- `app_factory.py`
  - 啟動時會先呼叫 `get_ai_settings()` 做 AI env fail fast。
- `middleware/`
  - CORS
  - CSRF
  - security headers
  - SlowAPI rate limit
  - debug gate
- `logging.py` / `obs_events.py`
  - 輸出結構化 log。
  - CLI 工具也共用同一套 logging 格式，方便 Loki / Grafana 聚合。

### 4. auth

- 目錄：`backend/api/routes/auth/`、`backend/services/auth/`、`backend/services/email/`
- 目前是 cookie-based session 模式，不是 JWT 前端自持 token。
- 能力包含：
  - 註冊
  - 登入 / 登出 / me
  - Email 驗證
  - 忘記密碼 / 重設密碼
- 郵件透過 Resend 發送；若沒有設定 Resend env，相關流程會失敗。

### 5. catalog

- 目錄：`backend/services/catalog/`、`backend/models/catalog.py`
- PostgreSQL 是 catalog 的 source of truth。
- catalog 資料由 crawler staging merge 進來，並以 `crawler_publication_pointer(env)` 指向目前有效的 published run。
- retrieval 與 catalog query 都以 publication pointer 為讀取口徑，不直接讀任意 staging run。

### 6. crawler pipeline

- 目錄：`backend/services/crawler/`、`backend/tools/crawler/`、`backend/tools/db/`、`backend/tools/ops/crawler/`
- 主要責任：
  - HTTP fetch
  - parser 與 SKU hints
  - schema gate
  - DQ gate
  - link consistency gate
  - staging ingestion
  - merge 到 catalog
  - publish / pointer 切換
- compose 內的 `pcbuild-scheduler` 會持續跑增量更新；`pcbuild-retention` 負責 retention 清理。

### 7. chat / AI pipeline

- 目錄：`backend/services/chat/`
- 現行主線：
  - demand normalization / inference
  - retrieval
  - context pack compression / render / hash
  - provider runtime dispatch
  - response normalize
  - gate / DQ
  - snapshot artifact persistence
  - staging / quarantine
- AI provider 由 `backend/services/chat/config.py` 管理，正式基線以 OpenAI-compatible 為主。
- Typesense 若啟用，會優先用於 retrieval；失敗時會記錄 fallback event 並回退 PostgreSQL。

### 8. tests

- 目錄：`backend/tests/`
- 目前測試重心集中在：
  - chat context pack / provider / service / ops harness
  - crawler link consistency 與 staging / ingest runtime
  - auth / logging / email template 等周邊
- 本地 WSL 建議優先跑純 Python 測試，不在 WSL 跑 Docker 驗收。

### 9. ops CLI

- 目錄：`backend/tools/`
- 現行 stable public CLI surface 可分成四類：
  - crawler parse / stage / ingest
  - crawler ops / publication
  - chat ops / acceptance
  - maintenance
- `backend.tools.ops.chat.*` 與 `backend.tools.ops.crawler.*` 是 canonical implementation tree；根路徑 wrapper 主要用來維持穩定 CLI surface。

### 10. observability

- 目錄：`observability/`
- 目前 repo 已包含：
  - Loki config
  - Alloy config
  - Grafana dashboard / alert 匯出檔
- 觀測是現行架構的一部分，但本階段不是以擴充 dashboard 為主要目標。

## 關鍵資料流

### A. crawler / catalog 資料流

```text
retail source
-> raw snapshot
-> parse
-> schema gate
-> DQ gate / link consistency gate
-> staging tables
-> merge / upsert into catalog
-> publication
-> publication pointer(env -> run_id)
```

重點說明：

1. raw snapshot 先落地，不直接入庫。
2. parse 後的 item 會先寫入 staging 與 gate result。
3. 只有 gate pass 的 item 會 merge 到 catalog。
4. publish 並不是覆蓋整庫，而是建立 `run_id` 的 published version，再更新 pointer。
5. catalog query 與 chat retrieval 都讀 pointer 指向的版本，保留回滾能力。

### B. user chat / AI 資料流

```text
user chat
-> demand resolution / normalization
-> retrieval
-> compress / render context pack
-> provider call
-> normalize response
-> gate / DQ
-> snapshot artifact
-> staging or quarantine
-> publish public response
```

重點說明：

1. chat 不直接讓前端選模型，也不接受 provider override。
2. retrieval 只取 Top-K 候選，並做白名單壓縮後再渲染成固定文字格式。
3. `context_pack_hash` 來自 canonical text，方便跨 provider / model 比對。
4. provider 成功不等於答案可直接公開，仍要經過 gate / DQ。
5. 最後會留下 request-level artifact，供後續 inspect、regression 與回放。

## 重要目錄導覽

- `web/`
  前端靜態頁面與資產。
- `backend/api/`
  對外 API 與依賴注入。
- `backend/core/`
  app 建立、middleware、logging、settings、security。
- `backend/models/`
  ORM model，涵蓋 auth、catalog、crawler staging / publication。
- `backend/schemas/`
  API schema 與 chat contract。
- `backend/services/auth/`
  session、驗證信與密碼重設工作流。
- `backend/services/catalog/`
  catalog 查詢與 merge upsert 依賴。
- `backend/services/chat/`
  AI / chat 正式主線。
- `backend/services/crawler/`
  crawler 抓取、解析、gate 與 staging。
- `backend/tools/crawler/`
  raw snapshot 抓取與 snapshot parse CLI。
- `backend/tools/db/`
  stage from snapshot、merge from staging 與 staging ingest 相關 CLI。
- `backend/tools/ops/`
  chat / crawler / maintenance 的正式 ops CLI wrapper。
- `backend/tests/`
  目前可在 WSL 跑的純 Python 測試入口。
- `observability/`
  Loki / Alloy / Grafana 配置與匯出檔。
- `docs/`
  README 補充文件、ops SOP、smoke / setup / 架構說明。

## 關鍵 artifact / trace 欄位

- `request_id`
  chat 單次請求識別碼，也是 snapshot 查詢的第一入口。
- `provider`
  本次實際使用的 AI provider。
- `model`
  本次實際使用的模型名稱。
- `context_pack_hash`
  context pack canonical text 的 SHA-256，用來比對 retrieval / render 是否漂移。
- `snapshot_id`
  單筆 snapshot 的識別值；目前檔案型 artifact 會映射到 request-level 目錄。
- `run_id`
  crawler ingest / publication 的版本識別碼。
- `raw_request` / `raw_response`
  provider exchange 摘要，已做 redact。
- `staging`
  gate / DQ 通過後留下的 staging 記錄。
- `publish`
  crawler 端由 publication pointer 指向當前版本；chat 端則指公開文字回覆是否可發布。

## 目前架構的設計邊界

- 前端不可選模型，也不可覆寫 provider / base_url / api_key。
- AI provider / model 一律由 `.env` 控制。
- OpenAI-compatible transport 是目前正式整合主線。
- Docker 部署與完整驗收只在伺服器主機執行；本機 WSL 不跑 Docker。
- PostgreSQL 是 catalog source of truth；Typesense 只是可選檢索加速層。
- 本階段不再以擴新 provider 為主要工作，也不做大規模重構。
- `t9_*` / `t10_*` 舊代號仍存在於部分 event key、artifact path 與 compat wrapper，但不代表新的 canonical 命名。

## 已知限制

- build 配單品質與推薦合理性仍在改善中，不能寫成「已完美完成」。
- 某些功能雖可用，但仍屬 MVP 或實驗性整合，例如 Typesense 最小整合與部分 acceptance harness。
- Gemini 路徑雖仍在程式中，但不是目前正式驗收與文件主線。
- snapshot / staging / quarantine 目前以檔案 artifact 為主，不是全部資料都進資料庫。
- 觀測堆疊已存在，但本階段重點是穩定主線與文件，而不是重做 dashboard。

## 接手建議

1. 先讀 README，掌握專案定位、環境分工與限制。
2. 再讀 `docs/setup/full-environment-setup.md`，確認 WSL 與 server 的操作邊界。
3. 需要追 chat 問題時，優先看 `request_id`、`context_pack_hash`、snapshot artifact。
4. 需要追 crawler 問題時，優先看 publication pointer、`run_id`、staging gate 結果與 crawler health。
