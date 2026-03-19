# PCBuild-zh
![PCBuild-zh preview](docs/images/readme-preview.png)
台灣零售導向的中文 AI 電腦配單平台，核心以 RAG 與相容性規則引擎產生可溯源的配單建議。

目前版本定位為維護期基線（`v1.0.0`）：
- 聚焦推薦品質、既有外部免費開源 AI 主線、最小必要操作文件
- 正式 AI 主線以 openai-compatible provider 為基準

正式站點：`https://pcbuild.redfiretw.xyz/`
最新版本：`v1.0.0`

## 專案簡介

PCBuild-zh 目標是把台灣零售端的零件資料、相容性規則、可追溯的資料管線，以及 AI 對話式推薦整合成一條可維護的後端主線。它不是單純聊天介面，也不是只做關鍵字搜尋，而是希望讓「需求理解 -> 候選檢索 -> 相容性與品質把關 -> 中文回答」變成可驗收、可回放、可逐步改善的流程。

這個專案要解決的核心問題是：

- 台灣零售零件資訊分散、命名雜訊高、價格與規格需要持續更新。
- AI 配單若沒有資料治理與相容性約束，容易產生不合理或不可追溯的答案。
- 推薦品質需要能透過 snapshot、staging、publish、request trace 來回頭檢查，而不是只看前端最後一句回答。

目前主張的核心價值是：

- 台灣零售資料為基礎，而不是抽象化的國外料單。
- AI provider / model 只由後端 `.env` 控制，前端不可選模型。
- chat 主線不是直接把資料庫丟給模型，而是經過 demand normalization、retrieval、context pack、gate / DQ、staging / publish。
- crawler / catalog / chat 都保留 traceability，重點欄位包含 `request_id`、`provider`、`model`、`context_pack_hash`、`snapshot_id`、`run_id`。

## 快速導覽

- [正式站點](https://pcbuild.redfiretw.xyz/)
- [最新版本（Release）](../../releases/latest)
- [後端結構與維護文件](docs/project-architecture.md)
- [AI 接入與基線文件](docs/ops/chat-ops-index.md)
- [觀測與儀表板相關檔案](observability/)

## 作品集定位

本專案除了展示台灣零售導向的中文 AI 電腦配單能力，也作為我以 AI 輔助完成實際專案的代表作品。

我負責需求收斂、系統架構規劃、後端流程設計、部署與維運整理，並在開發過程中導入 AI 協助進行重構、測試補強、文件整理與迭代驗收。

此版本重點展示：
- 如何以 RAG 與相容性規則降低配單建議的幻覺與不一致
- 如何整理既有後端與維運文件，將專案收斂至維護期基線
- 如何把 AI 納入實際開發流程，而不是只停留在概念驗證

## 為什麼要做這個專案

- 讓中文使用者可以用自然語言描述需求，得到更接近台灣零售現況的零件建議。
- 把 RAG、相容性檢查、推薦品質治理落成一個可交付的 MVP，而不是停在概念驗證。
- 讓未來接手的人不必重讀一大堆舊 round1 / boundary 文件，也能知道目前正式主線是什麼、該怎麼跑、哪些地方仍是 MVP。

## 目前狀態

目前專案定位是「第一階段可維護 MVP / 收尾版基線」，不是所有想法都已完成的大成品。

已完成的核心能力：

- FastAPI 後端與靜態前端整合，前端提供 chat、登入、註冊與驗證頁面。
- 認證流程包含 session、Email 驗證、忘記密碼與 Resend 郵件整合。
- crawler / catalog 資料管線已具備 `fetch -> parse -> schema gate -> DQ / link consistency -> staging -> merge -> publication pointer` 主線。
- chat / AI 主線已具備 `demand normalization -> retrieval -> context pack -> provider call -> normalize -> gate / DQ -> snapshot -> staging / quarantine`。
- AI provider / model 採 env-only 切換，正式驗收主線以 OpenAI-compatible (`openai_compat`) 為主。
- 已有 smoke / regression / release check / snapshot inspect / staging inspect / crawler health 等 ops CLI。
- Typesense 已做最小整合，PostgreSQL 仍是 source of truth；Typesense 不可用時會 fallback 回 PostgreSQL retrieval。

仍屬 MVP / 實驗性或持續改善中的部分：

- build 配單品質、budget 利用率、CPU/GPU 平衡與主機板 tier matching 仍在調整。
- 推薦品質與相容性不是「已完美完成」，仍需靠 regression、人工 smoke 與 trace artifact 持續校正。
- Typesense 為最小整合版本，重點是加速搜尋與保持 fallback，不是全功能搜尋平台。
- Gemini 路徑在程式內仍存在，但不是目前文件與驗收的主線。

## 核心功能

- 零件資料抓取與入庫：從零售來源抓 raw snapshot，經 parser、schema gate、DQ / link consistency 檢查後進入 staging，再 merge 到 catalog，最後用 publication pointer 切換有效版本。
- AI chat 主線：先做需求判讀與 normalization，再做 retrieval、context pack 壓縮與渲染，最後呼叫 provider，並對回覆做 normalize、gate、DQ、staging / quarantine。
- 可追溯 artifact：保留 raw request / raw response / request context / context pack / lineage / staging / quarantine 等檔案。
- 維運工具：provider health check、regression report、release check、snapshot inspect、staging inspect、crawler health、publication listing、Typesense sync。
- Observability：結構化 log、Loki / Grafana / Alloy 配置與 dashboard 匯出檔已在 repo 中。

## 專案架構總覽

- `web/`
  靜態前端頁面與 JS/CSS 資產，包含 chat、auth 與驗證相關頁面。
- `backend/api/`
  FastAPI route、依賴注入與 auth route。
- `backend/core/`
  app factory、settings、middleware、logging、security log、observability helper。
- `backend/services/chat/`
  AI / chat 主線，包含 provider client、demand inference、retrieval、context pack、gate / DQ、snapshot 與 staging。
- `backend/services/crawler/`
  crawler fetch、parser、schema gate、DQ gate、link consistency gate 與 staging helper。
- `backend/services/catalog/`
  catalog 查詢與 staging merge/upsert 相關存取邏輯。
- `backend/tools/`
  crawler、DB、chat、publication、maintenance 等 CLI 與 ops wrapper。
- `observability/`
  Loki、Alloy、Grafana dashboard / alert 匯出與設定。
- `docs/`
  架構、setup、chat ops、crawler health、smoke test 與 baseline 文件。

更完整的分層與資料流請看 [docs/project-architecture.md](docs/project-architecture.md)。

## 專案目錄概覽

- `alembic/`
  資料庫 migration。
- `backend/models/`
  ORM model，涵蓋 auth、catalog、crawler staging / publication。
- `backend/schemas/`
  API schema 與 chat contract。
- `backend/tests/`
  chat、crawler 與部分核心流程測試。
- `scripts/ops/`
  server 端日常維運腳本，例如 AI baseline freeze、crawler health check。

## 快速開始

### 本機 Windows + WSL

本機 WSL 的定位只有三件事：

- 改程式與改文件
- 跑純 Python 驗證，例如 `pytest`、`compileall`
- 做 git 操作

本機 WSL 不負責：

- `docker compose up`
- 啟動 PostgreSQL / Redis / Typesense 容器
- 執行 server 端 provider health / regression / release check

最小本機流程：

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
cp .env.example .env
PYTHONPATH=. .venv/bin/pytest -q backend/tests/chat
PYTHONPATH=. .venv/bin/python -m compileall backend/services/chat backend/tests/chat backend/schemas
```

完整步驟請看 [docs/setup/full-environment-setup.md](docs/setup/full-environment-setup.md)。

### 伺服器主機

伺服器主機才負責 deployment、Docker 驗收與正式 ops。

最小 server 流程：

```bash
git pull
export APP_GIT_SHA="$(git rev-parse --short=12 HEAD)"
docker compose up -d --build fastapi
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
docker compose exec -T fastapi python -m backend.tools.ops.chat_regression_report
docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10
```

`fastapi` 會連帶啟動其依賴服務：`pcbuild-db`、`pcbuild-redis`、`typesense`、`migrate`。
`pcbuild-scheduler`、`pcbuild-retention`、`cloudflared`、`loki`、`grafana`、`alloy` 則依部署需求另外啟動。

若不想手動 export `APP_GIT_SHA`，可改用：

```bash
./scripts/compose_with_git_sha.sh up -d --build fastapi
```

## 完整架設文件

- [整體環境架設：Windows + WSL 與 Server 主機](docs/setup/full-environment-setup.md)
- [專案架構說明](docs/project-architecture.md)

## `.env` 設定說明

- 範例檔：[`./.env.example`](.env.example)
- AI provider / model 切換原則：只改 `.env`，前端不提供 provider / model / base_url 覆寫入口。
- 正式驗收主線建議維持 `AI_PROVIDER=openai_compat`。
- 伺服器 Docker 端只有 `docker-compose.yml` 明確映射的欄位會進容器；其他 env 主要供本機非 Docker Python 執行使用。

## 測試與驗收

### WSL 非 Docker 驗證

建議先跑：

```bash
PYTHONPATH=. .venv/bin/pytest -q backend/tests/chat
PYTHONPATH=. .venv/bin/python -m compileall backend/services/chat backend/tests/chat backend/schemas
```

需要時可再補跑 crawler 相關測試：

```bash
PYTHONPATH=. .venv/bin/pytest -q backend/tests/crawler/link_consistency_gate
```

### 伺服器 Docker 驗收

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
docker compose exec -T fastapi python -m backend.tools.ops.chat_regression_report
docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10
```

crawler / data pipeline 驗收請看：

- [docs/SMOKE_TEST.md](docs/SMOKE_TEST.md)
- [docs/ops/crawler-health.md](docs/ops/crawler-health.md)

## AI provider / model 切換規則

- 唯一入口是 `.env`
- 後端在 app startup 會 fail fast 檢查 `AI_PROVIDER` / `AI_MODEL` / `AI_OAI_BASE_URL` 等設定
- `/api/chat` schema 明確禁止前端傳入 `provider`、`model`、`base_url`、`api_key` 覆寫欄位
- 正式主線以 OpenAI-compatible transport 為主

## 目前限制 / 本階段不做事項

- 前端不可選模型，也不處理 provider / base_url 自訂輸入。
- 不把文件寫成「全部已完成」；目前仍是第一階段收尾版基線。
- build 配單品質、budget 利用率、候選排序與相容性仍有持續改善空間。
- 不在這一輪擴新 provider，也不把 Gemini / 本地模型 / 多平台比較拉回主線。
- 本機 WSL 不跑 Docker；完整部署與驗收只在伺服器主機。
- 不在這一輪做大規模重構、DB schema 重整或前端大改版。

## 建議操作順序

1. 先讀 [docs/project-architecture.md](docs/project-architecture.md) 確認系統分層與資料流。
2. 在本機 WSL 進行程式與文件修改，先跑本機最小驗證。
3. 推送後，切到伺服器主機執行 `git pull` 與 `docker compose up -d --build fastapi`。
4. 依序跑 provider health、regression report、release check。
5. 若是 crawler / catalog 變更，再跑 [docs/SMOKE_TEST.md](docs/SMOKE_TEST.md) 與 [docs/ops/crawler-health.md](docs/ops/crawler-health.md) 的檢查。
6. 若有異常，優先用 `request_id`、`snapshot_id`、`context_pack_hash`、`run_id` 回頭查 snapshot / staging / publish artifact。

## Roadmap

這個專案目前只保留最小必要方向：

- 持續改善 build 配單品質與相容性規則
- 穩定既有 OpenAI-compatible AI 主線與回歸驗收
- 補齊可交付、可維護、可接手的操作文件

## 文件導覽

- [docs/project-architecture.md](docs/project-architecture.md)
- [docs/setup/full-environment-setup.md](docs/setup/full-environment-setup.md)
- [docs/ops/chat-ops-index.md](docs/ops/chat-ops-index.md)
- [docs/ops/chat-provider-health.md](docs/ops/chat-provider-health.md)
- [docs/ops/chat-snapshot-audit.md](docs/ops/chat-snapshot-audit.md)
- [docs/ops/ai-baseline-freeze.md](docs/ops/ai-baseline-freeze.md)
- [docs/ops/crawler-health.md](docs/ops/crawler-health.md)
- [docs/ops/backup.md](docs/ops/backup.md)
- [docs/SMOKE_TEST.md](docs/SMOKE_TEST.md)

## 歷史文件 / 封存文件

若需追早期整理決策或過渡期 inventory，請看 `docs/archive/`。

## License / 備註

目前 repo 內未附明確 LICENSE 檔；若有對外散佈或商業使用需求，請先確認授權邊界。
