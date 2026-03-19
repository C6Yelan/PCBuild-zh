# AI P4 前置：AI Provider 架設與驗收追蹤文件（.env 切換版）

版本：v1  
目的：在進入 AI P4（Provider 健康檢查 / smoke prompts）之前，把「可切換的 AI Provider」架好，並且每次切換都能用同一套 smoke prompts 驗證可用性與可追蹤性。  
原則：**只能用 `.env` 切換**，前端不可選模型 / 不可傳 base_url；API key 不可寫入 log / 不可回傳前端。

---

## 0. 名詞與範圍

- Provider：一個「推理服務來源」（Gemini、OpenAI 付費、外部推理平台、本地自架）。
- Model：該 Provider 下的模型名稱（由 Provider 解釋）。
- OpenAI-compatible：提供類似 `/v1/chat/completions` 的介面，可用同一套 client 只換 `base_url` 即切換推理後端。

本文件涵蓋你要架的 4 類：
1) Gemini（Google AI Studio / Gemini API）  
2) 本地自架開源模型（OpenAI-compatible server）  
3) 外部開源推理平台 API（OpenAI-compatible endpoint）  
4) 未來：OpenAI 付費 API  

---

## A0. 治理基礎（Contract / 安全邊界）

### 做什麼
- 固定「後端內部統一請求/回覆格式（contract）」：業務層不依賴任何供應商 SDK/格式。
- 固定「安全邊界」：**base_url 與 api_key 只能由環境變數提供**；前端不可傳入/不可覆寫；key 不可寫 log。

### 產物
- [ ] AI contract（內部 `ChatRequest` / `ChatResponse` 定義與欄位）
- [ ] ai_trace 最小欄位：`request_id, provider, model, context_pack_hash, latency_ms, ok, error_type`
- [ ] 後端防護：拒絕任何「前端指定 base_url / model」的輸入路徑

### 驗收（打勾才能往下）
- [ ] 可以用 `request_id` 回溯到：raw_request/raw_response/context_pack_hash/資料版本（snapshot/run_id）
- [ ] log 不包含任何 API key

---

## A1. 環境變數規格（模型切換唯一入口）

### 做什麼
把所有切換集中到 `.env`，並準備「可回退」的切換流程。

### `.env`（最小集合）
通用：
- [ ] `AI_PROVIDER`：例 `openai_compat` / `gemini`（未來可加更多）
- [ ] `AI_MODEL`
- [ ] `AI_TIMEOUT_SECONDS`（例：30）
- [ ] `AI_MAX_OUTPUT_CHARS`（例：2000）

OpenAI-compatible 專用：
- [ ] `AI_OAI_BASE_URL`（例：`http://localhost:8001/v1` 或外部平台 endpoint）
- [ ] `AI_OAI_API_KEY`（可留空但欄位保留；一致治理）

Gemini 專用：
- [ ] `GEMINI_API_KEY`（或 `GOOGLE_API_KEY`，建議只設一個）

### 產物
- [ ] `.env.example`（不含機密，只含欄位與範例值）
- [ ] `.env`（實際機密，**不可 commit**）
- [ ] 「切換紀錄」：每次切換記一筆（日期/commit/provider/model/base_url 指紋）

### 驗收
- [ ] 刪掉 `.env` 後服務不應啟動（或會明確報錯），避免用到預設值造成誤用
- [ ] 前端完全沒有「選模型」或「輸入 endpoint」能力

---

## A2. OpenAI-compatible 主線先打通（不管後端是哪一家）

### 做什麼
先確保你的後端能用「OpenAI chat messages」格式呼叫任意 OpenAI-compatible 端點（只換 `.env`）。

### 產物
- [ ] provider=`openai_compat` 的 adapter（或 client wrapper）
- [ ] 失敗分類（至少）：`timeout` / `429` / `5xx` / `network_error` / `parse_error`
- [ ] raw snapshot 保存（最少要能在磁碟或 DB 回溯）

### 驗收
- [ ] 用一題最小 prompt 能成功回覆
- [ ] ai_trace 會記錄：provider/model/latency/ok/error_type

---

## A3. 外部「開源推理平台 API」（OpenAI-compatible endpoint）

> 目的：先拿它當「穩定 baseline」，快速驗證整條管線可用，之後再接本地自架。

### 做什麼
- 選一家提供 OpenAI-compatible endpoint 的推理平台（只要符合：能改 `base_url`、能用你的 OpenAI-compatible client）。
- 在 `.env` 設定：
  - `AI_PROVIDER=openai_compat`
  - `AI_OAI_BASE_URL=<該平台的 openai 相容 endpoint>`
  - `AI_OAI_API_KEY=<該平台 key>`
  - `AI_MODEL=<該平台提供的模型名>`

### 產物
- [ ] `provider_profile/<platform>.md`（記錄 base_url、模型名、速率限制備註、你實測 p50/p95）
- [ ] 一份 smoke prompts 結果（見 A6）

### 驗收
- [ ] smoke prompts 全數通過（或可接受的少量 DQ fail，但不可空回覆）
- [ ] 429/timeout 有被正確分類與記錄（可用於 Grafana 觀測）

---

## A4. 本地自架「開源模型」（OpenAI-compatible server）

> 目的：本地推理也走同一套 OpenAI-compatible client，讓後端不用改呼叫邏輯，只換 `.env`。

### 做什麼（擇一或多個）
- vLLM（偏 GPU/吞吐）：啟動 OpenAI-compatible server  
- llama-cpp-python（偏輕量、本機）：啟動 OpenAI-compatible web server  
- LocalAI（整合型）：提供 OpenAI-compatible API

啟動後，在 `.env` 設定：
- `AI_PROVIDER=openai_compat`
- `AI_OAI_BASE_URL=http://<你的本地推理主機>:<port>/v1`
- `AI_OAI_API_KEY=`（若你本地 server 有設 token 就填）
- `AI_MODEL=<你 server 掛載的模型識別>`

### 產物
- [ ] `provider_profile/local_<engine>.md`（記錄：啟動方式、硬體需求、模型版本、你實測 p50/p95）
- [ ] 同一份 smoke prompts 報告（與 A3 可比較）

### 驗收
- [ ] 與 A3 同一份 smoke prompts 跑完，可對照差異（文字品質/延遲/錯誤率）
- [ ] 本地 server 掛掉時，後端 error_type 分類清楚（不會卡死 worker）

---

## A5. Gemini（Google AI Studio / Gemini API）

> 注意：Gemini 不必強行塞進 OpenAI-compatible；建議視為「獨立 provider adapter」，但仍沿用相同的內部 contract 與 ai_trace。

### 做什麼
- 設定環境變數（建議只設一個）：`GEMINI_API_KEY`（或 `GOOGLE_API_KEY`）
- 在 `.env` 設定：
  - `AI_PROVIDER=gemini`
  - `AI_MODEL=<Gemini 模型名>`
- 實作 Gemini adapter：
  - 輸入：由你的內部 `ChatRequest` 映射到 Gemini SDK/REST 所需格式
  - 輸出：normalize 成你的 `ChatResponse(text=...)`
  - 同樣寫入 ai_trace/raw snapshot（key 不落 log）

### 產物
- [ ] `provider_profile/gemini.md`（模型名、限制、你實測 p50/p95）
- [ ] smoke prompts 報告（同一份題目，便於交叉測試）

### 驗收
- [ ] smoke prompts 可完成
- [ ] 任一 request_id 可回放 raw snapshot 與 normalize 後的結果

---

## A6. 固定 smoke prompts（P4 會用到）

### 做什麼
準備固定 5～10 題（同一套題目跑所有 provider/model），用於：
- P4 啟動/切換健康檢查
- 每次改 `.env` 後的回歸測試
- 交叉測試品質/延遲差異

### 覆蓋建議（純文字）
- [ ] 短問答（基本可用）
- [ ] 多輪對話（上下文）
- [ ] 明確格式要求（如「請用三點列出」）
- [ ] 領域題（配單、相容性、預算取捨）

### 驗收標準（建議先量化）
- [ ] 空回覆 / 亂碼：0（或趨近 0）
- [ ] p95 latency：可觀測、可追蹤（至少在 log 可聚合）
- [ ] timeout/429：有分類、有比例、可觀測
- [ ] 任一 fail：可用 request_id 回溯 raw snapshot

---

## A7. 切換流程 SOP（部署切換、可回退）

> 你的作業原則：本機只改程式碼並 push；部署端 git pull 後用 docker compose 重啟；不在主機安裝 Python；測試/工具在 fastapi 容器內執行。

### SOP
1. [ ] 修改 `.env`（provider/model/base_url/key）
2. [ ] 重啟 fastapi（部署端）
3. [ ] 先跑 P4 smoke prompts（容器內）
4. [ ] 觀察監控（成功率、429、延遲）
5. [ ] 若異常：回退上一組 `.env` → 重啟 → 重跑 smoke（快速止血）

### 驗收
- [ ] 切換一次 provider/model，不需要改任何程式碼（只改 `.env`）
- [ ] 任何切換都會產生一份 smoke/regression 報告（可比對）

---

## A8. Go / No-Go（進入 P4 之前的最終檢核）

- [ ] 至少 1 個 Provider 已可穩定通過 smoke prompts（建議：先完成 A3）
- [ ] ai_trace 欄位齊全（request_id/provider/model/context_pack_hash/latency/ok/error_type）
- [ ] key 不落 log；base_url 不可由前端輸入
- [ ] 切換 `.env` → 重啟 → smoke → 觀測 → 回退 的 SOP 已跑通一次