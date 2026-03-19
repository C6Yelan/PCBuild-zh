# Chat Ops Index

> 角色：chat 營運文件入口。這份文件只做導覽，不重複維護各工具的 SOP 細節。

## 目前正式入口

### 收尾版本主線
- 目前正式支援的 AI 主線是 `openai_compat` + env-only 切換。
- chat 主流程固定為 `NormalizedDemand -> retrieval / semantic policy / compatibility gate -> post-gate build scoring -> clean context pack -> final answer`。
- `.env` 是唯一切換入口；前端不負責選 provider / model / base_url。
- Windows + WSL 本機只負責改碼、純 Python 驗證與 git 操作；所有 `docker compose` 與 chat ops 驗收都只在伺服器主機執行。
- Gemini、本地模型、多平台比較、dashboard 都不是這一階段的主線工作。
- 若 normalization 失敗或 clean candidate 不足，系統必須保守降級並直接說明資料不足，不得硬湊 build。
- build / upgrade 類題目若 trace 有 `build_scoring_summary`，人工判讀應優先看 `budget_utilization_score`、`cpu_gpu_balance_score`、`motherboard_tier_match_score`。

### Canonical / Compat 定位
- canonical implementation tree 在 `backend.tools.ops.chat.*`。
- stable public wrapper 仍是 `python -m backend.tools.ops.chat_provider_healthcheck`、`python -m backend.tools.ops.chat_regression_report`、`python -m backend.tools.ops.chat_snapshot_inspect`、`python -m backend.tools.ops.chat_staging_inspect`、`python -m backend.tools.ops.chat_release_check`。
- `--mode p10` 仍是 release acceptance 的 compat flag，不作為新的命名標準。

### Provider smoke / health
- 文件：`docs/ops/chat-provider-health.md`
- 用途：確認目前 `.env` 指向的 provider / model 能否走完既有 chat service 主流程。
- 相關 CLI：
  - `python -m backend.tools.ops.chat_provider_healthcheck`

### Snapshot / staging / quarantine 稽核
- 文件：`docs/ops/chat-snapshot-audit.md`
- 用途：依 `request_id` 追 snapshot artifact、staging record、quarantine entry。
- 相關 CLI：
  - `python -m backend.tools.ops.chat_snapshot_inspect --request-id <REQUEST_ID>`
  - `python -m backend.tools.ops.chat_staging_inspect --request-id <REQUEST_ID>`
  - `python -m backend.tools.ops.chat_staging_inspect --list-quarantine --limit <N>`

### Baseline freeze / regression / release acceptance
- 文件：`docs/ops/ai-baseline-freeze.md`
- 用途：凍結基線、保存 regression 與 release acceptance 結果、記錄回退依據。
- 相關 CLI：
  - `python -m backend.tools.ops.chat_regression_report`
  - `python -m backend.tools.ops.chat_release_check --mode p10`

## 使用順序建議
1. 本機 Windows + WSL：只做改碼、純 Python 驗證、`git add` / `git commit` / `git push`
2. 本機最小驗收：`PYTHONPATH=. .venv/bin/pytest -q backend/tests/chat`、`PYTHONPATH=. .venv/bin/python -m compileall backend/services/chat backend/tests/chat backend/schemas`
3. 伺服器主機：先看 `chat-provider-health.md`
4. 要做最小必要驗收：只在伺服器主機依序跑 provider health、regression report、release check `--mode p10`
5. 要追單筆 request artifact：看 `chat-snapshot-audit.md`
6. 要做基線凍結、回歸比對、release 驗收：看 `ai-baseline-freeze.md`
7. 若需要查歷史 boundary / compat 決策，請看 `docs/archive/chat-round1-boundary.md`；它是封存文件，不屬於日常維運 SOP
