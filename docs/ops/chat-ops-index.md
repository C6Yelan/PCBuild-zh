# Chat Ops Index

> 角色：chat 營運文件入口。這份文件只做導覽，不重複維護各工具的 SOP 細節。

## 目前正式入口

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

## 歷史 / 過渡文件
- `docs/ops/chat-round1-boundary.md`
  - 用途：保存 round 1 架構整理時的 boundary 與 compat 決策。
  - 現況：歷史文件，不作為當前 chat ops 唯一入口。

## 使用順序建議
1. 日常 smoke / provider 檢查：先看 `chat-provider-health.md`
2. 要追單筆 request artifact：看 `chat-snapshot-audit.md`
3. 要做基線凍結、回歸比對、release 驗收：看 `ai-baseline-freeze.md`
4. 需要理解 round 1 為何保留某些 compat path：再回頭看 `chat-round1-boundary.md`
