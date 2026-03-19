# 文件索引

這裡集中整理 PCBuild-zh 目前仍在使用的文件入口。README 首頁只保留專案定位與快速導覽，環境架設、驗收與維運細節請從本頁進入。

## 環境架設 / Setup

- [從零開始架設整體環境](setup/full-environment-setup.md)：Windows + WSL 本機開發流程、伺服器主機 Docker / Compose 啟動、常見問題排除。
- [專案架構說明](project-architecture.md)：系統分層、關鍵資料流、重要目錄與 trace artifact 說明。

## AI / Chat Ops

- [Chat Ops Index](ops/chat-ops-index.md)：AI 主線的正式入口、health、snapshot 稽核與 release acceptance 導覽。
- [Chat Provider Health Check](ops/chat-provider-health.md)：provider 切換後的健康檢查與判讀方式。
- [Chat Snapshot Audit](ops/chat-snapshot-audit.md)：如何從 request / snapshot / quarantine artifact 追查問題。
- [AI 基線凍結紀錄模板](ops/ai-baseline-freeze.md)：基線版本的驗收紀錄與回退 SOP 模板。

## Crawler / Smoke / Health

- [Smoke Test](SMOKE_TEST.md)：增量更新管線、scheduler 驗證與 retention 檢查。
- [Crawler Health Check](ops/crawler-health.md)：crawler 一鍵檢查、手動指令與結果判讀。

## Backup / 維運文件

- [備份與保留作業說明](ops/backup.md)：備份路徑、排程、保留策略與還原演練摘要。

## Archive

- [archive/](archive/)：保留舊版邊界文件、CLI surface 與歷史整理筆記，供追溯與比對，不作為目前首頁主線文件。
