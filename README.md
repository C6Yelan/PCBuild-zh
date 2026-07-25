# PCBuild-zh

> [!WARNING]
> 本專案已停止開發，不再提供功能更新、部署維護或使用支援。
>
> Repository 保留作為早期原型、系統設計嘗試與開發歷程紀錄，不建議直接用於實際購買決策或正式環境。

PCBuild-zh 是一個以台灣零售零件資料為基礎的中文 AI 電腦配單原型。

專案嘗試將需求理解、零件檢索、相容性規則與中文回答整合成一套可追溯的處理流程，而不是只依賴語言模型直接產生配單。

## 專案狀態

開發已停止，最後保留版本為 [`v1.0.0`](../../releases/tag/v1.0.0)。

停止開發前已完成的主要內容：

- FastAPI 後端與靜態前端
- 基本帳號驗證與聊天流程
- 零件 crawler 與 catalog 資料管線
- Retrieval、context pack 與部分相容性規則
- Request、snapshot、staging 與 quarantine 等追蹤資料
- Smoke test、provider health 與 release check 等驗收工具

## 已知限制

- 推薦品質與預算分配未完成充分驗證。
- 相容性規則仍不完整，不能取代人工檢查。
- 零件資料可能已經過期。
- 部分流程仍停留在原型或 MVP 階段。
- 線上 Demo 可能停止運作。
- 本專案不適合直接作為正式購買或商業服務依據。

## 專案結構

- `web/`：靜態前端與聊天、帳號相關資產
- `backend/api/`、`backend/core/`：FastAPI routes、設定、middleware 與 logging
- `backend/services/chat/`：Retrieval、context pack、規則檢查與追蹤流程
- `backend/services/crawler/`、`backend/services/catalog/`：零件資料擷取、整理與查詢
- `backend/tools/`、`observability/`：維運工具與觀測設定

更多內容可參考：

- [文件索引](docs/README.md)
- [專案架構](docs/project-architecture.md)
- [Smoke Test](docs/SMOKE_TEST.md)
- [Release 紀錄](../../releases)

## 保留原因

雖然本專案沒有繼續發展成完整產品，但仍保留以下開發經驗：

- 將 RAG、規則檢查與資料管線整合進實際應用
- 設計可追溯的 AI 處理流程
- 整理 FastAPI 專案結構、測試與維運文件
- 理解從概念原型發展到可靠產品時，資料品質、規則完整度與驗證流程的重要性

## License

[MIT](LICENSE)
