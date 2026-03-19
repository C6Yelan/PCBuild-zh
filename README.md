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
