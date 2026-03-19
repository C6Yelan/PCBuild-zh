# AI 基線凍結紀錄模板

> 角色：治理 / baseline 文件。這份文件負責保存 provider health、regression、release acceptance 與回退依據，不是日常單一步驟 SOP 入口。

## 1. 目的
- 用於在本次基線凍結中保存目前 AI 行為基線，建立後續比對與回退依據。
- 本文件只記錄營運驗收與環境指紋，不修改 backend 主邏輯，不涉及 API 契約變更。
- 填寫時禁止寫入 API key、Authorization header、完整 `AI_OAI_BASE_URL` 明文。
- chat 文件入口與角色分工見 `docs/ops/chat-ops-index.md`。

## 1.1 目前收尾範圍
- 正式 AI 主線以 `openai_compat` 為準。
- `.env` 是唯一切換 `AI_PROVIDER` / `AI_MODEL` / `AI_OAI_BASE_URL` 的入口。
- Windows + WSL 本機只負責改碼、純 Python 驗證與 git 操作；所有 `docker compose` 驗收命令都只在伺服器主機執行。
- 本輪驗收只要求 provider health、regression report、release check `--mode p10`。
- Gemini、本地模型、多平台比較、前端模型選擇、Grafana / Loki / dashboard 都不列入這份基線。

## 1.2 Canonical / Compat 定位
- chat 現行 canonical package 在 `backend/services/chat/{clients,context_pack,contracts,payloads,provider,service,staging}/`。
- `backend/services/chat` 根下仍保留的 `provider_caller.py`、`service_seams.py`、`service_orchestration.py`、`chat_payload_context.py`、`snapshot_payloads.py` 等檔案，屬 compat / forwarding surface，不是新的主結構命名。
- chat ops 的 canonical implementation 在 `backend.tools.ops.chat.*`；日常 CLI 仍以 `python -m backend.tools.ops.chat_*` 為 stable public surface。
- `chat_release_check --mode p10` 中的 `p10` 是穩定 compat flag，不是新的正式命名標準。

## 2. 基線日期
- 日期：`<YYYY-MM-DD>`
- 時區：`<UTC 或 UTC+08:00>`
- 凍結執行人：`<name>`

## 3. git commit SHA
- `git rev-parse HEAD`：`<40-char sha>`
- 如需對照部署版本，可補充 `APP_GIT_SHA`：`<sha or tag>`

## 4. AI 設定指紋
只記錄可公開比對的指紋，不記錄 secrets 與完整 upstream URL。

| 欄位 | 值 |
| --- | --- |
| `AI_PROVIDER` | `<value>` |
| `AI_MODEL` | `<value>` |
| `AI_TIMEOUT_SECONDS` | `<value>` |
| `AI_MAX_OUTPUT_CHARS` | `<value>` |
| `AI_OAI_BASE_URL_SHA12` | `<12-char sha256 prefix 或 ->` |
| `AI_RAW_SNAPSHOT_DIR` | `<value>` |

備註：
- `AI_OAI_BASE_URL_SHA12` 來源為 `sha256(AI_OAI_BASE_URL)` 前 12 碼。
- 若目前 provider 不使用 OpenAI-compatible base URL，可填 `-`。

## 4.1 Observability 記錄注意事項
- Loki / Grafana label 應只使用低基數、穩定欄位，例如 `provider`、`model`、`env`、`component`、`status`。
- `request_id`、`snapshot_id`、`context_pack_hash` 應記在 log body 或 structured metadata，不應升成 label。

## 5. 基線驗收結果
| 檢查項目 | 結果 | 補充 |
| --- | --- | --- |
| provider health check | `<pass/fail>` | `report_path=<path>` |
| regression report path | `<path>` | 建議直接貼 tool 輸出的 `report_path` |
| release check result | `<pass/fail>` | `mode=p10`, `snapshot_root=<path>` |

建議同步保存：
- 基線檢查輸出目錄：`/tmp/ai-baseline-freeze-<UTC timestamp>/`
- `provider_healthcheck.stdout.json`
- `chat_regression_report.stdout.json`
- `chat_release_acceptance.stdout.json`
- `baseline_summary.txt`

## 6. 真實 request 樣本
在完成固定驗收指令後，請手動打一筆真實 chat request，再補以下欄位：

| 欄位 | 值 |
| --- | --- |
| `request_id` | `<request_id>` |
| `snapshot_dir` | `<AI_RAW_SNAPSHOT_DIR>/<request_id>` |
| `staging_status` | `<staged/skipped>` |
| `quarantine_status` | `<not_quarantined/quarantined/not_applicable>` |
| `context_pack_hash` | `<hash or ->` |

補充紀錄建議：
- request 摘要：`<一句話描述，不貼完整敏感內容>`
- 實際觀察：`<是否符合目前線上預期>`

### 已填範例關鍵字（2026-03-10）
以下為一筆已 staged 的真實 request 摘錄，可作為本次基線參考：

| 欄位 | 值 |
| --- | --- |
| `request_id` | `db09422b014a472b9e9d9745a1fcdf39` |
| `snapshot_dir` | `/app/data/ai_raw_snapshots/db09422b014a472b9e9d9745a1fcdf39` |
| `staging_status` | `staged` |
| `quarantine_status` | `not_quarantined` |
| `context_pack_hash` | `5020d803163f5cc82b6c0873a55060b1147cb331db2b0dd5a3372b59bdc4cffd` |

關鍵字摘錄：
- provider / model：`openai_compat`、`llama-3.3-70b-versatile`
- request 狀態：`ok=true`、`gate_status=pass`、`dq_status=pass`、`publish_reason=staged_pass`
- request 上下文：`request_mode=user_text`、`demand_source=inferred`、`triggered_retrieval=true`、`env=prod`、`top_k=2`
- 驗證摘要：`latency_ms=2050`、`validation_passed=true`、`dq_passed=true`、`keyword_hit_count=28`、`keyword_pool_size=125`
- 類別關鍵字：`CPU`、`MB`、`RAM`、`SSD`、`PSU`、`CASE`
- 需求關鍵字：`文書機`、`預算2萬內`、`內顯`、`性價比`
- 零件關鍵字：`AMD R5 3400G`、`AMD R5 5500GT`、`華擎 B450M-HDV R4.0`、`華擎 H610M-H2/M.2`、`UMAX NB 8GB DDR3L-1600`、`UMAX S330 240GB`、`全漢 聖武士 350W`、`保銳 ENERPAZO EP237白`

使用方式：
- 若之後切 provider / model 或調整 context pack 生成規則，可先拿這組關鍵字檢查是否仍維持相同需求判讀、相同類別覆蓋與相近零件候選。
- 若新基線出現 `gate_status`、`dq_status`、`staging_status` 或 `context_pack_hash` 明顯漂移，應先比對 regression report 與 snapshot artifact，再決定是否接受新基線。

## 7. 固定驗收指令
本機（Windows + WSL）先完成：

```bash
git add <files>
git commit
git push
```

以下命令只在伺服器主機執行。

先在伺服器主機 repo root 執行基線檢查腳本：

```bash
scripts/ops/freeze_ai_baseline.sh
```

若需要在伺服器主機逐項重跑，固定指令如下：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_provider_healthcheck
docker compose exec -T fastapi python -m backend.tools.ops.chat_regression_report
docker compose exec -T fastapi python -m backend.tools.ops.chat_release_check --mode p10
```

手動打一筆真實 request 後，可再在伺服器主機用下列指令追蹤 snapshot：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.chat_snapshot_inspect --request-id <REQUEST_ID>
```

補充：
- 若只做 provider smoke / health，不必整份重跑，直接看 `docs/ops/chat-provider-health.md`
- 若只做 snapshot / quarantine 稽核，直接看 `docs/ops/chat-snapshot-audit.md`

## 7.1 結果判讀
- `chat_provider_healthcheck` exit code `0`：固定 smoke cases 全通過；`2`：至少一題失敗。
- `chat_regression_report` exit code `0`：目前固定題組無失敗；`2`：至少一題失敗，需比對 `failed_cases` 與 `report_path`。
- `chat_release_check --mode p10` exit code `0`：acceptance harness 通過；`2`：至少一個 deterministic check 失敗。
- 三者任一不通過，都不應更新本次基線。

## 8. 回退 SOP
1. 先找出上一份已確認可接受的基線紀錄，確認其 `git commit SHA` 與 AI 設定指紋。
2. 若本輪同時啟用了 Typesense retrieval，先把 `TYPESENSE_ENABLED=false` 作為最快停用手段；若仍需整版回退，再把部署環境回退到前一版 commit。
3. 將 `.env` 內 `AI_PROVIDER`、`AI_MODEL`、`AI_TIMEOUT_SECONDS`、`AI_MAX_OUTPUT_CHARS`、`AI_OAI_BASE_URL` 恢復到上一份基線值；若需要也同步恢復 Typesense 相關 env。
4. 在伺服器主機重新啟動 `fastapi` 服務，確認容器內環境與回退目標一致。
5. 重新執行固定驗收指令，確認：
   - provider health check 回到預期結果
   - regression report 與前一份基線一致或差異可解釋
   - `chat_release_check --mode p10` 回到 `pass`
6. 再手動打一筆真實 chat request，確認新的 `request_id`、`snapshot_dir`、`staging_status`、`quarantine_status` 與 `context_pack_hash` 皆符合回退後預期。
