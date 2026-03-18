# Smoke Test（增量更新管線）

## 服務名稱註記
本文件依 `docker-compose.yml` 現況撰寫，服務 key 為：`fastapi`、`pcbuild-db`、`pcbuild-scheduler`、`pcbuild-retention`。若未來 key 變更，請以 `docker-compose.yml` 為準替換命令中的服務名稱。

## 路徑 / 命名定位
- 本文件使用的 stable public CLI 入口：
  - `python -m backend.tools.crawler.crawl_parse_snapshot`
  - `python -m backend.tools.db.stage_from_snapshot_cli`
  - `python -m backend.tools.ops.run_incremental`
- 目前 canonical implementation package 已在：
  - `backend.tools.crawler.parse.*`
  - `backend.tools.db.stage_from_snapshot.*`
  - `backend.tools.db.staging_capture_support.*`
  - `backend.tools.db.staging_ingest_support.*`
  - `backend.tools.ops.crawler.*`
- `t9_*` / `t10_*` module 名稱、event key 與 artifact path（例如 `temp/t7/...`、`temp/t10/...`）目前屬穩定 compat / contract，不是新的 canonical 命名。

## 目的
快速驗證增量更新管線核心流程可用：`fetch -> parse/gates -> stage -> merge ->（可選 publish）`，並確認 link consistency 檢查（`t5` artifacts）會在每輪增量 stage 被執行。

## 前置條件
1. `docker compose` 可正常操作此專案服務。
2. 目標服務已啟動，至少包含：`fastapi`、`pcbuild-db`、`pcbuild-scheduler`、`pcbuild-retention`。
3. 測試以下示例以 `coolpc + cpu` 為主；若改測其他零件，可將 `cpu` 改成 `<cpu|mb|ram|ssd|hdd|cooler|liquid_cooling|gpu|case|psu|case_fan|expansion_card>`。

## Smoke Test（手動跑一次，強制產生 changed part）
1. 刪除 fetch_state（強制下一輪當作 changed）：

```bash
docker compose exec -T pcbuild-db psql -U pcbuild -d pcbuild -c "delete from crawler_fetch_state where source='coolpc' and part_type='cpu';"
```

2. 跑一次增量（不 publish）：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.run_incremental --source coolpc --parts cpu --no-publish --max-items 2000 --t5-limit 50
```

3. 驗證 DB fetch_state 有回填（至少 `content_sha256` / `last_status_code` / `last_success_at` / `updated_at` 不為空）：

```bash
docker compose exec -T pcbuild-db psql -U pcbuild -d pcbuild -c "select part_type, content_sha256, last_status_code, last_success_at, updated_at from crawler_fetch_state where source='coolpc' and part_type='cpu';"
```

4. 驗證 link consistency 產物落地（在最新含 cpu snapshot 的 run 目錄中找到 `t5` artifacts）：

```bash
docker compose exec -T fastapi sh -lc 'RUN=""; for d in $(ls -td /app/temp/t10/* 2>/dev/null); do [ -f "$d/parts/cpu/snapshot/meta.json" ] && RUN="$d" && break; done; echo "RUN=$RUN"; ls -la "$RUN/parts/cpu/t7_artifacts/t5" && find "$RUN/parts/cpu/t7_artifacts/t5" -maxdepth 1 -type f -print | sort'
```

5. 期望結果：
1. `run_incremental` exit code 為 `0`。
2. 第 3 步查詢至少回傳 `1` 筆資料，且 `content_sha256`、`last_status_code`、`last_success_at`、`updated_at` 皆有值。
3. `t5` 目錄存在，且可看到 `t5.summary.json`、`t5.passed.json`、`t5.quarantine.json`、`t5.input.json`、`t5.link_report.jsonl`（實際檔案數可依執行結果略有差異）。

## Smoke Test（排程驗證：scheduler 週期運作與 link consistency 觸發）
查看 scheduler 日誌：

```bash
docker compose logs --tail 200 pcbuild-scheduler
```

期望可看到：
1. `t10_scheduler_tick_done`
2. `t10_start`
3. 在有 changed part 時，看到 `t5_link_started` / `t5_link_finished`

## Retention 驗證（常駐服務與 dry-run/confirm）
查看 retention 日誌：

```bash
docker compose logs --tail 200 pcbuild-retention
```

（可選）手動 dry-run：

```bash
docker compose exec -T fastapi python -m backend.tools.ops.db_retention --dry-run
```

期望可看到 `precheck_stats` / `delete_summary` 等輸出（`delete_summary` 會在 `--confirm` 實際刪除流程中出現）。
