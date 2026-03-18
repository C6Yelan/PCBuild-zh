# Crawler Health Check

## 目的
- 快速分辨 `coolpc` 這類 crawler source 是「真的沒更新」還是「fetch / gate / publish 卡住」。
- 對應目前專案的增量 scheduler、publish runtime、Loki log、PostgreSQL 狀態表。

## 一鍵檢查
在 repo 根目錄執行：

```bash
scripts/ops/check_crawler_health.sh
```

需求：
- 需要 `docker compose`
- 若有 `jq`，腳本會把 JSON 區塊整理得更易讀；沒有也能執行

常用變體：

```bash
scripts/ops/check_crawler_health.sh --hours 72
scripts/ops/check_crawler_health.sh --source coolpc --env prod
```

## 如何判讀
- `tick_done > 0` 代表 scheduler 最近有實際跑完一輪；如果是 `0`，先查 `pcbuild-scheduler` 容器。
- `t10_no_change` 和 `publish_skipped_no_changed_parts` 很高，但沒有 `fetch_errors` / `stage_fail` / `publish_fail`，比較像來源站真的沒更新。
- `fetch_errors`、`fetch_http_403_429_503`、`robots_block` 有值，才比較像被擋、上游錯誤或連線層問題。
- `stage_fail` 或 `gate_fail` 有值，代表 fetch 後面還有 parse / DQ / link consistency gate 問題。
- `publish_fail` 有值，代表 staging / merge 之後卡在 publish runtime。

## 手動指令
最近 publish：

```bash
docker compose exec fastapi python -m backend.tools.ops.list_publications --limit 10 --env prod
```

最近 scheduler 執行：

```bash
docker compose logs --since=48h pcbuild-scheduler 2>&1 | rg 'event=t10_scheduler_tick_(done|failed|skipped_locked)'
```

確認是不是 no-change：

```bash
docker compose logs --since=48h pcbuild-scheduler 2>&1 | rg 'event=t10_no_change|reason=skipped_no_changed_parts'
```

抓 fetch / block 類問題：

```bash
docker compose logs --since=48h pcbuild-scheduler fastapi 2>&1 | rg 'event=t10_fetch.*status=error|event=t10_fetch.*status_code=(403|429|503)|Blocked by robots|unexpected_status'
```

看 gate / publish 失敗：

```bash
docker compose logs --since=48h pcbuild-scheduler fastapi 2>&1 | rg 'event=t10_stage_done.*rc=[1-9]|event=gate_result.*status=fail|event=t9_publish_failed'
```

看 fetch state：

```bash
docker compose exec pcbuild-db psql -U pcbuild -d pcbuild -c "
select source, part_type, last_status_code, last_success_at, updated_at
from crawler_fetch_state
where source='coolpc'
order by updated_at desc;"
```

看最近 ingest run 是否有 publish：

```bash
docker compose exec pcbuild-db psql -U pcbuild -d pcbuild -c "
select r.created_at, r.run_id,
       case when p.run_id is null then false else true end as published
from crawler_ingest_run r
left join crawler_publication p on p.run_id = r.run_id
where r.source='coolpc'
order by r.created_at desc
limit 20;"
```

看最近 gate fail：

```bash
docker compose exec pcbuild-db psql -U pcbuild -d pcbuild -c "
select created_at, run_id, gate_name, item_key
from crawler_stg_gate_result
where status='fail'
  and created_at > now() - interval '2 days'
order by created_at desc
limit 50;"
```

## 補充
- Grafana 的 `T9 No Successful Publish (24h)` 告警名稱沿用舊代號；它只代表 24 小時內沒有 `published=true` 的 publish 成功事件，不等於 crawler 一定被封鎖。
- `crawler_fetch_state` 只保留每個 part 最新一次狀態，適合看現在最後結果，不適合單靠它還原完整時間線。
- `temp/t10/<run_id>/summary.json` 是單次執行最完整的摘要；腳本也會把最新一份抓出來。
