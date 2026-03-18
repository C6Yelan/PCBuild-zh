# 備份與保留作業說明

## 1) 目標與範圍
- 本機備份階段會產出 PostgreSQL 備份：
  - 使用 `pg_dump -Fc` 產出各資料庫的 `db_*.dump`。
  - 使用 `pg_dumpall --globals-only` 產出 `globals.sql`（角色與全域設定）。
- 專案設定檔備份：將 `compose/.env*` 打包為 tar 檔。
- cloudflared 備份：將 cloudflared 目錄打包為 tar 檔。
- 備份資料會再寫入 restic 加密 snapshots（repo 端保存）。

## 2) 路徑
- 本機 staging：`/opt/pcbuild-backups/local/{pg,configs}`
- restic repo：`/opt/pcbuild-backups/restic-repo`
- 作業日誌：`/opt/pcbuild-backups/logs`
- 腳本入口：`/opt/pcbuild-backups/bin`

## Repo 內的腳本模板
- repo 提供伺服器備份腳本模板路徑：`scripts/server-backup/`
- 內容包含：
  - `backup_now.sh`
  - `cleanup_local.sh`
  - `retention_weekly.sh`
  - `check_weekly.sh`
- 部署時請將上述腳本複製到 `/opt/pcbuild-backups/bin/` 後再由 cron 呼叫。

## 3) 排程（cron）
- 每日 `03:30`：執行 `/opt/pcbuild-backups/bin/backup_now.sh`
- 每週日 `05:10`：執行 `/opt/pcbuild-backups/bin/retention_weekly.sh`
- 每週日 `05:40`：執行 `/opt/pcbuild-backups/bin/check_weekly.sh`
- 排程刻意避開 `04:30` 的 publish job，降低同時段 I/O 與資源競爭。

## 4) Repo retention
- 週期性保留策略指令：
  - `restic forget --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --prune`
- 此策略只影響 restic repo 內的 snapshots，不會直接清理本機 `local` staging 檔案。

## 5) Local cleanup（重點）
- `local` 屬於 staging 區，若不清理會持續膨脹。
- 已新增清理腳本：`/opt/pcbuild-backups/bin/cleanup_local.sh`
- 預設保留天數：
  - `pg` 保留 7 天
  - `configs` 保留 30 天
- `cleanup_local.sh` 已整合在 `backup_now.sh` 流程中，且只在 restic backup 成功完成後才執行；若備份失敗則不清理，保留現場供除錯。

## 6) 手動操作
- backup：`/opt/pcbuild-backups/bin/backup_now.sh`
- retention：`/opt/pcbuild-backups/bin/retention_weekly.sh`
- check：`/opt/pcbuild-backups/bin/check_weekly.sh`

## 7) 還原演練摘要
- 先套用 `globals.sql`（以 `psql` 還原角色與全域設定）。
- 再以 `pg_restore` 逐一還原 `db_*.dump` 至目標資料庫。
- 完成後驗證權限與應用程式連線流程是否正常。

## 8) 安全性補強簡述
- `/var/backups` 權限收斂：
  - 目錄權限 `700`
  - 檔案權限 `600`
- `dpkg-db-backup.service` drop-in 設定 `UMask=0077`：
  - `/etc/systemd/system/dpkg-db-backup.service.d/override.conf`
