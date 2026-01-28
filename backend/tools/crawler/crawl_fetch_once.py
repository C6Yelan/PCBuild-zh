# backend/tools/crawl_fetch_once.py
from __future__ import annotations

import argparse
import json
import re
import hashlib
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from backend.services.crawler import CrawlerHttpClient, CrawlerSettings


_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _safe_slug(s: str, *, max_len: int = 80) -> str:
    s = s.strip().lower()
    s = _SAFE_NAME_RE.sub("-", s).strip("-")
    return s[:max_len] if len(s) > max_len else s


def _validate_url(url: str) -> None:
    u = urlparse(url)
    if u.scheme not in ("http", "https"):
        raise SystemExit("只允許 http/https URL。")
    if not u.netloc:
        raise SystemExit("URL 缺少網域（netloc）。")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="單次抓取頁面並落地 raw snapshot（先存檔，不解析、不入庫）。"
    )
    parser.add_argument("url", help="要抓取的 URL（http/https）")
    parser.add_argument(
        "--out",
        default="_crawler_raw",
        help="輸出資料夾（預設：專案根目錄下的 _crawler_raw）",
    )
    args = parser.parse_args()

    _validate_url(args.url)

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parsed = urlparse(args.url)
    host = _safe_slug(parsed.hostname or "unknown-host")
    path_slug = _safe_slug(parsed.path.strip("/")) or "root"

    # 以 URL hash 避免同名覆蓋
    url_hash = hashlib.sha256(args.url.encode("utf-8")).hexdigest()[:12]
    snap_dir = out_dir / f"{ts}_{host}_{path_slug}_{url_hash}"
    snap_dir.mkdir(parents=True, exist_ok=False)

    settings = CrawlerSettings()
    with CrawlerHttpClient(settings) as client:
        result = client.fetch(args.url)

    body_path = snap_dir / "body.txt"
    meta_path = snap_dir / "meta.json"

    # 先用 text 落地（HTML/JSON 都可）；後續若要保留原始 bytes 再擴充
    body_text = result.text
    body_path.write_text(body_text, encoding="utf-8", errors="replace")

    content_hash = hashlib.sha256(body_text.encode("utf-8", errors="replace")).hexdigest()

    meta = {
        "retrieved_at_utc": ts,
        "url": result.url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "content_sha256": content_hash,
        "headers": dict(result.headers),
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"OK: {args.url}")
    print(f"Saved: {snap_dir}")
    print(f"Status: {result.status_code}  Final: {result.final_url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
