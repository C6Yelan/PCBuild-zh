from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def normalize_official_url(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.netloc.lower() != "rog.asus.com":
        return url

    path = parsed.path or ""
    if path.startswith("/globalarticles/"):
        suffix = path[len("/globalarticles/") :]
        normalized_path = f"/articles/{suffix}"
    elif path.startswith("/globaltag/"):
        suffix = path[len("/globaltag/") :]
        normalized_path = f"/tag/{suffix}"
        if not normalized_path.endswith("/"):
            normalized_path = f"{normalized_path}/"
    else:
        return url

    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, parsed.query, parsed.fragment))
