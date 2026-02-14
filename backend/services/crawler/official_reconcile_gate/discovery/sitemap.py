from __future__ import annotations

import gzip
from xml.etree import ElementTree as ET


class SitemapParseError(ValueError):
    def __init__(self, reason: str, detail: str = "") -> None:
        message = reason if not detail else f"{reason}: {detail}"
        super().__init__(message)
        self.reason = reason
        self.detail = detail


def decode_sitemap_bytes(
    payload: bytes,
    *,
    url: str,
    content_type: str = "",
    content_encoding: str = "",
) -> bytes:
    if not isinstance(payload, (bytes, bytearray)):
        raise SitemapParseError("invalid_payload_type", type(payload).__name__)

    if not _should_decode_gzip(bytes(payload), url=url):
        return bytes(payload)

    try:
        return gzip.decompress(bytes(payload))
    except OSError as exc:
        raise SitemapParseError("invalid_gzip", str(exc)) from exc


def parse_sitemap(xml_bytes: bytes) -> tuple[str, list[str]]:
    root = _parse_xml_root(xml_bytes)
    root_name = _local_name(root.tag).lower()
    if root_name == "urlset":
        return ("urlset", _collect_locs(root, parent_name="url"))
    if root_name == "sitemapindex":
        return ("index", _collect_locs(root, parent_name="sitemap"))
    raise SitemapParseError("unknown_root", root_name)


def _collect_locs(root: ET.Element, *, parent_name: str) -> list[str]:
    out: list[str] = []
    for child in list(root):
        if _local_name(child.tag).lower() != parent_name:
            continue
        loc = ""
        for loc_node in list(child):
            if _local_name(loc_node.tag).lower() != "loc":
                continue
            text = (loc_node.text or "").strip()
            if text:
                loc = text
                break
        if loc:
            out.append(loc)
    return out


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _should_decode_gzip(
    payload: bytes,
    *,
    url: str,
) -> bool:
    lower_url = (url or "").lower()
    return lower_url.endswith(".gz") or payload[:2] == b"\x1f\x8b"


def _parse_xml_root(xml_bytes: bytes) -> ET.Element:
    if not isinstance(xml_bytes, (bytes, bytearray)):
        raise SitemapParseError("invalid_payload_type", type(xml_bytes).__name__)

    errors: list[str] = []
    for candidate in _xml_parse_candidates(bytes(xml_bytes)):
        try:
            return ET.fromstring(candidate)
        except ET.ParseError as exc:
            errors.append(str(exc))
            continue

    detail = errors[-1] if errors else "unable to parse sitemap XML"
    raise SitemapParseError("invalid_xml", detail)


def _xml_parse_candidates(raw: bytes) -> list[bytes]:
    candidates: list[bytes] = [raw]
    for encoding in ("utf-8-sig", "utf-8"):
        normalized_text = raw.decode(encoding, "ignore").lstrip("\ufeff \t\r\n")
        normalized = normalized_text.encode("utf-8")
        if normalized and normalized not in candidates:
            candidates.append(normalized)
    return candidates
