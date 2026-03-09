# backend/services/chat/gate.py
from __future__ import annotations

from dataclasses import dataclass
import unicodedata


@dataclass(slots=True)
class TextValidationReport:
    passed: bool
    sanitized_text: str
    reasons: list[str]
    warnings: list[str]
    removed_chars_count: int
    max_chars: int
    original_length: int
    sanitized_length: int


def validate_text_response(text: str, *, max_chars: int) -> TextValidationReport:
    normalized_text = text.replace("\r\n", "\n")
    sanitized_chars: list[str] = []
    removed_chars_count = 0

    for char in normalized_text:
        if char in {"\n", "\r", "\t"}:
            sanitized_chars.append(char)
            continue
        if unicodedata.category(char).startswith("C"):
            removed_chars_count += 1
            continue
        sanitized_chars.append(char)

    sanitized_text = "".join(sanitized_chars)
    warnings: list[str] = []
    if removed_chars_count > 0:
        warnings.append("control_chars_removed")

    reasons: list[str] = []
    if not sanitized_text.strip():
        reasons.append("empty_text")
    if len(sanitized_text) > max_chars:
        reasons.append("text_too_long")

    return TextValidationReport(
        passed=not reasons,
        sanitized_text=sanitized_text,
        reasons=reasons,
        warnings=warnings,
        removed_chars_count=removed_chars_count,
        max_chars=max_chars,
        original_length=len(text),
        sanitized_length=len(sanitized_text),
    )
