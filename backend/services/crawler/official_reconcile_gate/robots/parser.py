from __future__ import annotations

from .types import RobotsGroup, RobotsPolicy, RobotsRule


def parse_robots_txt(text: str) -> RobotsPolicy:
    groups: list[RobotsGroup] = []
    current_user_agents: list[str] = []
    current_rules: list[RobotsRule] = []

    def flush_group() -> None:
        nonlocal current_user_agents, current_rules
        if not current_user_agents:
            current_rules = []
            return
        groups.append(
            RobotsGroup(
                user_agents=list(_dedupe_preserve_order(current_user_agents)),
                rules=list(current_rules),
            )
        )
        current_user_agents = []
        current_rules = []

    for raw_line in (text or "").splitlines():
        line = _strip_comment(raw_line).strip()
        if not line:
            flush_group()
            continue

        if ":" not in line:
            continue
        field, value = line.split(":", 1)
        field_name = field.strip().lower()
        field_value = value.strip()

        if field_name == "user-agent":
            if current_rules:
                flush_group()
            token = field_value.lower()
            if token:
                current_user_agents.append(token)
            continue

        if field_name in ("allow", "disallow"):
            if not current_user_agents:
                continue
            current_rules.append(
                RobotsRule(
                    directive="allow" if field_name == "allow" else "disallow",
                    pattern=field_value,
                )
            )
            continue

        # Ignore unknown fields.
        continue

    flush_group()
    return RobotsPolicy(mode="rules", groups=groups)


def _strip_comment(line: str) -> str:
    if "#" not in line:
        return line
    return line.split("#", 1)[0]


def _dedupe_preserve_order(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
