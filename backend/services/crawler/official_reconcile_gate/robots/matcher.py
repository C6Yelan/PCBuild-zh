from __future__ import annotations

from .types import RobotsGroup, RobotsPolicy, RobotsRule


def is_allowed(
    policy: RobotsPolicy,
    user_agent_token: str,
    url_path: str,
) -> tuple[bool, dict[str, object] | None]:
    if policy.mode == "allow_all":
        return (True, None)
    if policy.mode == "disallow_all":
        return (False, None)

    rules = _effective_rules(policy, user_agent_token)
    if not rules:
        return (True, None)

    path = _normalize_url_path(url_path)
    best_rule: RobotsRule | None = None
    best_match_len = -1

    for rule in rules:
        match_len = _match_len(rule.pattern, path)
        if match_len < 0:
            continue
        if match_len > best_match_len:
            best_match_len = match_len
            best_rule = rule
            continue
        if match_len == best_match_len and best_rule is not None:
            if best_rule.directive == "disallow" and rule.directive == "allow":
                best_rule = rule

    if best_rule is None:
        return (True, None)

    allowed = best_rule.directive == "allow"
    matched = {
        "directive": best_rule.directive,
        "pattern": best_rule.pattern,
        "match_len": best_match_len,
    }
    return (allowed, matched)


def has_matching_group(policy: RobotsPolicy, user_agent_token: str) -> bool:
    if policy.mode != "rules":
        return True
    ua = (user_agent_token or "").lower()
    if not ua:
        return False
    specific, wildcard = _split_groups(policy, ua)
    if specific:
        return True
    return bool(wildcard)


def _effective_rules(policy: RobotsPolicy, user_agent_token: str) -> list[RobotsRule]:
    ua = (user_agent_token or "").lower()
    if not ua:
        return []
    specific, wildcard = _split_groups(policy, ua)
    target_groups = specific if specific else wildcard
    out: list[RobotsRule] = []
    for group in target_groups:
        out.extend(group.rules)
    return out


def _split_groups(policy: RobotsPolicy, ua: str) -> tuple[list[RobotsGroup], list[RobotsGroup]]:
    specific_groups: list[RobotsGroup] = []
    wildcard_groups: list[RobotsGroup] = []
    for group in policy.groups:
        for token in group.user_agents:
            token_lower = (token or "").lower()
            if not token_lower:
                continue
            if token_lower == "*":
                wildcard_groups.append(group)
                continue
            if ua.startswith(token_lower):
                specific_groups.append(group)
                break
    return (specific_groups, wildcard_groups)


def _normalize_url_path(value: str) -> str:
    if not value:
        return "/"
    if value.startswith("/"):
        return value
    return "/" + value


def _match_len(pattern: str, path: str) -> int:
    # RFC9309 baseline: matching starts with first octet.
    if pattern == "":
        return 0
    if path.startswith(pattern):
        return len(pattern)
    return -1
