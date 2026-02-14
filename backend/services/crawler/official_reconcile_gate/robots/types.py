from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

RobotsDirective = Literal["allow", "disallow"]
RobotsMode = Literal["rules", "allow_all", "disallow_all"]
RobotsFetchStatus = Literal["success", "unavailable", "unreachable", "redirected", "parse_error"]


@dataclass(frozen=True)
class RobotsRule:
    directive: RobotsDirective
    pattern: str


@dataclass(frozen=True)
class RobotsGroup:
    user_agents: list[str] = field(default_factory=list)
    rules: list[RobotsRule] = field(default_factory=list)


@dataclass(frozen=True)
class RobotsPolicy:
    mode: RobotsMode
    groups: list[RobotsGroup] = field(default_factory=list)
    note: str = ""

    @staticmethod
    def allow_all(note: str = "") -> "RobotsPolicy":
        return RobotsPolicy(mode="allow_all", groups=[], note=note)

    @staticmethod
    def disallow_all(note: str = "") -> "RobotsPolicy":
        return RobotsPolicy(mode="disallow_all", groups=[], note=note)


@dataclass(frozen=True)
class RobotsFetchResult:
    status: RobotsFetchStatus
    policy: RobotsPolicy
    robots_url: str
    final_url: str | None = None
    http_status: int | None = None
    error: str | None = None
    fetched_at: float = 0.0
