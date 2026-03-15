from __future__ import annotations

import logging

from backend.core import obs_events, seclog


def test_log_security_keeps_security_prefix_and_drops_sensitive_keys(monkeypatch) -> None:
    events: list[tuple[int, str]] = []

    monkeypatch.setattr(
        seclog._logger,
        "log",
        lambda level, msg: events.append((level, msg)),
    )

    seclog.log_security(
        "password_reset_email_sent",
        user_id="u-1",
        token="secret-token",
    )

    assert events == [
        (
            logging.INFO,
            "category=security event=password_reset_email_sent "
            "client=- method=- path=- user_id=u-1",
        )
    ]


def test_log_loki_event_keeps_prefix_order_and_structured_json(monkeypatch) -> None:
    logger = logging.getLogger("pcbuild.pipeline.test")
    events: list[tuple[int, str]] = []

    monkeypatch.delenv("PCBUILD_LOG_TO_PID1", raising=False)
    monkeypatch.setattr(
        logger,
        "log",
        lambda level, msg: events.append((level, msg)),
    )

    obs_events.log_loki_event(
        logger,
        event="t10_fetch",
        source="coolpc",
        stage="fetch",
        env="prod",
        retry=2,
        note="hello world",
        payload={"ok": True},
    )

    assert events == [
        (
            logging.INFO,
            'category=pipeline event=t10_fetch source=coolpc stage=fetch env=prod '
            'note="hello world" payload="{\\"ok\\":true}" retry=2',
        )
    ]
