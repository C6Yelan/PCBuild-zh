# backend/tests/chat/inference/test_demand_inference.py
from backend.services.chat.contracts import ChatMessage
from backend.services.chat.demand_inference import infer_chat_demand


def test_infer_chat_demand_for_explicit_build_request() -> None:
    demand = infer_chat_demand("幫我配一台 2 萬內文書機", history=None)

    assert demand == {
        "categories": ["CPU", "MB", "RAM", "SSD", "PSU", "CASE"],
        "top_k": 5,
        "env": "prod",
    }


def test_infer_chat_demand_adds_gpu_when_request_is_explicit() -> None:
    demand = infer_chat_demand("幫我配一台 4 萬內遊戲機，要有獨顯", history=None)

    assert demand is not None
    assert demand["categories"] == ["CPU", "MB", "RAM", "SSD", "PSU", "CASE", "GPU"]


def test_infer_chat_demand_returns_none_for_general_chat() -> None:
    assert infer_chat_demand("你好，今天天氣不錯", history=None) is None


def test_infer_chat_demand_keeps_single_component_question_narrow() -> None:
    demand = infer_chat_demand("最近有推薦的 CPU 嗎？", history=None)

    assert demand == {
        "categories": ["CPU"],
        "top_k": 5,
        "env": "prod",
    }


def test_infer_chat_demand_keeps_component_question_narrow_even_with_budget() -> None:
    demand = infer_chat_demand("CPU 預算 1 萬內有什麼推薦？", history=None)

    assert demand == {
        "categories": ["CPU"],
        "top_k": 5,
        "env": "prod",
    }


def test_infer_chat_demand_returns_none_for_budget_only_chat_without_build_context() -> None:
    assert infer_chat_demand("預算 2 萬內", history=None) is None


def test_infer_chat_demand_detects_recommend_a_pc_as_build_intent() -> None:
    demand = infer_chat_demand("推薦一台 3 萬內的電腦", history=None)

    assert demand == {
        "categories": ["CPU", "MB", "RAM", "SSD", "PSU", "CASE"],
        "top_k": 5,
        "env": "prod",
    }


def test_infer_chat_demand_can_use_recent_user_history() -> None:
    history = [
        ChatMessage(role="user", content="我想組一台文書機"),
        ChatMessage(role="assistant", content="可以，預算大概多少？"),
    ]

    demand = infer_chat_demand("預算 2 萬內", history=history)

    assert demand == {
        "categories": ["CPU", "MB", "RAM", "SSD", "PSU", "CASE"],
        "top_k": 5,
        "env": "prod",
    }
