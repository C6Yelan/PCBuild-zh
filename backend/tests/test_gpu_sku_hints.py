# backend/tests/test_gpu_sku_hints.py
from backend.services.crawler.parsers.sku_hints.gpu import extract_gpu_hints


def test_rx9070gre_keeps_suffix() -> None:
    title = "SAPPHIRE NITRO+ RX9070GRE 16GB GDDR6"
    sku_hint, extra = extract_gpu_hints(title)
    assert sku_hint == "RX 9070 GRE"
    assert extra["chip_hint"] == "RX 9070 GRE"


def test_rx7650gre_keeps_suffix() -> None:
    title = "PowerColor RX 7650 GRE 8GB"
    sku_hint, extra = extract_gpu_hints(title)
    assert sku_hint == "RX 7650 GRE"
    assert extra["chip_hint"] == "RX 7650 GRE"


def test_bracket_model_code_p10300a() -> None:
    title = "ZOTAC GeForce RTX 5070 12GB (P10300A-10L)"
    _sku_hint, extra = extract_gpu_hints(title)
    assert extra["product_model_hint"] == "P10300A-10L"


def test_bracket_model_code_p10300e() -> None:
    title = "ZOTAC GeForce RTX 5070 12GB (P10300E-10L)"
    _sku_hint, extra = extract_gpu_hints(title)
    assert extra["product_model_hint"] == "P10300E-10L"
