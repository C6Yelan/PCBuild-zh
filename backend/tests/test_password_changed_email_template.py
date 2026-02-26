# backend/tests/test_password_changed_email_template.py
from backend.services.email.templates.password_changed import build_password_changed_email


def test_password_changed_email_template_contains_security_notice() -> None:
    subject, html = build_password_changed_email()

    assert subject == "PCBuild 密碼已變更通知"
    assert "你的 PCBuild 帳號密碼已成功更新。" in html
    assert "如果這次變更不是你本人操作" in html
    assert "忘記密碼" in html
