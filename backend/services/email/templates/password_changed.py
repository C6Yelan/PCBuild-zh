# backend/services/email/templates/password_changed.py
from __future__ import annotations


def build_password_changed_email() -> tuple[str, str]:
    """
    密碼已修改通知信樣板。
    """
    subject = "PCBuild 密碼已變更通知"

    html = f"""
    <!DOCTYPE html>
    <html lang="zh-Hant">
      <head>
        <meta charset="utf-8" />
        <title>{subject}</title>
      </head>
      <body style="
        margin:0;
        padding:24px;
        background-color:#ffffff;
        color:#111827;
        font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
      ">
        <div style="
          max-width:480px;
          margin:0 auto;
          background-color:#f9fafb;
          border-radius:16px;
          padding:24px;
          border:1px solid #e5e7eb;
        ">
          <h1 style="font-size:20px; margin:0 0 16px;">
            PCBuild 密碼已變更
          </h1>

          <p style="margin:0 0 16px; line-height:1.6;">
            你的 PCBuild 帳號密碼已成功更新。
          </p>

          <p style="margin:0 0 16px; line-height:1.6;">
            如果這次變更不是你本人操作，請立即使用「忘記密碼」重新設定密碼，以確保帳號安全。
          </p>

          <p style="margin:0; font-size:12px; color:#6b7280;">
            這是一封系統自動發送的安全通知信。
          </p>
        </div>
      </body>
    </html>
    """

    return subject, html
