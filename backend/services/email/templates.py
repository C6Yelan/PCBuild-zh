# backend/services/email/templates.py
from __future__ import annotations


def build_signup_verification_email(verify_url: str) -> tuple[str, str]:
    """
    註冊帳號用的驗證信樣板。
    未來如果有「登入驗證」可以另外新增 build_login_verification_email。
    
    回傳: (subject, html)
    """
    subject = "PCBuild 帳號驗證"

    html = f"""
    <!DOCTYPE html>
    <html lang="zh-Hant">
      <head>
        <meta charset="utf-8" />
        <title>{subject}</title>
      </head>
      <body style="font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background-color: #0b1120; color: #e5e7eb; padding: 24px;">
        <div style="max-width: 480px; margin: 0 auto; background-color: #020617; border-radius: 16px; padding: 24px; border: 1px solid #1e293b;">
          <h1 style="font-size: 20px; margin-bottom: 16px;">PCBuild 帳號驗證</h1>
          <p style="margin-bottom: 16px; line-height: 1.6;">
            感謝註冊 PCBuild。請點擊以下按鈕完成信箱驗證：
          </p>
          <p style="text-align: center; margin: 24px 0;">
            <a href="{verify_url}" style="display: inline-block; padding: 10px 18px; border-radius: 999px; background: #22c55e; color: #020617; text-decoration: none; font-weight: 600;">
              完成帳號驗證
            </a>
          </p>
          <p style="font-size: 12px; color: #9ca3af; line-height: 1.6;">
            如果按鈕無法點擊，請將以下連結貼到瀏覽器網址列：
            <br />
            <span style="word-break: break-all; color: #e5e7eb;">{verify_url}</span>
          </p>
          <p style="font-size: 12px; color: #6b7280; margin-top: 24px;">
            如果這不是你本人操作，可以忽略此信。
          </p>
        </div>
      </body>
    </html>
    """

    return subject, html
