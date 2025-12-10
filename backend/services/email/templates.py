# backend/services/email/templates.py
from __future__ import annotations


def build_signup_verification_email(verify_url: str) -> tuple[str, str]:
    """
    註冊帳號用的驗證信樣板（淺色主題，Gmail 深色模式會自動反轉）。
    """
    subject = "PCBuild 帳號驗證"

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
            PCBuild 帳號驗證
          </h1>

          <p style="margin:0 0 16px; line-height:1.6;">
            感謝註冊 PCBuild。請點擊以下按鈕完成信箱驗證：
          </p>

          <p style="text-align:center; margin:24px 0;">
            <a href="{verify_url}" style="
              display:inline-block;
              padding:10px 18px;
              border-radius:999px;
              background-color:#22c55e;
              color:#ffffff;
              text-decoration:none;
              font-weight:600;
            ">
              完成帳號驗證
            </a>
          </p>

          <p style="margin:0 0 8px; font-size:12px; color:#4b5563; line-height:1.6;">
            如果按鈕無法點擊，請將以下連結貼到瀏覽器網址列：
          </p>

          <p style="
            margin:0 0 16px;
            font-size:12px;
            word-break:break-all;
            color:#2563eb;
          ">
            {verify_url}
          </p>

          <p style="margin:0; font-size:12px; color:#6b7280;">
            如果這不是你本人操作，可以忽略此信。
          </p>
        </div>
      </body>
    </html>
    """

    return subject, html


def build_password_reset_email(reset_url: str) -> tuple[str, str]:
    """
    忘記密碼用的重設密碼信樣板（與註冊驗證信相同版型）。
    """
    subject = "PCBuild 密碼重設"

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
            PCBuild 密碼重設
          </h1>

          <p style="margin:0 0 16px; line-height:1.6;">
            我們收到了你在 PCBuild 提出的「忘記密碼」請求。請在 <strong>20 分鐘內</strong> 點擊下方按鈕重設密碼：
          </p>

          <p style="text-align:center; margin:24px 0;">
            <a href="{reset_url}" style="
              display:inline-block;
              padding:10px 18px;
              border-radius:999px;
              background-color:#22c55e;
              color:#ffffff;
              text-decoration:none;
              font-weight:600;
            ">
              前往重設密碼
            </a>
          </p>

          <p style="margin:0 0 8px; font-size:12px; color:#4b5563; line-height:1.6;">
            如果按鈕無法點擊，請將以下連結貼到瀏覽器網址列：
          </p>

          <p style="
            margin:0 0 16px;
            font-size:12px;
            word-break:break-all;
            color:#2563eb;
          ">
            {reset_url}
          </p>

          <p style="margin:0 0 4px; font-size:12px; color:#6b7280;">
            若你並未要求重設密碼，可以放心忽略此信，你的帳號不會有任何變更。
          </p>

          <p style="margin:0; font-size:12px; color:#6b7280;">
            出於安全考量，此重設連結在 20 分鐘後會自動失效。
          </p>
        </div>
      </body>
    </html>
    """

    return subject, html

