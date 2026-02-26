// web/assets/js/pages/register.js
const form = document.getElementById("register-form");
const emailInput = document.getElementById("email");
const usernameInput = document.getElementById("username");
const passwordInput = document.getElementById("password");
const passwordConfirmInput = document.getElementById("password-confirm");
const registerBtn = document.getElementById("register-btn");
const errorEl = document.getElementById("error");
const emailField = document.querySelector('[data-field="email"]');
const usernameField = document.querySelector('[data-field="username"]');
const passwordField = document.querySelector('[data-field="password"]');
const passwordConfirmField = document.querySelector('[data-field="password-confirm"]');

// 已登入者不應停留在註冊頁：直接導回首頁（用 replace 避免返回又回到註冊頁）
(async function redirectIfAuthed() {
try {
    const resp = await fetch("/api/auth/me", {
    method: "GET",
    credentials: "same-origin",
    });

    if (resp.ok) {
    window.location.replace("/");
    }
} catch (_) {
    // 後端離線 / 網路錯誤：不要強制跳轉，讓使用者仍可看到註冊頁與錯誤訊息
}
})();

function refreshGlobalErrorFromFields() {
const fields = [
    emailField,
    usernameField,
    passwordField,
    passwordConfirmField,
];
const hasError = fields.some(
    (field) => field && field.classList.contains("field-error")
);

// 當所有欄位都沒有紅框錯誤，就把下方總體錯誤訊息清掉
if (!hasError) {
    errorEl.textContent = "";
}
}

emailInput.addEventListener("blur", validateEmailField);
usernameInput.addEventListener("blur", validateUsernameField);
passwordInput.addEventListener("blur", validatePasswordField);
passwordConfirmInput.addEventListener("blur", validatePasswordConfirmField);

function clearFieldErrors() {
[emailField, usernameField, passwordField, passwordConfirmField].forEach(
    (field) => {
    if (!field) return;
    field.classList.remove("field-error");
    const msgEl = field.querySelector(".field-error-text");
    if (msgEl) msgEl.textContent = "";
    }
);
}

function clearSingleFieldError(field) {
if (!field) return;
field.classList.remove("field-error");
const msgEl = field.querySelector(".field-error-text");
if (msgEl) msgEl.textContent = "";

// 這個欄位改正後，檢查是不是所有紅框都消失了
refreshGlobalErrorFromFields();
}

function validateEmailField() {
if (!emailField) return;
clearSingleFieldError(emailField);
const value = emailInput.value.trim();

if (!value) {
    setFieldError(emailField, "請填寫 Email。");
    return;
}
if (value.length > 50) {
    setFieldError(emailField, "Email 最多 50 個字元。");
    return;
}
if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    setFieldError(emailField, "請輸入正確的 Email 格式。");
}
}

function validateUsernameField() {
if (!usernameField) return;
clearSingleFieldError(usernameField);
const value = usernameInput.value.trim();

if (!value) {
    setFieldError(usernameField, "請填寫使用者名稱。");
    return;
}
if (value.length > 50) {
    setFieldError(usernameField, "使用者名稱最多 50 個字元。");
}
}

function validatePasswordField() {
if (!passwordField) return;
clearSingleFieldError(passwordField);
const value = passwordInput.value;

if (!value) {
    setFieldError(passwordField, "請填寫密碼。");
    return;
}
if (value.length < 8) {
    setFieldError(passwordField, "密碼長度至少需 8 個字元。");
}
}

function validatePasswordConfirmField() {
if (!passwordConfirmField) return;
clearSingleFieldError(passwordConfirmField);
const value = passwordConfirmInput.value;

if (!value) {
    setFieldError(passwordConfirmField, "請再次輸入密碼。");
    return;
}
if (passwordInput.value && value !== passwordInput.value) {
    setFieldError(passwordConfirmField, "兩次輸入的密碼不一致。");
}
}

function setFieldError(field, message) {
if (!field) return;
field.classList.add("field-error");
const msgEl = field.querySelector(".field-error-text");
if (msgEl) msgEl.textContent = message || "";
}

form.addEventListener("submit", async (e) => {
e.preventDefault();
errorEl.textContent = "";

// 1. 先用欄位自己的驗證函式刷新一次所有錯誤
validateEmailField();
validateUsernameField();
validatePasswordField();
validatePasswordConfirmField();

const fields = [
    emailField,
    usernameField,
    passwordField,
    passwordConfirmField,
];
const hasError = fields.some(
    (field) => field && field.classList.contains("field-error")
);

// 若目前仍有任何欄位錯誤，就阻止送出
if (hasError) {
    if (!errorEl.textContent) {
    errorEl.textContent = "請修正紅色標示的欄位。";
    }
    return;
}

// 2. 沒有前端錯誤才送到後端
const email = emailInput.value.trim();
const username = usernameInput.value.trim();
const password = passwordInput.value;

registerBtn.disabled = true;
const originalText = registerBtn.textContent;
registerBtn.textContent = "註冊中…";

try {
    const resp = await fetch("/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({
        email,
        username,
        password,
    }),
    });

    let data = null;
    try {
    data = await resp.json();
    } catch {
    data = null;
    }

    if (!resp.ok) {
    let msg = "註冊失敗，請稍後再試。";

    if (
        resp.status === 400 &&
        data &&
        data.detail &&
        typeof data.detail === "object"
    ) {
        const errors = data.detail.errors || {};
        const globalMessages = [];

        Object.entries(errors).forEach(([field, rawMsg]) => {
        const fieldMsg = String(rawMsg || "");
        switch (field) {
            case "email":
            setFieldError(emailField, fieldMsg);
            break;
            case "username":
            setFieldError(usernameField, fieldMsg);
            break;
            case "password":
            setFieldError(passwordField, fieldMsg);
            break;
            case "password_confirm":
            setFieldError(passwordConfirmField, fieldMsg);
            break;
            case "_global":
            globalMessages.push(fieldMsg);
            break;
            default:
            globalMessages.push(fieldMsg);
            break;
        }
        });

        if (globalMessages.length > 0) {
        msg = globalMessages.join(" ");
        } else {
        msg = "請修正紅色標示的欄位。";
        }
    }

    errorEl.textContent = msg;
    return;
    }

// 3. 註冊成功：後端已建立帳號並寄出驗證信（此階段不建立登入態 / 不寫入 Cookie）
//    前端只需導向「請驗證電子郵件」說明頁，不在網址帶出任何 Email 或 token
//
// Pending 頁 UX：用 sessionStorage 暫存必要資訊（不放 URL、不放 localStorage）。
// 注意：sessionStorage 可被 JS 讀取；為降低留存風險，只存短期且後續會清除。
try {
    const now = Date.now();

    // UI-only：供 Pending 頁「可刷新可恢復」用，不等同 token 有效期
    const EXPIRES_IN_MINUTES = 30;

    sessionStorage.setItem("pcbuild_verify_email", email);
    sessionStorage.setItem(
    "pcbuild_verify_email_expires_at",
    String(now + EXPIRES_IN_MINUTES * 60 * 1000)
    );

    // 註冊流程進入 Pending：完成驗證後通常會引導去登入（後續 Pending/Success 會用到）
    sessionStorage.setItem("pcbuild_verify_flow", "signup");

    // 註冊當下後端已寄出驗證信：直接讓 Pending 頁顯示 60 秒冷卻倒數
    sessionStorage.setItem("pcbuild_verify_cooldown_until", String(now + 60 * 1000));
} catch (e) {
    // 若瀏覽器禁用 storage 或滿額，不影響註冊流程
}

window.location.href = "/verify-email-pending.html";
} catch (err) {
    errorEl.textContent = "註冊失敗，請稍後再試。";
} finally {
    registerBtn.disabled = false;
    registerBtn.textContent = originalText;
}
});

// === Password visibility toggle（register 專用；以 attribute 控制 SVG hidden） ===
(function setupPwToggle() {
  const setHiddenAttr = (el, hide) => {
    if (!el) return;
    if (hide) el.setAttribute("hidden", "");
    else el.removeAttribute("hidden");
  };

  const syncBtnIcons = (btn) => {
    const isShowing = btn.getAttribute("aria-pressed") === "true";
    const eye = btn.querySelector(".pw-icon-eye");
    const eyeOff = btn.querySelector(".pw-icon-eye-off");
    if (!eye || !eyeOff) return;

    // 狀態式 icon：show -> eye；hide -> eye-off
    setHiddenAttr(eye, !isShowing);
    setHiddenAttr(eyeOff, isShowing);
  };

  // Init：載入時把 icon 與 aria-pressed 同步，避免初始顯示錯
  document.querySelectorAll(".pw-toggle").forEach(syncBtnIcons);

  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".pw-toggle");
    if (!btn) return;

    e.preventDefault();

    const targetId =
      btn.getAttribute("data-pw-target") || btn.getAttribute("aria-controls");
    if (!targetId) return;

    const input = document.getElementById(targetId);
    if (!input) return;

    const isPressed = btn.getAttribute("aria-pressed") === "true";
    const nextPressed = !isPressed;

    // pressed=true 代表「顯示密碼」
    try {
      input.type = nextPressed ? "text" : "password";
    } catch (_) {
      return;
    }

    btn.setAttribute("aria-pressed", nextPressed ? "true" : "false");
    syncBtnIcons(btn);

    // 保持輸入體驗（避免點 icon 後游標不見）
    input.focus({ preventScroll: true });
  });
})();

