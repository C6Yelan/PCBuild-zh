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
const REGISTER_GENERIC_OK_MESSAGE =
    "已收到你的請求。若帳號符合條件，你會收到一封 Email 提供下一步指引。若你已註冊，請直接登入或使用忘記密碼。";

const genericActionsEl = document.createElement("p");
genericActionsEl.className = "hint";
genericActionsEl.style.display = "none";
genericActionsEl.style.marginTop = "4px";
genericActionsEl.style.textAlign = "center";

const loginCta = document.createElement("a");
loginCta.href = "/login.html";
loginCta.textContent = "前往登入";

const divider = document.createTextNode(" · ");

const forgotCta = document.createElement("a");
forgotCta.href = "/forgot-password.html";
forgotCta.textContent = "忘記密碼";

genericActionsEl.appendChild(loginCta);
genericActionsEl.appendChild(divider);
genericActionsEl.appendChild(forgotCta);
errorEl.insertAdjacentElement("afterend", genericActionsEl);

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
    clearGlobalError();
}
}

function clearGlobalError() {
errorEl.textContent = "";
errorEl.style.color = "";
}

function setGlobalError(message) {
errorEl.textContent = message || "";
errorEl.style.color = "";
}

function clearGenericRegisterNotice() {
genericActionsEl.style.display = "none";
}

function showGenericRegisterNotice() {
errorEl.textContent = REGISTER_GENERIC_OK_MESSAGE;
errorEl.style.color = "var(--text)";
genericActionsEl.style.display = "";
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

function sanitizeRegisterFieldError(fieldName, message) {
const raw = String(message || "").trim();
if (!raw) return "";

const looksLikeAccountState =
    /已註冊|已存在|不存在|already|exists|not\s+found|registered|taken|verified/i.test(raw);
if (!looksLikeAccountState) return raw;

switch (fieldName) {
    case "email":
    return "請輸入正確的 Email 格式。";
    case "username":
    return "使用者名稱格式不正確，請重新確認。";
    default:
    return "輸入資料有誤，請重新確認。";
}
}

form.addEventListener("submit", async (e) => {
e.preventDefault();
clearGlobalError();
clearGenericRegisterNotice();

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
    setGlobalError("請修正紅色標示的欄位。");
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
    let hasFieldErrors = false;

    if (
        (resp.status === 400 || resp.status === 422) &&
        data &&
        data.detail
    ) {
        const globalMessages = [];
        if (typeof data.detail === "object" && !Array.isArray(data.detail)) {
        const errors = data.detail.errors || {};
        Object.entries(errors).forEach(([field, rawMsg]) => {
            const fieldMsg = sanitizeRegisterFieldError(field, rawMsg);
            switch (field) {
            case "email":
                setFieldError(emailField, fieldMsg);
                hasFieldErrors = true;
                break;
            case "username":
                setFieldError(usernameField, fieldMsg);
                hasFieldErrors = true;
                break;
            case "password":
                setFieldError(passwordField, fieldMsg);
                hasFieldErrors = true;
                break;
            case "password_confirm":
                setFieldError(passwordConfirmField, fieldMsg);
                hasFieldErrors = true;
                break;
            case "_global":
                globalMessages.push(fieldMsg);
                break;
            default:
                globalMessages.push(fieldMsg);
                break;
            }
        });
        } else if (Array.isArray(data.detail)) {
        data.detail.forEach((item) => {
            const loc = Array.isArray(item && item.loc) ? item.loc : [];
            const field = String(loc[loc.length - 1] || "");
            const fieldMsg = sanitizeRegisterFieldError(
            field,
            (item && item.msg) || "輸入資料有誤。"
            );
            switch (field) {
            case "email":
                setFieldError(emailField, fieldMsg);
                hasFieldErrors = true;
                break;
            case "username":
                setFieldError(usernameField, fieldMsg);
                hasFieldErrors = true;
                break;
            case "password":
                setFieldError(passwordField, fieldMsg);
                hasFieldErrors = true;
                break;
            case "password_confirm":
                setFieldError(passwordConfirmField, fieldMsg);
                hasFieldErrors = true;
                break;
            default:
                break;
            }
        });
        }

        if (globalMessages.length > 0) {
        msg = globalMessages.join(" ");
        } else if (hasFieldErrors) {
        msg = "請修正紅色標示的欄位。";
        }
    }

    setGlobalError(msg);
    return;
    }

    if (data && data.ok === true) {
    showGenericRegisterNotice();
    return;
    }

    setGlobalError("註冊失敗，請稍後再試。");
} catch (err) {
    setGlobalError("註冊失敗，請稍後再試。");
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
