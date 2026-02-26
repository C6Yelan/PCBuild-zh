// web/assets/js/pages/login.js
const form = document.getElementById("login-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const loginBtn = document.getElementById("login-btn");
const errorEl = document.getElementById("error");
const emailField = document.querySelector('[data-field="email"]');
const passwordField = document.querySelector('[data-field="password"]');

// 已登入者不應停留在登入頁：直接導回首頁（用 replace 避免返回又回到登入頁）
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
    // 後端離線 / 網路錯誤：不要強制跳轉，讓使用者仍可看到登入頁與錯誤訊息
}
})();

function clearFieldErrors() {
[emailField, passwordField].forEach((field) => {
    if (!field) return;
    field.classList.remove("field-error");
    const msgEl = field.querySelector(".field-error-text");
    if (msgEl) msgEl.textContent = "";
});
}

function clearSingleFieldError(field) {
if (!field) return;
field.classList.remove("field-error");
const msgEl = field.querySelector(".field-error-text");
if (msgEl) msgEl.textContent = "";
refreshGlobalErrorFromFields();
}

function setFieldError(field, message) {
if (!field) return;
field.classList.add("field-error");
const msgEl = field.querySelector(".field-error-text");
if (msgEl) msgEl.textContent = message || "";
}

function refreshGlobalErrorFromFields() {
const fields = [emailField, passwordField];
const hasError = fields.some(
    (field) => field && field.classList.contains("field-error")
);
if (!hasError) {
    errorEl.textContent = "";
}
}

function validateEmailField() {
if (!emailField) return;
clearSingleFieldError(emailField);
const value = emailInput.value.trim();

if (!value) {
    setFieldError(emailField, "請輸入 Email。");
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

function validatePasswordField() {
if (!passwordField) return;
clearSingleFieldError(passwordField);
const value = passwordInput.value;

if (!value) {
    setFieldError(passwordField, "請輸入密碼。");
    return;
}
if (value.length < 8) {
    setFieldError(passwordField, "密碼長度至少需 8 個字元。");
}
}

// blur 時檢查，不在每次 keypress 檢查
emailInput.addEventListener("blur", validateEmailField);
passwordInput.addEventListener("blur", validatePasswordField)

form.addEventListener("submit", async (e) => {
e.preventDefault();
errorEl.textContent = "";
clearFieldErrors();

// 先用欄位驗證函式算一遍錯誤，不再重複寫 if 判斷
validateEmailField();
validatePasswordField();

const fields = [emailField, passwordField];
const hasError = fields.some(
    (field) => field && field.classList.contains("field-error")
);

if (hasError) {
    if (!errorEl.textContent) {
    errorEl.textContent = "請修正紅色標示的欄位。";
    }
    return;
}

const email = emailInput.value.trim();
const password = passwordInput.value;

loginBtn.disabled = true;
const originalText = loginBtn.textContent;
loginBtn.textContent = "登入中…";

try {
    const resp = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({
        email,
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
        const errors =
            (data && data.detail && data.detail.errors) ? data.detail.errors : {};
        const emailError = String(errors.email || "");

        // 顯示欄位錯誤
        if (errors.email) {
            setFieldError(emailField, emailError);
        }
        if (errors.credentials) {
            errorEl.textContent = String(errors.credentials || "");
        } else if (!errorEl.textContent) {
            errorEl.textContent = "登入失敗，請稍後再試。";
        }
        return;
        }

    // 登入成功：session cookie 已設定，導回首頁
    window.location.href = "/";
} catch (err) {
    errorEl.textContent = "登入失敗，請稍後再試。";
} finally {
    loginBtn.disabled = false;
    loginBtn.textContent = originalText;
}
});

// === Password visibility toggle（顯示中 -> eye-off；隱藏中 -> eye） ===
(function setupPwToggle() {
  const setHiddenAttr = (el, hide) => {
    if (!el) return;
    if (hide) el.setAttribute("hidden", "");
    else el.removeAttribute("hidden");
  };

  const syncBtnState = (btn) => {
    const targetId =
      btn.getAttribute("data-pw-target") || btn.getAttribute("aria-controls");
    if (!targetId) return;

    const input = document.getElementById(targetId);
    if (!input) return;

    const isShowing = btn.getAttribute("aria-pressed") === "true";
    const expectedType = isShowing ? "text" : "password";
    if (input.type !== expectedType) {
      try {
        input.type = expectedType;
      } catch (_) {}
    }

    const eye = btn.querySelector(".pw-icon-eye");
    const eyeOff = btn.querySelector(".pw-icon-eye-off");
    setHiddenAttr(eye, isShowing);
    setHiddenAttr(eyeOff, !isShowing);

    const showLabel =
      btn.getAttribute("data-label-show") || "顯示密碼（注意：在公開環境可能外露）";
    const hideLabel = btn.getAttribute("data-label-hide") || "隱藏密碼";
    const actionLabel = isShowing ? hideLabel : showLabel;
    btn.setAttribute("aria-label", actionLabel);
    btn.setAttribute("title", actionLabel);
  };

  // Init：載入時把 input type / icon 與 aria-pressed 同步
  document.querySelectorAll(".pw-toggle").forEach(syncBtnState);

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

    btn.setAttribute("aria-pressed", nextPressed ? "true" : "false");
    syncBtnState(btn);

    input.focus({ preventScroll: true });
  });
})();
