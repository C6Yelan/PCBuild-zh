// web/assets/js/pages/forgot-password.js
const form = document.getElementById("forgot-form");
const emailInput = document.getElementById("email");
const forgotBtn = document.getElementById("forgot-btn");
const errorEl = document.getElementById("error");
const emailField = document.querySelector('[data-field="email"]');

// ===== 冷卻倒數（後端為主） =====
// 後端在 429 時會回 Retry-After: <seconds>
// 前端只做 UI 倒數與 reload 復原（sessionStorage）
const COOLDOWN_KEY = "pcbuild_forgot_cooldown_until"; // 毫秒 timestamp
const BTN_BASE_TEXT = forgotBtn.textContent.trim();
const COOLDOWN_FALLBACK_SECONDS = 60;
let cooldownTimer = null;

function setGlobalError(message, source) {
errorEl.textContent = message || "";
errorEl.dataset.source = source || ""; // "fields" | "server" | "cooldown" | ""
}

function _parseRetryAfterSeconds(resp) {
const raw = resp.headers.get("Retry-After");
if (!raw) return null;
const n = parseInt(raw, 10);
return Number.isFinite(n) && n > 0 ? n : null;
}

function _readCooldownUntilMs() {
try {
    const raw = sessionStorage.getItem(COOLDOWN_KEY);
    const ms = raw ? parseInt(raw, 10) : NaN;
    return Number.isFinite(ms) ? ms : null;
} catch {
    return null;
}
}

function _writeCooldownUntilMs(untilMs) {
try {
    sessionStorage.setItem(COOLDOWN_KEY, String(untilMs));
} catch {
    // ignore
}
}

function _clearCooldownStorage() {
try {
    sessionStorage.removeItem(COOLDOWN_KEY);
} catch {
    // ignore
}
}

function _startCooldown(untilMs) {
if (cooldownTimer) {
    clearInterval(cooldownTimer);
    cooldownTimer = null;
}

const tick = () => {
    const now = Date.now();
    const remaining = Math.max(0, Math.ceil((untilMs - now) / 1000));

    if (remaining <= 0) {
    _clearCooldownStorage();
    forgotBtn.disabled = false;
    forgotBtn.textContent = BTN_BASE_TEXT;
    if (errorEl.dataset.source === "cooldown") {
        setGlobalError("", "");
    }
    if (cooldownTimer) {
        clearInterval(cooldownTimer);
        cooldownTimer = null;
    }
    return;
    }

    forgotBtn.disabled = true;

    // 按鈕內顯示倒數（不加「秒」字）
    forgotBtn.textContent = `${BTN_BASE_TEXT}(${remaining})`;

    // 下方 global 只顯示固定提示（不再顯示倒數）
    setGlobalError("若需再次寄送，請稍候再試。", "cooldown");
};

tick();
cooldownTimer = setInterval(tick, 250);
}

function _applyCooldownSeconds(seconds) {
const untilMs = Date.now() + seconds * 1000;
_writeCooldownUntilMs(untilMs);
_startCooldown(untilMs);
}

function refreshGlobalErrorFromFields() {
const fields = [emailField];
const hasError = fields.some(
    (field) => field && field.classList.contains("field-error"),
);

if (!hasError && errorEl.dataset.source === "fields") {
    setGlobalError("", "");
}
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

emailInput.addEventListener("blur", validateEmailField);

// 頁面載入時嘗試復原冷卻倒數（允許 reload 後繼續倒數）
(function restoreCooldownOnLoad() {
const untilMs = _readCooldownUntilMs();
if (untilMs && untilMs > Date.now()) {
    _startCooldown(untilMs);
} else {
    _clearCooldownStorage();
}
})();

form.addEventListener("submit", async (e) => {
e.preventDefault();
setGlobalError("", "");

// 冷卻期間內：直接阻擋送出
const existingUntilMs = _readCooldownUntilMs();
if (existingUntilMs && existingUntilMs > Date.now()) {
    _startCooldown(existingUntilMs);
    return;
}

validateEmailField();

const fields = [emailField];
const hasError = fields.some(
    (field) => field && field.classList.contains("field-error"),
);

if (hasError) {
    if (!errorEl.textContent) {
    setGlobalError("請修正紅色標示的欄位。", "fields");
    }
    return;
}

const email = emailInput.value.trim();

forgotBtn.disabled = true;
const originalText = forgotBtn.textContent;
forgotBtn.textContent = "處理中…";

try {
    const resp = await fetch("/api/auth/forgot-password", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ email }),
    });

    let data = null;
    try {
    data = await resp.json();
    } catch {
    data = null;
    }

    if (!resp.ok) {
    // 429：太頻繁 => 只顯示全域錯誤 + 後端回傳的剩餘秒數倒數，不標紅 email
    if (resp.status === 429) {
        const seconds = _parseRetryAfterSeconds(resp) || COOLDOWN_FALLBACK_SECONDS;
        clearSingleFieldError(emailField);
        _applyCooldownSeconds(seconds);
        return;
    }

    let msg = "重設密碼請求失敗，請稍後再試。";
    let source = "server";

    if (resp.status === 400 && data && typeof data.detail === "object") {
        const errors = data.detail.errors || {};
        const globalMessages = [];

        Object.entries(errors).forEach(([field, rawMsg]) => {
        const fieldMsg = String(rawMsg || "");
        switch (field) {
            case "email":
            setFieldError(emailField, fieldMsg);
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
        source = "server";
        } else {
        msg = "請修正紅色標示的欄位。";
        source = "fields";
        }
    }

    setGlobalError(msg, source);
    return;
    }

    // 成功：記錄 email 供 sent 頁遮罩顯示（與冷卻機制無關）
    try {
    sessionStorage.setItem("pcbuild_forgot_email", email);
    } catch {
    // ignore
    }

    // 200 也可能是「已受理但仍在冷卻期間」，統一尊重 Retry-After，
    // 讓使用者返回本頁時維持一致倒數體驗。
    const retryAfter = _parseRetryAfterSeconds(resp);
    if (retryAfter && retryAfter > 0) {
      _writeCooldownUntilMs(Date.now() + retryAfter * 1000);
    }

    window.location.href = "/forgot-password-sent.html";
} catch {
    setGlobalError("重設密碼請求失敗，請稍後再試。", "server");
} finally {
    const untilMs = _readCooldownUntilMs();
    if (untilMs && untilMs > Date.now()) {
    // 仍在冷卻倒數：按鈕狀態交給 _startCooldown 維護
    return;
    }
    forgotBtn.disabled = false;
    forgotBtn.textContent = originalText;
}
});
