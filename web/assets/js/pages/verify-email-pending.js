// web/assets/js/pages/verify-email-pending.js
// =========================================================
// verify-email-pending.html
// - 本頁不在載入時自動寄信（避免頁面導向造成重複寄送）
// - 冷卻倒數以 sessionStorage 保留，允許 reload 後恢復
// - 方案 A：register 成功後把 email + expiresAt 存進 sessionStorage，本頁可顯示遮罩 email
// - 方案 B：若讀不到 email，就顯示輸入框讓使用者補輸入 email 才能重寄
// =========================================================

// === sessionStorage keys（請確保與 register.html / index.html 使用相同 key）
const EMAIL_KEY = "pcbuild_verify_email";
const EMAIL_EXPIRES_AT_KEY = "pcbuild_verify_email_expires_at"; // 毫秒 timestamp
const FLOW_KEY = "pcbuild_verify_flow"; // "signup" | "home"
const COOLDOWN_KEY = "pcbuild_verify_cooldown_until"; // 毫秒 timestamp

const DEFAULT_MIN_INTERVAL_SECONDS = 60;

// DOM
const messageEl = document.getElementById("message");
const hintTextEl = document.getElementById("hint-text");
const resendBtn = document.getElementById("resend-button");
const backLinkEl = document.getElementById("back-link");

const fallbackWrapEl = document.getElementById("email-fallback");
const fallbackEmailEl = document.getElementById("fallback-email");
const fallbackErrEl = document.getElementById("fallback-email-error");
const cooldownHintEl = document.getElementById("cooldown-hint");
const RESEND_BTN_BASE_TEXT = "重新寄送驗證信";
const COOLDOWN_REASON_KEY = "pcbuild_verify_cooldown_reason"; // "rate" | ""

// State
let currentEmail = "";
let isLoggedIn = false;
let isActive = false; // 只有 isLoggedIn=true 時才可信
let countdownTimer = null;
let cooldownReason = ""; // "rate" 才顯示「太頻繁」

function safeGetSessionItem(key) {
try {
    return sessionStorage.getItem(key);
} catch (e) {
    return null;
}
}
function safeSetSessionItem(key, value) {
try {
    sessionStorage.setItem(key, value);
} catch (e) {}
}
function safeRemoveSessionItem(key) {
try {
    sessionStorage.removeItem(key);
} catch (e) {}
}

function setBackLink(flow) {
if (!backLinkEl) return;
if (flow === "home") {
    backLinkEl.href = "/";
    backLinkEl.textContent = "已完成驗證？回到首頁";
} else {
    backLinkEl.href = "/login.html";
    backLinkEl.textContent = "已完成驗證？前往登入";
}
}

function maskEmailFixed(email) {
const parts = String(email || "").split("@");
if (parts.length !== 2) return "";
const local = parts[0] || "";
const domain = parts[1] || "";
if (!local || !domain) return "";

const STAR_COUNT = 6; // 固定數量，不反映真實長度
const prefix = (local + "**").slice(0, 2); // local 不足 2 也會補齊
return `${prefix}${"*".repeat(STAR_COUNT)}@${domain}`;
}

function readStoredEmail() {
const rawEmail = safeGetSessionItem(EMAIL_KEY) || "";
const rawExp = safeGetSessionItem(EMAIL_EXPIRES_AT_KEY) || "";
if (!rawEmail) return "";

if (rawExp) {
    const exp = Number(rawExp);
    if (!Number.isFinite(exp) || Date.now() > exp) {
    safeRemoveSessionItem(EMAIL_KEY);
    safeRemoveSessionItem(EMAIL_EXPIRES_AT_KEY);
    return "";
    }
}
return rawEmail;
}

function renderFallback(show) {
if (!fallbackWrapEl) return;
fallbackWrapEl.style.display = show ? "" : "none";
if (fallbackErrEl) {
    fallbackErrEl.style.display = "none";
    fallbackErrEl.textContent = "";
}
}

function setFallbackError(msg) {
if (!fallbackErrEl) return;
if (!msg) {
    fallbackErrEl.style.display = "none";
    fallbackErrEl.textContent = "";
    return;
}
fallbackErrEl.textContent = msg; // textContent 安全
fallbackErrEl.style.display = "";
}

function renderUnverified(flow) {
setBackLink(flow);

if (flow === "home") {
    messageEl.textContent =
    "您的帳號尚未完成 Email 驗證。請至註冊信箱開啟驗證信並完成驗證。";
    hintTextEl.textContent =
    `完成驗證後，回到首頁重新整理即可開始使用。若未收到或信件已過期，可使用下方按鈕重新寄送（每次間隔 ${DEFAULT_MIN_INTERVAL_SECONDS} 秒）。\n`;
} else {
    const masked = currentEmail ? maskEmailFixed(currentEmail) : "";
    messageEl.textContent = masked
    ? `我們已將驗證信寄送到 ${masked}。請至註冊信箱開啟驗證信並完成驗證。`
    : "請至註冊信箱開啟驗證信並完成驗證。";
    hintTextEl.textContent =
    `完成驗證後，請前往登入頁重新登入，以更新帳號狀態。若未收到或信件已過期，可使用下方按鈕重新寄送（每次間隔 ${DEFAULT_MIN_INTERVAL_SECONDS} 秒）。\n`;
}
}

function renderMissingEmailContext(flow) {
setBackLink(flow);
messageEl.textContent =
    "我們無法取得您註冊時的 Email（可能因為瀏覽器清除暫存、跨分頁/跨裝置開啟，或資料已逾時）。";
hintTextEl.textContent =
    "為了重新寄送驗證信，請在下方輸入您的註冊 Email。輸入內容只會用於寄送驗證信，且會短暫保存以便您刷新頁面後仍可繼續操作。";
}

function renderAlreadyVerified(flow) {
// 已完成驗證：依 flow + 是否有合法 session 決定導引
if (flow === "home" && isLoggedIn) {
    messageEl.textContent =
    "您的帳號已完成 Email 驗證。您目前已登入，可直接回到首頁繼續使用。";
    hintTextEl.textContent =
    "若首頁仍顯示「尚未驗證」，請回到首頁後重新整理一次。";
    setBackLink("home");
} else {
    messageEl.textContent =
    "您的帳號已完成 Email 驗證。為了更新帳號狀態，請前往登入頁重新登入。";
    hintTextEl.textContent =
    "您可以關閉此頁面，或點擊下方「前往登入」連結。";
    setBackLink("signup");
}

resendBtn.disabled = true;
resendBtn.textContent = "已完成驗證";

// 已完成就不需要留存 email（降低留存時間）
safeRemoveSessionItem(EMAIL_KEY);
safeRemoveSessionItem(EMAIL_EXPIRES_AT_KEY);
renderFallback(false);

// 已完成驗證：停止倒數並清除冷卻
_stopCooldownTimer();
_clearCooldownStorage();
if (cooldownHintEl) {
    cooldownHintEl.textContent = "";
    cooldownHintEl.style.display = "none";
}
}

function _readCooldownUntilMs() {
const raw = safeGetSessionItem(COOLDOWN_KEY);
if (!raw) return null;
const ms = Number(raw);
return Number.isFinite(ms) ? ms : null;
}
function _readCooldownReason() {
return safeGetSessionItem(COOLDOWN_REASON_KEY) || "";
}

function _writeCooldownReason(reason) {
cooldownReason = reason || "";
if (cooldownReason) safeSetSessionItem(COOLDOWN_REASON_KEY, cooldownReason);
else safeRemoveSessionItem(COOLDOWN_REASON_KEY);
}

function showSendFail() {
_writeCooldownReason(""); // 非 429 不顯示「太頻繁」
if (cooldownHintEl) {
    cooldownHintEl.style.display = "";
    cooldownHintEl.textContent = "驗證信寄送失敗，請稍後再試。";
}
resendBtn.disabled = false;
resendBtn.textContent = RESEND_BTN_BASE_TEXT;
}

function _writeCooldownUntilMs(untilMs) {
safeSetSessionItem(COOLDOWN_KEY, String(untilMs));
}

function _clearCooldownStorage() {
safeRemoveSessionItem(COOLDOWN_KEY);
safeRemoveSessionItem(COOLDOWN_REASON_KEY);
}

function _stopCooldownTimer() {
if (countdownTimer) {
    clearInterval(countdownTimer);
    countdownTimer = null;
}
}

function _renderCooldownUI(remainingSeconds) {
const s = Math.max(0, Number(remainingSeconds) || 0);

// 按鈕顯示括號倒數
resendBtn.disabled = s > 0;
resendBtn.textContent = s > 0 ? `${RESEND_BTN_BASE_TEXT} (${s})` : RESEND_BTN_BASE_TEXT;

// 紅字只提示原因，不重複顯示秒數（避免雙倒數）
if (!cooldownHintEl) return;

if (s > 0 && cooldownReason === "rate") {
    cooldownHintEl.style.display = "";
    cooldownHintEl.textContent = "驗證信寄送太頻繁，請稍候再試。";
} else {
    cooldownHintEl.textContent = "";
    cooldownHintEl.style.display = "none";
}
}

function _startCooldown(untilMs) {
_stopCooldownTimer();

const tick = () => {
    const remaining = Math.max(0, Math.ceil((untilMs - Date.now()) / 1000));

    if (remaining <= 0) {
    _clearCooldownStorage();
    _renderCooldownUI(0);
    _stopCooldownTimer();
    return;
    }

    _renderCooldownUI(remaining);
};

tick();
countdownTimer = setInterval(tick, 250);
}

function _applyCooldownSeconds(seconds) {
const s = Number(seconds);
const sec = Number.isFinite(s) && s > 0 ? Math.ceil(s) : DEFAULT_MIN_INTERVAL_SECONDS;
const untilMs = Date.now() + sec * 1000;
_writeCooldownUntilMs(untilMs);
_startCooldown(untilMs);
}

function restoreCooldownFromStorage() {
cooldownReason = _readCooldownReason();
const untilMs = _readCooldownUntilMs();
if (untilMs && untilMs > Date.now()) {
    _startCooldown(untilMs);
} else {
    _clearCooldownStorage();
    _renderCooldownUI(0);
}
}

function parseRetryAfterSeconds(resp) {
const raw = resp.headers.get("Retry-After");
if (!raw) return null;
const n = parseInt(raw, 10);
return Number.isFinite(n) && n > 0 ? n : null;
}

function isValidEmailFormat(email) {
const s = String(email || "").trim();
if (!s) return false;
const at = s.indexOf("@");
if (at <= 0) return false;
if (at === s.length - 1) return false;
return true;
}

async function tryFetchMe() {
try {
    const resp = await fetch("/api/auth/me", {
    method: "GET",
    credentials: "same-origin",
    });
    if (!resp.ok) return null;
    return await resp.json();
} catch (e) {
    return null;
}
}

function getFlow() {
const raw = safeGetSessionItem(FLOW_KEY);
if (raw === "signup" || raw === "home") return raw;
return isLoggedIn ? "home" : "signup";
}

async function init() {
restoreCooldownFromStorage();

const me = await tryFetchMe();
if (me) {
    isLoggedIn = true;
    isActive = !!me.is_active;
    currentEmail = String(me.email || "");
} else {
    isLoggedIn = false;
    isActive = false;
    currentEmail = readStoredEmail();
}

const flow = getFlow();

if (isLoggedIn && isActive) {
    renderAlreadyVerified(flow);
    return;
}

renderUnverified(flow);

// 未登入且讀不到 email → 顯示方案 B
if (!currentEmail && !isLoggedIn) {
    renderMissingEmailContext(flow);
    renderFallback(true);
    return;
}
renderFallback(false);
}

resendBtn.addEventListener("click", async () => {
const untilMs = _readCooldownUntilMs();
if (untilMs && untilMs > Date.now()) {
    _startCooldown(untilMs);
    return;
}

// 若已登入，先確認是否已完成驗證（避免剛驗證完仍停留在 pending）
if (isLoggedIn) {
    const me = await tryFetchMe();
    if (me) {
    isActive = !!me.is_active;
    currentEmail = String(me.email || "");
    if (isActive) {
        renderAlreadyVerified(getFlow());
        return;
    }
    }
}

let emailToUse = currentEmail;

// 方案 B：需要輸入 email
if (!emailToUse && fallbackEmailEl) {
    const input = String(fallbackEmailEl.value || "").trim();
    if (!isValidEmailFormat(input)) {
    setFallbackError("請輸入正確的 Email 格式。");
    return;
    }
    setFallbackError("");
    emailToUse = input;

    // 存短期 expiresAt，讓 reload 可恢復遮罩顯示（降低留存）
    safeSetSessionItem(EMAIL_KEY, emailToUse);
    safeSetSessionItem(
    EMAIL_EXPIRES_AT_KEY,
    String(Date.now() + 30 * 60 * 1000) // 30 分鐘
    );
    currentEmail = emailToUse;          // 讓畫面可以遮罩顯示
    renderUnverified(getFlow());        // 重新渲染 pending 文字（會顯示遮罩 email）
    renderFallback(false);              // 隱藏輸入框，回到遮罩 email 的 pending 介面
}

if (!emailToUse) return;

resendBtn.disabled = true;

try {
    const resp = await fetch("/api/auth/resend-verification", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: emailToUse }),
    credentials: "same-origin",
    });

    if (resp.ok || resp.status === 429) {
    const retry = parseRetryAfterSeconds(resp) || DEFAULT_MIN_INTERVAL_SECONDS;

    if (resp.status === 429) _writeCooldownReason("rate");
    else _writeCooldownReason("");

    _applyCooldownSeconds(retry);
    return;
    }

    // 伺服器有回應，但不是 200/429
    showSendFail();
    return;

} catch (e) {
    // 網路/連線層錯誤（FastAPI 關掉、連線失敗等）
    showSendFail();
    return;
}
});

init();
