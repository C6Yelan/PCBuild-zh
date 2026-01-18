// web/assets/js/pages/index.js
const API = "/api/chat";
const log = document.getElementById('log');
const chatInput = document.getElementById('chat-input');
const chatSendBtn = document.getElementById('chat-send-btn');
const chatHint = document.getElementById('chat-hint');
const topBarActions = document.getElementById('top-bar-actions');

marked.setOptions({ gfm: true, breaks: true, headerIds: false, mangle: false });

// === 新增：集中清理 Email 驗證流程用的 sessionStorage ===
const VERIFY_STORAGE_KEYS = [
  "pcbuild_verify_email",
  "pcbuild_verify_email_expires_at",
  "pcbuild_verify_flow",
  "pcbuild_verify_cooldown_until",
];

function clearVerifySessionStorage() {
  try {
    for (const k of VERIFY_STORAGE_KEYS) sessionStorage.removeItem(k);
  } catch (_) {
    // ignore
  }
}

/* === 新增：在前端保存最近 N 筆對話（純文字） === */
const HISTORY_LIMIT = 8;
const history = [];  // [{role:"user"|"ai", content:"..."}]

function row(who, innerHTML) {
  const wrap = document.createElement('div');
  wrap.className = 'chat-row';
  const avatar = document.createElement('div');
  avatar.className = `avatar ${who}`;
  avatar.textContent = (who === 'user') ? '🧑' : '🤖';
  const message = document.createElement('div');
  message.className = 'message markdown-body';
  message.innerHTML = innerHTML;
  wrap.appendChild(avatar);
  wrap.appendChild(message);
  return wrap;
}

function appendMarkdown(who, md, inline=false) {
  const html = inline ? marked.parseInline(md) : marked.parse(md);
  const safe = DOMPurify.sanitize(html);
  const wrap = row(who, safe);
  log.appendChild(wrap);
  log.scrollTop = log.scrollHeight;
}

/* 自動增高維持你原本版本 */
function autoResize() {
  const maxPx = Math.floor(window.innerHeight * 0.40);
  const minPx = parseFloat(getComputedStyle(chatInput).minHeight) || 52;
  chatInput.style.height = 'auto';
  const h = Math.min(chatInput.scrollHeight, maxPx);
  chatInput.style.height = Math.max(h, minPx) + 'px';
  chatInput.style.overflowY = (chatInput.scrollHeight > maxPx) ? 'auto' : 'hidden';
}

async function send() {
if (!chatEnabled) {
  if (chatMode === "unverified") configureChatForUnverifiedUser();
  else configureChatForGuest();
  return;
}

  const m = chatInput.value.trim();
  if (!m) return;

  // UI 先顯示
  appendMarkdown('user', m, true);

  // === 準備 payload：把最近 N 筆 history 一起送到後端 ===
  const payload = {
    message: m,
    history: history.slice(-HISTORY_LIMIT)   // 注意：role 必須是 "user" 或 "ai"
  };

  chatInput.value = '';
  autoResize();
  chatInput.focus();
  chatSendBtn.disabled = true;

  try {
    const r = await fetch(API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
    });

    // 401：session 失效 → 彈窗 + 鎖 UI + 切回登入/註冊
    if (r.status === 401) {
      handleSessionInvalid("您已被登出或登入狀態已失效，請重新登入後再繼續使用。");
      return;
    }

    // 403：可用於「未驗證」或「權限不足」→ 鎖聊天（不彈 session 失效）
    if (r.status === 403) {
      configureChatForUnverifiedUser();
      return;
    }

    // 其他非 2xx：顯示一般錯誤（不要當成登出）
    if (!r.ok) {
      appendMarkdown("ai", "目前服務暫時無法處理請求，請稍後再試。", false);
      return;
    }

    // 只有成功才解析 JSON
    const data = await r.json();
    const aiText = String(data?.reply ?? "");

    // UI 顯示 AI
    appendMarkdown('ai', aiText, false);

    // === 成功後再把「本輪」加入 history（純文字，不要塞 HTML）===
    history.push({ role: 'user', content: m });
    history.push({ role: 'ai', content: aiText });

    // 可選：只保留上限，避免記憶體暴增
    if (history.length > HISTORY_LIMIT * 2) {
      history.splice(0, history.length - HISTORY_LIMIT * 2);
    }
  } catch (e) {
    appendMarkdown('ai', `發生錯誤：\`${String(e)}\``, false);
  } finally {
    // 依目前狀態決定是否啟用按鈕，避免 401/403 已鎖定 UI 後又被 finally 打開
    chatSendBtn.disabled = !chatEnabled;
  }
}

let chatEnabled = false;
let chatMode = "guest"; // "guest" | "unverified" | "active"

// 未登入使用者的聊天介面設定
function configureChatForGuest() {
  chatMode = "guest";
  chatEnabled = false;

  if (chatInput) {
    chatInput.value = '';
    chatInput.disabled = true;
    chatInput.placeholder = "要使用 AI 聊天與配單功能，請先登入或註冊帳號。";
  }
  if (chatSendBtn) {
    chatSendBtn.disabled = true;
  }
  if (chatHint) {
    chatHint.textContent = "您目前尚未登入，無法使用 AI 聊天功能。請先登入或註冊帳號。";
  }
}

// 未驗證使用者的聊天介面設定
function configureChatForUnverifiedUser() {
  chatMode = "unverified";
  chatEnabled = false;

  if (chatInput) {
    chatInput.value = '';
    chatInput.disabled = true;
    chatInput.placeholder = "帳號尚未完成 Email 驗證，暫時無法使用 AI 聊天功能。";
  }
  if (chatSendBtn) {
    chatSendBtn.disabled = true;
  }
  if (chatHint) {
    chatHint.textContent = "您的帳號尚未完成 Email 驗證。請先完成驗證後再使用 AI 聊天功能。";
  }
}

// 已啟用使用者的聊天介面設定
function configureChatForActiveUser() {
  chatMode = "active";
  chatEnabled = true;

  if (chatInput) {
    chatInput.disabled = false;
    chatInput.placeholder = "請輸入想詢問的配單需求或問題…";
  }
  if (chatSendBtn) {
    chatSendBtn.disabled = false;
  }
  if (chatHint) {
    chatHint.textContent = '';
  }
}

let hadValidSession = false;      // 本頁曾經驗證過有 session（避免訪客一進來就跳「被登出」）
let sessionModalShown = false;
let heartbeatTimer = null;
let heartbeatStartTimer = null;

const sessionModal = document.getElementById("session-modal");
const sessionModalMsg = document.getElementById("session-modal-msg");
const sessionModalCloseBtn = document.getElementById("session-modal-close");

// 1) 點 X 關閉
if (sessionModalCloseBtn) {
  sessionModalCloseBtn.addEventListener("click", closeSessionExpiredModal);
}

// 2) 點遮罩（只在點到 backdrop 本身時）
if (sessionModal) {
  sessionModal.addEventListener("click", (e) => {
    if (e.target === sessionModal) closeSessionExpiredModal();
  });
}

// 3) Esc 關閉
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (sessionModal && sessionModal.getAttribute("aria-hidden") === "false") {
    closeSessionExpiredModal();
  }
});

let lastActiveEl = null;

function closeSessionExpiredModal() {
  if (!sessionModal) return;
  sessionModal.setAttribute("aria-hidden", "true");

  // 關閉後就停留在 guest 首頁（你已在 handleSessionInvalid 做了 guest UI 切換）
  // 恢復焦點（可選）
  if (lastActiveEl && typeof lastActiveEl.focus === "function") {
    try { lastActiveEl.focus(); } catch (_) {}
  }
}

function openSessionExpiredModal(message) {
  if (sessionModalShown) return;
  sessionModalShown = true;

  lastActiveEl = document.activeElement;

  if (sessionModalMsg && message) sessionModalMsg.textContent = message;
  sessionModal.setAttribute("aria-hidden", "false");

  // 讓焦點落在 modal（可及性）
  const focusTarget = sessionModalCloseBtn || sessionModal.querySelector('a,button,[tabindex]:not([tabindex="-1"])');
  if (focusTarget) focusTarget.focus();
}

// 把右上角 actions 恢復成「註冊 / 登入」
function renderTopBarGuest() {
  if (!topBarActions) return;

  // 清空既有節點（比 textContent="" 更明確）
  topBarActions.replaceChildren();

  const reg = document.createElement("a");
  reg.href = "/register.html";
  reg.className = "top-bar__button";
  reg.textContent = "註冊";

  const login = document.createElement("a");
  login.href = "/login.html";
  login.className = "top-bar__button";
  login.textContent = "登入";

  topBarActions.append(reg, login);
}

// 統一入口：session 失效時的 UI 切換
function handleSessionInvalid(reason = "您的登入狀態已失效，請重新登入後再繼續使用。") {
  // 1) 停止心跳
  stopSessionHeartbeat();

  // 2) 標記為無有效 session
  hadValidSession = false;

  // 2) 切 UI：關閉聊天、切回 guest topbar
  configureChatForGuest();
  renderTopBarGuest();

  // 3) 彈窗
  openSessionExpiredModal(reason);
}

function stopSessionHeartbeat() {
  if (heartbeatStartTimer) {
    clearTimeout(heartbeatStartTimer);
    heartbeatStartTimer = null;
  }
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}


async function heartbeatTick() {
  if (document.visibilityState !== "visible") return;

  try {
    const resp = await fetch("/api/auth/me", { method: "GET", credentials: "same-origin" });

    if (resp.status === 401) {
      if (hadValidSession) handleSessionInvalid("您已被登出或登入狀態已失效，請重新登入。");
      return;
    }
  } catch (_) {
    // 網路錯誤不視為登出
  }
}

// 啟動心跳檢查（含隨機初始延遲）
function startSessionHeartbeat() {
  stopSessionHeartbeat();

  const BASE_MS = 60_000;
  const JITTER_MS = 5_000;

  const firstDelay = BASE_MS + Math.floor(Math.random() * (JITTER_MS + 1));

  heartbeatStartTimer = setTimeout(() => {
    heartbeatTick();
    heartbeatTimer = setInterval(heartbeatTick, BASE_MS);
  }, firstDelay);
}

// Page Visibility：從 hidden 回來時，補跑一次（不用等下一個 interval）
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && hadValidSession && !sessionModalShown) {
    // 回到頁籤就補檢查一次
    heartbeatTick();        // 立刻檢查一次
    startSessionHeartbeat(); // 再以 60s + jitter 重新排程
  }
});

async function initHomeAuthGuard() {
  try {
    const resp = await fetch("/api/auth/me", {
      method: "GET",
      credentials: "same-origin",
    });

    if (!resp.ok) {
      renderTopBarGuest();
      configureChatForGuest();
      hadValidSession = false;
      stopSessionHeartbeat();
      return;
    }
    hadValidSession = true;
    startSessionHeartbeat();

    const data = await resp.json();
    await loadAuthState(data);

    if (data && data.is_active === false) {
      configureChatForUnverifiedUser();
      return;
    }
    // 新增：已驗證狀態，清掉任何殘留的 verify sessionStorage
    clearVerifySessionStorage();
    configureChatForActiveUser();
  } catch (err) {
    console.error("initHomeAuthGuard failed:", err);
    configureChatForGuest();
    renderTopBarGuest();
    hadValidSession = false;
    stopSessionHeartbeat();
  }
}

async function loadAuthState(preloadedData = null) {
  if (!topBarActions) return;

  try {
    // 若外部已提供 data（例如 initHomeAuthGuard 已 fetch /me），就直接使用，避免重複請求
    let data = preloadedData;

    if (!data) {
      const resp = await fetch("/api/auth/me", {
        method: "GET",
        credentials: "same-origin",
      });

      if (!resp.ok) return;

      data = await resp.json();
    }
    // 新增：若帳號已驗證，清掉 verify sessionStorage（避免其他頁沒清到）
    if (data && data.is_active === true) clearVerifySessionStorage();
    const username = data.username || data.email || "User";

    // 已登入 → 顯示使用者名稱 +（尚未驗證連結）+ 登出按鈕
    topBarActions.textContent = "";

    // 把「歡迎文字」與「尚未驗證」放同一個區塊（上下排列）
    const userBlock = document.createElement("div");
    userBlock.style.display = "flex";
    userBlock.style.flexDirection = "column";
    userBlock.style.alignItems = "flex-end";
    userBlock.style.gap = "4px";
    userBlock.style.marginRight = "12px";

    const welcome = document.createElement("span");
    welcome.style.fontSize = "14px";
    welcome.textContent = `歡迎，${username}`;
    userBlock.appendChild(welcome);

    // 未驗證：顯示紅色超連結（在歡迎文字下方）
    // 點擊後：先嘗試重寄驗證信 + 寫入冷卻時間到 sessionStorage + 轉到 pending 頁
    if (data && data.is_active === false) {
      const COOLDOWN_KEY = "pcbuild_verify_cooldown_until";
      const DEFAULT_WAIT_SEC = 60;

      const verifyLink = document.createElement("a");
      verifyLink.href = "/verify-email-pending.html";
      verifyLink.textContent = "尚未驗證（點此前往驗證）";
      verifyLink.title = "前往 Email 驗證與重新寄送驗證信";
      verifyLink.style.fontSize = "12px";
      verifyLink.style.color = "#ff4d4f";
      verifyLink.style.textDecoration = "underline";

      verifyLink.addEventListener("click", async (e) => {
        e.preventDefault();
          // 新增：標記這次是「已登入未驗證 → 從首頁進入驗證」流程
        try {
          sessionStorage.setItem("pcbuild_verify_flow", "home");
        } catch (_) {}

        // 如果同分頁已有冷卻中的時間戳，就不要重打 API，直接進 pending 讓它顯示倒數
        let untilMs = 0;
        try {
          untilMs = parseInt(sessionStorage.getItem(COOLDOWN_KEY) || "0", 10) || 0;
        } catch (_) {
          untilMs = 0;
        }

        if (untilMs && Date.now() < untilMs) {
          window.location.href = "/verify-email-pending.html";
          return;
        }

        try {
          const r = await fetch("/api/auth/resend-verification", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({}), // 由後端用 session 判定 user，不放 email
          });

          // 成功或被 rate limit 時，寫入冷卻時間，讓 pending 頁一載入就能倒數
          if (r.ok || r.status === 429) {
            let waitSec = DEFAULT_WAIT_SEC;

            // 200/429 都盡量尊重後端 Retry-After（秒）
            const ra = r.headers.get("Retry-After");
            const n = ra ? parseInt(ra, 10) : NaN;
            if (!Number.isNaN(n) && n > 0) waitSec = Math.min(n, 600);

            try {
              sessionStorage.setItem(COOLDOWN_KEY, String(Date.now() + waitSec * 1000));
            } catch (_) {}
          }
        } catch (_) {
          // 網路錯誤不阻擋轉導：不顯示成功/失敗，只讓使用者到 pending 頁再操作
        } finally {
          window.location.href = "/verify-email-pending.html";
        }
      });

      userBlock.appendChild(verifyLink);
    }

    topBarActions.appendChild(userBlock);

    const logoutBtn = document.createElement("button");
    logoutBtn.id = "logout-btn";
    logoutBtn.className = "top-bar__button";
    logoutBtn.type = "button";
    logoutBtn.textContent = "登出";
    topBarActions.appendChild(logoutBtn);

    logoutBtn.addEventListener("click", async () => {
      try {
        await fetch("/api/auth/logout", {
          method: "POST",
          credentials: "same-origin",
        });
      } catch (e) {
        // ignore
      } finally {
        clearVerifySessionStorage();
        window.location.href = "/";
      }
    });
  } catch (e) {
    console.error("loadAuthState error:", e);
  }
}


chatSendBtn.onclick = send;
/* Enter 送出；Shift+Enter 換行 */
chatInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    send();
  }
});
chatInput.addEventListener('input', autoResize);
window.addEventListener('resize', autoResize);
document.addEventListener('DOMContentLoaded', () => {
  configureChatForGuest();
  autoResize();
  initHomeAuthGuard();
});