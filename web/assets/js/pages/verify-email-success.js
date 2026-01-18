// web/assets/js/pages/verify-email-success.js
(async () => {
const contentEl = document.getElementById("success-content");
const hintEl = document.getElementById("success-hint");
const primary = document.getElementById("primary-action");
const secondary = document.getElementById("secondary-action");

function showSecondary(show) {
    if (!secondary) return;
    secondary.style.display = show ? "" : "none";
}

function apply(mode) {
    if (mode === "home") {
    // 已登入同帳號驗證成功：只引導回首頁，不出現前往登入連結
    contentEl.textContent =
        "Email 驗證成功。您目前已登入（同帳號），可直接回到首頁開始使用。";
    hintEl.textContent =
        "若首頁仍顯示「尚未驗證」，請回到首頁後重新整理一次。";

    primary.textContent = "回到首頁";
    primary.href = "/";

    showSecondary(false);
    return;
    }

    // mode === "login"（註冊驗證成功）：維持原本「前往登入」引導
    contentEl.textContent =
    "Email 驗證成功。為了更新帳號狀態，請前往登入頁重新登入。";
    hintEl.textContent =
    "若您是從註冊流程完成驗證，重新登入後即可開始使用。";

    primary.textContent = "前往登入";
    primary.href = "/login.html";

    // 次要：回首頁（保留）
    if (secondary) {
    secondary.textContent = "回到首頁";
    secondary.href = "/";
    }
    showSecondary(true);
}

const params = new URLSearchParams(window.location.search);
let mode = (params.get("mode") || "").toLowerCase();

// 後端通常會帶 mode；若有人直接開此頁，才用 /api/auth/me 推斷
if (mode !== "home" && mode !== "login") {
    try {
    const resp = await fetch("/api/auth/me", {
        method: "GET",
        credentials: "same-origin",
    });
    if (resp.ok) {
        const data = await resp.json().catch(() => null);
        if (data && data.is_active === true) mode = "home";
    }
    } catch (_) {}
    if (mode !== "home") mode = "login";
}

apply(mode);
try {
    sessionStorage.removeItem("pcbuild_verify_email");
    sessionStorage.removeItem("pcbuild_verify_email_expires_at");
    sessionStorage.removeItem("pcbuild_verify_flow");
    sessionStorage.removeItem("pcbuild_verify_cooldown_until");
    sessionStorage.removeItem("pcbuild_verify_cooldown_reason");
} catch (_) {}
})();