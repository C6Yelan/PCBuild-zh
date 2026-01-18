// web/assets/js/pages/forgot-password-sent.js
function maskEmail(email) {
    const parts = String(email || "").split("@");
    if (parts.length !== 2) return "";
    const local = parts[0] || "";
    const domain = parts[1] || "";
    if (!local || !domain) return "";

    const STAR_COUNT = 6; // 固定星號數量
    const prefix = local.slice(0, 1); // 永遠只顯示 1 個字元，避免透露是否 >=2

    return `${prefix}${"*".repeat(STAR_COUNT)}@${domain}`;
}

const emailWrapEl = document.getElementById("msg-email-wrap");
const maskedEmailEl = document.getElementById("masked-email");

let email = "";
try {
    email = sessionStorage.getItem("pcbuild_forgot_email") || "";
    sessionStorage.removeItem("pcbuild_forgot_email");
} catch (e) {
    email = "";
}

const masked = maskEmail(email);
if (masked) {
    maskedEmailEl.textContent = masked;
    emailWrapEl.style.display = "";
}