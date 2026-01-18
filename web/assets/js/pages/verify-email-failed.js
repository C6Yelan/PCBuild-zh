// web/assets/js/pages/verify-email-failed.js
try {
sessionStorage.removeItem("pcbuild_verify_cooldown_until");
sessionStorage.removeItem("pcbuild_verify_cooldown_reason");
} catch (_) {}
