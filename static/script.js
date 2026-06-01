/**
 * AMSES — Shared Frontend Script
 * script.js
 */

// Animate feature cards staggered on home page
document.addEventListener("DOMContentLoaded", () => {
  const cards = document.querySelectorAll(".feature-card");
  cards.forEach((card, i) => {
    card.style.opacity = "0";
    card.style.transform = "translateY(16px)";
    card.style.transition = "opacity 0.5s ease, transform 0.5s ease";
    setTimeout(() => {
      card.style.opacity = "1";
      card.style.transform = "translateY(0)";
    }, 600 + i * 80);
  });
});

// Utility: read a cookie
function getCookie(name) {
  const match = document.cookie.match(new RegExp("(^|;) ?" + name + "=([^;]*)(;|$)"));
  return match ? match[2] : null;
}

// Utility: format timestamp
function timeAgo(ts) {
  const d = new Date(ts.replace(" ", "T"));
  const diff = Math.floor((Date.now() - d.getTime()) / 1000);
  if (diff < 60)  return diff + "s ago";
  if (diff < 3600) return Math.floor(diff / 60) + "m ago";
  return Math.floor(diff / 3600) + "h ago";
}