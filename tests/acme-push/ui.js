// signs in and calls the card's API: node ui.js '{"action":"on","on":true}'
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage();
  await p.goto('http://127.0.0.1:8080/settings/'); await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav', { timeout: 15000 });
  const out = [];
  for (const a of process.argv.slice(2)) out.push(await p.evaluate(x => api('acme-push', JSON.parse(x)).catch(e => ({error: String(e.message || e)})), a));
  console.log(JSON.stringify(out)); await b.close();
})();
