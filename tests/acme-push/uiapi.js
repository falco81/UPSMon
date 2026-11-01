// node uiapi.js '[["web",{...}],["acme-push",{...}],["acme",null]]'  (null body = GET)
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage();
  await p.goto('http://127.0.0.1:8080/settings/'); await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav', { timeout: 15000 });
  const calls = JSON.parse(process.argv[2]); const out = [];
  for (const [ep, body] of calls) out.push(await p.evaluate(([ep, body]) => (body === null ? api(ep) : api(ep, body)).catch(e => ({error: String(e.message || e)})), [ep, body]));
  console.log(JSON.stringify(out)); await b.close();
})();
