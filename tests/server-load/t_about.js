const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1500, height: 1000 } });
  const asked = []; p.on('request', r => { if (/api=load/.test(r.url())) asked.push(r.url()); });
  await p.goto('http://localhost:8080/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => api('settings', {settings: {load_meter: 1}}));
  await p.reload(); await p.waitForSelector('#hload:not([hidden])'); await p.waitForTimeout(1000);
  await p.goto('http://localhost:8080/settings/#settings/about'); await p.reload(); await p.waitForTimeout(2500);
  const box = await p.evaluate(() => { const i = document.querySelector('[data-key="load_meter"], #s-load_meter, input[name="load_meter"]'); const c = i && i.closest('.field, .set, .card, div'); return {found: !!i, checked: i && i.checked, text: c ? c.textContent.trim().slice(0, 120) : ''}; });
  console.log('switch in About:', JSON.stringify(box));
  const el = await p.$('[data-key="load_meter"], #s-load_meter, input[name="load_meter"]');
  if (el) { await el.scrollIntoViewIfNeeded(); await p.screenshot({ path: process.argv[2] }); }
  // switch off through the pane: click, then Save the changes
  if (el) { await p.click('#set-load_meter-sw + *, label:has(#set-load_meter-sw), #set-load_meter-sw', {force: true}).catch(e => console.log('click', e.message.slice(0, 80))); await p.waitForTimeout(300);
    console.log('checked now:', await p.evaluate(() => document.getElementById('set-load_meter-sw').checked)); await p.click('button:has-text("Uložit změny")'); await p.waitForTimeout(1500); }
  await p.reload(); asked.length = 0; await p.waitForTimeout(5000);
  console.log('after switching off: header', !!(await p.$('#hload')), ', asked', asked.length,
    ', setting', await p.evaluate(() => api('whoami').then(d => d.who.load_meter)));
  await b.close();
})();
