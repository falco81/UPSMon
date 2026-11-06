const { chromium } = require('playwright');
let ok = 0, bad = 0; const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
(async () => {
  const b = await chromium.launch(); const ctx = await b.newContext({ viewport: { width: 1500, height: 900 } }); const p = await ctx.newPage();
  const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto('http://localhost:8080/settings/'); await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav'); await p.evaluate(() => api('settings', {settings: {load_meter: 1}}));
  await p.reload(); await p.waitForSelector('#hload:not([hidden])'); await p.waitForTimeout(8000);
  /* the four graphs move together: the same offset at the same moment */
  const sync = await p.evaluate(() => new Promise(res => { const out = [];
    const t = () => { const gs = [...document.querySelectorAll('#hload .hl-spark g.hl-slide')];
      if (gs.length) out.push(gs.map(g => +(new DOMMatrix(getComputedStyle(g).transform).e).toFixed(2)));
      if (out.length < 12) setTimeout(t, 250); else res(out); }; t(); }));
  const spread = Math.max(...sync.map(r => Math.max(...r) - Math.min(...r)));
  check('the graphs move together (the largest difference ' + spread + ')', sync.length >= 10 && spread < 0.05, sync.slice(0, 4));
  /* away to the dashboard and back: the numbers and the graphs at once, before any reading */
  const before = await p.evaluate(() => ({text: $('hload').textContent, n: HLOAD.hist.cpu.length}));
  await p.goto('http://localhost:8080/'); await p.waitForTimeout(4000);
  let asked = 0; p.on('request', r => { if (/api=load/.test(r.url())) asked++; });
  await p.route(/api=load/, async route => { await new Promise(r => setTimeout(r, 1500)); await route.continue().catch(() => {}); });   /* the first reading late */
  await p.goto('http://localhost:8080/settings/'); await p.waitForSelector('#hload', { state: 'attached' });
  const at = await p.evaluate(() => ({shown: !$('hload').hidden, text: $('hload').textContent, n: (HLOAD.hist || {cpu: []}).cpu.length, chips: document.querySelectorAll('#hload .hl').length}));
  check('back: shown at once, before the first reading', at.shown && at.chips >= 2 && /%/.test(at.text), at);
  check('back: the graph kept, the time away as a gap (' + before.n + ' -> ' + at.n + ')', at.n >= before.n && at.n <= before.n + 3, at.n);
  await p.unroute(/api=load/).catch(() => {});
  await p.waitForTimeout(4500);
  const upd = await p.evaluate(() => HLOAD.hist.cpu.length);
  check('… and the next reading brings it up to date', upd > at.n || upd === 40, upd);
  /* long away (an hour): the last numbers at once, the graph a gap */
  await p.evaluate(() => { const k = JSON.parse(localStorage.getItem('upsmon-hload')); k.at -= 3600e3; localStorage.setItem('upsmon-hload', JSON.stringify(k)); });
  await p.route(/api=load/, async route => { await new Promise(r => setTimeout(r, 1500)); await route.continue().catch(() => {}); });
  await p.reload(); await p.waitForSelector('#hload', { state: 'attached' });
  const lng = await p.evaluate(() => ({shown: !$('hload').hidden, text: $('hload').textContent, max: Math.max(...HLOAD.hist.cpu)}));
  check('an hour away: the last numbers at once', lng.shown && /%/.test(lng.text), lng);
  check('… the graph an empty gap', lng.max === 0, lng.max);
  await p.unroute(/api=load/).catch(() => {});
  /* signed out: nothing kept */
  await p.evaluate(() => closeModal && closeModal());
  await p.click('#signout'); await p.waitForTimeout(1500);
  check('signed out: what was kept is gone', await p.evaluate(() => localStorage.getItem('upsmon-hload')) === null, null);
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go'); await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => api('settings', {settings: {load_meter: 0}}));
  console.log('page errors:', errs.join(' | ') || 'none'); console.log(ok + ' ok, ' + bad + ' failed'); await b.close();
})();
