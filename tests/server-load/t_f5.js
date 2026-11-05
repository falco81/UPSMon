const { chromium } = require('playwright');
const S = '/tmp/claude-0/-home-user-UPSMon/eb6ab9f9-d3d4-5653-939f-615b11af19f7/scratchpad/';
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1500, height: 900 } });
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto('http://localhost:8080/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => api('settings', {settings: {load_meter: 1}}));
  await p.reload(); await p.waitForSelector('#hload:not([hidden])', { timeout: 10000 });
  await p.waitForTimeout(16000);
  const before = await p.evaluate(() => HLOAD.hist.cpu.length);
  const pathBefore = await p.evaluate(() => (document.querySelector('#hload polyline, #hload path') || {}).outerHTML || '');
  check('filled before F5 (points)', before >= 5, before);
  await p.reload();
  /* at once, before the first new reading comes back */
  await p.waitForSelector('#hload', { state: 'attached' });
  const right = await p.evaluate(() => ({shown: !$('hload').hidden, n: (HLOAD.hist || {cpu: []}).cpu.length,
                                         path: (document.querySelector('#hload polyline, #hload path') || {}).outerHTML || ''}));
  check('after F5 at once: the header shown', right.shown, right);
  check('after F5 at once: the graph still there (' + right.n + ' points)', right.n >= before && right.n <= before + 2, right.n);
  const ys = s => (s.match(/points="([^"]*)"/) || [0, ''])[1].trim().split(/\s+/).map(q => q.split(',')[1]);
  const a = ys(pathBefore), z = ys(right.path);
  check('after F5 at once: the same curve, the old points kept', a.length > 3 && z.join(' ').indexOf(a.slice(1, -1).join(' ')) >= 0, [a.join(' '), z.join(' ')]);
  await p.waitForTimeout(4000);
  const later = await p.evaluate(() => HLOAD.hist.cpu.length);
  check('… and it goes on from there', later > right.n || later === 40, later);
  await p.screenshot({ path: S + 'load-f5.png', clip: {x: 0, y: 0, width: 1500, height: 70} });
  console.log('page errors:', errs.join(' | ') || 'none');
  console.log(ok + ' ok, ' + bad + ' failed');
  await b.close();
})();
