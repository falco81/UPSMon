const { chromium } = require('playwright');
let ok = 0, bad = 0; const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1500, height: 900 } }); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto('http://localhost:8080/settings/'); await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => api('settings', {settings: {load_meter: 1}}));
  await p.evaluate(() => sessionStorage.clear());
  await p.reload(); await p.waitForSelector('#hload:not([hidden])'); await p.waitForTimeout(2000);
  await p.evaluate(() => api('prefs', {hload: 'graphs'}).then(d => { ME.prefs = d.prefs; }));
  /* not full yet: nothing moves */
  const notFull = await p.evaluate(() => { HLOAD.hist = {cpu: [5, 6], mem: [1, 2], disk: [0, 0], net: [0, 0]}; hloadDraw(HLOAD.last); return document.querySelectorAll('#hload animateTransform').length; });
  check('two minutes not full: no animation', notFull === 0, notFull);
  const r = await p.evaluate(() => new Promise(res => {
    clearInterval(HLOAD.timer);                       /* no readings any more: what moves now moves by itself */
    const f = n => Array.from({length: n}, (_, i) => (i * 7) % 100);
    HLOAD.hist = {cpu: f(40), mem: f(40), disk: f(40), net: f(40)};
    hloadDraw(Object.assign({}, HLOAD.last, {cpu: 50}));
    const svg = document.querySelector('#hload .hl-spark'), g = svg.querySelector('g.hl-slide');
    const anims = document.querySelectorAll('#hload animateTransform').length, sparks = document.querySelectorAll('#hload .hl-spark').length;
    const x = () => g.getCTM().e;
    const t0 = performance.now(), tr = [];
    const tick = () => { const t = performance.now() - t0; tr.push(+x().toFixed(2));
      if (t < 3500) setTimeout(tick, 400);
      else res({anims, sparks, tr, a: tr[1], m: tr[4], z: tr[tr.length - 1], same: document.querySelector('#hload .hl-spark') === svg,
                pts: svg.querySelector('polyline').getAttribute('points').split(' ').length}); };
    tick();
  }));
  check('one animation per graph (' + r.anims + ' of ' + r.sparks + ')', r.anims === r.sparks && r.anims >= 2, r);
  check('it slides to the left by itself', r.a > r.m && r.m > r.z, r);
  check('and stops where the line is (0)', Math.abs(r.z) < 0.2, r.z);
  check('nothing redrawn meanwhile (the same SVG)', r.same, r);
  check('the point that went out drawn on the left while it slides', r.pts === 41, r.pts);
  /* drawn again mid-way (the panel opened): goes on from where it is */
  const mid = await p.evaluate(() => new Promise(res => {
    HLOAD.pushAt = Date.now() - 1500; HLOAD.drop = {cpu: 1, mem: 1, disk: 1, net: 1};
    HLOAD.noPush = true; hloadDraw(HLOAD.last); HLOAD.noPush = false;
    requestAnimationFrame(() => requestAnimationFrame(() => { const g = document.querySelector('#hload .hl-spark g.hl-slide'); const step = 56 / 39;
      const svg = document.querySelector('#hload .hl-spark'); const sc = svg.getBoundingClientRect().width / 56;
      res({e: g.getCTM().e - svg.getCTM().e, step, sc}); }));
  }));
  check('drawn again half way: half a step left (' + mid.e.toFixed(2) + ')', Math.abs(mid.e / mid.sc - mid.step / 2) < 0.25, mid);
  const pan = await p.evaluate(() => { HLOAD.pushAt = Date.now() - 500; HLOAD.drop = {cpu: 1, mem: 1, disk: 1, net: 1}; const r = {};
    ['tiles', 'table', 'map', 'wide'].forEach(st => { ME.prefs.hpanel = st; HLOAD.open = 'cpu';
      if (!$('hload-panel')) { const q = document.createElement('div'); q.id = 'hload-panel'; document.body.appendChild(q); }
      hloadPanelDraw(); r[st] = [document.querySelectorAll('#hload-panel animateTransform').length, document.querySelectorAll('#hload-panel .hp-area, #hload-panel .hl-spark').length]; });
    HLOAD.open = null; return r; });
  check('the panel graphs slide too ' + JSON.stringify(pan), Object.values(pan).every(x => x[0] === x[1]) && Object.values(pan).some(x => x[0] > 0), pan);
  const reduced = await (async () => { const c2 = await b.newContext({ reducedMotion: 'reduce' }); const q = await c2.newPage();
    await c2.addCookies(await p.context().cookies());
    await q.goto('http://localhost:8080/settings/'); await q.waitForSelector('#hload:not([hidden])');
    const n = await q.evaluate(() => { clearInterval(HLOAD.timer); const f = n => Array.from({length: n}, (_, i) => i); HLOAD.hist = {cpu: f(40), mem: f(40), disk: f(40), net: f(40)};
      hloadDraw(Object.assign({}, HLOAD.last, {cpu: 50})); return document.querySelectorAll('#hload animateTransform').length; });
    await c2.close(); return n; })();
  check('reduced motion: nothing moves', reduced === 0, reduced);
  await p.screenshot({ path: process.argv[2], clip: {x: 0, y: 0, width: 1500, height: 70} });
  await p.evaluate(() => api('prefs', {hload: null}));
  console.log('page errors:', errs.join(' | ') || 'none'); console.log(ok + ' ok, ' + bad + ' failed'); await b.close();
})();
