const { chromium } = require('playwright');
/* Live: the real readings every 3 s. Where is the newest point (on the screen)
   every 100 ms - it must keep moving left, never stand still for long. */
(async () => {
  const b = await chromium.launch(); const p = await b.newPage({ viewport: { width: 1500, height: 900 } });
  await p.goto('http://localhost:8080/settings/'); await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav'); await p.evaluate(() => api('settings', {settings: {load_meter: 1}}));
  await p.evaluate(() => sessionStorage.clear());
  await p.reload(); await p.waitForSelector('#hload:not([hidden])'); await p.waitForTimeout(7000);
  const r = await p.evaluate(() => new Promise(res => {
    const out = [], t0 = performance.now();
    const tick = () => {
      const svg = document.querySelector('#hload .hl-spark'), pl = svg && svg.querySelector('polyline');
      let x = null;
      if (pl) { const pts = pl.points; const q = pts.getItem(pts.numberOfItems - 2); const m = pl.getCTM(); x = +(m.a * q.x + m.e).toFixed(2); }
      out.push([Math.round(performance.now() - t0), x, HLOAD.hist.cpu.length]);
      if (performance.now() - t0 < 15000) setTimeout(tick, 100); else res({out, every: HLOAD.every});
    };
    tick();
  }));
  /* the longest time the line stood still */
  let still = 0, longest = 0, prev = null;
  r.out.forEach(([t, x]) => { if (prev !== null && x !== null && Math.abs(x - prev) < 0.005) { still += 100; longest = Math.max(longest, still); } else still = 0; prev = x; });
  console.log('step every', r.every, 's; points', r.out[r.out.length - 1][2], '; the longest standstill', longest, 'ms');
  console.log(longest <= 400 ? 'SMOOTH' : 'STOPS');
  await p.evaluate(() => api('settings', {settings: {load_meter: 0}}));
  await b.close();
})();
