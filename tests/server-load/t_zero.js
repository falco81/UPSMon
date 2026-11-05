const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto('http://localhost:8080/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => api('settings', {settings: {load_meter: 1}}));
  await p.reload(); await p.waitForSelector('#hload:not([hidden])', { timeout: 15000 }); await p.waitForTimeout(3000);
  const r = await p.evaluate(() => {
    const out = {};
    out.w = [hlWidth(0), hlWidth(0.49), hlWidth(0.5), hlWidth(140), hlWidth(null), hlWidth('x')];
    const keep = /total|size|^n$|mhz|speed|^at$|count|cores_n|threads/;
    const zero = o => { if (typeof o === 'number') return 0; if (Array.isArray(o)) return o.map(zero); if (o && typeof o === 'object') { const z = {}; for (const k in o) z[k] = typeof o[k] === 'number' && !keep.test(k) ? 0 : zero(o[k]); return z; } return o; };
    const smp = hpSample();
    HLOAD.last = zero(smp.last); HLOAD.detail = zero(smp.detail);
    const fix = o => { if (o && typeof o === 'object') { if ('available' in o && 'total' in o) o.available = o.total; if ('mem_available' in o) o.mem_available = o.mem_total; Object.values(o).forEach(fix); } }; fix(HLOAD.last); fix(HLOAD.detail); if (HLOAD.last.mem_total) HLOAD.last.mem_used = 0;
    if (HLOAD.detail.procs) ['cpu', 'mem'].forEach(k => (HLOAD.detail.procs[k] || []).forEach(q => { q.cpu = 0.3; q.rss = 0; }));
    HLOAD.timer && clearInterval(HLOAD.timer); HLOAD.noPoll = true;
    const bad = [];
    const check = (where) => {
      document.querySelectorAll('.hl-bar > span, .hp-bar > span').forEach(s => { if (s.style.width && s.style.width !== '0%') bad.push(where + ' bar ' + s.style.width + ' ' + (s.closest('tr') || s.parentNode.parentNode).textContent.slice(0, 40)); });
      document.querySelectorAll('.hl-ring-fg, .hp-ring-fg').forEach(c => { const d = c.getAttribute('stroke-dasharray'); if (!/^0\.0 /.test(d)) bad.push(where + ' ring ' + d); });
    };
    let n = 0;
    ['graphs', 'pills', 'line', 'rings'].forEach(look => { ME.prefs.hload = look; hloadDraw(HLOAD.last); check(look); n++; });
    ['tiles', 'table', 'map', 'wide'].forEach(st => ['cpu', 'mem', 'disk', 'net'].forEach(k => {
      ME.prefs.hpanel = st; HLOAD.open = k;
      if (!$('hload-panel')) { const q = document.createElement('div'); q.id = 'hload-panel'; document.body.appendChild(q); }
      hloadPanelDraw(); check(st + '/' + k); n++;
    }));
    out.n = n; out.bad = bad;
    out.bars = document.querySelectorAll('#hload-panel .hp-bar').length;
    return out;
  });
  console.log(JSON.stringify(r, null, 1));
  const ok = JSON.stringify(r.w) === '[0,0,1,100,0,0]' && r.n === 20 && !r.bad.length;
  await p.evaluate(() => api('settings', {settings: {load_meter: 0}}));
  console.log('page errors:', errs.join(' | ') || 'none'); console.log(ok ? 'ALL OK' : 'FAILED');
  await b.close();
})();
