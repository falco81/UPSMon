/* What is to be done by hand (4.5.0), on the pages of a test instance (run as
   root beside it): kept in Settings → Upgrades with a count beside Upgrades in
   the menu (nothing over the pages), Done, Look again, the dashboard, a
   read-only account, and the window before an upgrade. */
const { chromium } = require('playwright');
const fs = require('fs');
const { execSync } = require('child_process');
const BASE = process.env.BASE || 'http://localhost:8080';
const ND = '/etc/upsmon/notices.d';
const FLAG = '/tmp/upsmon-nt-test-flag';
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
const db = sql => execSync(`python3 -c "import sqlite3,sys;c=sqlite3.connect('/var/lib/upsmon/upsmon.db');c.execute(sys.argv[1]);c.commit()" "${sql.replace(/"/g, '\\"')}"`);
const gone = f => { try { fs.unlinkSync(f); } catch (e) { } };
(async () => {
  fs.mkdirSync(ND, { recursive: true });
  gone(FLAG);
  fs.writeFileSync(ND + '/t-danger.json', JSON.stringify({id: 't-danger', level: 'danger', title: 'Run the step by hand',
    text: 'It cannot be done from the pages. (' + Date.now() + ')', commands: ['sudo ./install.sh --upgrade'], cs: {title: 'Spusťte krok ručně'}}));
  fs.writeFileSync(ND + '/t-check.json', JSON.stringify({id: 't-check', level: 'warn', title: 'Waits for a file', text: String(Date.now()),
    check: {file_exists: FLAG}}));
  const b = await chromium.launch(); const ctx = await b.newContext({ viewport: { width: 1400, height: 900 } });
  await ctx.addCookies([{ name: 'upsmon_lang', value: 'en', url: BASE }]);
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE + '/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go'); await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => api('notices', {do: 'check'}));
  await p.reload(); await p.waitForSelector('#ctl-nav .nt-badge', { timeout: 10000 });
  check('nothing over the pages: no band at the top', !(await p.$('#nt-banner')) && !(await p.isVisible('#nt-list')), null);
  const badge = await p.evaluate(() => { const x = document.querySelector('#ctl-nav [data-pane="upgrade"] .nt-badge'); return x && {n: x.textContent, cls: x.className}; });
  check('the menu: a count beside Upgrades, in red', badge && badge.n === '2' && /nt-danger/.test(badge.cls), badge);
  await p.evaluate(() => showPane('upgrade')); await p.waitForTimeout(1000);
  const bands = () => p.evaluate(() => [...document.querySelectorAll('#nt-list .nt-band')].map(x => ({cls: x.className, t: x.querySelector('.nt-title').textContent,
    btns: [...x.querySelectorAll('.nt-acts button')].map(y => y.textContent.trim())})));
  const bs = await bands();
  const dg = bs.find(x => /Run the step/.test(x.t)), ck = bs.find(x => /Waits/.test(x.t));
  check('Settings → Upgrades: a band each, the worst first', bs.length >= 2 && /nt-danger/.test(bs[0].cls), bs);
  check('the first card of Upgrades', await p.evaluate(() => document.querySelector('#pane-upgrade .card').id === 'nt-card'), null);
  check('the danger one: Done', dg && dg.btns.includes('Done'), dg);
  check('the one with a check: Look again too', ck && ck.btns.includes('Look again'), ck);
  check('the command with Copy', await p.evaluate(() => [...document.querySelectorAll('#nt-list .nt-code')].some(c => /install\.sh --upgrade/.test(c.textContent) && /Copy/.test(c.textContent))), null);
  if (process.env.SHOT) await p.screenshot({ path: process.env.SHOT });
  /* the check holds: Look again */
  fs.writeFileSync(FLAG, '');
  await p.evaluate(() => [...document.querySelectorAll('#nt-list .nt-band')].find(x => /Waits/.test(x.textContent)).querySelector('.nt-acts button').click());
  await p.waitForTimeout(1500);
  const r = await p.evaluate(() => api('notices').then(d => d.done.find(n => n.id === 't-check')));
  check('its check holds, Look again: done by itself', r && r.state === 'resolved', r);
  check('… the count down to 1', await p.evaluate(() => (document.querySelector('#ctl-nav .nt-badge') || {}).textContent) === '1', null);
  /* Done */
  await p.evaluate(() => [...document.querySelectorAll('#nt-list .nt-band')].find(x => /Run the step/.test(x.textContent)).querySelector('.nt-acts button:last-child').click());
  await p.waitForTimeout(500);
  await p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /It is done/.test(x.textContent)).click());
  await p.waitForTimeout(1200);
  const dn = await p.evaluate(() => api('notices').then(d => d.done.find(n => n.id === 't-danger')));
  check('Done: kept as done with the name', dn && dn.state === 'done' && dn.closed_by === 'admin', dn);
  check('… no band, no count', (await p.$$('#nt-list .nt-band')).length === 0 && !(await p.$('#ctl-nav .nt-badge')), null);
  check('… "Done lately" lists both', await p.evaluate(() => /Done lately/.test($('nt-list').textContent) && /Run the step/.test($('nt-list').textContent) && /done by itself/.test($('nt-list').textContent)), null);
  /* the dashboard: how bad, never what */
  fs.writeFileSync(ND + '/t-danger2.json', JSON.stringify({id: 't-danger2', level: 'danger', title: 'A secret thing', text: String(Date.now())}));
  await p.evaluate(() => api('notices', {do: 'check'}));
  const dash = await ctx.newPage();
  await dash.goto(BASE + '/'); await dash.waitForTimeout(3000);
  const dt = await dash.evaluate(() => ({shown: !document.getElementById('nt-banner').hidden, text: document.getElementById('nt-banner').textContent}));
  check('the dashboard: said, in red', dt.shown && /done by hand/.test(dt.text), dt);
  check('… without what it is', !/secret/i.test(dt.text), dt);
  const st = await dash.evaluate(() => fetch('/?api=status').then(r => r.json()).then(d => d.notices).catch(e => String(e)));
  check('/api/status: only how many and how bad', st && st.open >= 1 && st.level === 'danger' && Object.keys(st).length === 2, st);
  await dash.close();
  /* a read-only account: Done refused */
  await p.evaluate(() => api('users', {action: 'add', name: 'ntro', role: 'readonly', password: 'Readonly-pass-9', note: '', must_change: 0}).catch(() => 0));
  const c2 = await b.newContext({ viewport: { width: 1400, height: 900 } }); const q = await c2.newPage();
  await q.goto(BASE + '/settings/'); await q.fill('#in-name', 'ntro'); await q.fill('#in-pass', 'Readonly-pass-9'); await q.click('#in-go');
  await q.waitForSelector('#ctl-nav');
  const ro = await q.evaluate(() => api('notices', {do: 'done', id: 't-danger2'}).then(() => 'went', e => e.status));
  check('read-only: Done refused', ro === 403, ro);
  await c2.close();
  await p.evaluate(() => api('users', {action: 'delete', name: 'ntro'}).catch(() => 0));
  /* before an upgrade: a package that asks to be read first */
  db(`INSERT OR REPLACE INTO meta (k, v) VALUES ('upgrade:pkg', '${JSON.stringify({sha: '0'.repeat(64), version: '4.4.0', bytes: 1, pieces: 0,
    notices: [{id: 'pre1', since: '4.4.0', when: 'before', level: 'danger', confirm: true, title: 'Back up first', commands: ['upsmon --backup'], source: 'package'}]})}')`);
  await p.reload(); await p.waitForSelector('#ctl-nav'); await p.evaluate(() => showPane('upgrade')); await p.waitForTimeout(1500);
  check('the package card: what it asks, with a tick', await p.evaluate(() => /Back up first/.test($('up-notices').textContent) && !!$('up-notices').querySelector('input[type=checkbox]')), null);
  const r409 = await p.evaluate(() => api('upgrade', {action: 'start'}).then(() => 'went', e => [e.status, e.detail]));
  check('start without it ticked: refused (409)', JSON.stringify(r409) === JSON.stringify([409, 'notices']), r409);
  await p.evaluate(() => { NT.ack = {}; ntUpgrade({action: 'start'}).catch(e => { window.__ntErr = e.message; }); });
  await p.waitForSelector('#modal .nt-band', { timeout: 5000 });
  const upBtn = () => p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /^Upgrade$/.test(x.textContent.trim())).disabled);
  check('the window: Upgrade not before it is ticked', await upBtn(), null);
  await p.click('#modal .nt-ack input');
  check('… ticked: it may', !(await upBtn()), null);
  await p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /^Upgrade$/.test(x.textContent.trim())).click());
  await p.waitForTimeout(1500);
  const after = await p.evaluate(() => window.__ntErr || '');
  check('… and past the gate (refused only for its own reason: older than what runs)', /newer than 4\.4\.0/.test(after), after);
  db(`DELETE FROM meta WHERE k = 'upgrade:pkg'`);
  for (const f of ['t-danger', 't-check', 't-danger2']) gone(ND + '/' + f + '.json');
  gone(FLAG);
  await p.evaluate(() => api('notices', {do: 'check'}));
  console.log('page errors:', errs.join(' | ') || 'none'); console.log(ok + ' ok, ' + bad + ' failed'); await b.close();
  process.exit(bad ? 1 : 0);
})();
