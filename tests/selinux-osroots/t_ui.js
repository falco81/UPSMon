/* SELinux and the system's trusted roots (4.6.0) on the pages of a test instance (run as root
   beside it, with something standing in for upsmon-web.path). CA files from CADIR (root.pem,
   int.pem, root.cer); the trusted roots are added for real and taken away again. */
const { chromium } = require('playwright');
const fs = require('fs');
const { execSync } = require('child_process');
const BASE = process.env.BASE || 'http://localhost:8080';
const CADIR = process.env.CADIR;
const SHOT = process.env.SHOT || '';
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
const db = sql => execSync(`python3 -c "import sqlite3,sys;c=sqlite3.connect('/var/lib/upsmon/upsmon.db');c.execute(sys.argv[1]);c.commit()" "${sql.replace(/"/g, '\\"')}"`);
const bundle = () => (fs.readFileSync('/etc/ssl/certs/ca-certificates.crt', 'utf8').match(/BEGIN CERTIFICATE/g) || []).length;
const wait = async (p, fn, ms) => { const end = Date.now() + (ms || 30000); while (Date.now() < end) { if (await p.evaluate(fn)) return true; await p.waitForTimeout(700); } return false; };
(async () => {
  const b = await chromium.launch(); const ctx = await b.newContext({ viewport: { width: 1400, height: 1000 }, deviceScaleFactor: SHOT ? 2 : 1 });
  await ctx.addCookies([{ name: 'upsmon_lang', value: process.env.LANG_UI || 'en', url: BASE }]);
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE + '/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go'); await p.waitForSelector('#ctl-nav');
  /* ---- the system's trusted roots ---- */
  const was = bundle();
  await p.evaluate(() => showPane('web'));
  await p.waitForSelector('#osr-host .pw-node', { timeout: 30000 });
  check('Certificates and TLS: the card, the server\'s box', await p.isVisible('#osr-card') && /local additions in/i.test(await p.textContent('#osr-host')), null);
  check('… somebody else\'s files shown, left alone', /leaves them as they are/.test(await p.textContent('#osr-host')), null);
  /* add: the root and the intermediate pasted, a server's own certificate refused in the dialog */
  await p.click('#osr-host button.primary');
  await p.waitForSelector('#modal textarea');
  await p.fill('#modal textarea', fs.readFileSync(CADIR + '/root.pem', 'utf8') + fs.readFileSync(CADIR + '/int.pem', 'utf8') + fs.readFileSync(CADIR + '/leaf.pem', 'utf8'));
  await wait(p, () => document.querySelectorAll('#modal .osr-one').length === 3, 10000);
  const seen = await p.evaluate(() => [...document.querySelectorAll('#modal .osr-one')].map(x => ({t: x.querySelector('.tag').textContent, bad: !!x.querySelector('.bad')})));
  check('the dialog reads as one types: root, intermediate, not taken', JSON.stringify(seen.map(x => x.t)) === JSON.stringify(['root', 'intermediate', 'not taken']) && seen[2].bad, seen);
  if (SHOT) await (await p.$('#modal .modal-card, #modal > div')).screenshot({ path: SHOT + '-osr-add.png' }).catch(() => 0);
  await p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /Add them|Přidat/.test(x.textContent)).click());
  await p.waitForTimeout(800);
  const ok1 = await wait(p, () => /as wanted|jak má být/i.test(($('osr-host') || {}).textContent || '') && document.querySelectorAll('#osr-host table tbody tr').length === 2, 40000);
  check('added: two rows, the server as wanted', ok1, await p.textContent('#osr-host'));
  const files = fs.readdirSync('/usr/local/share/ca-certificates').filter(n => /^upsmon-[0-9a-f]{16}\.crt$/.test(n));
  check('… two upsmon-<sha16>.crt files in the system\'s folder', files.length === 2, files);
  check('… the system\'s list two longer (' + was + ' -> ' + bundle() + ')', bundle() === was + 2, bundle());
  if (SHOT) await (await p.$('#osr-card')).screenshot({ path: SHOT + '-osr.png' });
  /* the same again: there already */
  const again = await p.evaluate(t => api('osroots', {action: 'add', text: t}).then(() => 'went', e => e.message), fs.readFileSync(CADIR + '/root.pem', 'utf8'));
  check('the same again: nothing added', /there already/.test(again), again);
  /* a DER file, the way the dialog reads it */
  const der = await p.evaluate(b64 => { const bin = atob(b64); const u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return osrFileText(u.buffer); }, fs.readFileSync(CADIR + '/root.cer').toString('base64'));
  const derc = await p.evaluate(t => api('osroots', {action: 'check', text: t}).then(x => x.certs.map(c => [c.kind, c.already])), der);
  check('a .cer (DER) read in the browser: the root, there already', JSON.stringify(derc) === JSON.stringify([['root', true]]), derc);
  /* a read-only account sees, cannot change */
  await p.evaluate(() => api('users', {action: 'add', name: 'osro', role: 'readonly', password: 'Readonly-pass-9', note: '', must_change: 0}).catch(() => 0));
  const c2 = await b.newContext(); const q = await c2.newPage();
  await q.goto(BASE + '/settings/'); await q.fill('#in-name', 'osro'); await q.fill('#in-pass', 'Readonly-pass-9'); await q.click('#in-go'); await q.waitForSelector('#ctl-nav');
  const rv = await q.evaluate(() => api('osroots').then(d => d.certs.length, e => e.status));
  const rw = await q.evaluate(() => api('osroots', {action: 'refresh'}).then(() => 'went', e => e.status));
  const rs = await q.evaluate(() => api('selinux').then(() => 'given', e => e.status));
  check('read-only: sees the authorities (2), may not change them (403), no SELinux (403)', rv === 2 && rw === 403 && rs === 403, [rv, rw, rs]);
  await c2.close();
  await p.evaluate(() => api('users', {action: 'delete', name: 'osro'}).catch(() => 0));
  /* remove the intermediate, then the root - from the page */
  for (let i = 0; i < 2; i++) {
    await p.evaluate(() => [...document.querySelectorAll('#osr-host table tbody tr')].pop().querySelector('.iconbtn:last-child').click());
    await p.waitForTimeout(500);
    await p.evaluate(() => [...document.querySelectorAll('#modal button')].reverse().find(x => /Take it away|Odebrat/.test(x.textContent) && x.offsetParent).click());
    await p.waitForTimeout(400);
    await p.evaluate(() => { const y = [...document.querySelectorAll('.sure-strip button')].find(x => /Take it away|Odebrat/.test(x.textContent)); if (y) y.click(); });
    await wait(p, n => document.querySelectorAll('#osr-host table tbody tr').length === n, 20000, 1 - i);
    await p.waitForTimeout(1500);
  }
  await wait(p, () => !document.querySelector('#osr-host table'), 30000);
  await p.waitForTimeout(6000);
  check('taken away from the page: the files gone, the list as before (' + bundle() + ')',
        !fs.readdirSync('/usr/local/share/ca-certificates').some(n => /^upsmon-/.test(n)) && bundle() === was, fs.readdirSync('/usr/local/share/ca-certificates'));
  check('… somebody else\'s files still there', fs.readdirSync('/usr/local/share/ca-certificates').length >= 1, null);
  /* ---- SELinux ---- */
  await p.evaluate(() => showPane('selinux'));
  await p.waitForSelector('#se-host .se-node', { timeout: 15000 });
  await p.evaluate(() => api('selinux', {action: 'check'}));
  const absent = await wait(p, () => { loadSelinux(); return /not on this machine|no SELinux/i.test(($('se-host') || {}).textContent || ''); }, 30000);
  check('SELinux: this machine has none - said so, no button', absent && !(await p.$('#se-host .se-btns')), await p.textContent('#se-host'));
  const states = {
    permissive: {mode: 'Permissive', config: 'permissive', policy: 'targeted', module: true, ready: false,
      labels: [{path: '/run/upsmon', label: 'httpd_var_run_t', want: 'httpd_var_run_t', why: 'the folder of the daemon\'s token and port', ok: true},
               {path: '/run/upsmon/admin-token', label: 'var_run_t', want: 'httpd_var_run_t', why: 'the token the settings pages ask with', ok: false},
               {path: '/var/www/upsmon', label: 'httpd_sys_content_t', want: 'httpd_sys_content_t', why: 'the pages', ok: true}],
      booleans: [{name: 'httpd_can_network_connect', why: 'the pages ask the daemon on 127.0.0.1:9849 and :9848', on: false}], ports: [],
      denials: {tool: true, total: 3, since: 0, settled: 0, groups: [{source: 'httpd_t', target: 'var_run_t', class: 'file', perms: 'read open', count: 3, what: 'php-fpm admin-token'}]},
      auditd: true, problems: ['x']},
    enforcing: {mode: 'Enforcing', config: 'enforcing', policy: 'targeted', module: true, ready: false,
      labels: [{path: '/run/upsmon', label: 'httpd_var_run_t', want: 'httpd_var_run_t', why: 'the folder of the daemon\'s token and port', ok: true}],
      booleans: [{name: 'httpd_can_network_connect', why: 'the pages ask the daemon on 127.0.0.1:9849 and :9848', on: true}], ports: [],
      denials: {tool: true, total: 0, since: 1, groups: []}, auditd: true, problems: []},
    disabled: {mode: 'Disabled', config: 'disabled', policy: 'targeted', problems: []},
    made: {mode: 'Disabled', config: 'permissive', relabel_pending: true, policy: 'targeted', problems: []}};
  const want = {permissive: ['Put in what upsmon needs', 'Switch to enforcing'], enforcing: ['Back to permissive'], disabled: ['Make it ready (permissive)'], made: []};
  for (const k of Object.keys(states)) {
    db(`INSERT OR REPLACE INTO meta (k, v) VALUES ('selinux:now', '${JSON.stringify({data: states[k], at: Date.now() / 1000, done: 'x', error: '', said: k === 'enforcing' ? ['SELinux is enforcing, and stays so after a restart'] : [], action: k === 'enforcing' ? 'enforce' : 'check'}).replace(/'/g, "''")}')`);
    db(`DELETE FROM meta WHERE k = 'selinux:want'`);
    await p.evaluate(() => loadSelinux()); await p.waitForTimeout(900);
    const btns = await p.evaluate(() => [...document.querySelectorAll('#se-host .se-btns button')].map(x => ({t: x.textContent.trim(), d: x.disabled})));
    check('SELinux ' + k + ': the buttons ' + JSON.stringify(want[k]), JSON.stringify(btns.map(x => x.t)) === JSON.stringify(want[k]), btns);
    if (k === 'permissive') {
      check('… enforcing not offered while something is missing', btns[1] && btns[1].d, btns);
      check('… the checklist: the wrong label, the boolean off, 3 refused', await p.evaluate(() => {
        const t = $('se-host').textContent; return /var_run_t\s+→\s+httpd_var_run_t/.test(t) && /httpd_can_network_connect = off/.test(t) && /refused 3 thing/.test(t) && /Not ready for enforcing yet/.test(t); }), await p.textContent('#se-host'));
    }
    if (k === 'enforcing') check('… "Enforcing - and everything upsmon needs is there"', /Enforcing - and everything upsmon needs is there/.test(await p.textContent('#se-host')), null);
    if (k === 'made') check('… made ready, waiting for a restart', /waiting for a restart/.test(await p.textContent('#se-host')), null);
    if (SHOT) await (await p.$('#se-host')).screenshot({ path: SHOT + '-se-' + k + '.png' });
  }
  /* asking a step: the ask written, the row pending, a look does not put it aside */
  db(`INSERT OR REPLACE INTO meta (k, v) VALUES ('selinux:now', '${JSON.stringify({data: states.permissive, at: Date.now() / 1000, done: 'x', said: [], action: 'check'}).replace(/'/g, "''")}')`);
  await p.evaluate(() => loadSelinux()); await p.waitForTimeout(700);
  await p.evaluate(() => [...document.querySelectorAll('#se-host .se-btns button')][0].click());
  await p.waitForTimeout(400);
  await p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /Put it in|Vložit/.test(x.textContent)).click());
  await p.waitForTimeout(400);
  const w1 = await p.evaluate(() => api('selinux').then(d => d.nodes[0].pending));
  await p.evaluate(() => api('selinux', {action: 'check'}));
  const w2 = await p.evaluate(() => api('selinux').then(d => d.nodes[0].pending));
  check('a step asked: pending (prepare); a look does not put it aside', w1 === 'prepare' && w2 === 'prepare', [w1, w2]);
  const ev = await p.evaluate(() => api('events&limit=30').then(d => JSON.stringify(d)));
  check('… in the events, with who asked', /admin asked SELinux/.test(ev), null);
  await wait(p, () => api('selinux').then(d => !d.nodes[0].pending), 30000);
  console.log('page errors:', errs.join(' | ') || 'none'); console.log(ok + ' ok, ' + bad + ' failed'); await b.close();
  process.exit(bad ? 1 : 0);
})();
