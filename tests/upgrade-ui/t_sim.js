/* The upgrade band (4.8.0) on a test instance, step by step, as an upgrade goes: .upgrade.json is
   written by hand, the daemon and php -S are killed and started again (run as root beside it).
   WEB: the web root of the instance (.upgrade.json is written there); START_API / KILL_API /
   START_PHP / KILL_PHP: shell commands; SHOTS: a folder for the screenshots (optional). */
const { chromium } = require('playwright');
const { execSync } = require('child_process');
const fs = require('fs');
const BASE = process.env.BASE || 'http://127.0.0.1:8080';
const F = (process.env.WEB || '/home/user/UPSMon/web') + '/.upgrade.json';
const SHOTS = process.env.SHOTS || '';
const LANG = process.env.LANG_UI || 'en';
const sh = (c) => { try { execSync(c, {stdio: 'ignore'}); } catch (e) { } };
const killApi = () => sh(process.env.KILL_API), startApi = () => sh(process.env.START_API);
const killPhp = () => sh(process.env.KILL_PHP), startPhp = () => sh(process.env.START_PHP);
const now = () => Math.floor(Date.now() / 1000);
let started = now();
function tell(state, part, words, extra) {
  fs.writeFileSync(F + '.t', JSON.stringify(Object.assign({state, id: 'sim1', version: '4.8.0', from: '4.7.1',
    by: 'admin on the pages', part, parts: 13, words, started, at: now(), said: '', downgrade: false}, extra || {})));
  fs.renameSync(F + '.t', F);
}
const gone = () => { try { fs.unlinkSync(F); } catch (e) { } };
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
const wait = (ms) => new Promise(r => setTimeout(r, ms));
async function until(p, fn, ms) {
  const end = Date.now() + ms;
  while (Date.now() < end) { try { if (await p.evaluate(fn)) return true; } catch (e) { } await wait(400); }
  return false;
}
(async () => {
  gone();
  const b = await chromium.launch();
  const ctx = await b.newContext({viewport: {width: 1500, height: 950}, deviceScaleFactor: SHOTS ? 2 : 1});
  await ctx.addCookies([{name: 'upsmon_lang', value: LANG, url: BASE}]);
  const p = await ctx.newPage();
  const errs = [];
  p.on('pageerror', e => errs.push(e.message));
  const shot = async (n) => { if (SHOTS) { await p.screenshot({path: `${SHOTS}/${n}.png`}); console.log('     shot ' + n); } };
  const band = () => p.evaluate(() => { const x = document.getElementById('upband');
    return x ? {hidden: x.hidden, cls: x.className, text: x.textContent.replace(/\s+/g, ' ').trim()} : null; });
  const watchToasts = () => p.evaluate(() => { window.__toasts = []; const o = window.toast;
    window.toast = function (w, k) { window.__toasts.push([String(w), k]); return o.apply(this, arguments); }; });
  const redToasts = () => p.evaluate(() => (window.__toasts || []).filter(t => t[1] === 'bad').map(t => t[0]));

  await p.goto(BASE + '/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav'); await wait(1500);
  await watchToasts();

  /* 1. started: the band, the pill */
  started = now();
  tell('running', 1, 'Checking this machine');
  check('running: the band appears within a tick', await until(p, () => { const x = document.getElementById('upband'); return x && !x.hidden; }, 8000), await band());
  let bd = await band();
  if (LANG === 'en') {
    check('… says "upsmon is being upgraded to 4.8.0", from, asked by, step 1 of 13',
          /upsmon is being upgraded to 4\.8\.0/.test(bd.text) && /from 4\.7\.1/.test(bd.text) && /asked by admin on the pages/.test(bd.text) && /step 1 of 13/.test(bd.text), bd.text);
    check('… the pill says in maintenance', await p.evaluate(() => document.getElementById('state-pill').textContent.trim()) === 'in maintenance', null);
  }
  await shot('01-running');
  tell('running', 4, 'Creating the service accounts');
  /* 2. Settings -> Upgrades */
  await p.evaluate(() => { showTab('settings'); showPane('upgrade'); }); await wait(2500);
  await shot('02-upgrades-pane');

  /* 3. the daemon restarting */
  tell('running', 11, 'Configuring nginx');
  killApi();
  await wait(9000);
  bd = await band();
  if (LANG === 'en') check('daemon away: "The daemon is restarting with the new version - not answering for N s"', /The daemon is restarting with the new version - not answering for \d+ s/.test(bd.text), bd.text);
  check('… no red "not answering" bar', await p.evaluate(() => document.getElementById('offline').hidden), null);
  check('… no red toast', (await redToasts()).length === 0, await redToasts());
  check('… Upgrades: the card from the disk', await p.evaluate(() => !document.getElementById('up-plan-card').hidden && !!document.querySelector('#up-retry .up-bar')), null);
  await shot('03-api-down');

  /* 4. nginx and PHP restarting */
  tell('running', 12, 'SELinux');
  killPhp();
  await wait(7000);
  bd = await band();
  if (LANG === 'en') check('PHP away: "nginx and PHP are restarting - these pages cannot be reached"', /nginx and PHP are restarting - these pages cannot be reached for \d+ s/.test(bd.text), bd.text);
  check('… still no red toast, no red bar', (await redToasts()).length === 0 && await p.evaluate(() => document.getElementById('offline').hidden), await redToasts());
  await shot('04-php-down');

  /* 5. PHP back, the daemon not yet */
  tell('running', 13, 'Starting the daemon');
  startPhp();
  await wait(5000);
  bd = await band();
  if (LANG === 'en') check('PHP back: the progress from the file again (step 13 of 13), the daemon still away', /step 13 of 13/.test(bd.text) && /The daemon is restarting/.test(bd.text), bd.text);
  await shot('05-php-back');

  /* 6. the daemon answers again, 7. done: loaded once */
  await p.evaluate(() => { window.__before = 1; });
  startApi();
  await wait(7000);
  bd = await band();
  check('daemon back: the band without "not answering"', !/not answering|cannot be reached/.test(bd.text) && !bd.hidden, bd.text);
  await shot('06-api-back');
  tell('done', 13, 'upsmon 4.8.0 runs');
  const reloaded = await until(p, () => window.__before === undefined && document.readyState === 'complete', 15000);
  check('done: the page loaded itself again (once)', reloaded, null);
  await wait(2500);
  bd = await band();
  check('… after it, no band (it was not seen running by this page)', !bd || bd.hidden, bd);
  await p.evaluate(() => { window.__again = 1; });
  await wait(7000);
  check('… and not loaded again in a loop', await p.evaluate(() => window.__again === 1), null);
  await shot('07-done');

  /* 8. failed */
  await watchToasts();
  started = now() - 95;
  tell('failed', 6, 'Installing the program', {id: 'sim2', said: 'install.sh --upgrade stopped (exit 1) during "Installing the program": the daemon is not running'});
  check('failed: a red band', await until(p, () => { const x = document.getElementById('upband'); return x && !x.hidden && /failed/.test(x.className); }, 8000), await band());
  bd = await band();
  if (LANG === 'en') check('… the reason, "Open Upgrades", it took 1 min 35 s', /exit 1/.test(bd.text) && /Open Upgrades/.test(bd.text) && /it took 1 min 3\d s/.test(bd.text), bd.text);
  await shot('08-failed');
  await p.evaluate(() => [...document.querySelectorAll('#upband a')].find(a => /Upgrades|Upgrady|upgrad/i.test(a.textContent)).click());
  await wait(1200);
  check('… Open Upgrades opens the pane', await p.evaluate(() => PANE === 'upgrade' && TAB === 'settings'), null);
  await p.click('#upband .upband-x'); await wait(300);
  check('… × hides it', (await band()).hidden, await band());
  await wait(6000);
  check('… and it stays hidden for that upgrade', (await band()).hidden, await band());

  /* 9. signed out during an upgrade */
  const c2 = await b.newContext({viewport: {width: 1100, height: 800}, deviceScaleFactor: SHOTS ? 2 : 1});
  await c2.addCookies([{name: 'upsmon_lang', value: LANG, url: BASE}]);
  const q = await c2.newPage();
  q.on('pageerror', e => errs.push('signin: ' + e.message));
  started = now() - 30;
  tell('running', 13, 'Starting the daemon', {id: 'sim3'});
  killApi();
  await wait(1500);
  await q.goto(BASE + '/settings/');
  await wait(3000);
  const sb = await q.evaluate(() => { const x = document.getElementById('upband'); return x ? {hidden: x.hidden, text: x.textContent.replace(/\s+/g, ' ').trim()} : null; });
  check('sign-in page during an upgrade: the band (not "the daemon is not answering")', sb && !sb.hidden &&
        await q.evaluate(() => ![...document.querySelectorAll('.signbox .offline:not(.upband)')].some(x => /not answering/.test(x.textContent))), sb);
  if (LANG === 'en') check('… "upsmon is being upgraded to 4.8.0", without who asked', /being upgraded to 4\.8\.0/.test(sb.text) && !/admin on the pages/.test(sb.text), sb.text);
  if (SHOTS) await q.screenshot({path: `${SHOTS}/09-signin.png`});
  await q.evaluate(() => { window.__before = 1; });
  startApi();
  check('… loaded again by itself once the daemon answers', await until(q, () => window.__before === undefined && document.readyState === 'complete', 20000), null);
  await wait(1500);
  check('… then the sign-in form, the band still there while it runs', await q.evaluate(() => !!document.getElementById('in-name') && !!document.querySelector('.signbox #upband')), null);

  /* 10. the dashboard */
  const d = await c2.newPage();
  d.on('pageerror', e => errs.push('dashboard: ' + e.message));
  await d.goto(BASE + '/'); await wait(2500);
  started = now() - 20;
  tell('running', 12, 'SELinux', {id: 'sim4'});
  killApi();
  check('dashboard: the band and "In maintenance"', await until(d, () => { const x = document.getElementById('upg-banner');
    return x && !x.hidden && /maintenance|údržb/i.test(document.getElementById('verdict').textContent); }, 12000),
    await d.evaluate(() => [document.getElementById('upg-banner').textContent, document.getElementById('verdict').textContent]));
  if (SHOTS) await d.screenshot({path: `${SHOTS}/10-dashboard.png`});
  await d.evaluate(() => { window.__before = 1; });
  startApi();
  await wait(6000);
  tell('done', 13, 'upsmon 4.8.0 runs', {id: 'sim4'});
  check('… done: the dashboard loaded once', await until(d, () => window.__before === undefined && document.readyState === 'complete', 20000), null);

  gone();
  console.log('page errors:', errs.join(' | ') || 'none');
  console.log(ok + ' ok, ' + bad + ' failed');
  await b.close();
  process.exit(bad ? 1 : 0);
})();
