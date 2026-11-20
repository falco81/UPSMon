/* Settings -> SELinux, what SELinux refuses sorted by what puts it right (4.9.0), on a test instance
   whose root helper has the stand-in SELinux tools of t_find.py on its PATH (see README.md).
   SHOT: a path prefix for screenshots (optional). */
const { chromium } = require('playwright');
const BASE = process.env.BASE || 'http://127.0.0.1:8080';
const SHOT = process.env.SHOT || '';
const LANG = process.env.LANG_UI || 'en';
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
const wait = (ms) => new Promise(r => setTimeout(r, ms));
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({viewport: {width: 1500, height: SHOT ? 3400 : 1000}, deviceScaleFactor: SHOT ? 2 : 1});
  await ctx.addCookies([{name: 'upsmon_lang', value: LANG, url: BASE}]);
  const p = await ctx.newPage();
  const errs = [];
  p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE + '/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go');
  await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => { showTab('settings'); showPane('selinux'); });
  const t0 = await p.evaluate(() => api('selinux').then(d => Number(d.nodes[0].at) || 0));
  await p.evaluate(() => api('selinux', {action: 'check'}));
  const until = async (fn, ms, arg) => { const end = Date.now() + ms; while (Date.now() < end) { if (await p.evaluate(fn, arg)) return true; await wait(500); } return false; };
  /* A look newer than the one there before (not the last test's, still shown), then drawn. */
  await until((t) => api('selinux').then(d => Number(d.nodes[0].at) > t && !d.nodes[0].pending), 30000, t0);
  await p.evaluate(() => loadSelinux());
  check('the findings drawn', await until((t) => SE.d && Number(SE.d.nodes[0].at) > t && document.querySelectorAll('#se-host .se-group').length > 0 &&
        !document.querySelector('#se-host .se-wait'), 30000, t0), null);
  const groups = () => p.evaluate(() => [...document.querySelectorAll('#se-host .se-group')].map(g => ({
    cls: g.className, n: g.querySelectorAll('.se-item').length, ticked: g.querySelectorAll('.se-item input:checked').length,
    boxes: g.querySelectorAll('.se-item input').length})));
  let g = await groups();
  const by = (k) => g.find(x => x.cls.indexOf('se-k-' + k) >= 0) || {n: 0, ticked: 0, boxes: 0};
  check('a label, a boolean, a rule of upsmon\'s (2) - all ticked', by('label').n === 1 && by('boolean').n === 1 && by('rule').n === 2 &&
        by('label').ticked + by('boolean').ticked + by('rule').ticked === 4, g);
  check('not for a button and not upsmon\'s - no box to tick', by('nobutton').n >= 2 && by('nobutton').boxes === 0 && by('other').n >= 1 && by('other').boxes === 0, g);
  const putWords = () => p.evaluate(() => { const x = [...document.querySelectorAll('#se-host .se-put button')][0]; return x ? x.textContent.trim() : ''; });
  if (LANG === 'en') check('the button counts: Put in what is selected (4)', await putWords() === 'Put in what is selected (4)', await putWords());
  check('enforcing locked', await p.evaluate(() => [...document.querySelectorAll('#se-host .se-btns button')].some(x => /enforcing|vynucov/i.test(x.textContent) && x.disabled)), null);
  if (SHOT) await (await p.$('#se-host .se-card')).screenshot({path: SHOT + '-findings.png'});
  // untick one rule: the count follows, the group is half ticked
  await p.evaluate(() => document.querySelector('#se-host .se-k-rule .se-item input').click());
  await wait(300);
  if (LANG === 'en') check('one unticked: (3), the group half ticked', await putWords() === 'Put in what is selected (3)' &&
        await p.evaluate(() => document.querySelector('#se-host .se-k-rule .se-group-h input').indeterminate), await putWords());
  await p.evaluate(() => document.querySelector('#se-host .se-k-rule .se-group-h input').click());
  await wait(300);
  if (LANG === 'en') check('select all of the group: (4) again', await putWords() === 'Put in what is selected (4)', await putWords());
  await p.evaluate(() => document.querySelector('#se-host .se-put button').click());
  await p.waitForSelector('#modal:not([hidden]) .se-plan');
  const plan = await p.evaluate(() => [...document.querySelectorAll('#modal .se-plan li code')].map(x => x.textContent));
  check('the confirm lists exactly what root will do', plan.length === 4 && plan.some(x => x === 'setsebool -P httpd_can_network_connect 1') &&
        plan.some(x => x === 'restorecon -R -v /var/www/upsmon/assets') && plan.filter(x => x.startsWith('(allow')).length === 2, plan);
  if (SHOT) await (await p.$('#modal .box')).screenshot({path: SHOT + '-confirm.png'});
  const sent = [];
  p.on('request', r => { if (/api=selinux/.test(r.url()) && r.method() === 'POST') sent.push(r.postData()); });
  await p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /Put it in|Nasadit|Vložit/.test(x.textContent)).click());
  check('put in: "put right just now", the local rules listed',
        await until(() => !!document.querySelector('#se-host .se-k-fixed') && !!document.querySelector('#se-host .se-rules'), 30000), await groups());
  check('… the page sent only the ids', sent.length === 1 && (() => { const j = JSON.parse(sent[0]); return j.action === 'fix' &&
        j.ids.length === 4 && j.ids.every(i => /^[0-9a-f]{12}$/.test(i)) && Object.keys(j).sort().join() === 'action,ids'; })(), sent);
  g = await groups();
  check('… 4 put right, nothing ticked left', by('fixed').n === 4 && by('rule').n === 0 && by('label').n === 0, g);
  const rules = await p.evaluate(() => [...document.querySelectorAll('#se-host .se-rules .se-item .mono')].map(x => x.textContent));
  check('… 2 local rules, each with Take it away', rules.length === 2 &&
        await p.evaluate(() => document.querySelectorAll('#se-host .se-rules .se-item button').length === 2), rules);
  const ev = await p.evaluate(() => api('events&limit=30').then(d => JSON.stringify(d)));
  check('… every step in Events', /SELinux: boolean httpd_can_network_connect on/.test(ev) && /SELinux: rule [0-9a-f]{12}/.test(ev) &&
        /upsmon_local\) put into the policy/.test(ev), null);
  if (SHOT) await (await p.$('#se-host .se-card')).screenshot({path: SHOT + '-after.png'});
  await p.evaluate(() => document.querySelector('#se-host .se-rules .se-item button').click());
  await p.waitForSelector('#modal:not([hidden])');
  await p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /Take it away|Odebrat/.test(x.textContent)).click());
  check('take one away: one rule left', await until(() => document.querySelectorAll('#se-host .se-rules .se-item').length === 1, 30000), null);
  console.log('page errors:', errs.join(' | ') || 'none');
  console.log(ok + ' ok, ' + bad + ' failed');
  await b.close();
  process.exit(bad ? 1 : 0);
})();
