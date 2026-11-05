const { chromium } = require('playwright');
const S = '/tmp/claude-0/-home-user-UPSMon/eb6ab9f9-d3d4-5653-939f-615b11af19f7/scratchpad/';
const BASE = 'http://localhost:8080/settings/';
const { execSync } = require('child_process');
const cli = a => execSync('cd /tmp && python3 /home/user/UPSMon/upsmon.py ' + a, {encoding: 'utf8'});
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
(async () => {
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1300, height: 950 } });
  const p = await ctx.newPage();
  const errs = []; p.on('pageerror', e => errs.push(e.message));
  const cdp = await ctx.newCDPSession(p);
  await cdp.send('WebAuthn.enable');
  const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true}});
  await p.goto(BASE);
  check('off: no passkey button on the sign-in page', !(await p.$('#pk-or')), null);
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go'); await p.waitForSelector('#ctl-nav');
  for (const k of (await p.evaluate(() => api('passkeys&all=1').then(d => d.passkeys)))) await p.evaluate(id => api('passkeys', {do: 'delete', id: id}), k.id);
  await p.evaluate(() => api('settings', {settings: {passkeys: 1}}));
  await p.click('#signout'); await p.waitForTimeout(1200); await p.goto(BASE);
  check('on, no passkey added yet: the button is offered (4.4.1)', await p.isVisible('#pk-go'), null);
  const login = async () => { await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go'); await p.waitForSelector('#ctl-nav', { timeout: 15000 }); };
  await login();
  await p.evaluate(() => api('settings', {settings: {passkeys: 0}})); await p.reload(); await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => showMe()); await p.waitForTimeout(1200);
  check('off: Add is disabled, and says why', await p.evaluate(() => { const b = [...document.querySelectorAll('#modal button')].find(x => /passkey of this device|passkey tohoto zařízení/.test(x.textContent)); return b && b.disabled && /switched off|vypnuté/.test(b.parentNode.textContent); }), null);
  const r403 = await p.evaluate(() => api('passkey-register', {step: 'begin'}).then(() => 'went', e => e.message));
  check('off: register refused', /switched off/.test(r403), r403);
  await p.evaluate(() => api('settings', {settings: {passkeys: 1}}));
  await p.reload(); await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => showMe()); await p.waitForTimeout(1200);
  await p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /passkey of this device|passkey tohoto zařízení/.test(x.textContent)).click());
  await p.waitForTimeout(2500);
  const mine = await p.evaluate(() => api('passkeys').then(d => d.passkeys));
  check('on: a passkey added from Your account', mine.length === 1 && mine[0].host === 'localhost', mine);
  await p.screenshot({ path: S + 'pk-me.png' });
  const again = await p.evaluate(() => api('passkey-register', {step: 'begin'}).then(d => d.publicKey.excludeCredentials.length));
  check('the one added is excluded next time', again === 1, again);
  // sign out, the button, sign in with it
  await p.evaluate(() => closeModal());
  await p.click('#signout'); await p.waitForTimeout(1500);
  await p.goto(BASE);
  check('signed out: the button is offered', await p.isVisible('#pk-go'), null);
  await p.screenshot({ path: S + 'pk-signin.png' });
  await p.click('#pk-go'); await p.waitForSelector('#ctl-nav', { timeout: 15000 }).catch(() => {});
  check('signed in with the passkey', !!(await p.$('#ctl-nav')), await p.textContent('#in-said').catch(() => ''));
  const used = await p.evaluate(() => api('passkeys').then(d => d.passkeys[0].last_used));
  check('… its last use written', used > 0, used);
  // the admin's view, and taking it away
  await p.evaluate(() => { showPane('people'); }); await p.waitForTimeout(1500);
  await p.evaluate(() => pkOf('admin')); await p.waitForTimeout(1200);
  check('the admin sees it from the row of the account', await p.evaluate(() => /localhost/.test($('modal-body').textContent)), null);
  await p.screenshot({ path: S + 'pk-admin.png' });
  const id = mine[0].id;
  await p.evaluate(id => api('passkeys', {do: 'delete', id: id}), id);
  await p.evaluate(() => closeModal()); await p.click('#signout'); await p.waitForTimeout(1200); await p.goto(BASE);
  check('none left: the button still offered while on', await p.isVisible('#pk-go'), null);
  // the device still has it: the server refuses it
  const refused = await p.evaluate(async () => {
    const d = await api('passkey-begin', {}); const o = d.publicKey; o.challenge = pkBytes(o.challenge);
    const cr = await navigator.credentials.get({publicKey: o});
    return api('passkey-login', {id: cr.id, clientDataJSON: pkText(cr.response.clientDataJSON), authenticatorData: pkText(cr.response.authenticatorData), signature: pkText(cr.response.signature)}).then(() => 'went', e => e.message);
  });
  check('a passkey taken away: refused, said so', /not known here/.test(refused), refused);
  console.log('page errors:', errs.join(' | ') || 'none');
  console.log(ok + ' ok, ' + bad + ' failed'); await b.close();
})();
