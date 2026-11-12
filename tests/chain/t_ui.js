/* The whole chain (4.7.0) on the pages of a test instance (run as root beside it):
   a certificate uploaded without its intermediate is completed as browsers do and said so on
   the card; one whose issuer cannot be fetched is said incomplete, with Complete the chain.
   CADIR holds leaf.pem / leaf.key (AIA -> a server that answers), leaf-down.pem (AIA -> one
   that does not); the CA's root must be in the system's trust (Trusted roots of the system). */
const { chromium } = require('playwright');
const fs = require('fs');
const BASE = process.env.BASE || 'http://localhost:8080';
const CADIR = process.env.CADIR;
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
(async () => {
  const b = await chromium.launch(); const ctx = await b.newContext({ viewport: { width: 1400, height: 1000 } });
  await ctx.addCookies([{ name: 'upsmon_lang', value: process.env.LANG_UI || 'en', url: BASE }]);
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE + '/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go'); await p.waitForSelector('#ctl-nav');
  const node = await p.evaluate(() => api('web').then(d => d.node));
  const key = fs.readFileSync(CADIR + '/leaf.key', 'utf8');
  const up = (cert) => p.evaluate(a => api('web', {action: 'tls_upload', target: a[0], cert: a[1], key: a[2]}).then(r => r, e => ({error: e.message})), [node, cert, key]);
  let r = await up(fs.readFileSync(CADIR + '/leaf.pem', 'utf8'));
  check('upload of the leaf alone: completed, said', /chain was incomplete: .*fetched/.test(r.message || '') && r.tls.chain_check.ok, r.message || r.error);
  await p.evaluate(() => showPane('web')); await p.waitForTimeout(1500);
  const card = async () => p.evaluate(() => [...document.querySelectorAll('#web-certs .cert-card')].map(c => c.textContent).join(' | '));
  check('the card: Chain complete (2 certificates up to …), fetched as browsers do',
        /complete \(2 certificate\(s\) up to [^)]+\)/.test(await card()) && /fetched, as browsers do/.test(await card()), await card());
  if (process.env.SHOT) await (await p.$('#web-certs .cert-card')).screenshot({ path: process.env.SHOT + '-ok.png' });
  r = await up(fs.readFileSync(CADIR + '/leaf-down.pem', 'utf8'));
  check('upload whose issuer cannot be fetched: kept with a clear warning', /incomplete - the intermediate .* is not sent/.test(r.message || ''), r.message || r.error);
  await p.evaluate(() => loadWeb()); await p.waitForTimeout(1500);
  check('the card: incomplete, the intermediate named, Complete the chain offered',
        /incomplete - the intermediate .* is not sent/.test(await card()) &&
        await p.evaluate(() => [...document.querySelectorAll('#web-certs button')].some(x => /Complete the chain/.test(x.textContent))), await card());
  if (process.env.SHOT) await (await p.$('#web-certs .cert-card')).screenshot({ path: process.env.SHOT + '-bad.png' });
  await p.evaluate(() => [...document.querySelectorAll('#web-certs button')].find(x => /Complete the chain/.test(x.textContent)).click());
  await p.waitForTimeout(2500);
  check('Complete the chain pressed: still incomplete, said why (the address does not answer)',
        await p.evaluate(() => /could not be fetched/.test(document.querySelector('#web-certs').textContent)), await card());
  const ev = await p.evaluate(() => api('events&limit=40').then(d => JSON.stringify(d)));
  check('… in the events', /the chain of the certificate of .* incomplete/.test(ev) || /incomplete - the intermediate/.test(ev), null);
  console.log('page errors:', errs.join(' | ') || 'none'); console.log(ok + ' ok, ' + bad + ' failed'); await b.close();
  process.exit(bad ? 1 : 0);
})();
