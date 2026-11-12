/* The whole chain (4.7.1) on the pages of a test instance (run as root beside it): a certificate
   uploaded without its intermediate is completed as browsers do; one whose issuer cannot be
   fetched is said incomplete in red, with Complete the chain (primary) and Upload the missing
   authority - and the dialog takes the intermediate. CADIR holds leaf.pem / leaf.key (AIA -> a
   server that answers), leaf-down.pem (AIA -> one that does not), int.pem; the CA's root must be
   in the system's trust (Trusted roots of the system). */
const { chromium } = require('playwright');
const fs = require('fs');
const BASE = process.env.BASE || 'http://localhost:8080';
const CADIR = process.env.CADIR;
const SHOT = process.env.SHOT || '';
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
(async () => {
  const b = await chromium.launch(); const ctx = await b.newContext({ viewport: { width: 1400, height: 1000 }, deviceScaleFactor: SHOT ? 2 : 1 });
  await ctx.addCookies([{ name: 'upsmon_lang', value: process.env.LANG_UI || 'en', url: BASE }]);
  const p = await ctx.newPage(); const errs = []; p.on('pageerror', e => errs.push(e.message));
  await p.goto(BASE + '/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go'); await p.waitForSelector('#ctl-nav');
  const node = await p.evaluate(() => api('web').then(d => d.node));
  const key = fs.readFileSync(CADIR + '/leaf.key', 'utf8');
  const up = (cert) => p.evaluate(a => api('web', {action: 'tls_upload', target: a[0], cert: a[1], key: a[2]}).then(r => r, e => ({error: e.message})), [node, cert, key]);
  const card = () => p.evaluate(() => { const c = document.querySelector('#web-certs .cert-card'); const ch = [...c.querySelectorAll('dt')].find(x => /^Chain$|^Řetěz/.test(x.textContent));
    const dd = ch && ch.nextElementSibling; const sp = dd && dd.querySelector('span');
    return {text: dd ? dd.textContent : '', cls: sp ? sp.className : '', btns: [...c.querySelectorAll('.cert-tools button')].map(x => ({t: x.textContent.trim(), primary: x.classList.contains('primary')}))}; });
  let r = await up(fs.readFileSync(CADIR + '/leaf.pem', 'utf8'));
  check('upload of the leaf alone: completed, said ("fetched: … - it was not sent with the certificate")',
        /The chain: complete - 2 certificates up to .* \(fetched: .* - it was not sent with the certificate\)/.test(r.message || '') && r.complete === true, r.message || r.error);
  await p.evaluate(() => showPane('web')); await p.waitForTimeout(1800);
  let c = await card();
  check('the card: Chain in green, the words', c.cls === 'good' && /^complete - 2 certificates up to/.test(c.text), c);
  check('… Check the chain (not primary), no Upload the missing authority', c.btns.some(x => x.t === 'Check the chain' && !x.primary) &&
        !c.btns.some(x => /missing authority/.test(x.t)), c.btns);
  if (SHOT) await (await p.$('#web-certs .cert-card')).screenshot({ path: SHOT + '-complete.png' });
  r = await up(fs.readFileSync(CADIR + '/leaf-down.pem', 'utf8'));
  check('upload whose issuer cannot be fetched: kept, said incomplete, complete: false (not an error)',
        /The chain: incomplete - the authority .* is not sent and could not be completed/.test(r.message || '') && r.complete === false && !r.error, r.message || r.error);
  await p.evaluate(() => loadWeb()); await p.waitForTimeout(1800);
  c = await card();
  check('the card: Chain in red, why', c.cls === 'bad' && /incomplete - the authority .* could not be fetched/.test(c.text), c);
  check('… Complete the chain primary, and Upload the missing authority', c.btns.some(x => x.t === 'Complete the chain' && x.primary) &&
        c.btns.some(x => x.t === 'Upload the missing authority'), c.btns);
  if (SHOT) await (await p.$('#web-certs .cert-card')).screenshot({ path: SHOT + '-incomplete.png' });
  await p.evaluate(() => [...document.querySelectorAll('#web-certs .cert-tools button')].find(x => x.textContent.trim() === 'Complete the chain').click());
  await p.waitForTimeout(2500);
  check('Complete the chain pressed, the address still down: a warning, no "HTTP 200"',
        await p.evaluate(() => [...document.querySelectorAll('.toast, #toast, .toasts *')].map(x => x.textContent).join(' ')).then(t => !/HTTP 200/.test(t)), null);
  await p.evaluate(() => [...document.querySelectorAll('#web-certs .cert-tools button')].find(x => x.textContent.trim() === 'Upload the missing authority').click());
  await p.waitForSelector('#modal textarea');
  const missing = await p.evaluate(() => document.querySelector('#modal .note b').textContent);
  check('the dialog says which: Missing in the chain: ' + missing, /CA G1$/.test(missing), missing);
  await p.fill('#modal textarea', fs.readFileSync(CADIR + '/int.pem', 'utf8'));
  if (SHOT) await (await p.$('#modal')).screenshot({ path: SHOT + '-dialog.png' }).catch(() => 0);
  await p.evaluate(() => [...document.querySelectorAll('#modal button')].find(x => /Add it to the chain/.test(x.textContent)).click());
  await p.waitForTimeout(2500);
  c = await card();
  check('the authority added by hand: Chain in green, complete', c.cls === 'good' && /^complete - 2 certificates/.test(c.text), c);
  const prof = await p.evaluate(n => api('web').then(d => d.tls[n]), node);
  check('… kept in the chain nginx gets', /BEGIN CERTIFICATE/.test(prof.chain || '') && prof.chain_state.ok === true, prof.chain_state);
  const ev = await p.evaluate(() => api('events&limit=40').then(d => JSON.stringify(d)));
  check('… in the events', /added .* to the chain of the certificate of/.test(ev), null);
  console.log('page errors:', errs.join(' | ') || 'none'); console.log(ok + ' ok, ' + bad + ' failed'); await b.close();
  process.exit(bad ? 1 : 0);
})();
