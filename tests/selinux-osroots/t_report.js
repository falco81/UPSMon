/* The SELinux report (4.6.0): asked from the page, made by root's helper, kept sealed in the
   database for an hour, taken as one .tar.gz - on a test instance (run as root beside it). */
const { chromium } = require('playwright');
const fs = require('fs');
const zlib = require('zlib');
const BASE = process.env.BASE || 'http://localhost:8080';
let ok = 0, bad = 0;
const check = (n, c, g) => { if (c) { ok++; console.log('OK   ' + n); } else { bad++; console.log('FAIL ' + n + '  -> ' + JSON.stringify(g)); } };
(async () => {
  const b = await chromium.launch(); const ctx = await b.newContext({ acceptDownloads: true });
  const p = await ctx.newPage();
  await p.goto(BASE + '/settings/');
  await p.fill('#in-name', 'admin'); await p.fill('#in-pass', 'secret123'); await p.click('#in-go'); await p.waitForSelector('#ctl-nav');
  await p.evaluate(() => showPane('selinux'));
  await p.waitForSelector('#se-host .se-card');
  const dl = p.waitForEvent('download', { timeout: 200000 });
  await p.evaluate(() => [...document.querySelectorAll('#se-host button')].find(x => /Download the report|Stáhnout report/.test(x.textContent)).click());
  const d = await dl;
  const path = await d.path();
  const raw = zlib.gunzipSync(fs.readFileSync(path)).toString('latin1');
  check('the report downloaded: ' + d.suggestedFilename(), /^upsmon-selinux-report-.*\.tar\.gz$/.test(d.suggestedFilename()), d.suggestedFilename());
  check('… with check.json, avc, labels, processes, README', ['check.json', 'avc.txt', 'labels.txt', 'processes.txt', 'README.txt'].every(n => raw.indexOf('upsmon-selinux-report/' + n) >= 0), null);
  check('… no token in it', !/admin-token\s*\n?[A-Za-z0-9_-]{30,}/.test(raw) && raw.indexOf(fs.readFileSync('/run/upsmon/admin-token', 'utf8').trim()) < 0, null);
  const ev = await p.evaluate(() => api('events&limit=20').then(x => JSON.stringify(x)));
  check('… asked and taken, in the events', /asked for the SELinux report/.test(ev) && /took the SELinux report/.test(ev), null);
  await b.close();
  console.log(ok + ' ok, ' + bad + ' failed');
  process.exit(bad ? 1 : 0);
})();
