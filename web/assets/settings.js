/* settings.js - the Settings of upsmon: the pages of OTP (its admin.js, 1.0.187),
   their Accounts, Certificates and TLS, Automatic certificates, Time, Restart and power off,
   The database, Backups, System updates, Upgrades and About, drawn by core.js the way OTP
   draws them, over the upsmon daemon's settings API. */

/* ======== the time picker of Events (OTP admin.js 5-5) ======== */
if ($('ev-time')) timePicker('ev-time', {start: {k: 'all'}, all: true});

/* ======== the header, the account (OTP admin.js 6-537) ======== */
/* admin.js - the administration pages of upsmon, drawn the way isemon draws its
   dashboard: the same header, tabs, rail, popups and panels (core.js), over
   the upsmon daemon's API. The page works nothing out for itself. */
'use strict';

ADMIN = !!(ME && ME.role === 'fulladmin');
var TOKADMIN = ADMIN;
var LIVE = true, SERIAL = STATUS ? STATUS.serial : '', PANE = 'people';
var SETTINGS = null, DIRTY = {}, DRAWN_NODE = '';
var PAGE = {events: 0};

function roleWords(role) {
  return role === 'fulladmin' ? 'full admin' : 'read only';
}
function roleTone(role) {
  return role === 'fulladmin' ? 'violet' : (role === 'tokenadmin' ? 'warn' : 'dim');
}

/* ---- what this account may not even see ---------------------------------- */
(function roles() {
  document.querySelectorAll('.admin-only').forEach(function (n) { if (!ADMIN) n.hidden = true; });
  document.querySelectorAll('.fulladmin-only').forEach(function (n) { if (!ADMIN) n.hidden = true; });
  document.querySelectorAll('.tokadmin-only').forEach(function (n) { if (!TOKADMIN) n.hidden = true; });
  document.querySelectorAll('.token-admin').forEach(function (n) { if (!TOKADMIN) n.hidden = true; });
  if (!ADMIN) $('readonly-note').hidden = false;
  if (!ADMIN) $('save-bar').hidden = true;
}());
dressButtons(document);

/* ---- PHP and php2shell, said to an administrator (as on isemon) ---------- */
(function phpSafety() {
  var box = $('phpsafety'), s = PHP_SAFETY;
  if (!box || !s || s.patched) return;
  /* A distribution that backported the fix keeps the old number; the daemon
     reads the packages' changelog, and when it says the fix is in, so be it. */
  if (STATUS && STATUS.php && STATUS.php.fixed) return;
  box.hidden = false;
  box.classList.toggle('warnish', !!s.guarded);
  box.textContent = 'PHP ' + s.version + ' running this page may have php2shell '
    + '(CVE-2026-109618, CVE-2026-109619): remote code execution by anybody who can reach the '
    + 'web server. Update it - ' + (s.needs ? s.needs + ' or later, ' : '') + 'or the package '
    + 'your distribution fixed (dnf upgrade \'php*\') - and restart php-fpm; ./install.sh '
    + '--upgrade does it. A distribution that backported the fix keeps the old number: check '
    + 'rpm -q --changelog php-fpm | grep CVE-2026-109618.';
}());

/* ---- tabs ------------------------------------------------------------------ */
var TABS = ['events', 'settings'];
window.optShowTab = function (name) {
  if (TABS.indexOf(name) < 0) name = 'settings';
  /* A tab this account may not use (its button is hidden) is not opened by
     the address either (1.0.15). */
  var btn = document.querySelector('.tabs button[data-tab="' + name + '"]');
  if (btn && btn.hidden) name = 'settings';
  TAB = name;
  document.querySelectorAll('.tabs button[data-tab]').forEach(function (b) {
    b.setAttribute('aria-selected', b.getAttribute('data-tab') === name ? 'true' : 'false');
  });
  TABS.forEach(function (one) { $('tab-' + one).hidden = one !== name; });
  writeHash();
  holdTheTallOnes();
  onTab(name);
};
document.querySelectorAll('.tabs button[data-tab]').forEach(function (b) {
  b.onclick = function () { showTab(b.getAttribute('data-tab')); };
});
/* The dashboard of the UPS (upsmon 4.0): the page everybody sees, without signing in. */
document.querySelectorAll('.tabs button[data-href]').forEach(function (b) {
  b.onclick = function () { location.href = b.getAttribute('data-href'); };
});
function writeHash() {
  var want = '#' + TAB + (TAB === 'settings' ? '/' + PANE : '');
  if (location.hash !== want) try { history.replaceState(null, '', want); } catch (e) { }
}
function onTab(name) {
  explainWhatWasDrawn(document);
  if (name === 'events') loadEvents();
  /* Coming back with changes not yet saved keeps them (1.0.15). */
  /* ...and the ones waiting in boxes of their own too (1.0.94): a pasted
     certificate vanished from its box while the bar still counted it. */
  if (name === 'settings') loadSettings(!Object.keys(DIRTY || {}).length && !Object.keys(PENDING || {}).length);
}

/* ---- the header and the live updates -------------------------------------- */
function paintHeader(s) {
  STATUS = s;
  var hs = document.querySelector('header .host');
  if (hs && s.node) {
    if (hs._base === undefined) hs._base = hs.textContent;
    hs.title = 'this page is answered by ' + s.node + ' · upsmon ' + (s.version || '');
  }
  /* The pill says what the dashboard says of the UPS (upsmon 4.0). */
  var pill = $('state-pill');
  var u = s.ups || {};
  var level = u.level || 'unknown';
  var inMaint = !!(s.maintenance && s.maintenance.on);
  var kind = {ok: 'ok', warn: 'warn', crit: 'crit'}[level] || 'unknown';
  if (inMaint && kind === 'ok') kind = 'warn';
  pill.className = 'pill ' + kind;
  pill.lastChild.textContent = inMaint ? 'in maintenance' : ({ok: 'UPS all good', warn: 'UPS needs attention',
    crit: 'UPS problem'}[level] || 'UPS: no data');
  pill.title = (u.name ? 'UPS ' + u.name + ': ' : '') + (u.status_text || u.status || 'the daemon has no reading of the UPS')
    + (u.charge !== undefined && u.charge !== null && u.charge !== '' ? ' · battery ' + u.charge + ' %' : '')
    + (u.load !== undefined && u.load !== null && u.load !== '' ? ' · load ' + u.load + ' %' : '');
  explainWhatWasDrawn(pill.parentNode);
  var pr = $('problems');
  clear(pr);
  (s.problems || []).forEach(function (p, i) {
    if (i) pr.appendChild(el('br'));
    pr.appendChild(document.createTextNode(p));
  });
  pr.hidden = !(s.problems && s.problems.length);
  $('updated-at').textContent = clockWords(new Date());
}

var REDRAW_OWED = false;
function tick() {
  if (!LIVE || document.hidden) return;
  api('status').then(function (s) {
    $('offline').hidden = true;
    var moved = s.serial !== SERIAL || REDRAW_OWED;
    SERIAL = s.serial;
    paintHeader(s);
    /* Not drawn again under somebody reading it (1.0.57): a selection, the
       pointer over a help panel, a box being typed in, or a page further
       back, where every new request moved the rows under the reader. */
    var here = $('tab-' + TAB);
    if (moved && TAB === 'events'
        && !document.querySelector('.modal:not([hidden])')
        && !userHolds(here) && !pointerBusy(here) && !(PAGE.events > 0)) {
      REDRAW_OWED = false;
      onTab(TAB);
    } else if (moved && TAB === 'events') {
      /* Held back under the reader (1.0.94): owed, not forgotten - the
         serial taken meant the next tick saw nothing new. */
      REDRAW_OWED = true;
    }
  }).catch(function (e) {
    var o = $('offline');
    o.hidden = false;
    o.textContent = 'The daemon is not answering: ' + (e.message || e);
  });
}
$('updated').onclick = function () {
  LIVE = !LIVE;
  $('updated').classList.toggle('paused', !LIVE);
  $('updated').querySelector('b').textContent = LIVE ? 'live' : 'paused';
  if (LIVE) tick();
};
$('signout').onclick = function () {
  api('logout', {}).then(function () { location.reload(); }, function () { location.reload(); });
};

/* ---- the account signed in --------------------------------------------- */
function showMe() {
  modal('Your account', function (body) {
    /* Who, as isemon draws it: the initials, the name, the role and where
       the account comes from (1.0.19). */
    var head = el('div', 'me-head');
    var ava = noI18n(el('div', 'me-ava' + (ME.role === 'fulladmin' ? ' admin' : ''), meInitials(ME.name, ME.display)));
    ava.setAttribute('aria-hidden', 'true');
    head.appendChild(ava);
    var who = el('div', 'me-who');
    who.appendChild(noI18n(el('div', 'me-n mono', ME.name)));
    if (ME.display && ME.display !== ME.name) who.appendChild(noI18n(el('div', 'me-d', ME.display)));
    var tags = el('div', 'me-tags');
    tags.appendChild(el('span', 'tag ' + roleTone(ME.role), roleWords(ME.role)));
    tags.appendChild(el('span', 'tag info', 'local account'));
    who.appendChild(tags);
    head.appendChild(who);
    body.appendChild(head);
    var may = el('div', 'me-sec');
    may.appendChild(el('h3', '', 'What you may do'));
    may.appendChild(el('p', '', ME.role === 'fulladmin' ? 'Anything: accounts, certificates, upgrades, settings.'
      : 'Look at every page. Nothing can be changed from this account; how your own tables are laid out is yours to change.'));
    body.appendChild(may);
    var lsec = el('div', 'me-sec');
    lsec.appendChild(el('h3', '', 'Language'));
    body.appendChild(lsec);
    var lang = selectBox((window.OTP_LANGS || []).map(function (l) { return [l.code, l.name]; }),
                         window.OTP_LANG);
    noI18n(lang);
    lang.onchange = function () {
      api('prefs', {lang: lang.value}).then(function () { location.reload(); }).catch(oops);
    };
    lsec.appendChild(formField('The language of these pages', lang));

    pkMeSection(body);
    if ($('hload')) {
      var hsec = el('div', 'me-sec');
      hsec.appendChild(el('h3', '', 'The load of the server'));
      hloadPickers(hsec);
      body.appendChild(hsec);
    }
    /* The columns of the tables - exactly isemon's. */
    var cols = el('div', 'me-sec');
    cols.appendChild(el('h3', '', 'Columns of the tables'));
    var line = el('div', 'me-row');
    var say = el('div', 'me-say');
    say.innerHTML = '<b>Edit the columns</b><br>While this is on, the edge of any column’s '
      + 'heading can be dragged to size it and the heading itself to move it, and the right '
      + 'button on a heading hides a column, brings a hidden one back or adds an empty one '
      + 'for room; each change is kept the moment you let go. It is for this sign-in only: signing out, the sign-in '
      + 'running out or the service restarting turn it off again. Off, the tables are drawn '
      + 'as you left them and nothing can move them.';
    line.appendChild(say);
    var sw = el('label', 'sw');
    var box = el('input');
    box.type = 'checkbox';
    box.id = 'me-cols-edit';
    box.checked = COLS_EDIT;
    box.setAttribute('aria-label', 'Edit the columns');
    sw.appendChild(box);
    sw.appendChild(el('span', 'knob'));
    line.appendChild(sw);
    cols.appendChild(line);
    box.onchange = function () {
      var on = box.checked;
      box.disabled = true;
      colsSwitch(on).then(function (d) {
        box.checked = !!d.edit;
      }).catch(function (e) {
        box.checked = COLS_EDIT;
        oops(e);
      }).then(function () { box.disabled = false; });
    };
    var laid = Object.keys(COLS).length;
    cols.appendChild(el('p', '', laid ? 'You have laid out ' + num(laid) + ' table(s).'
      : 'Every table is as it comes.')).style.marginTop = '10px';
    var acts = el('div', 'me-acts');
    var back = cmdButton('Put my columns back as they come', 'undo', 'small');
    back.id = 'me-cols-reset';
    explain(back, 'Every table you have laid out goes back as it comes: the widths and the '
      + 'order of the columns, on every page. Nobody else’s change.');
    back.disabled = !laid;
    back.onclick = function () {
      back.disabled = true;
      colsReset().then(function () { showMe(); }).catch(function (e) {
        back.disabled = false;
        oops(e);
      });
    };
    acts.appendChild(back);
    cols.appendChild(acts);
    body.appendChild(cols);

    /* Your own settings, to a file and back. */
    var mine = el('div', 'me-sec');
    mine.appendChild(el('h3', '', 'Your settings in a file'));
    mine.appendChild(el('p', '', 'How you have set these pages up for yourself — the '
      + 'columns of the tables and the language — saved as a JSON file, and read back here '
      + 'or on another machine running upsmon. Never your password, your role or anything else '
      + 'about the account.'));
    var io = el('div', 'me-acts');
    var out = cmdButton('Export my settings', 'download', 'small');
    out.id = 'me-export';
    out.onclick = function () { meExport(out); };
    io.appendChild(out);
    var inn = cmdButton('Import settings…', 'upload', 'small');
    inn.id = 'me-import';
    inn.onclick = function () { mePick(); };
    io.appendChild(inn);
    mine.appendChild(io);
    body.appendChild(mine);

    if (ME.source !== 'directory') {
      var pwsec = el('div', 'me-sec');
      pwsec.appendChild(el('h3', '', 'A new password'));
      var old = maskBox('', '', '');
      var nw = maskBox('', '', '');
      var g = el('div', 'formgrid');
      g.appendChild(formField('The one you have now', old));
      g.appendChild(formField('The new one (8 characters at least)', nw));
      pwsec.appendChild(g);
      var go = cmdButton('Change the password', 'lock', 'primary');
      go.style.marginTop = '10px';
      go.onclick = function () {
        api('password', {old: old.value, 'new': nw.value}).then(function (d) {
          toast(d.message, 'good'); closeModal();
        }).catch(oops);
      };
      pwsec.appendChild(go);
      body.appendChild(pwsec);
    }
  }, null, 'medium');
}
$('me-btn').onclick = showMe;

/** "Edit the columns" on or off for this sign-in: the daemon holds it. */
function colsSwitch(on) {
  return api('columns', {edit: !!on}).then(function (d) {
    colsEditing(!!d.edit);
    colsCardSay();
    toast(d.edit ? 'Columns can be sized and moved now — each change is kept at once'
      : 'Columns are held as they are', 'good');
    return d;
  });
}

/** The file a person's own settings go into: one object with a mark of
    what it is, where and when it came from, and `settings` by section -
    `columns` and `prefs`; a version that does not know a section leaves it
    alone. As isemon's, with its own kind. */
var ME_FILE_KIND = 'upsmon-user-settings';

function meExport(button) {
  if (button) button.disabled = true;
  api('my-settings').then(function (d) {
    var file = {
      kind: ME_FILE_KIND,
      format: 1,
      from: location.host,
      version: d.version || '',
      user: d.name || (ME && ME.name) || '',
      exported: new Date().toISOString(),
      settings: d.settings || {}
    };
    var blob = new Blob([JSON.stringify(file, null, 2) + '\n'], {type: 'application/json'});
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'upsmon-settings-' + String(file.user || 'me').replace(/[^a-z0-9._-]/gi, '_')
      + '-' + file.exported.slice(0, 10) + '.json';
    document.body.appendChild(link);
    link.click();
    setTimeout(function () { URL.revokeObjectURL(link.href); link.remove(); }, 1500);
    var n = Object.keys((file.settings || {}).columns || {}).length;
    toast('your settings were saved to ' + link.download + ' (' + num(n)
      + ' table layout(s))', 'good');
  }).catch(oops).then(function () { if (button) button.disabled = false; });
}

function mePick() {
  var pick = el('input');
  pick.type = 'file';
  pick.accept = '.json,application/json';
  pick.hidden = true;
  pick.onchange = function () {
    var file = pick.files && pick.files[0];
    pick.remove();
    if (file) meImport(file);
  };
  document.body.appendChild(pick);
  pick.click();
}

function meImport(file) {
  if (file.size > 2 * 1024 * 1024) {
    toast('that file is far bigger than any settings file (' + bytes(file.size) + ')', 'bad');
    return;
  }
  var reader = new FileReader();
  reader.onerror = function () { toast('that file could not be read', 'bad'); };
  reader.onload = function () {
    var got;
    try { got = JSON.parse(String(reader.result || '')); } catch (e) {
      toast('that is not a settings file: it is not JSON', 'bad');
      return;
    }
    /* Our own file, or just its `settings` on their own. isemon's file is
       read as well: the columns are kept the same way in both. */
    var settings = got && (got.kind === ME_FILE_KIND || got.kind === 'upsmon-user-settings-old' || got.kind === 'isemon-user-settings')
      ? got.settings
      : (got && got.settings && typeof got.settings === 'object' ? got.settings : got);
    if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
      toast('that is not a settings file', 'bad');
      return;
    }
    var cols = settings.columns && typeof settings.columns === 'object'
      ? Object.keys(settings.columns).length : null;
    var other = Object.keys(settings).filter(function (k) {
      return k !== 'columns' && k !== 'prefs';
    });
    var at = got.exported ? Date.parse(String(got.exported)) : NaN;
    modal('Import settings', function (body) {
      body.appendChild(peekFacts([
        ['Whose', got.user ? noI18n(el('span', 'mono', String(got.user))) : '–'],
        ['From', got.from ? noI18n(el('span', 'mono', String(got.from))) : '–'],
        ['Saved', isFinite(at) ? stamp(at / 1000) : '–'],
        ['upsmon version', got.version ? noI18n(el('span', 'mono', String(got.version))) : '–']]));
      body.appendChild(el('p', 'note', 'This file holds:'));
      var list = el('ul', 'me-list');
      if (cols !== null) list.appendChild(el('li', '', 'the columns of ' + num(cols) + ' table(s)'));
      if (settings.prefs && typeof settings.prefs === 'object' && settings.prefs.lang) {
        list.appendChild(el('li', '', 'the language of the page'));
      }
      if (other.length) {
        list.appendChild(el('li', '', other.join(', ') + ' — not kept by this version, left alone'));
      }
      body.appendChild(list);
      body.appendChild(el('p', 'note', 'They replace yours. Your password and your account are not touched.'));
    }, [{words: 'No, leave it', close: true},
        {words: 'Import them', cls: 'primary', close: true, go: function () {
        api('my-settings', {settings: settings}).then(function (d) {
          if (settings.columns && typeof settings.columns === 'object') {
            /* What the daemon kept, not what the file said: it is the same
               less whatever a layout cannot hold. */
            return api('my-settings').then(function (now) {
              colsTake((now.settings || {}).columns || {});
              colsApplyAll();
              return d;
            });
          }
          return d;
        }).then(function (d) {
          toast('imported: the columns of ' + num((d.took || {}).columns || 0) + ' table(s)'
            + ((d.ignored || []).length ? '; left alone: ' + d.ignored.join(', ') : ''), 'good');
          var lang = settings.prefs && typeof settings.prefs === 'object'
            ? String(settings.prefs.lang || '') : '';
          if (lang && lang !== (window.OTP_LANG || 'en')
              && (window.OTP_LANGS || []).some(function (l) { return l.code === lang; })) {
            location.reload();
            return;
          }
          colsCardSay();
        }).catch(oops);
      }}], true);
  };
  reader.readAsText(file);
}

/** The card on the Accounts pane: how many tables are laid out, and the
    switch's words. */
function colsCardSay() {
  var laid = Object.keys(COLS).length;
  if ($('cols-count')) {
    $('cols-count').textContent = laid ? num(laid) + ' table(s) laid out by you'
      : 'every table as it comes';
  }
  var b = $('cols-edit-go');
  if (b) {
    setButtonIcon(b, COLS_EDIT ? 'check' : 'edit',
                  COLS_EDIT ? 'Stop editing the columns' : 'Edit the columns');
    b.classList.toggle('primary', COLS_EDIT);
  }
  if ($('cols-reset')) $('cols-reset').disabled = !laid;
}
$('cols-edit-go').onclick = function () { colsSwitch(!COLS_EDIT).catch(oops); };
$('cols-reset').onclick = function () {
  confirmThen('Put my columns back',
    'Every table you have laid out goes back as it comes: the widths and the order of the '
    + 'columns, on every page. Nobody else’s tables change.',
    'Put them back', function () { colsReset().then(function () { colsCardSay(); loadUsers(); }).catch(oops); });
};
$('cols-export').onclick = function () { meExport($('cols-export')); };
$('cols-import').onclick = function () { mePick(); };


/* ======== Events (OTP admin.js 2373-2400) ======== */
/* ==========================================================================
   Events
   ========================================================================== */
function loadEvents() {
  var per = 100;
  apiLatest('events', 'events&q=' + encodeURIComponent($('ev-q').value) + '&kind=' + encodeURIComponent($('ev-kind').value)
      + tpQuery('ev-time') + '&limit=' + per + '&offset=' + PAGE.events * per).then(function (d) {
    QS.events.said(d.q_error || '');
    var sel = $('ev-kind');
    (d.kinds || []).forEach(function (k) { ensureOption(sel, k); });
    var host = $('ev-table');
    clear(host);
    var nd = manyNodes();
    host.appendChild(listTable(['When', 'Kind', 'Who', 'What'].concat(nd ? ['Node'] : []), d.rows, function (r) {
      var tr = el('tr');
      tr.appendChild(stampCell(r.ts));
      var k = el('td'); k.appendChild(el('span', 'tag ' + (r.level === 'warn' || r.level === 'bad' ? 'warn' : 'dim'), r.kind));
      tr.appendChild(k);
      tr.appendChild(noI18n(el('td', '', r.who || '')));
      tr.appendChild(el('td', '', r.words));
      if (nd) tr.appendChild(nodeCell(r.node));
      return tr;
    }, '', {own: true}));
    pager('ev-pager', PAGE.events, per, d.total, function (p) { PAGE.events = p; loadEvents(); });
  }).catch(oops);
}
$('ev-q').addEventListener('input', debounce(function () { PAGE.events = 0; loadEvents(); }, 300));


/* ======== Settings: the rail, the panes, the settings drawn from the daemon (OTP admin.js 2458-3452) ======== */
/* ==========================================================================
   Settings: the rail, the panes, and the settings drawn from the daemon
   ========================================================================== */
var RAIL = {pinned: false, open: null, shut: null};
function showPane(name) {
  if (!$('pane-' + name)) name = 'people';
  PANE = name;
  document.querySelectorAll('#ctl-nav button[data-pane]').forEach(function (b) {
    b.classList.toggle('on', b.dataset.pane === name);
  });
  document.querySelectorAll('.ctl-pane').forEach(function (p) { p.hidden = p.id !== 'pane-' + name; });
  writeHash();
  if (name === 'people') loadUsers();
  if (name === 'db') loadDb();
  if (name === 'backup') loadRbackup();
  if (name === 'power') loadPower();
  if (name === 'time') loadNtp();
  if (name === 'osup') loadOsup(); else ouPoll(false);
  if (name === 'acme') loadAcme(); else acPoll(false);
  if (name === 'about') drawAbout();
  if (name === 'upgrade') loadUpgrade();
  if (name === 'proxy') drawProxy();
  if (name === 'web') loadWeb();
  /* The save bar where there is a setting to save, and nowhere else - a page
     of clients or directories saves each one in its own window. */
  markDirtyCount();
}
document.querySelectorAll('#ctl-nav button[data-pane]').forEach(function (b) {
  b.onclick = function () { showPane(b.dataset.pane); };
});
function pinRail(on) {
  RAIL.pinned = !!on;
  var nav = $('ctl-nav'), pin = $('ctl-pin');
  nav.classList.toggle('pinned', RAIL.pinned);
  document.querySelector('.ctl-layout').classList.toggle('nav-pinned', RAIL.pinned);
  pin.setAttribute('aria-pressed', RAIL.pinned ? 'true' : 'false');
  explain(pin, RAIL.pinned ? 'The menu is staying open. Press again to let it hide itself at the edge of the screen.'
    : 'The menu hides itself at the edge of the screen and slides out when you point at it. Press this to keep it open.');
  try { localStorage.setItem('upsmon-rail-pinned', RAIL.pinned ? '1' : '0'); } catch (e) { }
}
(function rail() {
  var nav = $('ctl-nav'), pin = $('ctl-pin');
  pin.innerHTML = iconMarkup('pin', 17);
  pin.onclick = function (e) { e.stopPropagation(); pinRail(!RAIL.pinned); };
  nav.addEventListener('mouseenter', function () {
    clearTimeout(RAIL.shut);
    RAIL.open = setTimeout(function () { nav.classList.add('open'); }, 60);
  });
  nav.addEventListener('mouseleave', function () {
    clearTimeout(RAIL.open);
    RAIL.shut = setTimeout(function () {
      if (document.activeElement && document.activeElement.id === 'ctl-find' && $('ctl-find').value) return;
      nav.classList.remove('open');
    }, 260);
  });
  var was = '0';
  try { was = localStorage.getItem('upsmon-rail-pinned') || '0'; } catch (e) { }
  pinRail(was === '1');
}());
$('ctl-find').addEventListener('input', function () {
  var want = $('ctl-find').value.trim().toLowerCase();
  var box = $('ctl-found');
  clear(box);
  if (!want || !SETTINGS) { box.hidden = true; return; }
  // In the page's language as well (1.0.61): a word seen on screen in Czech
  // found nothing.
  var tr = function (x) {
    try { return (typeof i18nText === 'function' && x) ? (i18nText(x) || '') : ''; } catch (e) { return ''; }
  };
  var hits = SETTINGS.settings.filter(function (s) {
    return (s.name + ' ' + s.key + ' ' + s.says + ' ' + tr(s.name) + ' ' + tr(s.says))
      .toLowerCase().indexOf(want) >= 0;
  }).slice(0, 12);
  if (!hits.length) box.appendChild(el('div', 'ctl-none', 'Nothing by that name'));
  hits.forEach(function (s) {
    var b = el('button', 'ctl-hit');
    b.type = 'button';
    b.appendChild(el('span', 'ctl-hit-t', s.name));
    var pane = Object.keys(SETTINGS.panes).filter(function (p) { return SETTINGS.panes[p].indexOf(s.key) >= 0; })[0];
    var where = document.querySelector('.ctl-nav [data-pane="' + (pane || 'about') + '"]');
    b.appendChild(el('span', 'ctl-hit-w', where ? where.textContent.trim() : (pane || '')));
    b.onclick = function () {
      showPane(pane || 'about');
      $('ctl-find').value = '';
      box.hidden = true;
      var item = document.querySelector('.set-item[data-key="' + s.key + '"]');
      if (item) {
        item.scrollIntoView({block: 'center'});
        item.classList.remove('found');
        void item.offsetWidth;
        item.classList.add('found');
        item.addEventListener('animationend', function () { item.classList.remove('found'); }, {once: true});
      }
    };
    box.appendChild(b);
  });
  box.hidden = !hits.length;
});

function loadSettings(redraw) {
  api('settings').then(function (d) {
    SETTINGS = d;
    /* Another node answers than the one that drew the boxes (1.0.110): the
       VIP address moved. Measured against that node, its own settings looked
       changed - otp1 took the name otp2 from a page otp2 had drawn. Drawn
       again from the node answering now; what was typed and not saved is put
       aside, said so. */
    if (DRAWN_NODE && d.node && d.node !== DRAWN_NODE) {
      var aside = Object.keys(DIRTY).length;
      toast('this page is answered by ' + d.node + ' now, not ' + DRAWN_NODE + ' (the VIP address moved): the settings are drawn again from ' + d.node
        + (aside ? '; ' + aside + ' change(s) not saved were put aside' : ''), 'warn');
      DIRTY = {};
      drawSettings(); markDirtyCount();
      var hh = (location.hash || '').split('/');
      showPane(PANE || (hh[1] || 'radius'));
      return;
    }
    /* Typed while this was on its way (1.0.94): kept, not wiped by a redraw;
       the boxes are measured against what is saved now instead. */
    if (redraw !== false && !Object.keys(DIRTY).length) { drawSettings(); markDirtyCount(); }
    else {
      document.querySelectorAll('.set-item[data-key]').forEach(function (item) {
        var st = settingByKey(item.dataset.key);
        /* A secret just saved shows what is kept now (1.0.170): the box still
           held what was typed, never the dots of the saved one - it stayed
           "not saved" after every save. */
        if (st && st.secret && JUST_SAVED[st.key] && !(st.key in DIRTY) && $('set-' + st.key))
          $('set-' + st.key).value = st.value || '';
        if (st && $('set-' + st.key)) markDirty(item, st);
      });
    }
    JUST_SAVED = {};
    var h = (location.hash || '').split('/');
    showPane(PANE || (h[1] || 'radius'));
  }).catch(oops);
}
var JUST_SAVED = {};
function settingByKey(key) {
  return ((SETTINGS && SETTINGS.settings) || []).filter(function (s) { return s.key === key; })[0];
}
function isBool(s) {
  return typeof s.default === 'boolean' || (s.min === 0 && s.max === 1 && typeof s.default === 'number');
}
/* Settings that hold certificates in PEM (4.1.8): drawn as a memo. */
var PEM_KEYS = {acme_ca_pem: 1, isemon_ca: 1, siem_ca: 1};

function pemSays(text) {
  text = String(text || '').trim();
  if (!text) return ['empty - the system’s own trusted roots are used', 'dim'];
  var n = (text.match(/-----BEGIN CERTIFICATE-----/g) || []).length;
  var e = (text.match(/-----END CERTIFICATE-----/g) || []).length;
  if (/PRIVATE KEY-----/.test(text)) return ['a private key does not belong here - only the certificate', 'bad'];
  if (!n || n !== e) return ['not a certificate in PEM: it begins -----BEGIN CERTIFICATE----- and ends -----END CERTIFICATE-----', 'bad'];
  return [n === 1 ? '1 certificate in PEM' : n + ' certificates in PEM', 'good'];
}

function pemTools(item, input, s) {
  var bar = el('div', 'pem-bar');
  var said = el('span', 'pem-says');
  function look() {
    var x = pemSays(input.value);
    said.className = 'pem-says ' + x[1];
    said.textContent = x[0];
    item.classList.toggle('pem-bad', x[1] === 'bad');
  }
  function take(file) {
    if (!file) return;
    if (file.size > 256 * 1024) { toast('that file is far bigger than a certificate (' + bytes(file.size) + ')', 'bad'); return; }
    var r = new FileReader();
    r.onerror = function () { toast('that file could not be read', 'bad'); };
    r.onload = function () {
      var t = String(r.result || '');
      if (!/-----BEGIN CERTIFICATE-----/.test(t)) { toast(file.name + ' holds no certificate in PEM (a .cer in DER: openssl x509 -inform der -in it.cer)', 'bad'); return; }
      input.value = t.replace(/\r\n/g, '\n').trim() + '\n';
      input.dispatchEvent(new Event('input'));
      look();
    };
    r.readAsText(file);
  }
  if (ADMIN) {
    var load = cmdButton('Load a file…', 'upload', 'small');
    load.onclick = function () {
      var pick = el('input');
      pick.type = 'file';
      pick.accept = '.pem,.crt,.cer,.ca-bundle,text/plain,application/x-pem-file';
      pick.onchange = function () { take(pick.files && pick.files[0]); };
      pick.click();
    };
    var clear = cmdButton('Empty', 'close', 'small');
    clear.onclick = function () { input.value = ''; input.dispatchEvent(new Event('input')); look(); };
    bar.appendChild(load);
    bar.appendChild(clear);
    input.addEventListener('dragover', function (e) { e.preventDefault(); input.classList.add('over'); });
    input.addEventListener('dragleave', function () { input.classList.remove('over'); });
    input.addEventListener('drop', function (e) {
      e.preventDefault();
      input.classList.remove('over');
      take(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]);
    });
  }
  bar.appendChild(said);
  input.addEventListener('input', look);
  look();
  item.appendChild(bar);
}

var TALL = {portal_help: 1, portal_groups: 1, sms_body: 1, sms_headers: 1, isemon_targets: 1, admin_group_full: 1,
            admin_group_token: 1, admin_group_readonly: 1};

/* A pane drawn in sections (1.0.88): what belongs together side by side,
   and what only one choice uses in a panel of its own that is there only
   while that choice is made - not a page of greyed-out boxes. */
var PANE_LAYOUT = {
  codes: [
    {title: 'The codes', icon: 'token', cols: 5, keys: ['code_digits', 'code_ttl_s', 'code_tries', 'code_send_max', 'code_send_window_min']},
    {title: 'What they say', icon: 'globe', keys: ['code_lang', 'code_mail_fmt'], wide: {code_lang: 2, code_mail_fmt: 2}},
    {title: 'SMS', icon: 'phone', keys: ['sms_mode', 'sms_prefix', 'sms_plain'], wide: {sms_mode: 2},
     master: 'sms_mode', subs: [
       {when: 'teltonika', title: 'The Teltonika gateway', icon: 'router',
        lede: 'TRB140, RUT… on the network: sent through its own API, the way zigmon sends its texts.',
        keys: ['sms_tel_host', 'sms_tel_api', 'sms_tel_modem', 'sms_tel_https', 'sms_tel_user', 'sms_tel_password', 'sms_tel_verify'],
        extra: smsTelExtra},
       {when: 'http', title: 'An HTTP gateway', icon: 'net',
        lede: 'An operator’s or a service’s HTTP API: where, how, with what key, and what it answers when a text went.',
        keys: ['sms_url', 'sms_method', 'sms_token', 'sms_ok_status', 'sms_body', 'sms_headers'], wide: {sms_url: 3, sms_token: 2, sms_ok_status: 2}},
       {when: 'spool', title: 'A modem on this machine', icon: 'terminal',
        lede: 'smstools3 or gammu-smsd: every text a file in their spool folder, sent by their own daemon.',
        keys: ['sms_spool_dir'], wide: {sms_spool_dir: 2}},
       {when: 'off', note: 'SMS is off: codes by SMS cannot be chosen on the enrolment pages, and the realms do not offer them.'}]}
  ]
};
function layoutGrid(keys, wide, shown, cols) {
  var g = el('div', 'set-grid cols-' + (cols || 4));
  keys.forEach(function (key) {
    var s = settingByKey(key);
    if (!s) return;
    shown[key] = true;
    var it = settingItem(s);
    if (wide && wide[key] && !it.classList.contains('tall')) it.classList.add('span-' + wide[key]);
    g.appendChild(it);
  });
  return g;
}
function drawLaidOut(host, pane, shown) {
  var head = function (tag, sec) {
    var h = el(tag, 'set-sec-head');
    if (sec.icon) { var i = el('span', 'set-sec-icon'); i.innerHTML = iconMarkup(sec.icon, 15); h.appendChild(i); }
    h.appendChild(el('span', '', sec.title));
    return h;
  };
  PANE_LAYOUT[pane].forEach(function (sec) {
    var box = el('section', 'set-sec');
    box.appendChild(head('h3', sec));
    box.appendChild(layoutGrid(sec.keys, sec.wide, shown, sec.cols));
    (sec.subs || []).forEach(function (sub) {
      var p = el('div', 'set-sub');
      p.dataset.master = sec.master;
      p.dataset.when = sub.when;
      if (sub.note) {
        p.classList.add('set-sub-note');
        p.appendChild(el('div', 'says', sub.note));
      } else {
        p.appendChild(head('h4', sub));
        if (sub.lede) p.appendChild(el('div', 'says set-sub-lede', sub.lede));
        p.appendChild(layoutGrid(sub.keys, sub.wide, shown));
        if (sub.extra) p.appendChild(sub.extra());
      }
      box.appendChild(p);
    });
    host.appendChild(box);
  });
  /* Anything of the pane the layout does not name still shows, at the end. */
  var left = SETTINGS.panes[pane].filter(function (k) { return !shown[k] && settingByKey(k); });
  if (left.length) {
    var box = el('section', 'set-sec');
    box.appendChild(layoutGrid(left, null, shown));
    host.appendChild(box);
  }
}
function applySubs() {
  var val = function (key) {
    var m = $('set-' + key);
    return m ? String(m._get ? m._get() : m.value) : '';
  };
  document.querySelectorAll('.set-sub[data-master]').forEach(function (p) {
    p.hidden = val(p.dataset.master) !== p.dataset.when;
  });
  /* The gateway's certificates: there while its certificate is checked. */
  var ca = $('smsca');
  if (ca) {
    var on = function (k) { var v = val(k); return v === 'true' || v === '1'; };
    ca.hidden = !(on('sms_tel_verify') && on('sms_tel_https'));
    /* Said plainly when nothing checks who answers (1.0.101): the gateway's
       password and every code sent go to whoever is in between. */
    var warn = $('smsca-warn');
    if (!warn && ca.parentNode) {
      warn = el('div', 'note warn sms-warn');
      warn.id = 'smsca-warn';
      ca.parentNode.insertBefore(warn, ca);
    }
    if (warn) {
      var mode = val('sms_mode');
      var https = on('sms_tel_https'), verify = on('sms_tel_verify');
      warn.hidden = mode !== 'teltonika' || (https && verify);
      warn.textContent = !https
        ? 'Without HTTPS the gateway’s password and every code sent cross the network as they are: anybody on the way reads them.'
        : 'The gateway’s certificate is not checked: anybody between this server and the gateway can stand in for it and read its password and every code sent. Switch the check on and read its certificate from it below.';
    }
  }
}

/* Try the gateway (1.0.113): reached, signed in, its modems and what each
   says about the network - nothing is sent. With what is saved: changes not
   saved yet are asked to be saved first. */
function smsTelExtra() {
  var f = document.createDocumentFragment();
  var box = el('div', 'set-ca tel-test');
  var head = el('div', 'set-ca-head');
  var hi = el('span', 'set-sec-icon'); hi.innerHTML = iconMarkup('pulse', 15);
  head.appendChild(hi);
  head.appendChild(el('b', '', 'Is it talking to us?'));
  var go = cmdButton('Test the connection', 'play', 'small admin-only');
  go.classList.add('right');
  head.appendChild(go);
  box.appendChild(head);
  box.appendChild(el('div', 'says set-sub-lede', 'Signs in to the gateway with what is saved above and asks how its modems are - operator, signal, SIM. Nothing is sent; a test SMS goes from a token’s card.'));
  var out = el('div', 'tel-out');
  box.appendChild(out);
  go.onclick = function () {
    var unsaved = Object.keys(DIRTY).filter(function (k) { return /^sms_/.test(k); });
    if (unsaved.length) { toast('save the changes first - the test uses what is saved', 'warn'); return; }
    busy(go, true);
    clear(out);
    out.appendChild(el('p', 'note', 'Asking the gateway…'));
    api('mail', {action: 'tel_test'}).then(function (d) {
      busy(go, false);
      clear(out);
      var steps = el('div', 'tel-steps');
      (d.steps || []).forEach(function (st) {
        var r = el('div', 'tel-step ' + (st.ok ? 'good' : 'bad'));
        r.appendChild(el('span', 'tel-mark', st.ok ? '✓' : '✗'));
        r.appendChild(el('b', '', st.what));
        if (st.secs) r.appendChild(noI18n(el('span', 'muted small', ' ' + String(st.secs).replace('.', numLang() === 'cs' ? ',' : '.') + ' s')));
        if (st.said) {
          r.appendChild(document.createTextNode(' – '));
          r.appendChild(el('span', 'small' + (st.ok ? ' muted' : ' bad'), st.said));
        }
        steps.appendChild(r);
      });
      out.appendChild(steps);
      (d.modems || []).forEach(function (m) {
        var card = el('div', 'tel-modem' + (m.sends ? ' sends' : ''));
        var t = el('div', 'tel-modem-head');
        t.appendChild(noI18n(el('b', 'mono', m.id || '?')));
        if (m.sends) t.appendChild(el('span', 'tag ok', 'sends the codes'));
        card.appendChild(t);
        var dl = el('dl', 'tel-facts');
        (m.fields || []).forEach(function (kv) {
          if (kv[0] === 'id') return;
          var one = el('div', 'tel-fact');
          one.appendChild(el('dt', '', kv[0]));
          one.appendChild(noI18n(el('dd', 'mono', kv[1])));
          dl.appendChild(one);
        });
        card.appendChild(dl);
        out.appendChild(card);
      });
      out.appendChild(el('p', 'note small ' + (d.ok ? (d.checked ? 'good' : 'warn') : 'bad'), d.ok
        ? 'The gateway answers' + (d.checked ? ', its certificate checked' : (d.https ? ' - its certificate NOT checked' : ' - over plain HTTP')) + ' (' + num(d.took_ms) + ' ms).'
        : 'The gateway cannot send codes like this - see the step marked ✗.'));
      out.appendChild(hideBar(function () { clear(out); }));
    }).catch(function (e) { busy(go, false); clear(out); oops(e); });
  };
  f.appendChild(box);
  f.appendChild(smsCaBlock());
  return f;
}

/* The certificates the Teltonika gateway is checked against (1.0.89): its
   own, read from it with a click, or the authority and chain that signed
   it - pasted or read from a file, added with Save the changes. */
function smsCaBlock() {
  var box = el('div', 'set-ca');
  box.id = 'smsca';
  var head = el('div', 'set-ca-head');
  var hi = el('span', 'set-sec-icon'); hi.innerHTML = iconMarkup('shield', 15);
  head.appendChild(hi);
  head.appendChild(el('b', '', 'The certificates it is checked against'));
  var when = el('span', 'muted small right', '');
  head.appendChild(when);
  box.appendChild(head);
  box.appendChild(el('div', 'says set-sub-lede', 'The gateway’s own certificate (a TRB makes one itself), or the root and the chain of the authority that signed it. With some here only these are trusted, and a gateway written as an address is not checked for a name. With none, the authorities this machine trusts - and the name.'));
  var state = el('div', 'set-ca-list');
  box.appendChild(state);
  var pem = el('textarea', 'mono admin-only');
  pem.rows = 4;
  pem.placeholder = '-----BEGIN CERTIFICATE-----';
  box.appendChild(pem);
  var row = el('div', 'set-ca-tools admin-only');
  var fetch = cmdButton('Read it from the gateway', 'download', '');
  var file = cmdButton('Read a file…', 'upload', '');
  var drop = cmdButton('Take them all away', 'trash', 'danger');
  var input = el('input'); input.type = 'file'; input.accept = '.pem,.crt,.cer,.txt'; input.hidden = true;
  [fetch, file, drop, input].forEach(function (b) { row.appendChild(b); });
  var seen = el('div', 'set-ca-seen');
  box.appendChild(row);
  box.appendChild(seen);
  var draw = function () {
    api('mail').then(function (d) {
      var list = d.sms_ca_list || [];
      when.textContent = list.length ? num(list.length) + ' certificate(s) kept' : 'none imported';
      drop.hidden = !list.length;
      clear(state);
      if (list.length) state.appendChild(certTable(list, function (c) {
        confirmThen('Take this certificate out', '<b>' + htmlText(c.subject || 'this certificate')
          + '</b> is no longer trusted for the SMS gateway. The others stay.', 'Take it out', function () {
            api('mail', {action: 'sms_ca', mode: 'drop', fingerprint: c.fingerprint}).then(function (r) {
              toast(r.message, 'good'); draw();
            }).catch(oops);
          });
      }));
      explainWhatWasDrawn(box);
    }).catch(oops);
  };
  pem.addEventListener('input', function () {
    clear(seen);
    if (!pem.value.trim()) { delete PENDING.smsca; markDirtyCount(); return; }
    pendingSet('smsca', {save: function () {
      return api('mail', {action: 'sms_ca', mode: 'add', ca: pem.value.trim()}).then(function (r) {
        toast(r.message, 'good'); pem.value = ''; clear(seen); draw(); return true;
      });
    }, reset: function () { pem.value = ''; clear(seen); }});
  });
  fetch.onclick = function () {
    if (Object.keys(DIRTY || {}).some(function (k) { return /^sms_tel_(host|https)$/.test(k); })) {
      toast('save the gateway’s address first', 'bad'); return;
    }
    busy(fetch, true);
    api('mail', {action: 'sms_ca_fetch'}).then(function (r) {
      pem.value = r.pem || '';
      pem.dispatchEvent(new Event('input'));
      if ((r.certs || []).length) {
        seen.appendChild(el('div', 'says', 'What the gateway shows - check the fingerprint against the one on the gateway (System → Administration → Certificates) before Save the changes trusts it:'));
        seen.appendChild(certTable(r.certs));
        var top = r.certs[r.certs.length - 1];
        if (top && !top.self_signed) seen.appendChild(el('div', 'says', 'The gateway does not send the certificate of whom signed it: its own is then trusted as it is - only exactly this certificate passes.'));
        explainWhatWasDrawn(seen);
      }
    }).catch(oops).then(function () { busy(fetch, false); });
  };
  file.onclick = function () { input.click(); };
  input.onchange = function () { var f = input.files && input.files[0]; if (f) readCertFile(f, pem); input.value = ''; };
  drop.onclick = function () {
    confirmThen('Take every certificate of the SMS gateway away',
      'The gateway’s certificate will then have to be signed by an authority this machine already trusts, or the check has to be switched off.',
      'Take them all away', function () {
        api('mail', {action: 'sms_ca', mode: 'clear'}).then(function (r) { toast(r.message, 'good'); draw(); }).catch(oops);
      }, true);
  };
  draw();
  return box;
}

function drawSettings() {
  DRAWN_NODE = SETTINGS.node || '';
  var shown = {};
  Object.keys(SETTINGS.panes).forEach(function (pane) {
    var host = $('sect-' + pane);
    if (!host) return;
    clear(host);
    if (PANE_LAYOUT[pane]) { drawLaidOut(host, pane, shown); return; }
    var grid = el('div', 'set-grid');
    SETTINGS.panes[pane].forEach(function (key) {
      var s = settingByKey(key);
      if (!s) return;
      shown[key] = true;
      grid.appendChild(settingItem(s));
    });
    host.appendChild(grid);
  });
  var rest = SETTINGS.settings.filter(function (s) { return !shown[s.key]; });
  var host = $('sect-rest');
  clear(host);
  $('rest-card').hidden = !rest.length;
  if (rest.length) {
    var g = el('div', 'set-grid');
    rest.forEach(function (s) { g.appendChild(settingItem(s)); });
    host.appendChild(g);
  }
  applyOnlyWhen();
  if (typeof AC !== 'undefined' && AC.d) acmeNamesInSettings(AC.d);
  explainWhatWasDrawn($('tab-settings'));
  if (typeof PANE !== 'undefined' && PANE === 'backup' && typeof rbPassTools === 'function') rbPassTools();
}

/* Name, control, then the words, each in its own row of the grid, so every
   box on a row starts at the same height even where one name takes two
   lines (1.0.20). */
/* What a setting does, in three lines at most (1.0.156): a click opens the
   rest in place; the whole is on the name and its (i) as well. */
function saysClamped(words) {
  var box = saysBlock(words);
  box.classList.add('clamp');
  box.addEventListener('click', function () { box.classList.toggle('open'); });
  /* Marked once drawn, so only a text that is cut looks like one. */
  setTimeout(function () { if (box.scrollHeight > box.clientHeight + 2) box.classList.add('cut'); }, 0);
  return box;
}
function settingItem(s) {
  var item = settingItemBare(s);
  var tail = el('div', 'set-tail');
  Array.prototype.slice.call(item.children, 2).forEach(function (c) { tail.appendChild(c); });
  /* Right under the box (1.0.171), before what it says - words of different
     lengths put them at different heights along a row. */
  var others = nodeOthers(s);
  if (others) tail.insertBefore(others, tail.firstChild);
  item.appendChild(tail);
  return item;
}
/* A node's own setting, in a cluster (1.0.170): the other nodes' values under
   the box, each changed from here - the box is this node's, and the others'
   were only in Settings → High availability (the name of otp2's certificate
   could not be given on the page of the ACME certificates). */
function nodeOthers(s) {
  if (!s.node_key || !SETTINGS || !SETTINGS.cluster || s.secret) return null;
  var names = (SETTINGS.nodes || []).filter(function (n) { return n !== SETTINGS.node; });
  if (!names.length) return null;
  var box = el('div', 'node-others small' + (isBool(s) ? ' bool' : ''));
  names.forEach(function (n) {
    var has = s.per_node && Object.prototype.hasOwnProperty.call(s.per_node, n);
    var val = has ? s.per_node[n] : s.shared;
    var row = el('div', 'node-other');
    row.dataset.node = n;
    var redraw = function () { loadSettings(); };
    if (isBool(s)) {
      /* The node's switch first, right under the box's own (1.0.177): after
         the node's tag it stood off to the side of the one above. */
      var sw = switchBox(nodeValWords(s, val) === 'on');
      sw._input.disabled = !ADMIN;
      if (!has) sw.classList.add('inherited');
      sw._input.addEventListener('change', function () { nodeSave(s, n, !!sw._get(), redraw); });
      row.appendChild(sw);
      row.appendChild(noI18n(el('span', 'tag dim', n)));
    } else {
      row.appendChild(noI18n(el('span', 'tag dim', n)));
      row.appendChild(nodeValEl(s, val, 'mono small' + (has ? '' : ' muted')));
    }
    row.appendChild(el('span', 'muted', has ? 'its own' : 'the cluster’s'));
    if (ADMIN && !isBool(s)) {
      var eb = iconButton('edit', 'Change it for ' + n);
      eb.onclick = function () { nodeEdit(s, n, has ? val : null, redraw); };
      row.appendChild(eb);
    }
    if (ADMIN && has) {
      var back = iconButton('undo', 'Back to the cluster’s value');
      back.onclick = function () { nodeSave(s, n, s.shared, redraw); };
      row.appendChild(back);
    }
    box.appendChild(row);
  });
  return box;
}
function settingItemBare(s) {
  var item = el('div', 'set-item' + (isBool(s) ? ' set-bool' : ''));
  item.dataset.key = s.key;
  var label = el('label', '', s.name || s.key);
  label.setAttribute('for', 'set-' + s.key);
  var info = el('span', 'iinfo', 'i');
  info.setAttribute('role', 'button');
  info.tabIndex = 0;
  var asText = function (v) { return richText(Array.isArray(v) ? v.join(', ') : String(v)); };
  var where = s.source;
  var story = '<span class="k">on the command line this one is <b>upsmon --set ' + richText(s.key)
    + '=…</b> · running: ' + (s.secret ? (s.set ? 'set' : 'not set') : asText(s.value))
    + '<br><span class="' + (where === 'default' ? 'same' : 'diff') + '">' + richText(s.source_says || '')
    + (s.saved_by ? ' (by ' + richText(s.saved_by) + (s.saved_at ? ', ' + ago(s.saved_at) : '') + ')' : '')
    + '</span>'
    + (s.file_only ? '<br><span class="same">kept in ' + richText(SETTINGS.config_file)
       + ' - a database cannot hold its own address</span>' : '')
    + (where !== 'default' && !s.secret && String(s.value) !== String(s.default)
       ? '<br><span class="same">the built-in default is ' + asText(s.default) + '</span>' : '') + '</span>';
  var whole = s.says || 'No words have been written for this one yet.';
  if (s.node_key && SETTINGS.cluster) {
    story += '<br><span class="diff">' + richText('this node’s own - every node of the cluster has one of its own; the others’ are under the box, and all of them in Settings → High availability') + '</span>';
  }
  explain(info, whole, story);
  explain(label, whole, story);
  label.appendChild(info);
  /* A node's own setting, in a cluster (1.0.37): said beside its name. */
  if (s.node_key && SETTINGS.cluster) {
    /* The tags one block at the right, never broken over two lines: only the
       name wraps (1.0.172) - "otp1" went under the name on one box and stood
       beside it on the next. */
    var tags = el('span', 'node-tags');
    var nt = el('span', 'tag info', 'this node');
    nt.title = SETTINGS.node;
    tags.appendChild(nt);
    tags.appendChild(noI18n(el('span', 'tag dim', SETTINGS.node)));
    label.appendChild(tags);
  }
  if (label.firstChild && label.firstChild.nodeType === 3) {
    var txt = el('span', 'lbl-txt');
    txt.appendChild(label.firstChild);
    label.insertBefore(txt, label.firstChild);
  }
  item.appendChild(label);
  var input;
  if (isBool(s)) {
    input = switchBox(s.value === true || String(s.value) === '1');
    input._input.disabled = !ADMIN;
    input._input.addEventListener('change', function () { markDirty(item, s); });
    input.id = 'set-' + s.key;
    /* The name is a label for the checkbox itself, so a click on it flips
       the switch (1.0.15); the wrapper keeps the id the readers look up. */
    input._input.id = 'set-' + s.key + '-sw';
    label.setAttribute('for', input._input.id);
    item.appendChild(input);
    if (s.says) item.appendChild(saysClamped(s.short || s.says));   /* the whole on the (i) (1.0.156) */
    hsDress(item, s, input);
    if (s.key === 'high_security') hsSwitch(input, s);
    return item;
  }
  if (s.choices && s.choices.some(function (c) {
    return String((s.choice_words && s.choice_words[c]) || c).length > 30;
  })) item.classList.add('wide');
  if (s.choices) {
    input = selectBox(s.choices.map(function (c) { return [c, (s.choice_words && s.choice_words[c]) || c]; }), s.value);
  } else if (s.key === 'default_realm' || s.key === 'portal_realm') {
    var rl = (SETTINGS.realms || []).slice();
    if (s.value && rl.indexOf(s.value) < 0) rl.push(s.value);
    input = selectBox([['', s.key === 'default_realm' ? 'none - a name has to be written whole'
                                                      : 'as the default realm']]
      .concat(rl.map(function (d) { return [d, '@' + d]; })), s.value);
  } else if (s.key === 'admin_directory') {
    input = selectBox([['', 'none - only the accounts made here']].concat((SETTINGS.directories || []).map(function (d) { return [d, d]; })), s.value);
  } else if (typeof s.min === 'number') {
    input = el('input');
    input.type = 'number';
    input.min = s.min;
    input.max = s.max;
    input.value = s.value;
  } else if (PEM_KEYS[s.key]) {
    item.classList.add('tall', 'pem-item');
    input = el('textarea', 'pem-memo');
    input.value = s.value === null || s.value === undefined ? '' : String(s.value);
    input.rows = 12;
    input.spellcheck = false;
    input.setAttribute('wrap', 'off');
    input.setAttribute('autocomplete', 'off');
    input.placeholder = '-----BEGIN CERTIFICATE-----\nMIIF…\n-----END CERTIFICATE-----';
  } else if (TALL[s.key]) {
    item.classList.add('tall');
    input = el('textarea');
    input.value = s.value === null || s.value === undefined ? '' : String(s.value);
    input.rows = s.key === 'portal_help' ? 6 : 2;
  } else {
    input = s.secret ? maskBox(s.value, '', '') : textBox(s.value, '', '');
    if (s.secret) {
      input.placeholder = s.set ? 'set - leave as it is to keep it' : 'not set';
      input.addEventListener('focus', function () { if (input.value.indexOf('•') === 0) input.select(); });
    }
  }
  input.id = 'set-' + s.key;
  input.disabled = !ADMIN;
  input.addEventListener('input', function () { markDirty(item, s); });
  input.addEventListener('change', function () { markDirty(item, s); });
  item.appendChild(input);
  if (PEM_KEYS[s.key]) pemTools(item, input, s);
  if (s.key === 'portal_groups' && ADMIN) {
    /* The groups found in the directory and picked, rather than typed - the
       same list as for a realm and for the administrators' groups. */
    var pickRow = el('div', 'btnrow');
    pickRow.style.marginTop = '8px';
    var pickGo = cmdButton('Find and pick the groups', 'search', 'small');
    pickGo.id = 'portal-groups-find';
    pickGo.onclick = function () { portalGroupsPick(input, item, s); };
    pickRow.appendChild(pickGo);
    item.appendChild(pickRow);
  }
  if (s.says) item.appendChild(saysClamped(s.short || s.says));   /* the whole on the (i) (1.0.156) */
  hsDress(item, s, input);
  return item;
}

/* ---- High security (1.0.168) --------------------------------------------------
   While it is on, what it stands against is greyed out: a switch that may not
   go back, the choices that may not be chosen, a number's highest; the daemon
   refuses them anyway. Switched on only once nothing stands against it - what
   does is listed in a window, each with where it is set. */
function hsOn(rule) { return !!(STATUS && STATUS.high_security) && !(rule && (STATUS.hisec_waived || []).indexOf(rule) >= 0); }
function hsOptions(sel, bad, rule) {
  if (!hsOn(rule)) return;
  Array.prototype.forEach.call(sel.options, function (o) {
    if (bad.indexOf(o.value) >= 0) { o.disabled = true; o.title = 'not under high security'; }
  });
}
function hsDress(item, s, input) {
  var r = s.hisec;
  if (!r || !hsOn()) return;
  if (isBool(s)) {
    var on = s.value === true || String(s.value) === '1';
    if ((r.forbid || []).indexOf(on ? 0 : 1) >= 0) input._input.disabled = true;
  } else if (input && input.tagName === 'SELECT') {
    Array.prototype.forEach.call(input.options, function (o) {
      if ((r.forbid || []).indexOf(o.value) >= 0) { o.disabled = true; o.title = 'not under high security'; }
    });
  } else if (input && typeof r.most === 'number') {
    input.max = r.most;
  }
  var n = el('div', 'says hs-note', 'High security: ' + r.why + ' - not allowed.');
  (item.querySelector('.set-tail') || item).appendChild(n);
}
function hsSwitch(box, s) {
  box._input.addEventListener('change', function () {
    if (!box._input.checked || (s.value === true || String(s.value) === '1')) return;
    api('hisec').then(function (d) {
      if ((d.block || []).length) {
        box._input.checked = false;
        box._input.dispatchEvent(new Event('change'));
      }
      hsWindow(d, !(d.block || []).length);
    }).catch(oops);
  });
}
function hsWindow(d, may) {
  modal(may ? 'High security' : 'High security cannot be switched on yet', function (body) {
    var draw = function (v) {
      clear(body);
      var block = v.block || [];
      var ok = !block.length;
      body.appendChild(el('p', 'note' + (ok ? '' : ' warn'), ok
        ? 'Nothing stands against it now. Switch it on again and save: from then on every way of doing something less safely is refused - but the exceptions.'
        : num(block.length) + ' thing(s) stand against it. Set them as said, or make one an exception with its switch - then switch it on again.'));
      hsList(body, block, 'bad', 'Stands against it', draw);
      hsList(body, v.waived || [], 'waived', 'Exceptions - not enforced', draw);
    };
    draw(d);
  }, [{words: 'Close', close: true}], 'large');
}
/* One rule a row: what, what to set, where - and on the right the switch that
   makes it an exception: it then stops nothing and is not enforced. */
function hsList(host, rows, cls, title, redraw) {
  if (!rows.length) return;
  host.appendChild(el('h4', 'hs-h ' + (cls === 'waived' ? 'dim' : cls), title));
  var ul = el('div', 'hs-list');
  rows.forEach(function (x) {
    var it = el('div', 'hs-item ' + cls);
    it.appendChild(el('span', 'dot ' + (cls === 'bad' ? 'bad' : (cls === 'ok' ? 'ok' : (cls === 'warn' ? 'warn' : 'dim')))));
    var t = el('div', 'hs-t');
    t.appendChild(el('div', 'hs-what', x.title || x.what));
    if (x.details && x.details.length) t.appendChild(noI18n(el('div', 'small muted mono', x.details.join(', '))));
    var f = el('div', 'muted small');
    if (x.kind !== 'check') { f.appendChild(el('span', '', 'Set:')); f.appendChild(document.createTextNode(' ')); }
    f.appendChild(el('span', '', x.fix));
    if (x.pane) {
      var a = el('a', '', 'Open it →');
      a.href = '#settings/' + x.pane;
      a.onclick = function () { if ($('modal-box') && $('modal-box').contains(a)) closeModal(); };
      f.appendChild(document.createTextNode(' · '));
      f.appendChild(a);
    }
    t.appendChild(f);
    it.appendChild(t);
    if (x.rule && x.kind !== 'check' && ADMIN) {
      var sw = el('label', 'hs-ex');
      var box = switchBox(!!x.waived);
      sw.appendChild(el('span', 'small muted', 'Exception'));
      sw.appendChild(box);
      explain(sw, 'On: this rule is an exception - it does not stop high security and is not enforced while it is on. Every change is an event.');
      box._input.onchange = function () {
        var want = !!box._get();
        box._input.disabled = true;
        api('hisec', {action: 'waive', rule: x.rule, on: want}).then(function (v) {
          toast(want ? 'an exception now' : 'enforced again', 'good');
          if (STATUS) STATUS.hisec_waived = (v.waived || []).map(function (r) { return r.rule; });
          redraw(v);
          if ($('hs-host') && redraw !== drawHisec) drawHisec(v);
        }).catch(function (e) { box._input.disabled = false; box._set(!want); oops(e); });
      };
      it.appendChild(sw);
    }
    ul.appendChild(it);
  });
  host.appendChild(ul);
}

/** The groups that may enrol, found in the directory: each one's button
    puts it into the box or takes it out, and the box is saved with the
    other settings as before. */
function portalGroupsPick(input, item, s) {
  var dirs = SETTINGS.directories || [];
  if (!dirs.length) { toast('there is no directory to look in: Settings → Active Directory', 'bad'); return; }
  var names = function () {
    return input.value.split(/[;\n]+/).map(function (x) { return x.trim(); }).filter(Boolean);
  };
  var put = function (list) {
    input.value = list.join('\n');
    markDirty(item, s);
  };
  var has = function (g) {
    var cn = String(g.cn).toLowerCase(), dn = String(g.dn).toLowerCase();
    return names().filter(function (v) { v = v.toLowerCase(); return v === cn || v === dn; });
  };
  modal('Groups that may enrol', function (body) {
    body.appendChild(el('p', 'note', 'Find the groups in the directory and press May enrol beside each one that may: it goes into the box, and pressed again it comes out. Nested groups count - a member of a group inside one of these may enrol as well. Nothing is kept until Save the changes.'));
    var dir = selectBox(dirs.map(function (d) { return [d, d]; }), dirs[0]);
    noI18n(dir);
    /* The directory the enrolment pages sign people in against: the one of
       their realm, or of the default realm. */
    api('realms').then(function (d) {
      var want = String(readValue(settingByKey('portal_realm') || {key: 'portal_realm'}) || '')
        || String(readValue(settingByKey('default_realm') || {key: 'default_realm'}) || '');
      var r = (d.realms || []).filter(function (x) {
        return x.name === want || x.suffix === want;
      })[0] || (d.realms || []).filter(function (x) { return x.directory && x.enabled; })[0];
      if (r && r.directory && dirs.indexOf(r.directory) >= 0) {
        dir.value = r.directory;
        dir.dispatchEvent(new Event('change'));
      }
    }).catch(function () { /* the first one, then */ });
    if (dirs.length > 1) body.appendChild(formField('Look in the directory', dir));
    var chosen = el('div', 'chips');
    chosen.style.margin = '6px 0 12px';
    var drawChosen = function () {
      clear(chosen);
      var list = names();
      if (!list.length) { chosen.appendChild(el('span', 'muted small', 'No group yet: nobody may enrol.')); return; }
      list.forEach(function (n) {
        var c = el('span', 'chip');
        /* A DN shown by its name, the whole of it on hover (1.0.101). */
        var m = /^\s*cn=((?:\\.|[^,])+)/i.exec(n);
        var shown = noI18n(el('span', 'mono', m ? m[1].replace(/\\(.)/g, '$1') : n));
        shown.title = n;
        c.appendChild(shown);
        var x = iconButton('close', 'Take it out');
        x.onclick = function () {
          put(names().filter(function (v) { return v !== n; }));
          drawChosen();
          if (gb._paint) gb._paint();
        };
        c.appendChild(x);
        chosen.appendChild(c);
      });
    };
    body.appendChild(el('h3', 'peek-h', 'Chosen'));
    body.appendChild(chosen);
    drawChosen();
    var gb = groupBrowser({
      dir: function () { return dir._get ? dir._get() : dir.value; },
      buttons: [{words: 'May enrol', icon: 'check',
                 on: function (g) { return has(g).length > 0; },
                 toggle: function (g) {
                   var hit = has(g);
                   if (hit.length) put(names().filter(function (v) { return hit.indexOf(v) < 0; }));
                   /* Its whole DN (1.0.101): the one group picked, never any
                      group of that name somewhere else in the directory. */
                   else put(names().concat([g.dn]));
                   drawChosen();
                 }}]
    });
    body.appendChild(gb);
  }, [{words: 'Done', cls: 'primary', icon: 'check', close: true}], 'large');
}

function readValue(s) {
  var input = $('set-' + s.key);
  if (!input) return undefined;
  if (input._get) return input._get();
  if (typeof s.min === 'number' && !s.choices) return String(input.value).trim() === '' ? '' : Number(input.value);
  return input.value;
}
function markDirty(item, s) {
  /* Against what is saved now (1.0.94), not what was when the box was
     drawn: after a save the old value made a change back look like none. */
  s = settingByKey(s.key) || s;
  var now = readValue(s);
  var was = isBool(s) ? ((s.value === true || String(s.value) === '1') ? '1' : '0')
    : (s.value === null || s.value === undefined ? '' : String(s.value));   /* null is empty (1.0.57) */
  var changed = was !== String(now);
  item.classList.toggle('changed', changed);
  /* The database's address is what the steps below it ask about, never
     saved by the save bar (1.0.37): saved, the next restart opened a
     database nothing had been carried into. */
  if (/^db_(engine|host|port|name|user|password)$/.test(s.key)) { delete DIRTY[s.key]; markDirtyCount(); applyOnlyWhen(); return; }
  if (changed) DIRTY[s.key] = now; else delete DIRTY[s.key];
  markDirtyCount();
  applyOnlyWhen();
}
/* Changes that are not settings (1.0.56) - the firewall, the VIP address,
   a certificate authority pasted in - wait for the same save bar:
   PENDING[key] = {save: function () -> Promise (false: not done), reset}. */
var PENDING = {};
function pendingSet(key, p) { p.pane = p.pane || PANE; PENDING[key] = p; markDirtyCount(); }
/* The one save bar, at the bottom (1.0.123): on every pane where something
   is saved - settings, the firewall, the VIP address, the time servers, the
   message texts, the pages' looks - and on no other. A pane that does
   something at once (Network, Restart and power off, Backups…) has its own
   buttons for it and no save bar. */
var SAVE_PANES = ['fw', 'ha', 'time', 'texts', 'portal'];
function saveBarHere() {
  if (!ADMIN || TAB !== 'settings') return false;
  var pane = $('pane-' + PANE);
  if (!pane) return false;
  /* A setting of the daemon's own (data-key) - not a field that only looks
     like one, as on Network, where nothing is saved: it is done at once. */
  if (SAVE_PANES.indexOf(PANE) >= 0 || pane.querySelector('.set-item[data-key]')) return true;
  return Object.keys(PENDING).some(function (k) { return PENDING[k].pane === PANE; });
}
function markDirtyCount() {
  var n = Object.keys(DIRTY).length + Object.keys(PENDING).length;
  $('set-said').textContent = n ? n + ' change(s) not saved yet' : '';
  $('save-bar').classList.toggle('dirty', n > 0);
  /* Message texts, where only the editor scrolls (1.0.130): the bar is out of
     the way until something is changed, as it is below the end of any other
     page - and then at the bottom. */
  $('save-bar').style.display = saveBarHere() ? '' : 'none';
  saveBarPlace();
}
/* A question as a promise: true for the button, false for anything else. */
function askThen(title, words, buttonWords, danger) {
  return new Promise(function (done) {
    var said = false;
    var end = function (v) { if (!said) { said = true; done(v); } };
    confirmThen(title, words, buttonWords, function () { end(true); }, danger);
    var gen = MODAL_GEN;
    var watch = setInterval(function () {
      if (said) { clearInterval(watch); return; }
      if ($('modal').hidden || MODAL_GEN > gen + 1) { clearInterval(watch); setTimeout(function () { end(false); }, 50); }
    }, 300);
  });
}
function applyOnlyWhen() {
  applySubs();
  var rules = (SETTINGS && SETTINGS.only_when) || {};
  /* A setting is asleep when the one it depends on says so - and also when
     that one is asleep itself (1.0.165): On the day of a weekly restart was
     there to change with the restart switched off. The reason given is the
     first one up the line that is off. */
  var seen = {};
  function wake(key, depth) {
    if (seen[key]) return seen[key];
    var rule = rules[key];
    if (!rule || depth > 6) return (seen[key] = {live: true});
    var master = $('set-' + rule[0]);
    if (!master) return (seen[key] = {live: true});
    var up = wake(rule[0], depth + 1);
    if (!up.live) return (seen[key] = up);
    var now = master._get ? String(master._get()) : String(master.value);
    var want = rule[1];
    var live = want === '*' ? !!now.trim() : (want.slice(-4) === '-not' ? now !== want.slice(0, -4) : now === want);
    return (seen[key] = {live: live, by: rule[0], want: want, now: now});
  }
  Object.keys(rules).forEach(function (key) {
    var item = document.querySelector('.set-item[data-key="' + key + '"]');
    if (!item || !$('set-' + rules[key][0])) return;
    var w = wake(key, 0);
    var live = w.live, want = w.want, now = w.now;
    item.classList.toggle('asleep', !live);
    var says = item.querySelector('.asleep-why');
    // Written again on every pass (1.0.61): it went on naming the choice it
    // was first put in for.
    if (says) says.remove();
    if (!live) {
      var other = settingByKey(w.by) || {};
      (item.querySelector('.set-tail') || item).appendChild(el('div', 'says asleep-why', want === '*' ? 'Not in use until ' + other.name + ' is filled in.'
        : (isBool(other) ? 'Not in use while ' + other.name + ' is off.'
           : 'Not in use while ' + other.name + ' is “' + ((other.choice_words || {})[now] || now) + '”.')));
    }
  });
}
$('set-save').onclick = function () {
  var want = {};
  Object.keys(DIRTY).forEach(function (k) {
    var s = settingByKey(k);
    // A secret's dots are not a change (1.0.61): forgotten, not left on the
    // bar as "not saved" for ever.
    if (s && s.secret && String(DIRTY[k]).indexOf('•') === 0) { delete DIRTY[k]; return; }
    want[k] = DIRTY[k];
  });
  markDirtyCount();
  var keys = Object.keys(PENDING);
  if (!Object.keys(want).length && !keys.length) { toast('nothing has changed'); return; }
  busy($('set-save'), true);
  document.querySelectorAll('.set-item.refused').forEach(function (n) { n.classList.remove('refused'); });
  var chain = Promise.resolve(true);
  if (Object.keys(want).length) {
    chain = api('settings', {settings: want, drawn_by: DRAWN_NODE}).then(function (d) {
      toast(d.message, 'good');
      /* What was changed while the save was on its way stays changed
         (1.0.61): the redraw after it threw those away without a word. */
      var left = {};
      Object.keys(DIRTY).forEach(function (k) {
        if (!(k in want) || DIRTY[k] !== want[k]) left[k] = DIRTY[k];
      });
      /* What was saved is no longer a change (1.0.170): it stayed in DIRTY, so
         the page was never drawn again and a secret - shown as dots once
         saved - looked changed for ever. */
      Object.keys(want).forEach(function (k) { JUST_SAVED[k] = 1; });
      DIRTY = left;
      markDirtyCount();
      loadSettings(Object.keys(left).length ? false : undefined);
      if (paneLive('upgrade')) loadUpgrade();      /* the card to go back shown or not (1.0.144) */
      tick();
      return true;
    }).catch(function (e) {
      if (e.detail && e.detail.hisec) { hsWindow(e.detail.hisec, false); return false; }
      var said = String(e.message || e);
      /* The longest key the message starts with (1.0.57): portal before portal_help was taken. */
      var hit = SETTINGS.settings.filter(function (one) {
        return said.indexOf(one.key) === 0 && !/[A-Za-z0-9_]/.test(said.charAt(one.key.length));
      }).sort(function (a, b) { return b.key.length - a.key.length; })[0];
      if (hit) {
        var item = document.querySelector('.set-item[data-key="' + hit.key + '"]');
        if (item) { item.classList.add('refused'); item.scrollIntoView({block: 'center'}); }
        said = '“' + hit.name + '”' + said.slice(hit.key.length);
      }
      toast(said, 'bad');
      return false;
    });
  }
  /* Then the rest, one after the other; the first that fails stops it. */
  keys.forEach(function (k) {
    chain = chain.then(function (ok) {
      if (!ok || !PENDING[k]) return ok;
      return Promise.resolve(PENDING[k].save()).then(function (r) {
        if (r === false) return false;
        delete PENDING[k];
        return true;
      }).catch(function (e) { oops(e); return false; });
    });
  });
  chain.then(function () { markDirtyCount(); busy($('set-save'), false); });
};
$('set-reset').onclick = function () {
  var keys = Object.keys(PENDING);
  keys.forEach(function (k) { try { PENDING[k].reset(); } catch (e) { /* drawn again anyway */ } });
  PENDING = {};
  /* The changed values forgotten too (1.0.104): loadSettings draws nothing
     again while any is left, so Put them back did nothing at all. */
  DIRTY = {};
  document.querySelectorAll('.set-item.refused').forEach(function (n) { n.classList.remove('refused'); });
  markDirtyCount();
  loadSettings(); toast('put back as the daemon has them');
};
window.addEventListener('beforeunload', function (e) {
  if (Object.keys(DIRTY).length || Object.keys(PENDING).length) { e.preventDefault(); e.returnValue = ''; }
});


/* ======== every node as a card of its own (OTP admin.js 4364-4408) ======== */
/* ---- every node as a card of its own (1.0.169) ----------------------------------
   The standard of the panes that show the nodes - Time, Network, Syslog, isemon,
   Disks and logs: one card a node, its state in the head, the facts as tiles,
   what can be done on that node below; the settings for all in a card after. */
function nodeGrid() { return el('div', 'pw-grid node-grid'); }
function nodeCard(n, dot, tag, tagCls) {
  var c = el('div', 'card ntp-node');
  var head = el('div', 'pw-head');
  head.appendChild(el('span', 'dot ' + dot));
  head.appendChild(noI18n(el('b', '', n.node || n.name)));
  if (n.me) head.appendChild(el('span', 'tag info', 'this page'));
  if (tag) head.appendChild(el('span', 'tag ' + (tagCls || 'dim'), tag));
  c.appendChild(head);
  return c;
}
function nodeBig(c, value, words) {
  var big = el('div', 'ntp-big');
  big.appendChild(noI18n(el('span', 'ntp-off', value)));
  if (words) big.appendChild(el('span', 'muted small', ' ' + words));
  c.appendChild(big);
}
function nodeFresh(n) { return n.at && Date.now() / 1000 - n.at < 300; }
/* A test only a node can make, asked of it (or of every node) and its answer
   followed: onEach(node, answer) as each comes, onDone() at the end. */
function askNodes(what, body, onEach, onDone) {
  return api(what, body).then(function (x) {
    var left = (x.nodes || []).slice(), began = Date.now();
    var timer = setInterval(function () {
      api(what, {action: 'result', id: x.id}).then(function (r) {
        left = left.filter(function (n) {
          var got = (r.nodes || {})[n];
          if (got) { onEach(n, got); return false; }
          return true;
        });
        if (!left.length || Date.now() - began > 60000) {
          clearInterval(timer);
          left.forEach(function (n) { onEach(n, {ok: false, error: 'did not answer in a minute - is it running?'}); });
          if (onDone) onDone();
        }
      }).catch(function () {});
    }, 1000);
    return x;
  });
}


/* ======== accounts (OTP admin.js 4521-4847) ======== */
/* ---- accounts ------------------------------------------------------------- */
function loadUsers() {
  colsCardSay();
  api('users').then(function (d) {
    var host = $('us-table');
    clear(host);
    host.appendChild(listTable(['Name', 'Role', 'Signs in', 'State', 'Last signed in', 'From', 'Columns', 'Note', ''], d.users, function (u) {
      var tr = el('tr');
      var n = el('td'); n.appendChild(noI18n(el('span', 'mono', u.name)));
      if (u.display) n.appendChild(noI18n(el('span', 'sub', u.display)));
      tr.appendChild(n);
      var r = el('td'); r.appendChild(el('span', 'tag ' + roleTone(u.role), roleWords(u.role))); tr.appendChild(r);
      tr.appendChild(el('td', 'muted', u.source === 'directory' ? 'against the directory' : 'a password here'));
      var st = el('td'); st.appendChild(el('span', 'tag ' + (u.disabled ? 'crit' : 'ok'), u.disabled ? 'off' : 'on')); tr.appendChild(st);
      tr.appendChild(u.last_in ? stampCell(u.last_in) : el('td', 'muted', 'never'));
      tr.appendChild(noI18n(el('td', 'mono small', u.last_from || '')));
      tr.appendChild(el('td', 'muted small', u.cols_tables ? num(u.cols_tables) + ' table(s) laid out' : 'as they come'));
      tr.appendChild(noI18n(el('td', 'muted small', u.note || '')));
      var tools = el('td', 'rowtools');
      /* Every row has the same buttons in the same places (1.0.18): one
         that does not apply to this account is there, dimmed, and says why -
         an invisible gap looked like a mistake. */
      var info = iconButton('person', u.source === 'directory'
        ? 'In the directory: who it is, whether the account is switched off, its groups'
        : 'An account kept here, not in a directory');
      if (u.source === 'directory') info.onclick = function (ev) { ev.stopPropagation(); whoisPeek(u.name, 'account'); };
      else info.disabled = true;
      if (ADMIN) {
        /* The role first, the buttons as one group after it. */
        var role = selectBox(d.roles.map(function (x) { return [x.role, x.words]; }), u.role);
        role.onchange = function () { userDo({action: 'role', name: u.name, role: role.value}); };
        role.style.marginRight = '10px';
        tools.appendChild(role);
      }
      tools.appendChild(info);
      if (ADMIN) {
        if (u.source !== 'directory') {
          var pw = iconButton('lock', 'Set a new password');
          pw.onclick = function () {
            askInModal('A new password for ' + u.name, 'They choose their own at the next sign-in.',
              [{label: 'The new one (8 characters at least)', type: 'password'},
               {label: 'Again', type: 'password'}], 'Set it', 'lock', function (v) {
                if (v[0].length < 8) { toast('8 characters at least', 'bad'); return; }
                if (v[0] !== v[1]) { toast('the two are not the same', 'bad'); return; }
                closeModal();
                userDo({action: 'password', name: u.name, password: v[0], must_change: 1});
              });
          };
          tools.appendChild(pw);
        } else {
          var gap = iconButton('lock', 'The password is the directory’s: it is changed there');
          gap.disabled = true;
          tools.appendChild(gap);
        }
        var off = iconButton('power', u.disabled ? 'Let it sign in again' : 'Stop it signing in');
        off.onclick = function () { userDo({action: u.disabled ? 'enable' : 'disable', name: u.name}); };
        var x = iconButton('trash', 'Remove it');
        x.onclick = function () {
          confirmThen('Remove the account ' + u.name, 'It cannot sign in any more.', 'Remove it', function () {
            userDo({action: 'delete', name: u.name});
          });
        };
        tools.appendChild(off); tools.appendChild(x);
        var pk = iconButton('key', 'The passkeys of ' + u.name + ' - Face ID, Touch ID');
        pk.onclick = function (ev) { ev.stopPropagation(); pkOf(u.name); };
        tools.appendChild(pk);
        /* Somebody's own layout of the tables, put back as it comes. */
        var cb = iconButton('undo', u.cols_tables
          ? u.name + ' has laid out ' + num(u.cols_tables) + ' table(s) by hand. Put every one of them back as it comes: the widths, the order and the hidden columns. Nothing else of theirs changes.'
          : u.name + ' has every table as it comes: nothing to put back.');
        cb.classList.add('cols-back');
        if (u.cols_tables) {
          cb.onclick = function (ev) {
            ev.stopPropagation();
            confirmThen('The columns of ' + u.name,
              'Every table ' + htmlText(u.name) + ' has laid out goes back as it comes. They see it '
              + 'the next time a page loads.',
              'Put them back', function () {
                colsReset(u.name).then(function () {
                  if (ME && u.name === ME.name) colsCardSay();
                  loadUsers();
                }).catch(oops);
              });
          };
        } else {
          cb.disabled = true;
        }
        tools.appendChild(cb);
      }
      tr.appendChild(tools);
      return tr;
    }));
    explainWhatWasDrawn(host);
  }).catch(oops);
  loadLockouts();
  if (ADMIN) api('sessions').then(function (d) {
    var host = $('se-table');
    clear(host);
    host.appendChild(listTable(['Who', 'Where', 'From', 'Since', 'Last asked', ''], d.sessions, function (s) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', s.name)));
      tr.appendChild(el('td', '', s.kind === 'admin' ? 'these pages' : 'the enrolment pages'));
      tr.appendChild(noI18n(el('td', 'mono small', s.ip)));
      tr.appendChild(stampCell(s.created));
      tr.appendChild(el('td', 'muted', ago(s.last)));
      var tools = el('td', 'rowtools');
      var x = cmdButton('End it', 'cancel', 'small');
      // Asked first (1.0.61): it may be your own.
      x.onclick = function () {
        confirmThen('End this sign-in', htmlText(String(s.name || '?')) + (s.ip ? ' from ' + htmlText(String(s.ip)) : '')
          + ' is signed out at once.', 'End it', function () {
          api('sessions', {id: s.id}).then(function () { loadUsers(); }).catch(oops);
        });
      };
      tools.appendChild(x);
      tr.appendChild(tools);
      return tr;
    }));
  }).catch(oops);
}
/* Locked out (1.0.112): who has wrong attempts counted, on which node, how
   long the lockout still runs - cleared one by one or all at once. Fetched
   again every 10 s while the card is on the screen; the time left counts
   down every second in between. */
var LO = {data: null, skew: 0, fetched: 0, timer: null};
/* Two views of the same counts (1.0.137): Accounts - every kind; Sign-in
   protection - the VPN's places and the locked tokens, with a filter. */
var LO_VIEWS = [
  {table: 'lo-table', tools: 'lo-tools', card: 'lo-card', kinds: null},
  {table: 'gd-table', tools: 'gd-tools', card: 'gd-card', kinds: ['radius-src', 'token-locked', 'codes-sent'], find: 'gd-find'}
];
function loadLockouts() {
  if (!ADMIN || !LO_VIEWS.some(function (v) { return $(v.table); })) return;
  api('lockouts').then(function (d) {
    LO.data = d;
    LO.skew = d.now - Date.now() / 1000;
    LO.fetched = Date.now();
    drawLockouts();
    if (!LO.timer) LO.timer = setInterval(loTick, 1000);
  }).catch(function (e) { if (LO.timer) { clearInterval(LO.timer); LO.timer = null; } oops(e); });
}
function loTick() {
  var seen = LO_VIEWS.some(function (v) { var c = $(v.card); return c && c.offsetParent; });
  if (!seen || document.hidden) { clearInterval(LO.timer); LO.timer = null; return; }
  if (Date.now() - LO.fetched > 10000) { LO.fetched = Date.now(); loadLockouts(); return; }
  drawLockouts();
}
function loNow() { return Date.now() / 1000 + LO.skew; }
function loClear(body, words) {
  api('lockouts', body).then(function (r) {
    toast((words || r.message) + ((r.told || []).length ? ' - ' + r.told.join(', ') + ' clears it within a few seconds' : ''), 'good');
    loadLockouts();
    /* The other node clears its part at its next turn (5 s). */
    if ((r.told || []).length) setTimeout(loadLockouts, 7000);
  }).catch(oops);
}
function drawLockouts() {
  LO_VIEWS.forEach(function (v) { if ($(v.table)) drawLockoutsIn(v); });
}
/* How far a count has got towards its limit (1.0.137): a bar that fills. */
function loBar(n, limit, locked) {
  var bar = el('div', 'lo-bar' + (locked ? ' full' : ''));
  var fill = el('i');
  fill.style.width = (limit ? Math.min(100, Math.round(100 * n / limit)) : 0) + '%';
  bar.appendChild(fill);
  return bar;
}
function drawLockoutsIn(v) {
  var d = LO.data;
  var host = $(v.table);
  if (!d || !host) return;
  var now = loNow();
  var rows = [];
  var find = v.find && $(v.find) ? $(v.find).value.trim().toLowerCase() : '';
  (d.nodes || []).forEach(function (n) {
    (n.rows || []).forEach(function (r) {
      if (r.forgets <= now) return;
      if (v.kinds && v.kinds.indexOf(r.kind) < 0) return;
      if (find && (String(r.who).toLowerCase().indexOf(find) < 0)
          && !(r.others || []).some(function (o) { return String(o).toLowerCase().indexOf(find) >= 0; })) return;
      var x = Object.assign({}, r);
      x.node = n.node; x.stale = !n.fresh;
      if (x.locked && x.until <= now) x.locked = false;
      rows.push(x);
    });
  });
  rows.sort(function (a, b) { return (b.locked - a.locked) || (b.last - a.last); });
  liveFill($(v.tools), function (tools) {
  var locked = rows.filter(function (r) { return r.locked; }).length;
  if (rows.length) {
    if (locked) { var lc = el('span', 'small bad', num(locked) + ' locked out'); lc.style.marginRight = '12px'; tools.appendChild(lc); }
    if (!v.kinds) {
      var all = cmdButton('Clear them all', 'broom', 'small');
      all.onclick = function () {
        confirmThen('Clear every lockout?', 'Every count of wrong attempts is forgotten' + (d.cluster ? ' on every node' : '')
          + ' - the locked out may try again at once. Events keeps a line saying who did it.', 'Clear them all', function () {
          loClear({action: 'clear_all'});
        }, false);
      };
      tools.appendChild(all);
    } else {
      var these = cmdButton(find ? 'Clear these (' + num(rows.length) + ')' : 'Clear them all', 'broom', 'small');
      these.onclick = function () {
        var list = rows.slice();
        confirmThen(find ? 'Clear these?' : 'Clear them all?', (find ? 'The ' + num(list.length) + ' shown' : 'Every place and token shown')
          + ' may try again at once. Events keeps a line saying who did it.', 'Clear them', function () {
          Promise.all(list.map(function (r) {
            return api('lockouts', {action: 'clear', node: r.node, kind: r.kind, who: r.who}).catch(function () { return null; });
          })).then(function () { toast('cleared: ' + num(list.length), 'good'); loadLockouts(); setTimeout(loadLockouts, 7000); });
        }, false);
      };
      tools.appendChild(these);
    }
  }
  }, true);
  liveFill(host, function (host) {
  if (!rows.length) {
    host.appendChild(el('p', 'note good', find ? 'Nothing counted for "' + find + '".'
      : (v.kinds ? 'No place is counted or blocked, and no token is locked.' : 'Nobody is locked out, and no wrong attempt is being counted.')));
    return;
  }
  var heads = ['State', 'Who', 'Where', 'How many', 'Tried'].concat(d.cluster ? ['Node'] : []).concat(['Last', '']);
  host.appendChild(listTable(heads, rows, function (r) {
    var tr = el('tr', r.locked ? 'lo-locked' : '');
    var st = el('td');
    if (r.locked) {
      st.appendChild(el('span', 'tag crit', r.by === 'place' ? 'blocked' : 'locked out'));
      st.appendChild(el('div', 'small', span(r.until - now) + ' left'));
      if (r.why) st.appendChild(el('div', 'small muted', r.why));
    } else {
      st.appendChild(el('span', 'tag load', 'counting'));
      st.appendChild(el('div', 'small muted', 'forgotten in ' + span(r.forgets - now)));
    }
    tr.appendChild(st);
    var who = el('td');
    who.appendChild(noI18n(el('div', 'mono', r.who)));
    who.appendChild(el('div', 'small muted', r.by === 'address' ? 'an address' : (r.by === 'token' ? 'a token'
      : (r.by === 'place' ? 'a place (Calling-Station-Id)' : 'a name'))));
    tr.appendChild(who);
    tr.appendChild(el('td', 'small', r.what));
    var w = el('td', 'num lo-count');
    var line = el('div');
    line.appendChild(noI18n(el('b', '', num(r.fails))));
    line.appendChild(document.createTextNode(' / ' + num(r.limit)));
    w.appendChild(line);
    w.appendChild(loBar(r.fails, r.limit, r.locked));
    if (r.by === 'place' && r.names_limit) {
      var nl = el('div', 'small muted');
      nl.appendChild(document.createTextNode(num(r.names) + ' / ' + num(r.names_limit) + ' names'));
      w.appendChild(nl);
      w.appendChild(loBar(r.names, r.names_limit, false));
    }
    tr.appendChild(w);
    var tried = el('td', 'small');
    if ((r.others || []).length) {
      tried.appendChild(el('div', 'muted', r.by === 'address' || r.by === 'place' ? 'names:' : 'from:'));
      tried.appendChild(noI18n(el('div', 'mono', r.others.slice().reverse().join(', '))));
    } else tried.textContent = '–';
    tr.appendChild(tried);
    if (d.cluster) {
      /* Counted in the database (1.0.116): the same for every node. */
      var nd = r.node === '*' ? el('td', 'small muted', 'every node') : noI18n(el('td', 'mono small', r.node));
      if (r.stale) { nd.appendChild(document.createTextNode(' ')); nd.appendChild(el('span', 'tag warn', 'not heard from')); }
      tr.appendChild(nd);
    }
    tr.appendChild(el('td', 'muted small', ago(r.last - LO.skew)));
    var a = el('td', 'rowtools');
    var x = cmdButton('Clear', 'broom', 'small');
    explain(x, 'Its count of wrong attempts is forgotten: it may try again at once.');
    x.onclick = function () {
      loClear({action: 'clear', node: r.node, kind: r.kind, who: r.who}, 'cleared: ' + r.who);
    };
    a.appendChild(x);
    tr.appendChild(a);
    return tr;
  }, 'plain'));
  }, true);
}
if ($('gd-find')) $('gd-find').addEventListener('input', function () { drawLockouts(); });
function userDo(body) {
  /* Drawn again either way (1.0.44): a refused change stayed in its box. */
  api('users', body).then(function (d) { toast(d.message, 'good'); loadUsers(); })
    .catch(function (e) { oops(e); loadUsers(); });
}
$('us-add').onclick = function () {
  modal('A new account', function (body) {
    var g = el('div', 'formgrid');
    var name = textBox('', '', 'mono');
    var role = selectBox([['readonly', 'read only'], ['fulladmin', 'full admin']], 'readonly');
    var pw = secretBox('', '8 characters at least', 'mono');
    var note = textBox('', '', '');
    g.appendChild(formField('Name', name));
    g.appendChild(formField('Role', role));
    g.appendChild(formField('A first password', pw, 'They choose their own at the first sign-in.'));
    g.appendChild(formField('Note', note));
    body.appendChild(g);
    MODAL_GO = function (b) {
      if (b) busy(b, true);         // one account per press (1.0.61)
      api('users', {action: 'add', name: name.value, role: role.value, password: pw.value, note: note.value, must_change: 1})
        .then(function (d) { toast(d.message, 'good'); closeModal(); loadUsers(); }).catch(oops)
        .then(function () { if (b) busy(b, false); });
    };
  }, [{words: 'Close', close: true}, {words: 'Make it', cls: 'primary', icon: 'add', go: function (b) { MODAL_GO(b); }}], true);
};


/* ======== the database (OTP admin.js 4848-5879) ======== */
/* ---- the database --------------------------------------------------------- */
/* ==========================================================================
   The database - as isemon's Settings → The database (1.10.160 - 1.10.218)
   ========================================================================== */
var DBSTATE = null;
var ENGINE_SAID = {sqlite: 'the file on this machine', mariadb: 'MariaDB', postgres: 'PostgreSQL'};
var DUMP_SAID = {sqlite: 'a copy of the file', mariadb: 'a MariaDB dump',
                 postgres: 'a PostgreSQL dump', copy: 'a portable copy'};
var TABLE_SAID = {samples: 'samples of the UPS (full)', samples_hourly: 'samples of the UPS (hourly)',
                  snapshots: 'every variable, when it changed', outages: 'power failures', tests: 'self tests',
                  plug_samples: 'samples of the plug (full)', plug_hourly: 'samples of the plug (hourly)',
                  sensor_samples: 'readings of the sensors', 'history.events': 'events of the UPS',
                  'history.meta': 'notes of the UPS side',
                  tokens: 'tokens', radius_log: 'RADIUS requests', otp_log: 'checks of a code',
                  events: 'events', accounts: 'accounts', sessions: 'sign-ins',
                  clients: 'clients', realms: 'realms', directories: 'directories',
                  settings: 'settings', meta: 'notes of its own'};

function loadDb() {
  api('db').then(function (d) {
    DBSTATE = d;
    $('db-size').textContent = bytes(d.size) + ' · ' + d.where;
    drawEngine(d);
    drawDisk(d);
    drawCounts(d);
    keptTable($('db-backups'), d.copies || [], {
      kind: 'copy', head: 'Copies kept (' + d.keep + ' at most)',
      where: 'They are files on this machine, under ' + d.backup_dir + ', each with the key '
        + 'that opens the tokens beside it. Copy them off it if they are to survive the machine.'
    });
    keptTable($('db-dumps'), d.dumps || [], {
      kind: 'dump', head: 'Dumps kept (' + d.keep + ' at most)',
      where: 'They are files on this machine, under ' + d.dump_dir + ', each with the key '
        + 'that opens the tokens beside it. Copy them off it if they are to survive the machine.'
    });
    dumpCard(d);
    drawTune(d);
    drawErasable(d.erasable || {});
    if (d.job && d.job.running && ADMIN) dbWatch();     /* its progress is a full administrator's (1.0.146) */
    explainWhatWasDrawn($('pane-db'));
  }).catch(oops);
}

/* ---- which database everything is kept in -------------------------------- */
function dbAsked() {
  var out = {};
  ['db_engine', 'db_host', 'db_port', 'db_name', 'db_user', 'db_password', 'db_timeout_s'].forEach(function (k) {
    var input = $('set-' + k);
    if (!input) return;
    var v = input._get ? input._get() : input.value;
    if (k === 'db_password' && (v === '' || String(v).indexOf('•') === 0)) return;
    out[k] = (k === 'db_port' || k === 'db_timeout_s') ? (String(v).trim() === '' ? 0 : Number(v)) : v;
  });
  return out;
}
function engineChosen() { return String(dbAsked().db_engine || (DBSTATE && DBSTATE.engine) || 'sqlite'); }
function engineWord(name) { return ENGINE_SAID[name] || name; }

function drawEngine(d) {
  $('db-engine-file').textContent = d.config_file || 'the config file';
  $('db-engine-now').textContent = (ENGINE_SAID[d.engine] || d.engine) + ' · ' + d.where;
  var host = $('db-engine-says');
  clear(host);
  var c = d.counts || {};
  host.appendChild(peekFacts([
    ['In use now', d.version],
    ['Where', noI18n(el('span', 'mono', d.where))],
    ['Holding', num(c.tokens || 0) + ' token(s), ' + num(c.radius_log || 0) + ' RADIUS request(s)'],
    ['Room it takes', bytes(d.size || 0)]
  ]));
  Object.keys(d.drivers || {}).forEach(function (name) {
    var one = d.drivers[name];
    host.appendChild(el('p', 'btnhelp', engineWord(name) + ': '
      + (one.ready ? 'the driver is installed'
         : (one.says || 'no driver') + ' — install ' + one.package)));
  });
  engineButtons();
}
function engineButtons() {
  var chosen = engineChosen();
  var live = String((DBSTATE && DBSTATE.engine) || 'sqlite');
  var same = chosen === live;
  if ($('db-engine-setup')) $('db-engine-setup').disabled = chosen === 'sqlite';
  if ($('db-engine-move')) $('db-engine-move').disabled = same;
  if ($('db-engine-empty')) $('db-engine-empty').disabled = same;
  if ($('db-engine-use')) $('db-engine-use').disabled = same;
}
document.addEventListener('change', function (e) {
  if (e.target && e.target.id === 'set-db_engine') engineButtons();
});

function engineFacts(d) {
  var facts = [['Reached', d.reached ? 'yes' : 'no'], ['Where', d.where || '']];
  if (d.version) facts.push(['It says it is', d.version]);
  if (d.reached) {
    facts.push(['Tables there', num((d.tables || []).length) + ' of ours']);
    facts.push(['Records in it', num(d.rows || 0)]);
    facts.push(['May this account write', d.writable ? 'yes' : 'NO']);
  }
  return peekFacts(facts);
}

/* ---- the job going on, and the bar that says how far ---------------------- */
var DB_WATCHING = null;
function dbBusyButtons(on) {
  ['db-backup', 'db-dump-make', 'db-optimize', 'db-check', 'db-prune', 'db-tidy',
   'db-restore', 'dump-restore', 'db-engine-move', 'erase-go'].forEach(function (id) {
    var b = $(id);
    if (b) b.disabled = on || (id === 'erase-go' && !erasePicked().length)
      || ((id === 'db-restore' || id === 'dump-restore') && !b._held);
  });
}
/* A bar that has finished gets Hide this; one that starts again loses it. */
function goingCloser(box) {
  if (!box || box.querySelector('.hide-row')) return;
  box.appendChild(hideBar(function () { box.hidden = true; }));
}
function goingOpen(box) {
  if (!box) return;
  box.hidden = false;
  var r = box.querySelector('.hide-row');
  if (r) r.remove();
}
function dbWatch(done) {
  if (DB_WATCHING) return;
  DB_WATCHING = true;     /* taken at once (1.0.57): two watchers ran when asked twice in one round trip */
  var box = $('db-going');
  goingOpen(box);
  dbBusyButtons(true);
  var step = function () {
    api('db', {action: 'job'}).then(function (d) {
      var j = d.job || {};
      var pct = j.whole ? Math.min(100, Math.round(100 * j.done / j.whole)) : (j.running ? 5 : 100);
      $('db-going-fill').style.width = pct + '%';
      $('db-going-says').textContent = (j.what || '') + (j.says ? ' — ' + j.says : '')
        + (j.whole ? ' (' + num(j.done) + ' of ' + num(j.whole) + ')' : '');
      /* Every second while the pane is open; every five once it is left, so
         the job's end is still told and the daemon is not asked for nothing. */
      if (j.running) { DB_WATCHING = setTimeout(step, TAB === 'settings' && PANE === 'db' ? 1000 : 5000); return; }
      DB_WATCHING = null;
      dbBusyButtons(false);
      goingCloser($('db-going'));
      if (j.error) { toast(j.what + ' failed: ' + j.error, 'bad'); $('db-going-says').textContent = j.error; return; }
      var r = j.result || {};
      if (r.rows !== undefined) {
        toast('everything is in ' + r.where + ': ' + num(r.rows) + ' row(s) — now Start using it', 'good');
        $('db-going-says').textContent = 'done: ' + num(r.rows) + ' row(s) in ' + r.where
          + ' · a copy made first: ' + r.copy;
      } else if (r.erased) {
        toast('erased; a copy was made first: ' + r.copy, 'good');
        $('db-going-says').textContent = 'done · a copy made first: ' + r.copy;
      } else if (r.before !== undefined) {
        toast('the disk is given back: ' + bytes(r.before) + ' → ' + bytes(r.after), 'good');
        $('db-going-says').textContent = 'done: ' + bytes(r.before) + ' → ' + bytes(r.after);
      }
      if (done) done(r);
      loadDb();
    }).catch(function (e) { DB_WATCHING = null; dbBusyButtons(false); oops(e); });
  };
  step();
}

/* ---- the disk under it ----------------------------------------------------- */
function drawDisk(d) {
  var host = $('db-disk');
  clear(host);
  var disk = d.disk || {};
  var grew = d.growth || {};
  var cache = d.cache;
  if (cache && cache.low) {
    var slow = el('p', 'note bad');
    slow.appendChild(el('b', '', cache.engine));
    slow.appendChild(document.createTextNode(' keeps '));
    slow.appendChild(el('b', '', bytes(cache.cache)));
    slow.appendChild(document.createTextNode(' of its own in memory ('));
    slow.appendChild(noI18n(el('span', 'mono', cache.setting)));
    slow.appendChild(document.createTextNode(') for a database of '));
    slow.appendChild(el('b', '', bytes(cache.size)));
    slow.appendChild(document.createTextNode('. Its indexes do not fit, so a busy minute waits for the disk. A quarter of the machine’s memory is the usual setting.'));
    host.appendChild(slow);
    if (ADMIN) {
      var go = cmdButton('Tune it for this machine…', 'gear', '');
      go.onclick = openTune;
      host.appendChild(go);
    }
  }
  if (!disk.total) {
    host.appendChild(el('p', 'note', 'The disk this is on could not be measured.'));
    return;
  }
  var share = Number(disk.share || 0);
  var line = el('div', 'disk-bar ' + (share >= 92 ? 'crit' : (share >= 80 ? 'warn' : 'ok')));
  var fill = el('span');
  fill.style.width = Math.max(1, Math.min(100, share)) + '%';
  line.appendChild(fill);
  host.appendChild(line);
  var says = el('p', 'note');
  says.appendChild(el('b', '', bytes(disk.free)));
  says.appendChild(document.createTextNode(' free of ' + bytes(disk.total) + ' on '));
  says.appendChild(noI18n(el('span', 'mono', disk.where || '')));
  says.appendChild(document.createTextNode(' — '));
  says.appendChild(el('span', '', share + '% of it is used'));
  if (grew.a_day) {
    says.appendChild(document.createTextNode(', and this database has been growing '));
    says.appendChild(el('b', '', bytes(grew.a_day)));
    says.appendChild(document.createTextNode(' a day over the last ' + grew.over_days + ' day(s).'));
  } else {
    says.appendChild(document.createTextNode('. How fast it is growing is not known yet: the size is noted once a day, and two are needed.'));
  }
  host.appendChild(says);
  host.appendChild(el('p', 'note', 'That disk holds ' + (disk.holds || '') + '.'));
  if (disk.days_left !== null && disk.days_left !== undefined) {
    host.appendChild(el('p', 'note ' + (disk.days_left < 45 ? 'bad' : ''), disk.days_left > 3650
      ? 'At that rate the disk has years left.'
      : 'At that rate the disk has about ' + num(disk.days_left) + ' day(s) left. Forgetting old records, under the keep-for numbers above, is what shortens it.'));
  }
  var parts = d.parts || [];
  if (parts.length) {
    var wrap = listTable([d.engine !== 'sqlite' ? 'Where' : 'File', 'What it is', {words: 'Size', cls: 'num'}],
      parts, function (one) {
        var tr = el('tr');
        tr.appendChild(noI18n(el('td', 'mono', one.name)));
        tr.appendChild(el('td', 'muted', one.what));
        tr.appendChild(el('td', 'num', bytes(one.bytes)));
        return tr;
      });
    wrap.style.marginTop = '10px';
    host.appendChild(wrap);
  }
}

/* ---- what is in it ----------------------------------------------------------- */
function drawCounts(d) {
  var host = $('db-counts');
  clear(host);
  var rows = (d.tables || []).slice().sort(function (a, b) {
    return (b.bytes || 0) - (a.bytes || 0) || b.rows - a.rows;
  });
  var known = rows.some(function (t) { return t.bytes !== null && t.bytes !== undefined; });
  host.appendChild(listTable(['What', 'Table', {words: 'Rows', cls: 'num'}]
      .concat(known ? [{words: 'Size', cls: 'num'}] : []), rows, function (t) {
    var tr = el('tr');
    tr.appendChild(el('td', '', TABLE_SAID[t.table] || t.table));
    tr.appendChild(noI18n(el('td', 'mono muted small', t.table)));
    tr.appendChild(el('td', 'num', num(t.rows)));
    if (known) tr.appendChild(el('td', 'num', t.bytes === null || t.bytes === undefined ? '–' : bytes(t.bytes)));
    return tr;
  }));
  var key = el('p', 'note ' + (d.key_there ? '' : 'bad'));
  key.appendChild(document.createTextNode(d.key_there ? 'The key that opens the tokens: ' : 'The key that opens the tokens is MISSING: '));
  key.appendChild(noI18n(el('span', 'mono', d.key)));
  host.appendChild(key);
  if (d.free) {
    host.appendChild(el('p', 'btnhelp', d.engine === 'postgres'
      ? num(d.free) + ' row(s) deleted and not yet given back to the disk.'
      : bytes(d.free) + ' free inside it, which the engine uses again; Give the disk back hands it to the operating system.'));
  }
}

/* ---- the two lists of files kept beside it --------------------------------- */
function keptTable(into, rows, opts) {
  clear(into);
  if (!into || !rows || !rows.length) return;
  var dump = opts.kind === 'dump';
  into.appendChild(el('h4', '', opts.head));
  into.appendChild(listTable(['Name', dump ? 'What it is' : 'Taken off', {words: 'Size', cls: 'num'},
                              'Made', 'Key beside it', {words: '', cls: 'act'}], rows, function (b) {
    var line = el('tr');
    line.appendChild(noI18n(el('td', 'mono', b.name)));
    var came = (dump ? DUMP_SAID[b.kind] : ENGINE_SAID[b.from]) || '';
    var mine = !dump || b.mine !== false;
    var off = el('td', came ? (mine ? '' : 'muted') : 'muted', came || 'not said');
    if (!mine) explain(off, 'This dump was taken off a different engine from the one this '
      + 'installation is on now, so it cannot be put back here. Put that engine back on, or '
      + 'use a copy — a copy goes into any of the three.');
    else if (dump && b.kind === 'copy') explain(off, 'Made on a night when the program that '
      + 'dumps this engine was not on the machine, so a portable copy was made instead. It is '
      + 'a whole copy and goes back into any of the three.');
    line.appendChild(off);
    line.appendChild(el('td', 'num', bytes(b.bytes)));
    line.appendChild(stampCell(b.at));
    line.appendChild(el('td', b.key ? 'good' : 'bad', b.key ? 'yes' : 'no'));
    var act = el('td', 'rowtools');
    if (ADMIN) {
      var take = cmdButton('Download', 'down', 'small');
      explain(take, dump
        ? 'Save this dump to the machine you are sitting at - with the key that opens its tokens, '
          + 'locked with a passphrase you give, or without it.'
        : 'Save this copy to the machine you are sitting at - with the key that opens its tokens, '
          + 'locked with a passphrase you give, or without it.');
      take.onclick = function () { dbDownloadAsk({name: b.name, kind: dump ? 'dump' : '', key: b.key}); };
      act.appendChild(take);
      var back = cmdButton('Restore', 'undo', 'small danger');
      explain(back, 'Put <b>this</b> one back, without downloading it and uploading it again: '
        + 'everything in the live database is replaced by what is in this file. You are shown '
        + 'what is in it and asked first, and a copy of what is being replaced is made before '
        + 'anything changes.');
      back.disabled = !mine;
      if (mine) back.onclick = function () { restoreKept(b, opts.kind); };
      act.appendChild(back);
      var gone = cmdButton('Delete', 'trash', 'small danger');
      explain(gone, 'Delete this file, and the key beside it, from the server. The live database is not touched.');
      gone.onclick = function () {
        confirmThen(dump ? 'Delete this dump?' : 'Delete this copy?', 'The file ' + htmlText(b.name)
          + ' and the key beside it are deleted from this machine. The live database is '
          + 'not touched, and the others stay where they are.', 'Delete it', function () {
            api('db', {action: 'delete', name: b.name, kind: opts.kind}).then(function (x) {
              toast(x.message, 'good');
              loadDb();
            }).catch(oops);
          });
      };
      act.appendChild(gone);
    }
    line.appendChild(act);
    return line;
  }));
  into.appendChild(el('p', 'btnhelp', opts.where));
}

function dumpCard(d) {
  var says = $('db-dump-says');
  clear(says);
  var info = d.dump || {};
  $('db-dump-now').textContent = info.words || '';
  $('db-dump-make').disabled = false;
  $('db-dump-get').disabled = false;
  if (info.ready) {
    var line = el('p', 'note good');
    line.appendChild(document.createTextNode('Tonight’s will be '));
    line.appendChild(el('b', '', info.words || 'a dump'));
    if (info.suffix) {
      line.appendChild(document.createTextNode(', written as '));
      line.appendChild(noI18n(el('code', '', info.suffix)));
    }
    line.appendChild(document.createTextNode('.'));
    says.appendChild(line);
  } else {
    says.appendChild(el('p', 'note bad', info.why || 'A dump cannot be made on this machine.'));
    var fix = el('p', 'note');
    fix.appendChild(document.createTextNode('Until it is there, the nightly one is made as a portable copy instead — a whole copy, which goes back into any engine, but several times the size of a dump. To have dumps: '));
    fix.appendChild(noI18n(el('code', '', info.install || '')));
    says.appendChild(fix);
  }
}

/* ---- putting one back ------------------------------------------------------- */
function restoreKept(b, kind) {
  api('db', {action: 'restore_kept', name: b.name, kind: kind, check: true}).then(function (d) {
    askBeforeRestoring(d.says, b.name, function () {
      return api('db', {action: 'restore_kept', name: b.name, kind: kind});
    });
  }).catch(oops);
}

function askBeforeRestoring(says, what, go) {
  var n = (says && says.counts) || {};
  var kind = (says && says.kind) || '';
  modal('Put this database back?', function (body) {
    var facts = [['File', noI18n(el('span', 'mono', String(what)))],
                 ['What it is', DUMP_SAID[kind] || kind], ['Size', bytes(says.bytes || 0)],
                 ['Tables', num(says.tables || 0)], ['Accounts', num(n.accounts || 0)],
                 ['Full administrators', num(says.admins || 0)]];
    if (n.tokens !== undefined) facts.push(['Tokens', num(n.tokens)]);
    if (n.radius_log !== undefined) facts.push(['RADIUS requests', num(n.radius_log)]);
    if (n.otp_log !== undefined) facts.push(['Checks of a code', num(n.otp_log)]);
    if (says.version) facts.push(['Made by upsmon', says.version]);
    /* Where it was made (1.0.63): the machine's config.json came with it, to
       be read - it is never put back. */
    var m = says.machine || null;
    if (m) {
      var use = m.in_use || {};
      facts.push(['Made on', noI18n(el('span', 'mono', String(m.node || '?') + (m.host ? ' (' + m.host + ')' : '')))]);
      facts.push(['Its database', noI18n(el('span', 'mono', String(use.db_engine || '?')
        + (use.db_engine && use.db_engine !== 'sqlite' ? ' ' + (use.db_host || '') + ':' + (use.db_port || '') + '/' + (use.db_name || '') : '')))]);
      if (use.ha_mode) facts.push(['Its cluster', el('span', 'mono', use.ha_mode + ', slot ' + (use.ha_slot || '?') + ', the other node ' + (use.ha_peer || '?'))]);
    }
    body.appendChild(peekFacts(facts));
    if (m && m.config) {
      var det = el('details', 'note');
      det.appendChild(el('summary', '', 'Its ' + (m.config_file || 'config.json') + ' (only to read: it is not put back)'));
      det.appendChild(noI18n(el('pre', 'mono', JSON.stringify(m.config, null, 1))));
      body.appendChild(det);
    }
    if (kind === 'mariadb' || kind === 'postgres') {
      body.appendChild(el('p', 'note', 'How many records are in a dump is not read from it — that is what putting it back is for.'));
    }
    var warn = el('p', 'note bad');
    warn.textContent = 'Putting it back replaces everything in the live database with what is in that file. A copy of what is being replaced is made first and kept with the others, so this can be undone — but everything recorded since that file was made will only be in that copy.';
    body.appendChild(warn);
    body.appendChild(el('p', 'btnhelp', 'You will probably be signed out: who is signed in came with the file like everything else. The key that opens the tokens is taken from beside the file, or from inside a downloaded copy; where there is none, the key in use stays.'));
  }, [
    {words: 'No, leave it', close: true},
    {words: 'Restore it', cls: 'danger', icon: 'undo', close: true, go: function () {
      go().then(function (done) {
        if (done && done.job) { setTimeout(function () { rbRestoreWatch('Putting the database back'); }, 50); return; }
        toast('the database was restored; what it replaced is in ' + done.safety + ' — ' + done.key, 'good');
        setTimeout(function () { window.location.reload(); }, 2500);
      }).catch(oops);
    }}], true);
}

/* A big file goes to /admin/upload/ (1.0.98): there nginx asks whether a
   full administrator sends it before it takes a byte. Where that place is
   not set up (an nginx without auth_request) it answers 404, and the file
   goes the old way. */
var BIG_PATH = true;
function bigFetch(query, file) {
  var opts = {method: 'POST', body: file, credentials: 'same-origin',
              headers: {'X-Upsmon-Restore': '1', 'Content-Type': 'application/octet-stream'}};
  if (!BIG_PATH) return fetch(query, opts);
  return fetch('/admin/upload/' + query, opts).then(function (r) {
    if (r.status !== 404) return r;
    BIG_PATH = false;
    return fetch(query, opts);
  });
}
function dbSend(file, check) {
  return bigFetch('?api=db-restore' + (check ? '&check=1' : ''), file)
    .then(function (r) {
      return r.json().catch(function () {
        throw new Error('the server did not answer with anything readable (HTTP ' + r.status + ')');
      }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('the server said ' + r.status));
        return d;
      });
    });
}

/* ---- a copy or a dump with its key (1.0.123) ------------------------------
   Downloaded with the key that opens its tokens, locked with a passphrase -
   one file that is all of it - or without it; and the same file put back
   with the passphrase. */
function dbDownloadAsk(o) {
  var what = o.kind === 'dump' ? 'dump' : 'copy';
  modal(o.name ? 'Download ' + o.name : (what === 'dump' ? 'Download a dump made now' : 'Download a copy made now'), function (body) {
    var seg = el('div', 'seg');
    var withB = el('button', 'on', 'With the key'), noB = el('button', '', 'Without the key');
    withB.type = noB.type = 'button';
    seg.appendChild(withB); seg.appendChild(noB);
    body.appendChild(seg);
    var withBox = el('div');
    withBox.appendChild(el('p', 'note', what === 'dump'
      ? 'One file that is all of it: the dump and the key that opens its tokens, locked with the passphrase below. Put back here or on another machine (Put a dump back), the passphrase opens the key again. Lost, the key in the file is lost with it - it is not kept anywhere.'
      : 'One file that is all of it: the copy and the key that opens its tokens, locked with the passphrase below. Put back here or on another machine (Put a copy back), the passphrase opens the key again. Lost, the key in the file is lost with it - it is not kept anywhere.'));
    var p1 = secretBox('', '10 characters at least', 'mono');
    var p2 = secretBox('', 'the same again', 'mono');
    p1.id = 'dbk-p1'; p2.id = 'dbk-p2';
    var g = el('div', 'formgrid');
    g.appendChild(formField('Passphrase', p1));
    g.appendChild(formField('The passphrase again', p2));
    withBox.appendChild(g);
    body.appendChild(withBox);
    var noBox = el('div');
    noBox.hidden = true;
    noBox.appendChild(el('p', 'note warn', what === 'dump'
      ? 'The dump alone opens no token on another machine: the key is the .key file beside it in /var/lib/upsmon/dumps (or /var/lib/upsmon/secrets.key). Keep the two together.'
      : 'The copy alone opens no token on another machine: the key is the .key file beside it in /var/lib/upsmon/backups (or /var/lib/upsmon/secrets.key). Keep the two together.'));
    body.appendChild(noBox);
    body._with = true;
    withB.onclick = function () { body._with = true; withB.classList.add('on'); noB.classList.remove('on'); withBox.hidden = false; noBox.hidden = true; };
    noB.onclick = function () { body._with = false; noB.classList.add('on'); withB.classList.remove('on'); withBox.hidden = true; noBox.hidden = false; };
    MODAL_BODY_DBK = body;
  }, [
    {words: 'Cancel', close: true},
    {words: 'Download', cls: 'primary', icon: 'down', go: function (button) {
      var body = MODAL_BODY_DBK;
      if (!body._with) {
        closeModal();
        if (o.now) toast('it is being made; the download starts when it is ready', 'good');
        window.location.href = '?api=db-download' + (o.name ? '&name=' + encodeURIComponent(o.name) : '') + (o.kind === 'dump' ? '&kind=dump' : '');
        return;
      }
      var a = $('dbk-p1').value, b2 = $('dbk-p2').value;
      if (a.length < 10) { toast('a passphrase of 10 characters at least', 'bad'); return; }
      if (a !== b2) { toast('the two passphrases are not the same', 'bad'); return; }
      busy(button, true);
      if (o.now) toast('it is being made; the download starts when it is ready', 'good');
      api('db', {action: 'download_ticket', name: o.name || '', kind: o.kind || '', passphrase: a}).then(function (t) {
        closeModal();
        window.location.href = '?api=db-download&ticket=' + encodeURIComponent(t.ticket);
        toast(t.name + ' - keep the passphrase apart from the file', 'good');
      }).catch(oops).then(function () { busy(button, false); });
    }}]);
}
var MODAL_BODY_DBK = null;
function dbAskPassphrase(d, fileName) {
  modal('The key in ' + fileName, function (body) {
    body.appendChild(el('p', 'note', 'This file holds the database and the key that opens its tokens, locked with a passphrase. Give it, and both are put back.'));
    var p = secretBox('', '', 'mono');
    p.id = 'dbk-open';
    body.appendChild(formField('Passphrase', p));
    setTimeout(function () { p.focus(); }, 50);
  }, [
    {words: 'Cancel', close: true},
    {words: 'Open it', cls: 'primary', icon: 'key', go: function (button) {
      var pass = $('dbk-open').value;
      busy(button, true);
      api('db', {action: 'upload_restore', upload: d.upload, passphrase: pass, check: true}).then(function (x) {
        closeModal();
        setTimeout(function () {
          askBeforeRestoring(x.says, fileName + ' (with its key)', function () {
            return api('db', {action: 'upload_restore', upload: d.upload, passphrase: pass});
          });
        }, 30);
      }).catch(oops).then(function () { busy(button, false); });
    }}]);
}
function dropBox(ids, empty) {
  var box = $(ids.drop);
  if (!box) return;
  var go = $(ids.go);
  function picked(file) {
    go._held = file || null;
    var says = $(ids.what);
    clear(says);
    says.hidden = !go._held;
    go.disabled = !go._held;
    $(ids.says).textContent = go._held ? go._held.name + ' · ' + bytes(go._held.size) : empty;
    if (!go._held) return;
    says.appendChild(el('p', 'btnhelp', 'Nothing has happened yet. Press Restore from this file and it will be read first — if it is not one of ours, if it is a dump of a different engine, or if it has no administrator in it, it is refused and nothing here changes.'));
  }
  box.onclick = function () { $(ids.file).click(); };
  $(ids.file).onchange = function () { picked(this.files && this.files[0]); this.value = ''; };
  ['dragenter', 'dragover'].forEach(function (name) {
    box.addEventListener(name, function (e) { e.preventDefault(); box.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (name) {
    box.addEventListener(name, function (e) {
      e.preventDefault();
      box.classList.remove('over');
      if (name === 'drop' && e.dataTransfer && e.dataTransfer.files) picked(e.dataTransfer.files[0]);
    });
  });
  go.onclick = function () {
    var held = go._held;
    if (!held) return;
    busy(go, true);
    dbSend(held, true).then(function (d) {
      if (d.upload) { dbAskPassphrase(d, held.name); return; }
      askBeforeRestoring(d.says, held.name, function () { return dbSend(held, false); });
    }).catch(oops).then(function () { busy(go, false); });
  };
}

/* ---- the database server's own settings ---------------------------------- */
function drawTune(d) {
  var host = $('db-tune-says');
  clear(host);
  var t = d.tune || {};
  var file = d.engine === 'sqlite';
  $('db-tune').hidden = file;
  var last = t.last;
  $('db-tune-undo').hidden = file || !last || !!last.undone || last.engine !== d.engine;
  $('db-tune-restart').hidden = true;
  if (file) {
    host.appendChild(el('p', 'note', 'The file on this machine has no server to tune: this program sets it up itself.'));
    return;
  }
  if (last && last.engine === d.engine) {
    var p = el('p', 'note');
    if (last.undone) {
      p.appendChild(document.createTextNode('Put back as it was before'));
      p.appendChild(document.createTextNode(' ' + stamp(last.undone) + (last.undone_by ? ' · ' + last.undone_by : '') + '.'));
    } else {
      p.appendChild(document.createTextNode('Tuned for its machine'));
      p.appendChild(document.createTextNode(' ' + stamp(last.at) + (last.by ? ' · ' + last.by : '') + ':'));
      var set = last.set || {};
      Object.keys(set).sort().forEach(function (n, i) {
        p.appendChild(document.createTextNode(i ? ', ' : ' '));
        p.appendChild(noI18n(el('span', 'mono', n + ' = ' + set[n])));
      });
    }
    host.appendChild(p);
  } else {
    host.appendChild(el('p', 'note', 'Not tuned from this page yet.'));
  }
  if ((t.pending || []).length) {
    var w = el('p', 'note bad');
    w.appendChild(document.createTextNode('Waiting for the server’s next start:'));
    t.pending.forEach(function (n, i) {
      w.appendChild(document.createTextNode(i ? ', ' : ' '));
      w.appendChild(noI18n(el('span', 'mono', n)));
    });
    host.appendChild(w);
    if (t.restart && t.restart.may) {
      $('db-tune-restart').hidden = false;
    } else {
      if (t.restart && t.restart.why) host.appendChild(el('p', 'note', 'This program cannot restart it from here: ' + t.restart.why + '.'));
      host.appendChild(el('p', 'note', 'On the server, as root:'));
      host.appendChild(noI18n(el('pre', 'mono small', 'systemctl restart ' + ((t.restart && t.restart.unit) || 'postgresql'))));
      host.appendChild(el('p', 'btnhelp', 'Or let these pages do it: install.sh --upgrade puts in the rule that lets upsmon restart PostgreSQL on this machine, and nothing else (--no-db-restart takes it away).'));
    }
  }
  if ((t.lost || []).length) {
    var l = el('p', 'note bad');
    l.appendChild(document.createTextNode('MariaDB has been started again since, and these are back as they were:'));
    t.lost.forEach(function (n, i) {
      l.appendChild(document.createTextNode(i ? ', ' : ' '));
      l.appendChild(noI18n(el('span', 'mono', n)));
    });
    host.appendChild(l);
    host.appendChild(el('p', 'note', 'The file the popup gives keeps them over a restart.'));
  }
}

var TUNE = null;
function tuneAdminBoxes(body, engine) {
  var g = el('div', 'formgrid');
  var who = textBox(TUNE && TUNE.user || '', engine === 'postgres' ? 'postgres' : 'root', '');
  who.autocomplete = 'off';
  who.setAttribute('data-lpignore', 'true');
  var word = maskBox('', '', '');
  word.setAttribute('data-lpignore', 'true');
  word.value = TUNE && TUNE.pass || '';
  g.appendChild(formField('An administrator on that server', who, 'Only where upsmon’s own account may not change them. Used for this one request and stored nowhere: not in the settings, not in the database, not in any log.'));
  g.appendChild(formField('Its password', word));
  body.appendChild(g);
  return {who: who, word: word};
}
function tuneForget() {
  TUNE = null;
  Array.prototype.forEach.call(document.querySelectorAll('#modal-body input'), function (i) { i.value = ''; });
}
function tuneAsked() {
  var out = {machine: {}};
  if (!TUNE) return out;
  if (TUNE.boxes) { TUNE.user = TUNE.boxes.who.value.trim(); TUNE.pass = TUNE.boxes.word.value; }
  if (TUNE.hw) {
    TUNE.ram = TUNE.hw.ram.value.replace(',', '.').trim();
    TUNE.cpus = TUNE.hw.cpus.value.trim();
    TUNE.disk = TUNE.hw.disk.value;
  }
  if (TUNE.ram) out.machine.ram_gb = TUNE.ram;
  if (TUNE.cpus) out.machine.cpus = TUNE.cpus;
  if (TUNE.disk) out.machine.disk = TUNE.disk;
  out.admin_user = TUNE.user || '';
  out.admin_password = TUNE.pass || '';
  return out;
}
function openTune() {
  TUNE = {user: '', pass: '', ram: '', cpus: '', disk: '', plan: null};
  modal('Tuning the database server for its machine', function (body) {
    body.appendChild(el('p', 'note', 'Reading what the machine has and what the server is set to, and timing a few small writes…'));
  }, [{words: 'Close', close: true}], 'tune');
  MODAL_CLOSE = tuneForget;
  tuneLook();
}
function tuneLook(button) {
  var ask = tuneAsked();
  var ticket = modalTicket();
  if (button) busy(button, true);
  api('db', {action: 'tune_plan', machine: ask.machine}).then(function (d) {
    if (!modalStill(ticket)) return;
    TUNE.plan = d;
    tuneDraw(d);
  }).catch(function (e) {
    if (!modalStill(ticket)) return;
    if (button) busy(button, false);
    oops(e);
  });
}
function tuneValue(v) { return v === null || v === undefined || v === '' ? '–' : String(v); }
function tuneDraw(d, done) {
  var changes = (d.items || []).filter(function (it) { return it.change; });
  var buttons = [
    {words: 'Read again', icon: 'refresh', left: true, go: function (b) { tuneLook(b); }},
    {words: 'Close', close: true}
  ];
  if (changes.length) {
    buttons.splice(1, 0, {words: 'Put it in', cls: 'primary', icon: 'gear', admin: true,
                          go: function (b) { tuneApply(b); }});
  }
  /* What waits for the server's next start, started from here - as isemon
     does - where install.sh let this program restart it. */
  var waiting = (d.items || []).some(function (it) { return it.waiting || it.pending; });
  if (waiting && d.restart && d.restart.may) {
    buttons.splice(1, 0, {words: 'Restart the server…', cls: changes.length ? '' : 'primary',
                          icon: 'power', admin: true, go: function () { tuneRestartAsk(); }});
  }
  modal('Tuning ' + d.words + ' for its machine', function (body) {
    var f = d.facts || {};
    body.appendChild(peekFacts([
      ['Server', String(d.version || d.words).replace(/\s*\(.*\)\s*$/, '')],
      ['Where', d.where],
      ['Database', bytes(d.size)],
      f.ram ? ['Memory', bytes(f.ram)] : null,
      f.avail ? ['Free now', bytes(f.avail)] : null,
      f.cpus ? ['Processors', num(f.cpus)] : null,
      ['Disk', f.disk === 'hdd' ? 'a disk that spins' : 'SSD'],
      f.commit_ms !== null && f.commit_ms !== undefined
        ? ['A write made safe in', Number(f.commit_ms).toFixed(1).replace('.', numDecimal()) + ' ms'] : null,
      d.connections ? ['Connections allowed', num(d.connections)] : null
    ]));
    var from = {'this machine': 'Read from this machine, which the server runs on.',
                'typed': 'As typed below.'}[f.source || ''];
    if (from) body.appendChild(el('p', 'note', from));
    if (f.why && f.why !== 'chosen') body.appendChild(el('p', 'note', 'The disk: ' + f.why));
    if (d.need_facts) {
      body.appendChild(el('p', 'note bad', 'The server is on another machine and what it has could not be read from here. Type its memory and processors below and press Read again.'));
    }
    var row = el('div', 'tune-machine');
    var hw = {};
    [['ram', 'Memory, GB', f.ram ? String(Math.round(f.ram / 1073741824 * 10) / 10) : ''],
     ['cpus', 'Processors', f.cpus ? String(f.cpus) : '']].forEach(function (one) {
      var box = el('div', 'set-item');
      box.appendChild(el('label', '', one[1]));
      var input = el('input');
      input.type = 'text';
      input.inputMode = 'decimal';
      input.value = TUNE[one[0]] || one[2];
      box.appendChild(input);
      row.appendChild(box);
      hw[one[0]] = input;
    });
    var dbox = el('div', 'set-item');
    dbox.appendChild(el('label', '', 'Disk'));
    var sel = selectBox([['ssd', 'SSD'], ['hdd', 'a disk that spins']], TUNE.disk || f.disk || 'ssd');
    dbox.appendChild(sel);
    row.appendChild(dbox);
    hw.disk = sel;
    body.appendChild(row);
    TUNE.hw = hw;
    body.appendChild(el('p', 'btnhelp', 'Change any of these and press Read again: the settings are worked out afresh for what is typed.'));
    if (done) {
      if ((done.done || []).length || (done.later || []).length) {
        body.appendChild(el('p', 'note good', 'Put in: ' + ((done.done || []).join(', ') || 'nothing at once')
          + ((done.later || []).length ? ' · at the next start: ' + done.later.join(', ') : '')));
      }
      if ((done.failed || []).length) body.appendChild(el('p', 'note bad', 'Refused: ' + done.failed.join('; ')));
    }
    if ((d.items || []).length) {
      body.appendChild(el('h4', '', changes.length
        ? 'What would change' : 'Nothing to change: every setting is right for this machine'));
      var wrap = listTable(['Setting', 'Now', 'For this machine', 'Takes', 'Why'], d.items, function (it) {
        var tr = el('tr', it.change ? 'tune-change' : '');
        tr.appendChild(noI18n(el('td', 'mono', it.name)));
        tr.appendChild(noI18n(el('td', 'mono', tuneValue(it.now))));
        var want = el('td', 'mono ' + (it.change ? 'good' : 'muted'));
        want.appendChild(noI18n(el('span', '', tuneValue(it.want))));
        if (it.waiting) { want.appendChild(document.createTextNode(' ')); want.appendChild(el('span', 'tag warn', 'waiting for a start')); }
        tr.appendChild(want);
        tr.appendChild(el('td', it.restart ? 'warn' : 'muted', it.takes));
        tr.appendChild(el('td', 'muted small', it.why));
        return tr;
      }, 'plain tune-table');
      body.appendChild(wrap);
    }
    if (d.engine === 'postgres' && waiting && d.restart && !d.restart.may && d.restart.why) {
      body.appendChild(el('p', 'note bad', 'This program cannot restart it from here: ' + d.restart.why + '.'));
    }
    if (d.engine === 'postgres') {
      body.appendChild(el('p', 'btnhelp', d.restart && d.restart.may
        ? 'What takes effect only at the next start waits for it: Restart the server, under this popup, does that when you say so.'
        : 'What takes effect only at the next start waits for it: on the server, as root, systemctl restart ' + ((d.restart && d.restart.unit) || 'postgresql') + '.'));
    }
    if (d.engine === 'mariadb' && d.cnf) {
      body.appendChild(el('h4', '', 'To keep them over a restart'));
      body.appendChild(el('p', 'note', 'SET GLOBAL lasts until MariaDB is next started, and upsmon may not write in /etc. Put this in /etc/my.cnf.d/zz-upsmon-tuning.cnf on the server; the ones marked at the next start take effect only from there.'));
      body.appendChild(noI18n(el('pre', 'mono small', d.cnf)));
    }
    body.appendChild(el('h4', '', 'Who changes them'));
    TUNE.boxes = tuneAdminBoxes(body, d.engine);
  }, buttons, 'tune');
  MODAL_CLOSE = tuneForget;
}
function tuneApply(button) {
  var ask = tuneAsked();
  busy(button, true);
  api('db', {action: 'tune_apply', machine: ask.machine, admin_user: ask.admin_user,
             admin_password: ask.admin_password}).then(function (d) {
    TUNE.plan = d;
    tuneDraw(d, d);
    loadDb();
  }).catch(function (e) { busy(button, false); oops(e); });
}

/* ---- erasing what was collected ----------------------------------------- */
function drawErasable(d) {
  var host = $('erase-list');
  var was = {};
  Array.prototype.forEach.call(host.querySelectorAll('input[type=checkbox]'),
    function (b) { was[b.dataset.group] = b.checked; });
  clear(host);
  $('erase-size').textContent = bytes(d.bytes || 0) + ' in all';
  (d.groups || []).forEach(function (g) {
    var row = el('label', 'erase-one' + (g.rows ? '' : ' empty'));
    var box = document.createElement('input');
    box.type = 'checkbox';
    box.dataset.group = g.key;
    box.checked = !!was[g.key];
    box.disabled = !ADMIN || !g.rows;
    box.onchange = markErase;
    row.appendChild(box);
    var words = el('div', 'erase-words');
    var top = el('div', 'erase-top');
    top.appendChild(el('span', 'erase-name', g.name));
    top.appendChild(el('span', 'tag ' + (g.rows ? 'info' : 'dim'), g.rows ? num(g.rows) + ' row(s)' : 'already empty'));
    words.appendChild(top);
    words.appendChild(el('div', 'erase-says', g.says));
    row.appendChild(words);
    host.appendChild(row);
  });
  markErase();
}
function erasePicked() {
  return Array.prototype.filter.call(document.querySelectorAll('#erase-list input[type=checkbox]'),
    function (b) { return b.checked; }).map(function (b) { return b.dataset.group; });
}
function markErase() {
  var picked = erasePicked();
  var go = $('erase-go');
  go.disabled = !ADMIN || !picked.length || !!DB_WATCHING;
  setButtonIcon(go, 'forget', picked.length ? 'Erase ' + picked.length + ' of these…' : 'Erase what is ticked…');
}

if ($('db-engine-test')) {
  $('db-engine-test').onclick = function () {
    busy($('db-engine-test'), true);
    api('db', {action: 'try', settings: dbAsked()}).then(function (d) {
      modal('Trying ' + d.words, function (body) {
        body.appendChild(el('p', 'note', 'Nothing was saved and nothing was written: this opened it, asked what it is, counted what is in it and closed it again.'));
        body.appendChild(engineFacts(d));
        if (!d.reached) body.appendChild(el('p', 'note bad', String(d.trouble || '')));
        else if (d.in_use) body.appendChild(el('p', 'note', 'This is the database in use.'));
        else if (!d.writable) body.appendChild(el('p', 'note bad', 'It answers, but this account may not make anything in it. Set it up, or give the account rights on that database.'));
        else if (!d.rows) body.appendChild(el('p', 'note good', 'It is reachable and empty of ours, which is exactly what something to carry everything into should look like.'));
      }, [{words: 'Close', close: true}], true);
    }).catch(oops).then(function () { busy($('db-engine-test'), false); });
  };

  $('db-engine-setup').onclick = function () {
    var want = dbAsked();
    var who, word;
    modal('Setting up ' + engineWord(want.db_engine), function (body) {
      body.appendChild(el('p', 'note', 'This makes the database and the account on that server, and gives the account rights on that one database and no other. The first time, it needs an administrator on the server to do it — root on MariaDB, postgres on PostgreSQL, or anyone who may create a database.'));
      body.appendChild(el('p', 'note', 'That administrator is used for this one connection and is stored nowhere: not in the settings, not in the database, not in any log.'));
      body.appendChild(el('p', 'note', 'The account this program will use is made with a password of its own, generated here — you do not have to invent one. It is written into the config file, and shown once when this is done so you can keep a copy.'));
      body.appendChild(el('p', 'note', 'Press this again later and it does the other half of the job: if the account already gets in, nothing is made and no administrator is wanted — it opens the database and puts its tables right. Leave the two boxes empty for that.'));
      var g = el('div', 'formgrid');
      who = textBox('', want.db_engine === 'postgres' ? 'postgres' : 'root', '');
      who.autocomplete = 'off';
      word = maskBox('', '', '');
      g.appendChild(formField('An administrator on that server', who, 'Only needed the first time, or if the account cannot get in.'));
      g.appendChild(formField('Its password', word));
      body.appendChild(g);
    }, [{words: 'Close', close: true}, {words: 'Set it up', cls: 'primary', icon: 'key', go: function (b) {
      var ticket = modalTicket();
      busy(b, true);
      api('db', {action: 'setup', settings: want, admin_user: who.value.trim(), admin_password: word.value}).then(function (d) {
        if (!modalStill(ticket)) modal('The database, set up', function () {}, [{words: 'Close', close: true}]);
        var body = $('modal-body');
        clear(body);
        (d.made || []).forEach(function (line) { body.appendChild(el('p', 'note good', line)); });
        body.appendChild(engineFacts(d.try || {}));
        if (d.password) {
          body.appendChild(el('h4', '', 'The password made for ' + (want.db_user || 'it')));
          var pw = el('input');
          pw.type = 'text'; pw.readOnly = true; pw.className = 'mono'; pw.value = d.password;
          pw.onclick = function () { pw.select(); };
          noI18n(pw);
          body.appendChild(pw);
          var copy = cmdButton('Copy it', 'copy', 'small');
          copy.style.marginTop = '8px';
          copy.onclick = function () {
            pw.select();
            var ok = false;
            try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
            toast(ok ? 'copied' : 'press Ctrl+C — it is selected', ok ? 'good' : 'warn');
          };
          body.appendChild(copy);
          body.appendChild(el('p', 'note', 'It is saved in ' + (d.kept_in || 'the config file') + ' and nowhere else, so nothing has to be typed in above. This is the only time it is shown — keep a copy if you want one, though nothing here needs it again.'));
        }
        body.appendChild(el('p', 'note', 'The address is saved. Nothing has moved yet: carry everything across when you are ready.'));
        clear($('modal-foot'));
        var close = cmdButton('Close', 'close', '');
        close.onclick = closeModal;
        $('modal-foot').appendChild(close);
        loadSettings();
      }).catch(function (e) { busy(b, false); oops(e); });
    }}], 'medium');
  };

  $('db-engine-move').onclick = function () {
    var want = dbAsked();
    var word = engineWord(want.db_engine);
    modal('Carrying everything into ' + word, function (body) {
      body.appendChild(el('p', 'note', 'Every token, every request, every setting and every account is copied into ' + word + '. On a large database this takes minutes; you can close this and it carries on.'));
      body.appendChild(el('p', 'note', 'What is here is not touched, and a copy of it is made first in any case. Nothing starts using the other database until you say so afterwards.'));
    }, [{words: 'Leave it', close: true}, {words: 'Carry it across', cls: 'primary', icon: 'save', close: true, go: function () {
      api('db', {action: 'move', settings: want}).then(function () { dbWatch(); }).catch(oops);
    }}], true);
  };

  $('db-engine-empty').onclick = function () {
    var want = dbAsked();
    var word = engineWord(want.db_engine);
    modal('Emptying ' + word, function (body) {
      body.appendChild(el('p', 'note bad', 'This throws away everything of upsmon in the OTHER database — the ' + word + ' above, not the one in use. It is for when a first attempt at moving left something in it and the move will not go on.'));
      body.appendChild(el('p', 'note', 'Nothing in the database this installation is running on is touched, and this is refused outright if the two are the same.'));
    }, [{words: 'Leave it', close: true}, {words: 'Empty it', cls: 'danger', icon: 'forget', close: true, go: function () {
      api('db', {action: 'empty', settings: want}).then(function (d) { toast(d.message, 'good'); loadDb(); }).catch(oops);
    }}], true);
  };

  $('db-engine-use').onclick = function () {
    var want = dbAsked();
    var word = engineWord(want.db_engine);
    modal('Start using ' + word, function (body) {
      body.appendChild(el('p', 'note', 'This writes the address into ' + ((DBSTATE && DBSTATE.config_file) || 'the config file') + ' and restarts the daemon, which takes a few seconds. Nothing in either database is touched.'));
      body.appendChild(el('p', 'note', want.db_engine === 'sqlite'
        ? 'Everything will be read out of the file on this machine from then on, and the server may be uninstalled once you are happy.'
        : 'Everything will be read out of ' + word + ' from then on, and the file on this machine may be deleted once you are happy. Carry everything across first if you have not — this does not move anything.'));
    }, [{words: 'Not yet', close: true}, {words: 'Start using it', cls: 'primary', icon: 'power', close: true, go: function () {
      api('db', {action: 'use', settings: want}).then(function (d) {
        toast(d.message, 'good');
        setTimeout(function () { location.reload(); }, 9000);
      }).catch(oops);
    }}], true);
  };

  $('db-backup').onclick = function () {
    busy($('db-backup'), true);
    api('db', {action: 'backup'}).then(function (x) { toast(x.message, 'good'); loadDb(); })
      .catch(oops).then(function () { busy($('db-backup'), false); });
  };
  $('db-download').onclick = function () { dbDownloadAsk({kind: '', now: true, key: true}); };
  $('db-dump-make').onclick = function () {
    busy($('db-dump-make'), true);
    toast('dumping — this takes as long as the database is big');
    api('db', {action: 'dump'}).then(function (d) {
      toast('a dump was made: ' + d.name + ' (' + bytes(d.bytes) + ')', 'good');
      loadDb();
    }).catch(oops).then(function () { busy($('db-dump-make'), false); });
  };
  $('db-dump-get').onclick = function () { dbDownloadAsk({kind: 'dump', now: true, key: true}); };
  $('db-tidy').onclick = function () {
    busy($('db-tidy'), true);
    api('db', {action: 'tidy'}).then(function (x) { toast(x.message, 'good'); loadDb(); })
      .catch(oops).then(function () { busy($('db-tidy'), false); });
  };
  $('db-check').onclick = function () {
    busy($('db-check'), true);
    api('db', {action: 'check'}).then(function (d) {
      modal(d.ok ? 'Nothing in it is broken' : 'Something in it is broken', function (body) {
        var ul = el('ul', 'note');
        (d.said || []).forEach(function (one) { ul.appendChild(noI18n(el('li', 'mono small', one))); });
        body.appendChild(ul);
      }, [{words: 'Close', close: true}], true);
    }).catch(oops).then(function () { busy($('db-check'), false); });
  };
  $('db-optimize').onclick = function () {
    confirmThen('Give the disk back', 'Each table is rebuilt and held shut while it is. In a cluster this node '
      + 'answers no RADIUS meanwhile and the other node signs everybody in; alone, sign-ins wait for it - do it '
      + 'when few sign in. It needs room for a second copy of the biggest table. Worth '
      + 'doing after throwing a lot away, and not otherwise.', 'Give it back',
      function () { api('db', {action: 'give_back'}).then(function () { dbWatch(); }).catch(oops); }, false);
  };
  $('db-prune').onclick = function () {
    var days, everything;
    modal('Forget records older than…', function (body) {
      body.appendChild(el('p', 'note', 'The samples of the UPS, the plug and the sensors, and the events, older than this are '
        + 'deleted now. The accounts, the certificates and the settings are not touched.'));
      days = el('input'); days.type = 'number'; days.min = 1; days.value = 90;
      body.appendChild(formField('Older than (days)', days));
      everything = switchBox(false);
      everything._input.addEventListener('change', function () { days.disabled = !!everything._get(); });
      body.appendChild(formField('Every line, whatever its age — the whole log emptied', everything));
    }, [{words: 'Close', close: true}, {words: 'Forget them', cls: 'danger', icon: 'forget', go: function (b) {
      busy(b, true);
      api('db', {action: 'prune', days: Number(days.value), everything: !!everything._get()}).then(function (d) {
        toast(d.message, 'good'); closeModal(); loadDb();
      }).catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
  };
  $('db-tune').onclick = openTune;
  $('db-tune-restart').onclick = function () { tuneRestartAsk(); };
}
function tuneRestartAsk() {
  {
    var unit = ((DBSTATE && DBSTATE.tune && DBSTATE.tune.restart) || {}).unit || 'postgresql';
    modal('Restart ' + unit, function (body) {
      body.appendChild(el('p', 'note', 'PostgreSQL is stopped and started again so that the settings waiting for its next start take effect. It takes a few seconds; the RADIUS server waits for it meanwhile, and the requests in that moment are answered as soon as it is back.'));
      body.appendChild(el('p', 'note', 'Not done when it might not come back: a shared_buffers larger than the memory free now, or huge pages.'));
    }, [{words: 'Not now', close: true}, {words: 'Restart it', cls: 'primary', icon: 'power', go: function (b) {
      busy(b, true);
      api('db', {action: 'tune_restart'}).then(function (d) {
        toast(d.message, 'good'); closeModal(); loadDb();
      }).catch(function (e) { busy(b, false); oops(e); });
    }}], true);
  }
}
if ($('db-tune-undo')) {
  $('db-tune-undo').onclick = function () {
    var user, pass;
    modal('Put back as it was', function (body) {
      body.appendChild(el('p', 'note', 'Every setting this page changed goes back to what it was before. Empty: upsmon’s own account, where it has that right.'));
      var g = el('div', 'formgrid');
      user = textBox('', DBSTATE && DBSTATE.engine === 'postgres' ? 'postgres' : 'root', '');
      pass = maskBox('', '', '');
      g.appendChild(formField('An administrator on that server', user));
      g.appendChild(formField('Its password', pass, 'Used for this one request; kept nowhere.'));
      body.appendChild(g);
    }, [{words: 'Close', close: true}, {words: 'Put it back', cls: 'primary', icon: 'undo', go: function (b) {
      busy(b, true);
      api('db', {action: 'tune_undo', admin_user: user.value.trim(), admin_password: pass.value}).then(function (d) {
        toast('put back: ' + (d.done || []).join(', '), 'good'); closeModal(); loadDb();
      }).catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
  };
  $('erase-go').onclick = function () {
    var picked = erasePicked();
    if (!picked.length) return;
    var names = Array.prototype.filter.call(document.querySelectorAll('#erase-list input[type=checkbox]'),
      function (b) { return b.checked; }).map(function (b) {
        return b.closest('.erase-one').querySelector('.erase-name').textContent;
      });
    modal(picked.length === 1 ? 'Erase this?' : 'Erase these ' + picked.length + '?', function (body) {
      body.appendChild(el('p', 'note', 'This erases, for good:'));
      var ul = el('ul', 'ask-list');
      names.forEach(function (n) { ul.appendChild(el('li', '', n)); });
      body.appendChild(ul);
      body.appendChild(el('p', 'note', 'The tokens, the accounts and every setting are not touched.'));
      body.appendChild(el('p', 'muted', 'A copy of the database is made first, so this can be undone by restoring it.'));
    }, [{words: 'No, leave it', close: true}, {words: 'Erase it', cls: 'danger', icon: 'forget', close: true, go: function () {
      api('db', {action: 'erase', groups: picked, tidy: $('erase-tidy').checked}).then(function () {
        dbWatch();
      }).catch(oops);
    }}], true);
  };
  dropBox({drop: 'db-drop', file: 'db-file', says: 'db-drop-says', what: 'db-upload-what', go: 'db-restore'},
          'Drop a database file here, or press to choose one');
  dropBox({drop: 'dump-drop', file: 'dump-file', says: 'dump-drop-says', what: 'dump-upload-what', go: 'dump-restore'},
          'Drop a dump here, or press to choose one');
}


/* ======== about (OTP admin.js 5939-6104) ======== */
/* ---- about ---------------------------------------------------------------- */
function drawAbout() {
  var s = STATUS || {};
  var host = $('about-state');
  clear(host);
  host.appendChild(el('h2', '', 'upsmon ' + (s.version || '')));
  var u = s.ups || {};
  host.appendChild(peekFacts([['Running for', span(s.uptime || 0)], ['UPS', (u.name || '?') + (u.status ? ' · ' + u.status : '')],
                              ['Accounts', num(s.accounts)],
                              ['Database', ({sqlite: 'SQLite', mariadb: 'MariaDB', postgres: 'PostgreSQL'})[(s.database || {}).engine] || (s.database || {}).engine]]));
  var c = (s.radius || {}).counts || {};
  host.appendChild(kvTable(Object.keys(c).sort().map(function (k) { return [k, num(c[k])]; })));
  host.appendChild(el('p', 'muted small', 'One Python file (/usr/local/lib/upsmon/upsmon.py), the standard library, and these PHP pages that ask it. On the server: upsmon --help.'));
  if (ADMIN) drawConsoleLogin(host);
  drawSoftware(host);
}

/* The upsmon console when root signs in at the console or over SSH (1.0.141):
   a switch a node; the node's own root helper writes it. */
function drawConsoleLogin(host) {
  var box = el('div', 'sw-box');
  host.appendChild(box);
  box.appendChild(el('h3', 'sw-h', 'The console at login'));
  box.appendChild(el('p', 'note', 'On: root signing in at the machine\'s console or over SSH lands in the upsmon console (upsmon --console); q leaves it for the shell. Off: the ordinary shell, and upsmon --console opens it. Commands run over SSH, scp and sftp never get it. On the server: upsmon --console-at-login on|off.'));
  var list = el('div', '');
  box.appendChild(list);
  var tries = 0;
  function load() {
    api('console-login').then(function (d) {
      clear(list);
      var waiting = false;
      (d.nodes || []).forEach(function (n) {
        var row = el('div', 'kv-row');
        row.style.cssText = 'display:flex;align-items:center;gap:10px;margin:8px 0;flex-wrap:wrap';
        var sw = switchBox(!!n.on);
        sw._input.disabled = n.on === null || n.on === undefined || n.pending;
        var name = noI18n(el('b', '', n.name));
        row.appendChild(sw);
        row.appendChild(name);
        if (n.me) row.appendChild(el('span', 'tag info', 'this one'));
        /* The switch says on or off itself (1.0.148): words only when it cannot. */
        var said = n.pending ? 'being switched…' : (n.on === null || n.on === undefined) ? 'not said yet - the node says within a minute' : '';
        if (said) row.appendChild(el('span', 'muted small', said));
        if (n.error) row.appendChild(el('p', 'note bad', n.error));
        if (n.pending) waiting = true;
        /* The switch only says what it will be; the save bar at the bottom
           does it (1.0.147), as with every other setting. */
        var key = 'console-login:' + n.name;
        if (PENDING[key] && !sw._input.disabled) {      /* drawn again, still not saved */
          sw._input.checked = PENDING[key].on;
          row.classList.add('changed');
        }
        sw._input.onchange = function () {
          var on = sw._input.checked;
          row.classList.toggle('changed', on !== !!n.on);
          if (on === !!n.on) { delete PENDING[key]; markDirtyCount(); return; }
          pendingSet(key, {pane: 'about', on: on, save: function () {
            return api('console-login', {node: n.name, on: on}).then(function (r) {
              toast(r.message, 'good'); tries = 0; setTimeout(load, 2000);
              return true;
            });
          }, reset: function () { sw._input.checked = !!n.on; row.classList.remove('changed'); }});
        };
        list.appendChild(row);
      });
      if (waiting && tries++ < 30) setTimeout(load, 2000);
    }).catch(function (e) { clear(list); list.appendChild(el('p', 'note bad', String((e && e.message) || e))); });
  }
  load();
}

/* What every node runs on (1.0.99): upsmon, Python and its modules, the
   libraries under them, the pages' PHP and its extensions, nginx and the
   rest beside it - a column a node, what differs between them marked. */
function drawSoftware(host) {
  var box = el('div', 'sw-box');
  host.appendChild(box);
  box.appendChild(el('h3', 'sw-h', 'What it runs on'));
  var wait = el('p', 'muted small', 'asking…');
  box.appendChild(wait);
  api('software').then(function (d) {
    box.removeChild(wait);
    var nodes = d.nodes || [];
    var pages = d.pages || {};
    var sw = function (n, f) { var x = n.software || {}; return f(x) || ''; };
    var prog = function (k) { return function (x) { return (x.programs || {})[k]; }; };
    var mod = function (k) { return function (x) { return (x.modules || {})[k] || ''; }; };
    var rows = [
      ['upsmon', function (x) { return x.upsmon; }],
      ['group:Python'],
      ['Python', function (x) { return x.python; }],
      ['where', function (x) { return x.python_path; }],
      ['psycopg2 (PostgreSQL)', mod('psycopg2')],
      ['PyMySQL (MariaDB)', mod('pymysql')],
      ['colorama', mod('colorama')],
      ['OpenSSL (Python’s)', function (x) { return x.openssl; }],
      ['SQLite (library)', function (x) { return x.sqlite; }],
      ['group:The database'],
      ['server', function (x) { return x.database; }],
      ['pg_dump', prog('pg_dump')],
      ['mariadb-dump', prog('mariadb-dump')],
      ['group:The pages'],
      ['nginx', prog('nginx')],
      ['php-fpm', prog('php-fpm')],
      ['PHP (command line)', function (x) { return x.php_cli; }],
      ['group:The system'],
      ['system', function (x) { return x.os; }],
      ['kernel', function (x) { return x.kernel + (x.arch ? ' · ' + x.arch : ''); }],
      ['systemd', prog('systemd')],
      ['OpenSSL (system)', prog('openssl')],
      ['keepalived', prog('keepalived')],
      ['iptables', prog('iptables')],
      ['firewalld', prog('firewalld')]
    ];
    var t = el('table', 'rows sw-table');
    var th = el('thead'), hr = el('tr');
    hr.appendChild(el('th', '', ''));
    nodes.forEach(function (n) {
      var c = el('th', '');
      c.appendChild(noI18n(el('span', '', n.name)));
      if (n.me) c.appendChild(el('span', 'tag info', 'this one'));
      else if (!n.alive) c.appendChild(el('span', 'tag warn', 'not heard from'));
      hr.appendChild(c);
    });
    th.appendChild(hr); t.appendChild(th);
    var tb = el('tbody');
    rows.forEach(function (r) {
      var tr = el('tr');
      if (r[0].indexOf('group:') === 0) {
        tr.className = 'sw-group';
        var g = el('td', '', r[0].slice(6));
        g.colSpan = nodes.length + 1;
        tr.appendChild(g);
        tb.appendChild(tr);
        return;
      }
      var vals = nodes.map(function (n) { return sw(n, r[1]); });
      if (!vals.some(function (v) { return v; })) return;     /* nowhere: not shown */
      var differs = nodes.length > 1 && vals.some(function (v) { return v !== vals[0]; });
      tr.appendChild(el('td', 'k', r[0]));
      vals.forEach(function (v) {
        var c = noI18n(el('td', 'mono small' + (differs ? ' warn' : ''), v || '–'));
        if (differs) c.title = 'not the same on every node';
        tr.appendChild(c);
      });
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    box.appendChild(t);
    /* The pages: this PHP itself, as php-fpm runs it for the node that
       answered this page. */
    if (pages.php) {
      box.appendChild(el('h3', 'sw-h', 'The pages’ PHP (as php-fpm runs it here)'));
      box.appendChild(peekFacts([['PHP', pages.php], ['How', pages.sapi], ['OPcache', pages.opcache ? 'on' : 'off'],
                                 ['Web server', pages.server || '–']]));
      var ex = el('div', 'sw-ext');
      Object.keys(pages.extensions || {}).forEach(function (k) {
        var v = pages.extensions[k];
        ex.appendChild(noI18n(el('span', 'tag namepill', k + (v ? ' ' + v : ''))));
      });
      box.appendChild(el('div', 'muted small', 'Its extensions (' + num(Object.keys(pages.extensions || {}).length) + '):'));
      box.appendChild(ex);
    }
    explainWhatWasDrawn(box);
  }).catch(function (e) { wait.textContent = String(e.message || e); });
}


/* ======== upgrades (OTP admin.js 7695-8263) ======== */
/* ---- upgrades and maintenance (1.0.37) ------------------------------------ */
var UP = {timer: null, held: null, misses: 0};
var UP_STATE = {waiting: ['waiting', 'dim'], none: ['waiting', 'dim'], draining: ['taken out of service', 'warn'],
                installing: ['being put in', 'info'], checking: ['checking', 'info'],
                done: ['done', 'ok'], failed: ['failed', 'crit']};
function upgradeSend(file) {
  return bigFetch('?api=upgrade-package', file)
    .then(function (r) {
      return r.json().catch(function () {
        throw new Error('the server did not answer with anything readable (HTTP ' + r.status + ')');
      }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('the server said ' + r.status));
        return d;
      });
    });
}
/* Is this settings pane the one in front, in a tab in front (1.0.57)? The
   timers asked for their pane every 5 s after leaving Settings, and in tabs
   in the background, for as long as the page stayed open. */
function paneLive(name) {
  return TAB === 'settings' && PANE === name && $('pane-' + name) && !$('pane-' + name).hidden;
}
function upgradeAgain(ms) {
  /* Never dropped while the pane is open (1.0.73): in a tab in the
     background it waits and goes on when the tab is shown again, where
     before it stopped for good and only F5 brought it back. */
  clearTimeout(UP.timer);
  UP.timer = setTimeout(function () {
    if (!paneLive('upgrade')) return;
    if (document.hidden) { UP.sleeping = true; return; }
    loadUpgrade(true);
  }, ms);
}
document.addEventListener('visibilitychange', function () {
  if (!document.hidden && UP.sleeping) { UP.sleeping = false; if (paneLive('upgrade')) loadUpgrade(); }
});
function maintenanceAsk(n, on, then) {
  var alone = (UP.last && (UP.last.nodes || []).filter(function (x) { return x.alive; }).length) <= 1;
  if (!on) {
    api('upgrade', {action: 'maintenance', node: n.name, on: false}).then(function (r) { toast(r.message, 'good'); then(r); }).catch(oops);
    return;
  }
  modal('Take ' + n.name + ' out of service', function (body) {
    var p = el('p', 'note');
    p.textContent = alone
      ? 'While it is in maintenance the UPS, the plug and the sensors are still watched and their history kept, but nothing changes them: commands to the UPS, values set on it and the plug switched or reset are refused, and the dashboard and /api/health say maintenance. Its pages go on working.'
      : 'It is in maintenance while it is upgraded. Its pages go on working.';
    if (alone) p.className = 'note bad';
    body.appendChild(p);
    var why = textBox('', 'why - for the events', '');
    why.id = 'maint-why';
    body.appendChild(formField('Why', why));
  }, [{words: 'No, leave it', close: true},
      {words: 'Take it out', cls: alone ? 'danger' : 'primary', icon: 'power', close: true, go: function () {
        api('upgrade', {action: 'maintenance', node: n.name, on: true, why: ($('maint-why') || {}).value || ''})
          .then(function (r) { toast(r.message, 'good'); then(r); }).catch(oops);
      }}], true);
}
/* Behind the VIP address the answers come from either node, and while one
   is restarting or the address moves, the other's copy of a step may be a
   moment behind (1.0.70): what was shown is never taken back by an older
   answer - each node's step only goes forward. */
function upSteady(d) {
  var p = d && d.plan;
  if (!p) return d;
  /* A plan older than the one shown, from a node whose copy is behind
     (1.0.73): not drawn - the one shown stays. */
  if (UP.keep && UP.keep.id !== p.id && Number(p.at || 0) < Number(UP.keep.at || 0) && UP.last && UP.last.plan) {
    d.plan = UP.last.plan;
    return d;
  }
  if (!UP.keep || UP.keep.id !== p.id) UP.keep = {id: p.id, at: p.at, steps: {}};
  (p.steps || []).forEach(function (st, i) {
    var k = UP.keep.steps[st.name];
    if (k && Number(k.at || 0) > Number(st.at || 0)) p.steps[i] = k;
    else UP.keep.steps[st.name] = st;
  });
  var states = (p.steps || []).map(function (x) { return x.state; });
  if (states.indexOf('failed') >= 0) p.state = 'failed';
  else if (states.length && states.every(function (x) { return x === 'done'; })) p.state = 'done';
  return d;
}
/* New versions on the web (1.0.123): what the address had when last asked,
   and one click to put the newest in. */
function drawUpWeb(d) {
  var w = d.web || {};
  var o = w.online || {};
  liveFill($('up-web'), function (host) {
    var p = el('p', 'note ' + (o.error ? 'bad' : (o.newer ? 'good' : '')));
    if (!o.at) p.textContent = w.check ? 'Not looked at yet - within minutes, or press Look now.' : 'Not looked at: looking every day is switched off below. Look now asks once.';
    else if (o.error) p.textContent = 'Looked ' + ago(o.at) + ': ' + o.error;
    else if (o.newer) p.textContent = 'upsmon ' + o.newest.version + ' is there - this server runs ' + (o.here || d.version) + ' (looked ' + ago(o.at) + ')';
    else if (o.newest) p.textContent = 'Nothing newer: the newest there is ' + o.newest.version + ' and this server runs ' + (o.here || d.version) + ' (looked ' + ago(o.at) + ')';
    else p.textContent = 'No upsmon package there (looked ' + ago(o.at) + ')';
    host.appendChild(p);
    /* One chain above (1.0.146): the line for several newer versions sat in
       the middle of it and every case below it said the wrong thing. */
    if (o.at && !o.error && o.newer && (o.newer_list || []).length > 1) {
      host.appendChild(el('p', 'note', num(o.newer_list.length) + ' versions there are newer than this one - choose which to go to; the newest is chosen.'));
    }
    if (o.url) host.appendChild(noI18n(el('p', 'mono small muted', o.url)));
    var row = el('div', 'btnrow');
    var look = cmdButton('Look now', 'refresh', '');
    look.onclick = function () {
      busy(look, true);
      api('upgrade', {action: 'online_look'}).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
        .catch(oops).then(function () { busy(look, false); });
    };
    row.appendChild(look);
    var running = !!(d.plan && d.plan.state === 'running');
    if (o.newer && !running) {
      /* More than one newer there (1.0.142): which one, the newest chosen. */
      var list = (o.newer_list || []).filter(function (x) { return x && x.version; });
      var pick = list[0] && list[0].version === o.newest.version ? list[0] : o.newest;
      var choose = null;
      if (list.length > 1) {
        choose = selectBox(list.map(function (x, i) {
          return [x.version, x.version + (i === 0 ? ' (the newest)' : '')];
        }), pick.version);
        explain(choose, 'The versions there newer than the one this server runs. The newest is chosen; any of them can be put in instead.');
        row.appendChild(choose);
      }
      var up = cmdButton('Upgrade to ' + pick.version + ' now', 'play', 'primary');
      var chosen = function () {
        var v = choose ? choose.value : o.newest.version;
        return list.filter(function (x) { return x.version === v; })[0] || o.newest;
      };
      if (choose) {
        choose.onchange = function () {
          setButtonIcon(up, 'play', 'Upgrade to ' + chosen().version + ' now');
        };
      }
      up.onclick = function () {
        var many = (d.nodes || []).length > 1;
        var c = chosen();
        confirmThen('Upgrade to upsmon ' + c.version + '?', htmlText('It is fetched from ' + (c.url || o.url) + ', its signature checked, and '
          + (many ? 'the nodes are upgraded one at a time - each in maintenance while it is, so the service never stops.' : 'this server is upgraded: for a minute the dashboard is away.')), 'Upgrade', function () {
          busy(up, true);
          api('upgrade', {action: 'online_get', version: c.version, start: true}).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
            .catch(oops).then(function () { busy(up, false); });
        }, false);
      };
      row.appendChild(up);
      var only = cmdButton('Only fetch it', 'down', '');
      explain(only, 'Fetched and checked, and left ready below - put in when Upgrade is pressed.');
      only.onclick = function () {
        busy(only, true);
        api('upgrade', {action: 'online_get', version: chosen().version}).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
          .catch(oops).then(function () { busy(only, false); });
      };
      row.appendChild(only);
    }
    host.appendChild(row);
  });
}
/* Going back to an older version (1.0.143): asked for on purpose, in a card
   of its own - the versions at upgrade_url older than this one, each with what
   stands in its way; the database is checked against the one chosen. */
function upDownConfirm(version, go) {
  var d = UP.last || {};
  var many = (d.nodes || []).filter(function (n) { return n.alive; }).length > 1;
  confirmThen('Go back to upsmon ' + version + '?', htmlText('The version running now is replaced by the older ' + version + (many
    ? ' on every node, one at a time - each in maintenance while it is, so the service never stops.'
    : ' - for a minute the dashboard is away.') + ' The database stays as it is. What came in the newer versions is gone until you upgrade again.'),
    'Go back', go, true);
}
function upDownChangelog(version) {
  api('upgrade', {action: 'downgrade_changelog', version: version}).then(function (x) {
    var c = x.changelog || {};
    modal('What changed in ' + version, function (body) {
      if (c.from === 'package') body.appendChild(el('p', 'note small', 'Read from the package at the address - it is checked only when it is chosen.'));
      body.appendChild(c.entry ? noI18n(el('pre', 'lines', c.entry)) : el('p', 'note', 'The package says nothing about this version.'));
      if ((c.lost || []).length) {
        var det = el('details', 'fold');
        det.appendChild(el('summary', '', 'What going back gives up: ' + c.lost.length + ' newer version(s), up to ' + c.here));
        c.lost.forEach(function (one) { det.appendChild(noI18n(el('pre', 'lines', one.text))); });
        body.appendChild(det);
      }
    }, [{words: 'Close', close: true}], 'medium');
  }).catch(oops);
}
function drawUpDown(d) {
  var card = $('up-down-card');
  /* Offered only when switched on (1.0.144): Settings → Upgrades. */
  if (card) card.hidden = !(d && d.downgrade_on);
  var host = $('up-down');
  if (!host || host._made || !(d && d.downgrade_on)) return;
  host._made = true;
  var row = el('div', 'btnrow');
  var show = cmdButton('Show the versions to go back to', 'list', '');
  row.appendChild(show);
  host.appendChild(row);
  var list = el('div', '');
  host.appendChild(list);
  show.onclick = function () {
    busy(show, true);
    api('upgrade', {action: 'downgrade_list'}).then(function (x) {
      var g = x.downgrade || {};
      clear(list);
      var at = el('p', 'note small', 'At ' + (g.url || '?') + ' - this server runs ' + (g.here || '') + '; it may go back to ' + (g.lowest || g.floor || '?') + ' or newer.');
      at.style.marginTop = '10px';
      list.appendChild(at);
      var vs = g.versions || [];
      if (!vs.length) { list.appendChild(el('p', 'note', 'No version older than this one is there.')); return; }
      var running = !!((UP.last || {}).plan && UP.last.plan.state === 'running');
      var good = vs.filter(function (v) { return !(v.why || []).length; });
      var bad = vs.filter(function (v) { return (v.why || []).length; });
      /* One row a version, the buttons side by side (1.0.145): the reasons a
         version is refused are said once, folded below - not in every row. */
      var acts = function (v, ok) {
        var cell = el('div', '');
        cell.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-left:auto';
        var notes = cmdButton('What changed', 'list', 'small');
        notes.style.whiteSpace = 'nowrap';
        notes.onclick = function () { upDownChangelog(v.version); };
        cell.appendChild(notes);
        if (ok && !running) {
          var go = cmdButton('Go back to ' + v.version, 'undo', 'small danger');
          go.style.whiteSpace = 'nowrap';
          go.onclick = function () {
            upDownConfirm(v.version, function () {
              busy(go, true);
              api('upgrade', {action: 'downgrade_get', version: v.version, start: true}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); })
                .catch(oops).then(function () { busy(go, false); });
            });
          };
          cell.appendChild(go);
        }
        return cell;
      };
      /* Rows of their own, not a table (1.0.145): the version and its state on
         the left, the buttons on the right - on a narrow screen the buttons go
         below as a whole, never squeezed into a column. */
      var nowrap = function (node) {
        node.style.whiteSpace = 'nowrap';
        Array.prototype.forEach.call(node.querySelectorAll('span'), function (x) { x.style.whiteSpace = 'nowrap'; });
        return node;
      };
      var rows = function (items, ok) {
        var box = el('div', 'dg-rows');
        items.forEach(function (v) {
          var r = el('div', 'dg-row');
          r.style.cssText = 'display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 16px;padding:8px 10px;border-bottom:1px solid var(--line)';
          var left = el('div', '');
          left.style.cssText = 'display:flex;align-items:center;gap:10px;min-width:9em';
          left.appendChild(noI18n(el('b', '', v.version)));
          var tag = nowrap(el('span', ok ? 'tag ok' : 'tag warn', ok ? 'yes' : (v.short || 'no')));
          if (!ok) explain(tag, (v.why || []).join('\n'));
          left.appendChild(tag);
          r.appendChild(left);
          var right = acts(v, ok);
          Array.prototype.forEach.call(right.children, nowrap);
          r.appendChild(right);
          box.appendChild(r);
        });
        return box;
      };
      if (good.length) list.appendChild(rows(good, true));
      else list.appendChild(el('p', 'note', 'No version at the address may be gone back to.'));
      if (bad.length) {
        var det = el('details', 'fold');
        det.style.marginTop = '12px';
        det.appendChild(el('summary', '', bad.length + ' older version(s) it may not go back to' + (g.lowest ? ' - below ' + g.lowest : '')));
        var reasons = [];
        bad.forEach(function (v) { (v.why || []).forEach(function (w) { if (reasons.indexOf(w) < 0) reasons.push(w); }); });
        var why = el('ul', 'note small');
        why.style.margin = '8px 0';
        reasons.forEach(function (w) { why.appendChild(el('li', 'bad', w)); });
        det.appendChild(why);
        det.appendChild(rows(bad, false));
        list.appendChild(det);
      }
    }).catch(function (e) { clear(list); list.appendChild(el('p', 'note bad', String((e && e.message) || e))); })
      .then(function () { busy(show, false); });
  };
}
function drawUpgrade(d) {
  d = upSteady(d);
  UP.last = d;
  /* The nodes. */
  liveFill($('up-nodes'), function (host) {
  /* By name, so the rows keep their places whichever node answered (1.0.70). */
  var nodesSorted = (d.nodes || []).slice().sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
  host.appendChild(listTable(['Node', 'Version', 'Heard from', 'State', ''], nodesSorted, function (n) {
    var tr = el('tr');
    var nm = el('td');
    nm.appendChild(noI18n(el('b', '', n.name)));
    if (n.me) { nm.appendChild(document.createTextNode(' ')); nm.appendChild(el('span', 'tag info', 'this page')); }
    tr.appendChild(nm);
    tr.appendChild(noI18n(el('td', 'mono', n.version || '?')));
    tr.appendChild(el('td', 'muted', n.at ? ago(n.at) : '–'));
    var st = el('td');
    var m = n.maintenance || {};
    if (!n.alive) st.appendChild(el('span', 'tag crit', 'gone'));
    else if (m.on) st.appendChild(el('span', 'tag warn', 'in maintenance'));
    else st.appendChild(el('span', 'tag ok', 'in service'));
    if (m.on && m.why) st.appendChild(el('span', 'sub', m.why + (m.by ? ' · ' + m.by : '') + (m.at ? ' · ' + ago(m.at) : '')));
    tr.appendChild(st);
    var tools = el('td', 'rowtools');
    if (ADMIN && n.alive) {
      var b = cmdButton(m.on ? 'Back in service' : 'Maintenance', m.on ? 'play' : 'power', 'small');
      b.onclick = function (ev) { ev.stopPropagation(); maintenanceAsk(n, !m.on, drawUpgrade); };
      tools.appendChild(b);
    }
    tr.appendChild(tools);
    return tr;
  }, 'plain'));
  });
  drawUpWeb(d);
  /* The package. */
  var plan = d.plan;
  var running = !!(plan && plan.state === 'running');
  liveFill($('up-pkg'), function (pk) {
  if (d.package) {
    var p = d.package;
    var box = el('div', 'notice good');
    box.style.marginTop = '12px';
    if (p.downgrade) box.className = 'notice warn';
    box.appendChild(el('b', '', 'upsmon ' + p.version + (p.downgrade ? ' - older: ready to go back to' : '')));
    box.appendChild(el('div', 'small', 'signed by ' + (p.signed_by || '?') + ' · ' + bytes(p.bytes) + ' · sent by ' + (p.by || '?') + ' · ' + ago(p.at)));
    pk.appendChild(box);
    if (p.changelog) {
      var det = el('details', 'fold');
      det.appendChild(el('summary', '', 'What changed in ' + p.version));
      var pre = el('pre', 'lines', p.changelog);
      noI18n(pre);
      det.appendChild(pre);
      pk.appendChild(det);
    }
  }
  });
  $('up-forget').hidden = !d.package || running;
  $('up-start').disabled = !d.package || !d.ready || running;
  var many = (d.nodes || []).length > 1;
  var down = !!(d.package && d.package.downgrade);
  setButtonIcon($('up-start'), down ? 'undo' : 'play', down ? (many ? 'Go back on every node, one at a time' : 'Go back on this server')
    : (many ? 'Upgrade every node, one at a time' : 'Upgrade this server'));
  $('up-start').classList.toggle('danger', down);
  $('up-start').classList.toggle('primary', !down);
  drawUpDown(d);
  var rd = $('up-ready');
  clear(rd);
  if (d.package && !d.ready && !running) {
    (d.not_ready || []).forEach(function (w) { rd.appendChild(el('p', 'note bad', w)); });
  }
  if (!d.helper || !d.path_unit) {
    rd.appendChild(el('p', 'note bad', 'This server cannot put a version in by itself yet: upsmon-upgrade.path is not installed. Upgrade it once on the command line (install.sh --upgrade), which puts it in.'));
  }
  /* The plan. */
  $('up-plan-card').hidden = !plan;
  liveFill($('up-plan'), function (ph) {
  if (plan) {
    ph.appendChild(el('p', 'note', (plan.downgrade ? 'Going back to ' : 'To ') + plan.version + ' · started by ' + (plan.by || '?') + ' · ' + ago(plan.at) + ' · '
      + ({running: 'going on', done: 'done', failed: 'failed', cancelled: 'stopped'})[plan.state]));
    /* How far, as bars (1.0.67): the whole and each node. */
    var steps = plan.steps || [];
    var all = steps.length ? Math.round(steps.reduce(function (m, st) { return m + upPercent(st, plan); }, 0) / steps.length) : 0;
    ph.appendChild(upBar(all, plan.state === 'failed' ? 'bad' : (plan.state === 'done' ? 'good' : ''),
                         num(all) + ' % · ' + steps.filter(function (x) { return x.state === 'done'; }).length + ' of ' + steps.length + ' node(s) done', true));
    var upTable = listTable(['Node', 'Step', 'How far', 'What happened', 'When'], steps, function (st) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', st.name)));
      var w = UP_STATE[st.state] || UP_STATE.waiting;
      var c = el('td');
      c.appendChild(el('span', 'tag ' + w[1], w[0]));
      tr.appendChild(c);
      var pc = upPercent(st, plan);
      var bt = el('td', 'up-how');
      bt.appendChild(upBar(pc, st.state === 'failed' ? 'bad' : (st.state === 'done' ? 'good' : ''),
                           st.state === 'installing' && st.part_words ? num(pc) + ' % · ' + st.part_words : num(pc) + ' %'));
      tr.appendChild(bt);
      var said = el('td', 'small', st.said || '');
      if ((st.tail || []).length) {
        var more = el('details', 'fold');
        more.appendChild(el('summary', '', 'what install.sh said'));
        more.appendChild(noI18n(el('pre', 'lines', st.tail.join('\n'))));
        /* Left open across the redraws every 3 s (1.0.69). */
        UP.tailOpen = UP.tailOpen || {};
        if (UP.tailOpen[st.name]) more.open = true;
        more.ontoggle = function () { UP.tailOpen[st.name] = more.open; };
        said.appendChild(more);
      }
      tr.appendChild(said);
      tr.appendChild(el('td', 'muted', st.at ? ago(st.at) : '–'));
      return tr;
    }, 'plain');
    /* Columns of a fixed width (1.0.69): they jumped about with every redraw
       as the bars and the words in them changed. */
    (upTable.querySelector('table') || upTable).classList.add('up-plan-table');
    ph.appendChild(upTable);
    if (plan.state === 'done' && d.version !== VERSION_LOADED) {
      var r = el('p', 'note good');
      r.appendChild(document.createTextNode('This page is still the one of ' + VERSION_LOADED + '. '));
      var a = el('a', 'fgo', 'Load it again');
      a.onclick = function () { location.reload(); };
      r.appendChild(a);
      ph.appendChild(r);
    }
    if (plan.state !== 'running') ph.appendChild(hideBar(function () {
      return api('upgrade', {action: 'hide'}).then(function (x) { drawUpgrade(x); });
    }));
  }
  });
  $('up-cancel').hidden = !running;
  /* Each node's own install.sh output (1.0.70), kept as it comes - the
     answering node changes behind the VIP address, and the one card showed
     one node's, then the other's. */
  UP.logs = UP.logs || {};
  if (d.node) UP.logs[d.node] = d.log || [];
  var known = Object.keys(UP.logs).sort();
  if (!UP.logNode || !UP.logs[UP.logNode]) UP.logNode = d.node;
  var lseg = $('up-log-nodes');
  if (lseg) {
    clear(lseg);
    lseg.hidden = known.length < 2;
    known.forEach(function (nm) {
      var b = noI18n(el('button', UP.logNode === nm ? 'on' : '', nm));
      b.type = 'button';
      b.onclick = function () { UP.logNode = nm; drawUpgrade(UP.last); };
      lseg.appendChild(b);
    });
  }
  if ($('up-log-node')) $('up-log-node').textContent = UP.logNode || '';
  var lg = $('up-log');
  var lines = UP.logs[UP.logNode] || [];
  lg.textContent = lines.length ? lines.join('\n') : '–';
  noI18n(lg);
  /* Asked again every 3 s while it runs and for two minutes after it ended,
     every 15 s otherwise - so a change made on the other node, or an answer
     from a node a moment behind, is never the last word (1.0.73). */
  if (running) UP.endedAt = 0;
  else if (UP.wasRunning && !UP.endedAt) UP.endedAt = Date.now() / 1000;
  UP.wasRunning = running || (UP.wasRunning && !UP.endedAt);
  upgradeAgain(upRunning() ? 3000 : 15000);
}
/* How far one node is (1.0.67), from its step and how long it has been in
   it: waiting 0, taken out of service up to 20, install.sh 20-82 by its
   sections, checking 85-95, done 100. */
function upPercent(st, plan) {
  var now = Date.now() / 1000, since = now - Number(st.at || now);
  switch (st.state) {
    case 'done': return 100;
    case 'failed': return 100;
    case 'draining':
      return Math.round(3 + 17 * Math.min(1, since / Math.max(1, Number(plan.drain_s || 20))));
    case 'installing':
      var asked = now - Number(st.asked || st.at || now);
      return Math.round(Math.min(82, 20 + 60 * Math.min(0.95, Number(st.part || 0) / 6) + Math.min(6, asked / 15)));
    case 'checking': return Math.round(85 + Math.min(10, since / 3));
    default: return 0;
  }
}
function upBar(pc, kind, words, wide) {
  var box = el('div', 'going up-bar' + (wide ? ' wide' : '') + (kind ? ' ' + kind : ''));
  var bar = el('div', 'bar');
  var fill = el('span', '');
  fill.style.width = Math.max(0, Math.min(100, pc)) + '%';
  bar.appendChild(fill);
  box.appendChild(bar);
  if (words) box.appendChild(wide ? el('div', 'says', words) : noI18n(el('div', 'says', words)));
  return box;
}
/* The version these pages came with: what the script was asked for as. */
var VERSION_LOADED = (function () {
  var sc = document.querySelector('script[src*="admin.js"]');
  var m = sc && /[?&]v=([0-9.]+)/.exec(sc.getAttribute('src') || '');
  return m ? m[1] : '';
}());
function loadUpgrade(live) {
  /* A short deadline while an upgrade runs (1.0.66): the node answering may
     be restarting, or the VIP address moving to the other one. */
  var running = upRunning();
  clearTimeout(UP.timer);
  var mine = UP.ask = (UP.ask || 0) + 1;
  api('upgrade', undefined, running ? 8 : 0).then(function (d) {
    if (mine !== UP.ask) return;          /* a newer question is on its way */
    UP.misses = 0;
    if ($('up-retry')) $('up-retry').textContent = '';
    if (!VERSION_LOADED) VERSION_LOADED = d.version;
    if (live) liveRun(function () { drawUpgrade(d); }); else drawUpgrade(d);
  }).catch(function (e) {
    if (mine !== UP.ask) return;
    /* The node that answers these pages may be the one being restarted, or
       the VIP address may be moving to the other node: asked again, always
       (1.0.73) - not only while the last answer said "running", and without
       a limit. Said once, in a line of its own that is always there. */
    UP.misses = (UP.misses || 0) + 1;
    if (running || e.unreachable || UP.misses <= 3) {
      if ($('up-retry')) $('up-retry').textContent = ('A node is restarting or the VIP address is moving to the other node - asking again…');
      upgradeAgain(Math.min(2000 * UP.misses, 6000));
      return;
    }
    oops(e);
    upgradeAgain(15000);
  });
}
/* Whether an upgrade is under way, as far as this page knows (1.0.73): the
   plan says so, or a step is not finished, or it ended a short while ago -
   behind the VIP address the next answer may come from the node whose copy
   is a moment behind. */
function upRunning() {
  var p = UP.last && UP.last.plan;
  if (!p) return false;
  if (p.state === 'running') return true;
  if ((p.steps || []).some(function (st) { return st.state !== 'done' && st.state !== 'failed' && st.state !== 'cancelled' && st.state !== 'skipped'; })
      && p.state !== 'cancelled' && p.state !== 'failed') return true;
  return Date.now() / 1000 - Number(UP.endedAt || 0) < 120;
}
if ($('up-drop')) {
  (function () {
    var box = $('up-drop');
    var sending = false;
    function send(file) {
      if (!file || sending) return;     /* chosen twice: sent once (1.0.94) */
      sending = true;
      $('up-drop-says').textContent = 'checking ' + file.name + ' (' + bytes(file.size) + ')…';
      upgradeSend(file).then(function (d) {
        sending = false;
        toast(d.message || 'checked', 'good');
        $('up-drop-says').textContent = 'Drop the upsmon-X.Y.Z.tar.gz here, or press to choose it';
        drawUpgrade(d);
      }).catch(function (e) {
        sending = false;
        $('up-drop-says').textContent = 'Drop the upsmon-X.Y.Z.tar.gz here, or press to choose it';
        modal('The package was not taken', function (body) {
          body.appendChild(el('p', 'note bad', String(e.message || e)));
        }, null, true);
      });
    }
    box.onclick = function () { $('up-file').click(); };
    $('up-file').onchange = function () { send(this.files && this.files[0]); this.value = ''; };
    ['dragenter', 'dragover'].forEach(function (name) {
      box.addEventListener(name, function (e) { e.preventDefault(); box.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (name) {
      box.addEventListener(name, function (e) {
        e.preventDefault();
        box.classList.remove('over');
        if (name === 'drop' && e.dataTransfer && e.dataTransfer.files) send(e.dataTransfer.files[0]);
      });
    });
    $('up-start').onclick = function () {
      var d = UP.last || {};
      var p = d.package || {};
      var names = (d.nodes || []).filter(function (n) { return n.alive; }).map(function (n) { return n.name; });
      var many = names.length > 1;
      if (p.downgrade) { upDownConfirm(p.version, function () {
        api('upgrade', {action: 'start'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
      }); return; }
      confirmThen(many ? 'Upgrade every node to ' + p.version : 'Upgrade this server to ' + p.version,
        many ? 'One node at a time: it is taken out of service, upgraded, checked and brought back, and only then the next one. The VPN and the load balancer use the other node meanwhile.'
             : 'This server is the only one: while it is put in and restarted - a minute or two - the dashboard is away, and these pages stop answering for a moment.',
        'Upgrade', function () {
          api('upgrade', {action: 'start'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
        }, !many);
    };
    $('up-forget').onclick = function () {
      confirmThen('Throw the package away', 'The uploaded package is deleted; upload it again to upgrade.', 'Throw it away', function () {
        api('upgrade', {action: 'forget'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
      });
    };
    $('up-cancel').onclick = function () {
      confirmThen('Stop the upgrade', 'A node being put in right now is finished; the ones not begun stay as they are.', 'Stop it', function () {
        api('upgrade', {action: 'cancel'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
      });
    };
  }());
}


/* ======== certificates and TLS (OTP admin.js 8264-8944) ======== */
/* ==========================================================================
   Certificates and the VIP address (1.0.47)
   ========================================================================== */
var WEB = {last: null, timer: null};
function loadWeb() {
  loadPush();
  apiLatest('web', 'web').then(drawWeb).catch(oops);
  clearInterval(WEB.timer);
  WEB.timer = setInterval(function () {
    if (!paneLive('web')) { clearInterval(WEB.timer); return; }
    if (document.hidden) return;
    if ($('modal') && !$('modal').hidden) return;
    apiLatest('web', 'web').then(function (d) { liveRun(function () { drawWeb(d); }); }).catch(function () {});
  }, 5000);
}
function daysLeft(ts) { return ts ? Math.floor((ts - Date.now() / 1000) / 86400) : null; }
function certTone(days) { return days === null ? 'dim' : (days < 0 ? 'crit' : (days < 21 ? 'warn' : 'ok')); }
function webTargetWords(t) { return t === 'vip' ? 'the VIP address' : t; }

function certCard(d, target) {
  var prof = d.tls[target];
  var node = (d.nodes || []).filter(function (n) { return n.name === target; })[0];
  var w = target === 'vip' ? null : ((node || {}).web || {});
  var info = (prof && prof.info) || (w && w.cert_now) || null;
  if (target === 'vip' && !info) {
    var holder = (d.nodes || []).filter(function (n) { return (n.web || {}).vip_cert_now; })[0];
    if (holder && prof) info = holder.web.vip_cert_now;
  }
  var card = el('section', 'cert-card');
  var head = el('header', 'cert-h');
  var title = el('div', 'cert-title');
  title.appendChild(el('span', 'cert-target', target === 'vip' ? 'The VIP address of the cluster' : 'Node'));
  title.appendChild(noI18n(el('b', '', target === 'vip' ? (d.vip.fqdn || d.vip.address || '–') : target)));
  if (target === 'vip') {
    /* Said plainly what this card is (1.0.50). */
    title.appendChild(el('span', 'cert-for', d.vip.address
      ? 'the certificate answered on the VIP ' + String(d.vip.address).split('/')[0] + ', whichever node holds it'
      : 'the certificate of the VIP - the address is set on Settings → High availability'));
  }
  if (node && node.me) title.appendChild(el('span', 'tag dim', 'this one'));
  if (target !== 'vip') {
    /* The same line under every name, so the cards stand level (1.0.51). */
    title.appendChild(el('span', 'cert-for', 'the certificate answered on ' + target + '\'s own name and address' +
      (node && node.address ? ' (' + node.address + ')' : '')));
  }
  head.appendChild(title);
  var days = info ? daysLeft(info.not_after) : null;
  var badge = el('span', 'tag ' + certTone(days), days === null ? 'no certificate' :
    (days < 0 ? 'ran out' : (days < 21 ? days + ' days left' : 'valid')));
  head.appendChild(badge);
  card.appendChild(head);
  if (info) {
    var b = el('div', 'cert-body');
    b.appendChild(noI18n(el('div', 'cert-cn', info.cn || info.subject || '')));
    var bar = el('div', 'cert-life');
    var span = info.not_after && info.not_before ? (info.not_after - info.not_before) : 1;
    var used = info.not_before ? Math.max(0, Math.min(1, (Date.now() / 1000 - info.not_before) / span)) : 0;
    var fill = el('span', 'cert-life-fill ' + certTone(days));
    fill.style.width = Math.round(used * 100) + '%';
    bar.appendChild(fill);
    b.appendChild(bar);
    var facts = [['Issued by', noI18n(el('span', '', info.self_signed ? 'itself (self-signed)' : (info.issuer || '').replace(/^CN=/, '')))],
                 ['Valid until', info.not_after ? stamp(info.not_after) : '–'],
                 ['Key', (info.key || '–') + (prof && prof.alt && prof.alt.info && prof.alt.info.key ? ' + ' + prof.alt.info.key + ' (a second certificate beside it)' : '')]];
    if (info.san && info.san.length) facts.push(['Names', noI18n(el('span', '', info.san.join(', ')))]);
    if (prof) {
      facts.push(['Chain', prof.chain_info ? (prof.chain_info.length + ' between it and the root') : '–']);
      facts.push(['Root', prof.root_info && prof.root_info.length ? noI18n(el('span', '', prof.root_info[0].cn || 'given')) : 'not given']);
      if (prof.verify) facts.push(['Checked', prof.verify === 'ok' ? el('span', 'good', 'the chain leads to the root') : el('span', 'bad', prof.verify)]);
    }
    var kv = el('dl', 'cert-kv');
    facts.forEach(function (f) {
      kv.appendChild(el('dt', '', f[0]));
      var dd = el('dd');
      if (f[1] && f[1].nodeType) dd.appendChild(f[1]); else dd.textContent = f[1];
      kv.appendChild(dd);
    });
    b.appendChild(kv);
    card.appendChild(b);
  } else {
    card.appendChild(el('p', 'note', target === 'vip'
      ? 'None of its own: the VIP address answers with the certificate of the node it is on.'
      : 'Not known yet.'));
  }
  /* How TLS is spoken, as chips. */
  var chips = el('div', 'cert-chips');
  var preset = (prof && prof.preset) || 'standard';
  chips.appendChild(el('span', 'cchip', {standard: 'TLS 1.2 + 1.3, ECDHE', intermediate: 'Mozilla intermediate', modern: 'TLS 1.3 only', custom: 'custom'}[preset] || preset));
  if (prof && prof.dh && prof.dh !== 'none') chips.appendChild(noI18n(el('span', 'cchip', 'DH ' + prof.dh)));
  if (prof && prof.hsts) chips.appendChild(el('span', 'cchip', 'HSTS ' + Math.round(prof.hsts / 86400) + ' days'));
  if (prof && prof.pending) chips.appendChild(el('span', 'cchip warn', 'a request waits for its certificate'));
  /* Automatic certificates beside it (1.0.170): who renews this one. */
  var ac = d.acme || {};
  if (ac.on) {
    var acare = (ac.care || {})[target];
    var ach = el('span', 'cchip' + (acare ? '' : ' dim'), acare ? 'renewed by ACME' : 'ACME leaves it alone');
    explain(ach, acare ? 'Settings → Automatic certificates renews it before it runs out. Uploading one here, or making one self-signed, takes it out of ACME’s care - it is kept as it is.'
      : 'Kept as it is: Automatic certificates does not replace it (Look after it there gives it to ACME).');
    ach.style.cursor = 'pointer';
    ach.onclick = function () { location.hash = '#settings/acme'; };
    chips.appendChild(ach);
    var ast = (ac.state || {})[target] || {};
    if (acare && ast.ok === false && ast.said) chips.appendChild(el('span', 'cchip warn', 'the last order failed'));
  }
  if (!prof && target !== 'vip') chips.appendChild(el('span', 'cchip dim', 'as install.sh made it'));
  card.appendChild(chips);
  /* Is it in place on the node? */
  if (target === 'vip' && prof && d.vip && d.vip.on) {
    /* The VIP address's certificate is put in on every node (1.0.51). */
    (d.nodes || []).forEach(function (n) {
      var nw = n.web || {};
      if (nw.progress) { card.appendChild(certProgress(nw.progress, n.name)); return; }
      var st2 = el('div', 'cert-state');
      st2.appendChild(el('span', 'dot ' + (nw.state === 'failed' ? 'crit' : (nw.current ? 'ok' : 'warn'))));
      st2.appendChild(el('span', '', nw.state === 'failed' ? n.name + ': ' + ((nw.said || []).slice(-1)[0] || 'failed')
        : (nw.current ? 'in place on ' + n.name : 'being put in on ' + n.name + '…')));
      card.appendChild(st2);
    });
  } else if (target === 'vip' && prof && d.vip && !d.vip.on) {
    card.appendChild(el('p', 'note small', 'Put in on the nodes once the VIP address is turned on (Settings → High availability).'));
  }
  if (target !== 'vip' && w && w.progress) {
    card.appendChild(certProgress(w.progress, target));
  } else if (prof && target !== 'vip' && w) {
    var st = el('div', 'cert-state');
    st.appendChild(el('span', 'dot ' + (w.state === 'failed' ? 'crit' : (w.current ? 'ok' : 'warn'))));
    st.appendChild(el('span', '', w.state === 'failed' ? 'root could not put it in: ' + ((w.said || []).slice(-1)[0] || '')
      : (w.current ? 'in place on ' + target : 'being put in on ' + target + '…')));
    card.appendChild(st);
  }
  if (d.may) {
    var tools = el('div', 'cert-tools');
    /* Put in by hand while ACME renews it (1.0.170): said first - it leaves
       ACME's care, or ACME would replace it at its next renewal. */
    var byHand = function (go) {
      if (!(d.acme && d.acme.on && (d.acme.care || {})[target])) { go(); return; }
      confirmThen('ACME renews this certificate', 'One put in here by hand takes ' + webTargetWords(target)
        + ' out of ACME’s care: it is kept as it is, not replaced at the next renewal. Settings → Automatic certificates → Look after it gives it back.', 'Go on',go, false);
    };
    var up = cmdButton('Upload', 'upload', 'small');
    up.onclick = function () { byHand(function () { certUpload(target, prof); }); };
    tools.appendChild(up);
    var req = cmdButton(prof && prof.pending ? 'The waiting request' : 'Request (CSR)', 'list', 'small');
    req.onclick = function () { certRequest(target, prof); };
    tools.appendChild(req);
    var ss = cmdButton('Self-signed', 'key', 'small');
    ss.onclick = function () { byHand(function () { certSelf(target, d); }); };
    tools.appendChild(ss);
    var pol = cmdButton('TLS settings', 'gear', 'small');
    pol.onclick = function () { certPolicy(target, prof, d); };
    /* Whoever gave the certificate - ACME too - its protocols, ciphers, DH
       and HSTS are set here and kept when it is renewed (1.0.172). */
    explain(pol, 'The protocols, the ciphers, the DH parameters and HSTS of ' + webTargetWords(target) + ' - kept as they are whichever way the certificate came, ACME and its renewals too.');
    tools.appendChild(pol);
    var bef = (d.acme && d.acme.before || {})[target];
    if (bef && !bef.ran_out) tools.appendChild(acmePutBackButton(target, bef, function () { loadWeb(); }));
    if (prof && prof.cert) {
      var dl = cmdButton('Download', 'download', 'small');
      dl.title = 'The certificate in the format you choose - PEM, DER, PFX / PKCS#12 - with its private key and a password, or without';
      dl.onclick = function () { certExport(target, prof); };
      tools.appendChild(dl);
      var fg = cmdButton('Let go', 'forget', 'small danger-soft');
      fg.title = 'upsmon stops looking after it (nginx keeps what it has)';
      fg.onclick = function () {
        confirmThen('Stop looking after the TLS of ' + webTargetWords(target), 'nginx keeps the files it has now; upsmon no longer changes them.', 'Stop', function () {
          api('web', {action: 'tls_forget', target: target}).then(function (x) { toast(x.message, 'good'); loadWeb(); }).catch(oops);
        });
      };
      tools.appendChild(fg);
    }
    card.appendChild(tools);
  }
  return card;
}

/* What root is doing on a node, as a bar (1.0.50): the steps done, and in
   the long one - making DH parameters - the time gone against the time it
   usually takes (never shown as more than 95 % before it is done). */
function certProgress(p, target) {
  var box = el('div', 'cert-prog');
  var total = Number(p.total) || 6, step = Math.max(1, Number(p.step) || 1);
  var gone = Math.max(0, (Number(p.now) || 0) - (Number(p.at) || 0));
  var part = p.expect_s ? Math.min(0.95, gone / Number(p.expect_s)) : 0.5;
  var pct = Math.min(99, Math.round(((step - 1) + part) / total * 100));
  var head = el('div', 'cert-prog-h');
  head.appendChild(el('span', '', p.words || 'working'));
  head.appendChild(noI18n(el('b', '', pct + ' %')));
  box.appendChild(head);
  var bar = el('div', 'cert-prog-bar');
  var fill = el('span', '');
  fill.style.width = pct + '%';
  bar.appendChild(fill);
  box.appendChild(bar);
  var mm = function (sec) { sec = Math.round(sec); return Math.floor(sec / 60) + ':' + ('0' + (sec % 60)).slice(-2); };
  box.appendChild(el('div', 'cert-prog-s', p.expect_s
    ? 'on ' + target + ' - ' + mm(gone) + ' so far, usually about ' + Math.round(p.expect_s / 60 || 1) + ' min'
    : 'on ' + target + ' - step ' + step + ' of ' + total));
  return box;
}

/* Files read in the browser: PEM as text, a PFX as base64. */
function readCertFiles(files) {
  return Promise.all(Array.prototype.map.call(files, function (f) {
    return new Promise(function (ok, bad) {
      if (f.size > 200000) { bad(new Error(f.name + ' is far bigger than any certificate file')); return; }
      var r = new FileReader();
      r.onload = function () {
        var bytesArr = new Uint8Array(r.result);
        var head = String.fromCharCode.apply(null, bytesArr.slice(0, Math.min(bytesArr.length, 4096)));
        if (bytesArr[0] === 0x50 && bytesArr[1] === 0x4b && bytesArr[2] === 0x03 && bytesArr[3] === 0x04) {
          var zb = '';
          for (var zi = 0; zi < bytesArr.length; zi++) zb += String.fromCharCode(bytesArr[zi]);
          ok({name: f.name, zip: btoa(zb)});
        } else if (/-----BEGIN /.test(head) || /-----BEGIN /.test(new TextDecoder().decode(bytesArr))) {
          ok({name: f.name, pem: new TextDecoder().decode(bytesArr)});
        } else {
          var bin = '';
          for (var i = 0; i < bytesArr.length; i++) bin += String.fromCharCode(bytesArr[i]);
          ok({name: f.name, pfx: btoa(bin)});
        }
      };
      r.onerror = function () { bad(new Error(f.name + ' could not be read')); };
      r.readAsArrayBuffer(f);
    });
  }));
}

var CERT_PASTE_HINT = '-----BEGIN CERTIFICATE-----\n' +
  '1. the certificate of this name (the server\'s own)\n' +
  '-----END CERTIFICATE-----\n' +
  '-----BEGIN CERTIFICATE-----\n' +
  '2. the intermediate certificate(s), if there are any - one block each\n' +
  '-----END CERTIFICATE-----\n' +
  '-----BEGIN CERTIFICATE-----\n' +
  '3. the root certificate (optional)\n' +
  '-----END CERTIFICATE-----\n' +
  '-----BEGIN PRIVATE KEY-----\n' +
  '4. its private key (not needed when the request was made here)\n' +
  '-----END PRIVATE KEY-----\n\n' +
  'Any order is taken: they are sorted by themselves.';
function certUpload(target, prof) {
  var got = [];
  modal('A certificate for ' + webTargetWords(target), function (body) {
    body.appendChild(el('p', 'note', 'PEM files - the certificate, its key, the chain, the root, in any order or all in one - or one PFX / PKCS#12 file. A dual certificate is taken whole - the RSA one and its ECDSA twin for the same names, each with its key - in PEM, as two PFX files with the same password, or as the .zip Download → Both gave. ' +
      (prof && prof.pending ? 'A request waits here: the certificate the authority sent back is enough, its key is here.' : 'The key has to come with it.')));
    var drop = el('div', 'drop');
    var inp = el('input'); inp.type = 'file'; inp.multiple = true; inp.hidden = true;
    inp.accept = '.pem,.crt,.cer,.key,.pfx,.p12,.chain,.ca,.txt,.zip';
    var says = el('span', '', 'Drop the files here, or press to choose them');
    drop.appendChild(inp); drop.appendChild(says);
    var list = el('div', 'cert-files');
    function take(files) {
      readCertFiles(files).then(function (r) {
        got = got.concat(r);
        clear(list);
        got.forEach(function (x) { list.appendChild(noI18n(el('span', 'cchip', x.name + (x.zip ? ' (ZIP)' : x.pfx ? ' (PFX)' : ' (PEM)')))); });
        says.textContent = 'Read: ' + got.length + ' file(s). More can be added.';
      }).catch(oops);
    }
    drop.onclick = function () { inp.click(); };
    inp.onchange = function () { take(inp.files); inp.value = ''; };
    drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', function () { drop.classList.remove('over'); });
    drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('over'); take(e.dataTransfer.files); });
    body.appendChild(drop);
    body.appendChild(list);
    var paste = el('textarea', 'mono cert-paste');
    paste.id = 'cu-paste';
    paste.rows = 16;
    /* The usual order shown in the box itself (1.0.50); any order is taken. */
    paste.placeholder = CERT_PASTE_HINT;
    paste.spellcheck = false;
    body.appendChild(formField('Or paste PEM here', paste));
    var pw = secretBox('', 'only for a PFX or a key with a passphrase', 'mono');
    pw.id = 'cu-pw';
    body.appendChild(formField('Password', pw, 'Used here to open it, and not kept.'));
    body.appendChild(el('div', 'said', '')).id = 'cu-said';
  }, [{words: 'Cancel', close: true},
      {words: 'Put it in', cls: 'primary', icon: 'save', go: function (b) {
        var pem = got.filter(function (x) { return x.pem; }).map(function (x) { return x.pem; }).join('\n') + '\n' + ($('cu-paste').value || '');
        var pfx = got.filter(function (x) { return x.pfx; });
        var zips = got.filter(function (x) { return x.zip; });
        if (zips.length > 1) { toast('one .zip at a time', 'bad'); return; }
        if (pfx.length > 2) { toast('two PFX / PKCS#12 files at most - a dual certificate: RSA and ECDSA', 'bad'); return; }
        if (!pfx.length && !zips.length && !/-----BEGIN /.test(pem)) { toast('choose the files first, or paste the PEM', 'bad'); return; }
        busy(b, true);
        api('web', {action: 'tls_upload', target: target, cert: pem, pfx: pfx.length ? pfx[0].pfx : '', pfx2: pfx.length > 1 ? pfx[1].pfx : '', zip: zips.length ? zips[0].zip : '',
                    password: ($('cu-pw') || {}).value || ''}).then(function (x) {
          toast(x.message, 'good'); closeModal(); loadWeb();
        }).catch(function (e) { $('cu-said').className = 'said bad'; $('cu-said').textContent = e.message; }).then(function () { busy(b, false); });
      }}], 'medium');
}

function certNamesDefault(target, d) {
  if (target === 'vip') return d.vip.fqdn || '';
  var n = (d.nodes || []).filter(function (x) { return x.name === target; })[0];
  return n && /\./.test(n.host || '') ? n.host : '';
}
function certSubjectFields(body, target, d, withDays) {
  var g = el('div', 'formgrid');
  var cn = textBox(certNamesDefault(target, d), 'upsmon.example.cz', 'mono'); cn.id = 'cs-cn';
  var names = textBox('', 'otp1.example.cz, 192.0.2.11', 'mono'); names.id = 'cs-names';
  var kind = selectBox([['rsa2048', 'RSA 2048'], ['rsa3072', 'RSA 3072'], ['rsa4096', 'RSA 4096'], ['ec', 'EC P-256']], 'rsa2048'); kind.id = 'cs-kind';
  g.appendChild(formField('The name (CN)', cn, 'What people type in the browser.'));
  g.appendChild(formField('Other names', names, 'More names or addresses it is good for, by commas.'));
  g.appendChild(formField('The key', kind));
  var org = textBox('', 'Krajský úřad'); org.id = 'cs-org';
  g.appendChild(formField('Organisation', org));
  if (withDays) {
    var days = selectBox([['365', '1 year'], ['825', '27 months'], ['1825', '5 years'], ['3650', '10 years']], '825'); days.id = 'cs-days';
    g.appendChild(formField('Valid for', days));
  } else {
    var unit = textBox('', 'IT'); unit.id = 'cs-unit';
    var city = textBox('', 'Olomouc'); city.id = 'cs-city';
    var country = textBox('CZ', 'CZ'); country.id = 'cs-country'; country.maxLength = 2;
    g.appendChild(formField('Unit', unit));
    g.appendChild(formField('City', city));
    g.appendChild(formField('Country', country));
  }
  body.appendChild(g);
}
function certSubjectValues() {
  var v = function (id) { return ($(id) || {}).value || ''; };
  return {cn: v('cs-cn').trim(), names: v('cs-names'), kind: v('cs-kind'), org: v('cs-org'),
          unit: v('cs-unit'), city: v('cs-city'), country: v('cs-country'), days: v('cs-days')};
}

function certRequest(target, prof) {
  if (prof && prof.pending && prof.csr) { showCsr(target, prof.csr, prof); return; }
  modal('A certificate request for ' + webTargetWords(target), function (body) {
    body.appendChild(el('p', 'note', 'A new key is made here and stays here; the request (CSR) goes to your certificate authority. Upload what it sends back - the certificate alone is enough.'));
    certSubjectFields(body, target, WEB.last || {vip: {}}, false);
  }, [{words: 'Cancel', close: true},
      {words: 'Make the request', cls: 'primary', icon: 'list', go: function (b) {
        busy(b, true);
        api('web', Object.assign({action: 'tls_csr', target: target}, certSubjectValues())).then(function (x) {
          closeModal(); loadWeb(); showCsr(target, x.csr, x.tls);
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}
function showCsr(target, csr, prof) {
  modal('The request for ' + webTargetWords(target), function (body) {
    body.appendChild(el('p', 'note', 'Give this to your certificate authority. The key waits here; once the certificate comes back, upload it.'));
    var pre = noI18n(el('pre', 'mono cert-csr', csr));
    copyOnClick(pre, csr, 'the request was copied');
    body.appendChild(pre);
  }, [{words: 'Drop the request', icon: 'trash', go: function () {
        modalOver(function () { confirmThen('Drop the request', 'Its waiting key goes too; a certificate made for it can then not be used.', 'Drop it', function () {
          api('web', {action: 'tls_csr_drop', target: target}).then(function (x) { toast(x.message, 'good'); loadWeb(); }).catch(oops);
        }, true); });
      }},
      {words: 'Download .csr', icon: 'download', go: function () { saveFile((target === 'vip' ? 'web-address' : target) + '.csr', csr); }},
      {spacer: true},
      {words: 'Upload the certificate…', cls: 'primary', icon: 'upload', go: function () { closeModal(); certUpload(target, {pending: true}); }},
      {words: 'Close', close: true}], 'medium');
}

function certSelf(target, d) {
  modal('A self-signed certificate for ' + webTargetWords(target), function (body) {
    body.appendChild(el('p', 'note warn', 'Browsers warn about a self-signed certificate until it is trusted by hand. Good for a test, or until the real one comes.'));
    certSubjectFields(body, target, d, true);
  }, [{words: 'Cancel', close: true},
      {words: 'Make it and put it in', cls: 'primary', icon: 'key', go: function (b) {
        busy(b, true);
        api('web', Object.assign({action: 'tls_selfsigned', target: target}, certSubjectValues())).then(function (x) {
          toast(x.message, 'good'); closeModal(); loadWeb();
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}

function certPolicy(target, prof, d) {
  prof = prof || {};
  var st = {preset: prof.preset || 'standard',
            protocols: (prof.protocols || ['TLSv1.2', 'TLSv1.3']).slice(),
            ciphers: prof.ciphers || (d.presets.standard || {}).ciphers || '',
            dh: prof.dh || 'none', prefer: !!prof.prefer, hsts: (prof.hsts === undefined || prof.hsts === null || prof.hsts === '') ? 63072000 : Number(prof.hsts)};
  var PRESETS = [
    ['standard', 'Standard', 'TLS 1.2 + 1.3', 'ECDHE with AES-GCM and ChaCha20. Every browser of the last ten years.', 'recommended'],
    ['intermediate', 'Mozilla intermediate', 'TLS 1.2 + 1.3', 'Adds the DHE ciphers, for old clients. Wants DH parameters.', ''],
    ['modern', 'Mozilla modern', 'TLS 1.3 only', 'The strongest; old systems and some scanners cannot connect.', ''],
    ['custom', 'Custom', 'chosen here', 'The protocols and an OpenSSL cipher list of your own.', '']];
  modal('How ' + webTargetWords(target) + ' speaks TLS', function (body) {
    /* The protocols and ciphers: one tile each. */
    body.appendChild(el('h4', 'tls-h', 'Protocols and ciphers'));
    var tiles = el('div', 'tls-tiles');
    var custom = el('div', 'tls-custom');
    var used = el('details', 'tls-used');
    function paint() {
      Array.prototype.forEach.call(tiles.children, function (t) { t.classList.toggle('on', t.dataset.k === st.preset); });
      custom.hidden = st.preset !== 'custom';
      used.hidden = st.preset === 'custom';
      var p = d.presets[st.preset];
      if (p) {
        clear(used);
        used.appendChild(el('summary', '', 'The ciphers it uses'));
        used.appendChild(noI18n(el('code', 'tls-cipherlist', p.ciphers ? p.ciphers.split(':').join('\n') : 'TLS 1.3 chooses its own: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256')));
      }
      dhRow.classList.toggle('dim', st.preset === 'modern' || (st.preset === 'standard' && st.dh === 'none'));
    }
    PRESETS.forEach(function (p) {
      var t = el('button', 'tls-tile');
      t.type = 'button';
      t.dataset.k = p[0];
      var top = el('div', 'tls-tile-top');
      top.appendChild(el('b', '', p[1]));
      if (p[4]) top.appendChild(el('span', 'tag ok', p[4]));
      t.appendChild(top);
      t.appendChild(el('div', 'tls-tile-prot', p[2]));
      t.appendChild(el('div', 'tls-tile-s', p[3]));
      t.onclick = function () { st.preset = p[0]; paint(); };
      if (hsOn('web:tls') && (p[0] === 'intermediate' || p[0] === 'custom')) { t.disabled = true; t.appendChild(el('div', 'small hs-note', 'not under high security')); }
      tiles.appendChild(t);
    });
    body.appendChild(tiles);
    /* Custom: the protocols as switches, the cipher list. */
    var prow = el('div', 'tls-prot');
    ['TLSv1.2', 'TLSv1.3'].forEach(function (v) {
      var b = el('button', 'tls-pill');
      b.type = 'button';
      b.textContent = v.replace('TLSv', 'TLS ');
      noI18n(b);
      var sync = function () { b.classList.toggle('on', st.protocols.indexOf(v) >= 0); };
      b.onclick = function () {
        var i = st.protocols.indexOf(v);
        if (i >= 0 && st.protocols.length > 1) st.protocols.splice(i, 1); else if (i < 0) st.protocols.push(v);
        sync();
      };
      sync();
      prow.appendChild(b);
    });
    custom.appendChild(el('div', 'tls-sub', 'Protocols'));
    custom.appendChild(prow);
    var ciphers = el('textarea', 'mono tls-ciphers');
    ciphers.rows = 4; ciphers.spellcheck = false; ciphers.value = st.ciphers;
    ciphers.oninput = function () { st.ciphers = ciphers.value; };
    custom.appendChild(el('div', 'tls-sub', 'Ciphers for TLS 1.2 (an OpenSSL list; TLS 1.3 chooses its own)'));
    custom.appendChild(ciphers);
    body.appendChild(custom);
    body.appendChild(used);
    /* The rest, row by row. */
    body.appendChild(el('h4', 'tls-h', 'More'));
    var rows = el('div', 'tls-rows');
    var dh = selectBox(Object.keys(d.dh).map(function (k) { return [k, d.dh[k]]; }), st.dh);
    dh.onchange = function () { st.dh = dh.value; paint(); };
    var dhRow = tlsRow('DH parameters', 'Only the DHE ciphers use them (Mozilla intermediate, or your own). An RFC 7919 group is ready at once; made here takes from seconds to minutes.', dh);
    rows.appendChild(dhRow);
    var prefer = switchBox(st.prefer);
    prefer._input.onchange = function () { st.prefer = !!prefer._get(); };
    rows.appendChild(tlsRow('The server chooses the cipher', 'Off is right for these lists: every cipher in them is strong, and the client knows best which is fast for it.', prefer));
    var seg = el('div', 'seg');
    [[0, 'off'], [15768000, '6 months'], [31536000, '1 year'], [63072000, '2 years']].forEach(function (o) {
      var b = el('button', '', o[1]);
      b.type = 'button';
      b.onclick = function () { st.hsts = o[0]; Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); }); };
      if (st.hsts === o[0]) b.classList.add('on');
      seg.appendChild(b);
    });
    if (!seg.querySelector('.on')) seg.children[0].classList.add('on');
    rows.appendChild(tlsRow('HSTS', 'A browser that saw it comes back only over HTTPS for that long. Turn it on once HTTPS is surely staying.', seg));
    body.appendChild(rows);
    paint();
  }, [{words: 'Cancel', close: true},
      {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
        busy(b, true);
        api('web', {action: 'tls_policy', target: target, preset: st.preset, protocols: st.protocols,
                    ciphers: String(st.ciphers || '').trim(), dh: st.dh, prefer: st.prefer ? 1 : 0,
                    hsts: st.hsts}).then(function (x) {
          toast(x.message, 'good'); closeModal(); loadWeb();
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}
function tlsRow(words, says, control) {
  var row = el('div', 'arow');
  var t = el('div', 'arow-t');
  t.appendChild(el('div', 'arow-k', words));
  t.appendChild(el('div', 'arow-s', says));
  row.appendChild(t);
  var c = el('div', 'arow-c');
  c.appendChild(control);
  row.appendChild(c);
  return row;
}

function drawWeb(d) {
  WEB.last = d;
  var host = $('web-certs');
  liveFill(host, function (host) {
  Object.keys(d.tls).forEach(function (t) {
    if (t === 'vip' && !d.cluster) return;
    host.appendChild(certCard(d, t));
  });
  }, undefined, function () { explainWhatWasDrawn($('pane-web')); });
}

/* The VIP address lives on the High availability pane (1.0.49), kept up to
   date there every five seconds while it is open. */
var VIP_TIMER = null;
function loadVip(live) {
  if (!$('web-vip')) return;
  apiLatest('vip', 'web').then(function (d) { WEB.last = d; if (live) liveRun(function () { drawVip(d); }); else drawVip(d); explainWhatWasDrawn($('ha-vip-card')); }).catch(oops);
  clearInterval(VIP_TIMER);
  VIP_TIMER = setInterval(function () {
    if (!paneLive('ha')) { clearInterval(VIP_TIMER); return; }
    if (document.hidden) return;
    if ($('modal') && !$('modal').hidden) return;
    apiLatest('vip', 'web').then(function (d) { WEB.last = d; liveRun(function () { drawVip(d); }); explainWhatWasDrawn($('ha-vip-card')); }).catch(function () {});
  }, 5000);
}
var VIPD = null;
function vipFromServer(v, d) {
  var names = (d.nodes || []).map(function (n) { return n.name; });
  return {address: v.address || '', address6: v.address6 || '', fqdn: v.fqdn || '', vrid: String(v.vrid || 51),
          ifaces: Object.assign({}, v.ifaces || {}), mode: v.mode === 'stays' ? 'stays' : 'back',
          prefer: v.prefer || v.prefer_now || names[0] || '', on: !!v.on};
}
function vipDirty() {
  VIPD.dirty = true;
  VIPD.ver = (VIPD.ver || 0) + 1;
  pendingSet('vip', {save: vipSave, reset: function () { VIPD = null; loadVip(); }});
}
function vipSave() {
  var dr = VIPD, d = WEB.last || {}, v = d.vip || {};
  if (!dr) return Promise.resolve(true);
  var was = vipFromServer(v, d);
  var steps = [];
  if (dr.address !== was.address || (dr.address6 || '') !== (was.address6 || '') || dr.fqdn !== was.fqdn || String(dr.vrid) !== String(was.vrid)
      || JSON.stringify(Object.keys(dr.ifaces).sort().map(function (k) { return [k, dr.ifaces[k]]; }))
         !== JSON.stringify(Object.keys(was.ifaces).sort().map(function (k) { return [k, was.ifaces[k]]; }))) {
    steps.push(function () { return api('web', {action: 'vip_save', address: dr.address, address6: dr.address6 || '', fqdn: dr.fqdn, vrid: Number(dr.vrid || 51), ifaces: dr.ifaces}); });
  }
  if (dr.mode !== was.mode || (dr.mode === 'back' && dr.prefer !== was.prefer)) {
    steps.push(function () { return api('web', {action: 'vip_mode', mode: dr.mode, prefer: dr.prefer}); });
  }
  var ask = Promise.resolve(true);
  if (dr.on !== was.on) {
    if (dr.on) steps.push(function () { return api('web', {action: 'vip_on'}); });
    else {
      ask = askThen('Turn the VIP address off', 'keepalived stops on both nodes and the address is on neither. The nodes keep answering on their own addresses, and a load balancer of your own works as before.', 'Turn it off');
      steps.push(function () { return api('web', {action: 'vip_off'}); });
    }
  }
  var ver = dr.ver;
  return ask.then(function (yes) {
    if (!yes) return false;
    var chain = Promise.resolve();
    var last = null;
    steps.forEach(function (f) { chain = chain.then(f).then(function (x) { last = x; }); });
    return chain.then(function () {
      toast((last && last.message) || 'saved', 'good');
      if (VIPD && VIPD.ver !== ver) return false;   // changed meanwhile: still to be saved
      VIPD = null;
      setTimeout(loadVip, 1500);
      return true;
    });
  });
}
function drawVip(d) {
  var host = $('web-vip');
  liveFill(host, function (host) {
  if (!d.cluster) {
    host.appendChild(el('p', 'note', 'The VIP address is for a cluster of two: make this node one of two first (High availability).'));
    return;
  }
  var v = d.vip || {};
  /* What is set waits for the save bar (1.0.56): a draft of it. */
  /* Taken again from the server on every draw until something is changed
     here (1.0.57): kept from the first answer, a later save sent stale
     values back - undoing a move, or turning the address off. */
  if (!VIPD || !VIPD.dirty) VIPD = vipFromServer(v, d);
  var dr = VIPD;
  /* The big line: where it is now. */
  var top = el('div', 'vip-top');
  var holder = (v.holder || [])[0];
  var big = el('div', 'vip-big ' + (!v.on ? 'off' : (holder ? 'ok' : 'crit')));
  big.appendChild(noI18n(el('div', 'vip-addr', v.address || '–')));
  big.appendChild(el('div', 'vip-where', !v.on ? 'off' : (holder ? 'on ' + holder : 'on no node')));
  if (v.fqdn) big.appendChild(noI18n(el('div', 'vip-fqdn', v.fqdn)));
  top.appendChild(big);
  /* Where it goes back to (1.0.52): a node chosen, or wherever it is. */
  var ret = el('div', 'vip-return');
  ret.appendChild(el('div', 'lb-f-k', 'When the node it left is well again'));
  var stays = dr.mode === 'stays';
  var rseg = el('div', 'seg');
  var names = (d.nodes || []).map(function (n) { return n.name; });
  var prefNow = stays ? '' : (dr.prefer || names[0] || '');
  names.forEach(function (nm) {
    var b = el('button', '', 'always back to ' + nm); b.type = 'button';
    if (!stays && prefNow === nm) b.classList.add('on');
    b.disabled = !d.may;
    b.onclick = function () { dr.mode = 'back'; dr.prefer = nm; vipDirty(); drawVip(d); };
    rseg.appendChild(b);
  });
  var sb = el('button', '', 'it stays where it is'); sb.type = 'button';
  if (stays) sb.classList.add('on');
  sb.disabled = !d.may;
  sb.onclick = function () { dr.mode = 'stays'; vipDirty(); drawVip(d); };
  rseg.appendChild(sb);
  ret.appendChild(rseg);
  ret.appendChild(el('div', 'arow-s', stays
    ? 'No preference: the node that holds it keeps it. It moves only when that node fails (maintenance, an upgrade, unhealthy, gone) or when moved by hand - and stays where it went.'
    : 'Preferred node: the address is on ' + (prefNow || '?') + ' whenever it is healthy, and goes back to it by itself (within a few seconds) after a failover. Moving it by hand makes the other node the preferred one.'));
  top.appendChild(ret);
  if ((v.holder || []).length > 1) top.appendChild(el('p', 'note bad', 'On both nodes at once: they do not hear each other (VRRP between them is blocked, or the network is split). See docs/tls-and-vip.md.'));
  host.appendChild(top);
  /* The nodes. */
  host.appendChild(listTable(['Node', 'Now', 'May hold it', 'Interface', 'Put in place', ''], d.nodes || [], function (n) {
    var w = n.web || {};
    var hl = w.health || {};
    var tr = el('tr');
    var nm = el('td');
    nm.appendChild(noI18n(el('b', '', n.name)));
    if (v.on && v.mode !== 'stays' && (v.prefer_now === n.name)) nm.appendChild(el('span', 'tag dim', 'preferred'));
    tr.appendChild(nm);
    var role = el('td');
    var r = w.vip_here ? 'holds it' : ({MASTER: 'holds it', BACKUP: 'standby', FAULT: 'not well'}[w.role] || (v.on ? '–' : 'off'));
    role.appendChild(el('span', 'tag ' + (w.vip_here ? 'ok' : (w.role === 'FAULT' ? 'crit' : 'dim')), r));
    tr.appendChild(role);
    var h = el('td', 'small');
    if (!v.on) h.appendChild(el('span', 'muted', '–'));
    else if (!n.alive) h.appendChild(el('span', 'bad', 'not answering'));
    else h.appendChild(el('span', hl.ok ? 'good' : 'bad', hl.ok ? 'yes' : 'no - ' + (hl.why || '?')));
    tr.appendChild(h);
    var ifc = el('td');
    var opts = [['', 'the one with ' + (n.address || 'its address')]].concat((w.ifaces || []).filter(function (x) { return x !== 'lo'; }).map(function (x) { return [x, x]; }));
    var sel = selectBox(opts, (dr.ifaces || {})[n.name] || '');
    sel.dataset.node = n.name;
    sel.className = 'vip-iface';
    sel.disabled = !d.may;
    sel.onchange = function () { if (sel.value) dr.ifaces[n.name] = sel.value; else delete dr.ifaces[n.name]; vipDirty(); };
    ifc.appendChild(sel);
    tr.appendChild(ifc);
    var rt = el('td', 'small');
    rt.appendChild(el('span', w.state === 'failed' ? 'bad' : 'muted', w.state ? (w.state === 'done' ? (w.current ? 'in place' : 'being put in…') : 'failed: ' + ((w.said || []).slice(-1)[0] || '')) : '–'));
    tr.appendChild(rt);
    var tools = el('td', 'rowtools');
    if (d.may && v.on && n.alive && !w.vip_here) {
      var mv = cmdButton('Move it here', 'next', 'small');
      mv.onclick = function () {
        var nn = htmlText(n.name);
        confirmThen('Move the VIP address to ' + n.name, 'Whoever is on the pages through it is answered by ' + nn + ' within a few seconds; sign-ins stay (they are in the database). ' + (v.mode === 'stays' ? 'It then stays on ' + nn + '.' : nn + ' becomes the preferred node: the address goes back to it after a failover.'), 'Move it', function () {
          api('web', {action: 'vip_move', to: n.name}).then(function (x) { toast(x.message, 'good'); setTimeout(loadVip, 4000); }).catch(oops);
        });
      };
      tools.appendChild(mv);
    }
    if (d.may && w.state === 'failed') {
      var again = iconButton('refresh', 'Try again');
      again.onclick = function () { api('web', {action: 'retry', node: n.name}).then(function (x) { toast(x.message, 'good'); }).catch(oops); };
      tools.appendChild(again);
    }
    tr.appendChild(tools);
    return tr;
  }));
  if (!d.may) return;
  /* The settings. */
  var g = el('div', 'formgrid');
  g.style.marginTop = '14px';
  var addr = textBox(dr.address, '192.0.2.10/24', 'mono'); addr.id = 'vip-addr';
  var fqdn = textBox(dr.fqdn, 'upsmon.example.cz', 'mono'); fqdn.id = 'vip-fqdn';
  var vrid = textBox(dr.vrid, '51', 'mono'); vrid.id = 'vip-vrid'; vrid.inputMode = 'numeric';
  addr.oninput = function () { dr.address = addr.value.trim(); vipDirty(); };
  fqdn.oninput = function () { dr.fqdn = fqdn.value.trim(); vipDirty(); };
  vrid.oninput = function () { dr.vrid = vrid.value.trim(); vipDirty(); };
  g.appendChild(formField('The address, with its prefix', addr, 'A third address in the nodes\' network - not either node\'s.'));
  g.appendChild(formField('Its name', fqdn, 'What people type. With a certificate of its own (Settings → Certificates and TLS), it is answered with that one.'));
  g.appendChild(formField('VRRP id', vrid, '1 to 255; one no other VRRP (keepalived, a router) on that network uses.'));
  /* Dual stack (1.0.119): an IPv6 address moved with it. */
  var addr6 = textBox(dr.address6 || '', '2001:db8::10/64', 'mono');
  addr6.oninput = function () { dr.address6 = addr6.value.trim(); vipDirty(); };
  g.appendChild(formField('…and its IPv6 address (optional)', addr6, 'With IPv6 on in Settings → Network: moved with the IPv4 one by the same VRRP; nginx answers on it too. Empty: IPv4 only.'));
  host.appendChild(g);
  /* On or off: a switch, kept with the rest until saved. */
  var onrow = el('label', 'fw-master vip-onoff');
  var sw = switchBox(dr.on);
  sw._input.disabled = !dr.address && !dr.on;
  sw._input.onchange = function () { dr.on = !!sw._get(); vipDirty(); drawVip(d); };
  onrow.appendChild(sw);
  onrow.appendChild(el('span', '', dr.on ? 'the VIP address is on' : 'the VIP address is off'));
  host.appendChild(onrow);
  host.appendChild(el('p', 'muted small', 'Each node needs keepalived (put in by itself from AlmaLinux\'s own repository), VRRP (IP protocol 112) let in from the other node, and the address in the same network as its own - docs/tls-and-vip.md says what to open in a firewall.'));
  });
}



/* ======== backups to another machine (OTP admin.js 11075-12159) ======== */
/* ==== Backups to another machine (1.0.109) ===================================
   Destinations (a folder, FTP, FTPS, SFTP, SCP, SMB) with their sign-in -
   passwords, ssh keys made here or brought, the server's host key or its
   certificate checked, a client certificate for FTPS - a backup sent now or on
   a schedule, the history, the backups at each destination, and putting one
   back. Only a full administrator sees any of it. */
var RB = null;
var RB_POLL = null;
var RB_KIND_ICON = {folder: 'db', ftp: 'upload', ftps: 'lock', sftp: 'terminal', scp: 'terminal', smb: 'net'};
var RB_KIND_SAYS = {
  folder: 'A folder on this machine - an NFS or other share mounted here.',
  ftp: 'Plain FTP: the password and the file go over unencrypted - only inside a network you trust (the file itself is locked).',
  ftps: 'FTP over TLS - explicit (port 21) or implicit (990); the server’s certificate checked, a client certificate if it wants one.',
  sftp: 'SSH file transfer: a key made here or your own, or a password; the server’s host key checked.',
  scp: 'scp over SSH, and ssh to list and take away old ones - needs a shell on the server.',
  smb: 'A Windows or Samba share: the account, its domain, SMB3 encryption.'
};
function rbWhen(ts) {
  if (!ts) return '';
  var n = Number(ts);
  return isNaN(n) ? String(ts) : 'until ' + new Date(n * 1000).toLocaleDateString(numLang());
}
function rbBytes(n) {
  n = Number(n || 0);
  if (n < 1024) return num(n) + ' B';
  var u = ['kB', 'MB', 'GB', 'TB'], i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
}
function rbWhere(t) {
  if (t.kind === 'folder') return t.path || '';
  if (t.kind === 'smb') return '\\\\' + t.host + (t.port && t.port !== 445 ? ':' + t.port : '') + '\\' + (t.share || '') + (t.path ? '\\' + String(t.path).replace(/\//g, '\\') : '');
  return (t.user ? t.user + '@' : '') + t.host + (t.port ? ':' + t.port : '') + '/' + String(t.path || '').replace(/^\//, '');
}
function loadRbackup() {
  var top = $('rb-top');
  if (!top) return;
  if (!ME || ME.role !== 'fulladmin') {
    clear(top);
    top.appendChild(el('p', 'note', 'Only a full administrator sees and changes the backups: they hold every token.'));
    return;
  }
  api('rbackup').then(function (d) {
    RB = d;
    drawRbTop();
    drawRbTargets();
    drawRbRuns();
    rbPassTools();
    if (d.job && d.job.running) rbWatch();
  }).catch(oops);
}
function rbPassTools() {
  /* "Make one" beside the password of the backups: a long random one, shown
     once to be put into the password vault. */
  var item = document.querySelector('.set-item[data-key="rbackup_password"]');
  if (!item || item.querySelector('.rb-gen')) return;
  var b = cmdButton('Make a strong one', 'key', 'small rb-gen');
  b.style.alignSelf = 'flex-start';
  b.onclick = function () {
    var a = new Uint8Array(24);
    crypto.getRandomValues(a);
    var abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    var pw = '';
    for (var i = 0; i < a.length; i++) { pw += abc.charAt(a[i] % abc.length); if (i % 6 === 5 && i < a.length - 1) pw += '-'; }
    var box = item.querySelector('input');
    if (box) {
      if (box._set) box._set(pw); else box.value = pw;
      box.dispatchEvent(new Event('input', {bubbles: true}));
      box.dispatchEvent(new Event('change', {bubbles: true}));
    }
    modal('The password of the backups', function (body) {
      body.appendChild(el('p', 'note', 'Put it into your password vault now - this is the only time it is shown whole. Without it no backup can be opened, by anybody. Then press Save the changes.'));
      var p = noI18n(el('div', 'rb-pass mono', pw));
      body.appendChild(p);
      var c = cmdButton('Copy', 'copy', 'small');
      c.onclick = function () { copyText(pw, c, 'Copied'); };
      body.appendChild(c);
    }, [{words: 'Close', close: true}], true);
  };
  var says = item.querySelector('.says');
  if (says) says.parentNode.insertBefore(b, says); else item.appendChild(b);
}
function drawRbTop() {
  var host = $('rb-top');
  clear(host);
  var d = RB;
  var card = el('div', 'card full rb-hero');
  var last = (d.runs || [])[0];
  var mine = (d.runs || []).filter(function (r) { return r.node === d.node; })[0];
  var on = (d.targets || []).filter(function (t) { return t.enabled; });
  var state = !on.length ? 'warn' : (!mine ? 'warn' : (mine.ok ? 'good' : 'bad'));
  card.classList.add(state);
  var head = el('div', 'rb-hero-head');
  var ic = el('span', 'rb-hero-ic');
  ic.innerHTML = iconMarkup(state === 'good' ? 'check' : (state === 'bad' ? 'flag' : 'info'), 22);
  head.appendChild(ic);
  var words = el('div', 'rb-hero-words');
  var title = !on.length ? 'No destination yet - backups go nowhere'
    : (!mine ? 'No backup of this node has been sent yet'
      : (mine.ok ? 'The last backup of ' + d.node + ' went to every destination'
        : 'The last backup of ' + d.node + ' did not reach every destination'));
  words.appendChild(el('b', '', title));
  var facts = el('div', 'rb-hero-facts');
  var fact = function (k, v, cls) {
    var f = el('span', 'rb-fact ' + (cls || ''));
    f.appendChild(el('span', 'k', k));
    f.appendChild(el('span', 'v', v));
    facts.appendChild(f);
  };
  if (mine) fact('Last', ago(mine.at) + ' · ' + rbBytes(mine.bytes));
  fact('Next', d.next ? new Date(d.next).toLocaleString(numLang(), {weekday: 'short', day: 'numeric', month: 'numeric', hour: '2-digit', minute: '2-digit'}) : 'by hand only', d.next ? '' : 'warn');
  fact('Locked', d.locked ? 'with the password (AES-256)' : 'NOT locked - set the password', d.locked ? 'good' : 'bad');
  fact('Destinations', num(on.length) + ' of ' + num((d.targets || []).length) + ' switched on');
  /* The last try (1.0.169): whether the newest backup can be put back. */
  var tried = (d.verified || []).filter(function (v) { return v.node === d.node; })[0];
  fact('Tried', tried ? (tried.ok ? 'can be put back' : 'NOT GOOD') + ' · ' + ago(tried.at) : 'never', tried ? (tried.ok ? 'good' : 'bad') : 'warn');
  words.appendChild(facts);
  if (mine && !mine.ok) {
    var bad = (mine.targets || []).filter(function (x) { return !x.ok; });
    var why = el('div', 'rb-hero-why small bad');
    why.textContent = mine.error || bad.map(function (x) { return x.name + ': ' + (x.error || 'failed'); }).join(' · ');
    words.appendChild(why);
  }
  head.appendChild(words);
  var acts = el('div', 'rb-hero-acts');
  var now = cmdButton('Back up now', 'upload', 'primary');
  now.id = 'rb-now';
  now.disabled = !on.length || (d.job && d.job.running);
  explain(now, 'A backup made now and sent to every destination switched on - the same as the scheduled one.');
  now.onclick = function () {
    busy(now, true);
    api('rbackup', {action: 'run'}).then(function (x) { toast(x.message, 'good'); RB.job = x.job; rbWatch(); })
      .catch(function (e) { busy(now, false); oops(e); });
  };
  acts.appendChild(now);
  var tryb = cmdButton('Try the newest', 'check', '');
  tryb.disabled = !on.length || (d.job && d.job.running);
  explain(tryb, 'The newest backup of this node fetched back from the first destination, opened with the password, every file checked, the database read through and the tokens tried against the key in it - nothing is put back. And the newest nightly copy here read through.');
  tryb.onclick = function () {
    busy(tryb, true);
    api('rbackup', {action: 'verify'}).then(function (x) { toast(x.message, 'good'); RB.job = x.job; rbWatch(); })
      .catch(function (e) { busy(tryb, false); oops(e); });
  };
  acts.appendChild(tryb);
  var dl = cmdButton('Download one here', 'download', '');
  explain(dl, 'A backup made now, saved on the computer you are sitting at - locked with the password as the others.');
  dl.onclick = function () {
    if (!d.locked) {
      confirmThen('Download a backup that is not locked?', 'No password of the backups is set: the file will hold <b>every token’s key</b> readable. Set the password first unless you know where the file goes.', 'Download it', function () { window.location.href = '?api=rbackup-download'; }, false);
      return;
    }
    toast('the backup is being made - the download starts when it is ready', 'good');
    window.location.href = '?api=rbackup-download';
  };
  acts.appendChild(dl);
  var back = cmdButton('Put one back…', 'undo', '');
  back.onclick = rbPutBackFile;
  acts.appendChild(back);
  var guide = cmdButton('How to put it back', 'book', '');
  explain(guide, 'RESTORE.md - the exact steps to bring everything back from a backup, filled in with this installation, as every backup carries it. To read now, and to keep apart from the backups.');
  guide.onclick = rbGuide;
  acts.appendChild(guide);
  head.appendChild(acts);
  card.appendChild(head);
  var going = el('div', 'going wide');
  going.id = 'rb-going';
  going.hidden = !(d.job && d.job.running);
  going.innerHTML = '<div class="bar"><span id="rb-going-fill"></span></div><div class="says" id="rb-going-says"></div>';
  card.appendChild(going);
  if (!d.tools.openssl) card.appendChild(el('p', 'note bad', 'openssl is not on this machine: backups cannot be locked (dnf install openssl).'));
  host.appendChild(card);
  /* In a cluster each node backs itself up (1.0.169): every node's last
     backup and last try, side by side. */
  var names = Object.keys(d.last_by_node || {});
  (d.verified || []).forEach(function (v) { if (v.node && names.indexOf(v.node) < 0) names.push(v.node); });
  if (names.indexOf(d.node) < 0) names.push(d.node);
  if (names.length > 1) {
    var grid = nodeGrid();
    grid.classList.add('rb-nodes');
    names.sort().forEach(function (n) {
      var last = (d.last_by_node || {})[n];
      var tr = (d.verified || []).filter(function (v) { return v.node === n; })[0];
      var bad = (last && !last.ok) || (tr && !tr.ok);
      var c = nodeCard({node: n, me: n === d.node}, !last ? 'dim' : (bad ? 'bad' : 'ok'),
        !last ? 'no backup yet' : (last.ok ? 'went everywhere' : 'did not go everywhere'), !last ? 'dim' : (last.ok ? 'ok' : 'crit'));
      nodeBig(c, last ? ago(last.at) : '–', last ? 'the last backup' : '');
      c.appendChild(netFacts([['Size', last && last.bytes ? rbBytes(last.bytes) : ''], ['Tokens', last && last.tokens != null ? num(last.tokens) : ''],
        ['Tried', tr ? (tr.ok ? 'can be put back' : 'NOT GOOD') + ' · ' + ago(tr.at) : 'never']]));
      grid.appendChild(c);
    });
    host.appendChild(grid);
  }
  RB.verified = d.verified || [];
  drawRbTried();
}
/* The backups tried (1.0.169): each try, every check of it; the list can be
   emptied, or a try taken off - the backups themselves stay. */
function drawRbTried() {
  var card = $('rb-tried-card'), host = $('rb-tried'), tools = $('rb-tried-tools');
  if (!card) return;
  var rows = RB.verified || [];
  card.hidden = !rows.length;
  clear(host);
  clear(tools);
  if (!rows.length) return;
  var forget = function (q) {
    api('rbackup', Object.assign({action: 'verified_forget'}, q)).then(function (d) {
      toast(d.message, 'good'); RB.verified = d.verified || []; drawRbTried();
    }).catch(oops);
  };
  var wipe = cmdButton('Clear the list', 'trash', 'small');
  wipe.onclick = function () {
    confirmThen('Clear the list of backups tried?', 'Every try goes from this list (for both nodes). <b>The backups themselves stay where they are.</b> Events keeps a line saying who cleared it.', 'Clear the list', function () { forget({all: 1}); }, true);
  };
  tools.appendChild(wipe);
  var list = el('div', 'rb-tried');
  rows.slice(0, 8).forEach(function (v, i) {
    var it = el('details', 'rb-try ' + (v.ok ? 'good' : 'bad'));
    if (i === 0 && !v.ok) it.open = true;
    var sm = el('summary');
    sm.appendChild(el('span', 'dot ' + (v.ok ? 'ok' : 'bad')));
    sm.appendChild(el('b', '', v.ok ? 'Can be put back' : 'Not good'));
    sm.appendChild(noI18n(el('span', 'mono small', v.file || '?')));
    sm.appendChild(el('span', 'muted small', '·'));
    sm.appendChild(el('span', 'muted small', ago(v.at)));
    sm.appendChild(el('span', 'muted small', '·'));
    sm.appendChild(noI18n(el('span', 'muted small', (v.node || '') + ' → ' + (v.target_name || ''))));
    var x = el('button', 'xbtn rb-try-x');
    x.type = 'button';
    x.setAttribute('data-icon', 'close');
    x.title = 'Take it off the list';
    x.onclick = function (e) { e.preventDefault(); e.stopPropagation(); forget({at: v.at}); };
    sm.appendChild(x);
    it.appendChild(sm);
    var ul = el('div', 'rb-checks');
    (v.checks || []).forEach(function (k) {
      var row = el('div', 'rb-check');
      row.appendChild(el('span', 'dot ' + (k.ok ? 'ok' : 'bad')));
      row.appendChild(el('span', '', k.what));
      if (k.said) row.appendChild(noI18n(el('span', 'muted small', '- ' + k.said)));
      ul.appendChild(row);
    });
    it.appendChild(ul);
    list.appendChild(it);
  });
  host.appendChild(list);
  dressButtons(host);
}
/* RESTORE.md on the pages (1.0.110): read here, downloaded as the file. */
function rbGuide() {
  api('rbackup', {action: 'restore_md'}).then(function (d) {
    modal('How to put a backup back', function (body) {
      var lede = el('p', 'note');
      lede.innerHTML = 'The <code>RESTORE.md</code> every backup carries, as one made now would have it. Keep a copy apart from the backups - with the password of the backups in a vault.';
      body.appendChild(lede);
      var doc = noI18n(el('div', 'md-doc'));
      doc.appendChild(mdRender(d.md));
      body.appendChild(doc);
    }, [{words: 'Close', close: true},
        {words: 'Download RESTORE.md', cls: 'primary', icon: 'download', go: function () {
          var a = el('a');
          a.href = URL.createObjectURL(new Blob([d.md], {type: 'text/markdown;charset=utf-8'}));
          a.download = d.name || 'RESTORE.md';
          document.body.appendChild(a); a.click(); a.remove();
          setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
        }}], 'large');
  }).catch(oops);
}
/* Markdown as the guides are written: headings, paragraphs, lists, tables,
   fenced code (with a copy button), `code`, **bold**, *italic*. Built from
   elements - nothing in the text becomes HTML. */
function mdInline(text) {
  var frag = document.createDocumentFragment();
  var re = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*)/g, last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
    var t = m[0];
    if (t.charAt(0) === '`') frag.appendChild(el('code', '', t.slice(1, -1)));
    else if (t.slice(0, 2) === '**') frag.appendChild(el('b', '', t.slice(2, -2)));
    else frag.appendChild(el('i', '', t.slice(1, -1)));
    last = re.lastIndex;
  }
  if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
  return frag;
}
function mdRender(md) {
  var out = document.createDocumentFragment();
  var lines = String(md || '').split('\n'), i = 0;
  var para = [];
  var flush = function () {
    if (!para.length) return;
    var p = el('p');
    p.appendChild(mdInline(para.join(' ')));
    out.appendChild(p);
    para = [];
  };
  while (i < lines.length) {
    var ln = lines[i];
    if (/^```/.test(ln)) {
      flush();
      var code = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i += 1; }
      i += 1;
      var wrap = el('div', 'md-code');
      var pre = el('pre', '', code.join('\n'));
      wrap.appendChild(pre);
      var cp = iconButton('copy', 'Copy');
      (function (txt, b) {
        b.onclick = function () {
          (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(function () { toast('copied', 'good'); }).catch(function () { toast('select it and copy it by hand'); });
        };
      })(code.join('\n'), cp);
      wrap.appendChild(cp);
      out.appendChild(wrap);
      continue;
    }
    var h = /^(#{1,4})\s+(.*)$/.exec(ln);
    if (h) { flush(); var hn = el('h' + Math.min(6, h[1].length + 2)); hn.appendChild(mdInline(h[2])); out.appendChild(hn); i += 1; continue; }
    if (/^\|/.test(ln)) {
      flush();
      var rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) { rows.push(lines[i]); i += 1; }
      var tbl = el('table', 'md-table');
      var tb = el('tbody');
      rows.forEach(function (r, n) {
        if (/^\|[\s|:-]+\|$/.test(r)) return;
        var cells = r.replace(/^\|/, '').replace(/\|$/, '').split('|');
        if (n === 0 && cells.every(function (c) { return !c.trim(); })) return;
        var tr = el('tr');
        cells.forEach(function (c) { var td = el(n === 0 && rows.length > 1 && /^\|[\s|:-]+\|$/.test(rows[1]) ? 'th' : 'td'); td.appendChild(mdInline(c.trim())); tr.appendChild(td); });
        tb.appendChild(tr);
      });
      tbl.appendChild(tb);
      out.appendChild(tbl);
      continue;
    }
    if (/^\s*[-*] /.test(ln)) {
      flush();
      var ul = el('ul');
      var li = null;
      while (i < lines.length && (/^\s*[-*] /.test(lines[i]) || (li && /^\s{2,}\S/.test(lines[i])))) {
        if (/^\s*[-*] /.test(lines[i])) { li = el('li'); li._t = lines[i].replace(/^\s*[-*] /, ''); ul.appendChild(li); }
        else li._t += ' ' + lines[i].trim();
        i += 1;
      }
      Array.prototype.forEach.call(ul.children, function (x) { x.appendChild(mdInline(x._t)); });
      out.appendChild(ul);
      continue;
    }
    if (/^---+\s*$/.test(ln)) { flush(); out.appendChild(el('hr')); i += 1; continue; }
    if (!ln.trim()) { flush(); i += 1; continue; }
    para.push(ln.trim());
    i += 1;
  }
  flush();
  return out;
}
function rbWatch() {
  if (RB_POLL) return;
  var step = function () {
    api('rbackup', {action: 'job'}).then(function (x) {
      var j = x.job || {};
      var g = $('rb-going');
      if (g) {
        g.hidden = !j.running;
        var f = $('rb-going-fill');
        if (f) f.style.width = (j.whole ? Math.round(100 * j.done / j.whole) : 5) + '%';
        var sy = $('rb-going-says');
        if (sy) sy.textContent = j.says || '';
      }
      if (j.running) { RB_POLL = setTimeout(step, TAB === 'settings' && PANE === 'backup' ? 1000 : 5000); return; }
      RB_POLL = null;
      if (j.error) toast('the backup: ' + j.error, 'bad');
      else if (j.result) toast(j.result.ok ? 'the backup went to every destination' : 'the backup did not reach every destination', j.result.ok ? 'good' : 'bad');
      if (TAB === 'settings' && PANE === 'backup') loadRbackup();
    }).catch(function () { RB_POLL = null; });
  };
  step();
}
function drawRbTargets() {
  var host = $('rb-targets');
  clear(host);
  var add = cmdButton('Add a destination', 'add', 'primary small');
  add.onclick = rbPickKind;
  var ah = $('rb-add-host');
  clear(ah);
  ah.appendChild(add);
  var ts = RB.targets || [];
  if (!ts.length) {
    var empty = el('div', 'rb-empty');
    empty.appendChild(el('p', '', 'No destination yet. A backup kept only on this machine is lost with it: add a place on another machine.'));
    host.appendChild(empty);
    return;
  }
  var grid = el('div', 'rb-grid');
  ts.forEach(function (t) {
    var c = el('div', 'rb-card' + (t.enabled ? '' : ' off'));
    var top = el('div', 'rb-card-top');
    var ic = el('span', 'rb-kind k-' + t.kind);
    ic.innerHTML = iconMarkup(RB_KIND_ICON[t.kind] || 'db', 18);
    top.appendChild(ic);
    var nm = el('div', 'rb-card-name');
    nm.appendChild(noI18n(el('b', '', t.name)));
    nm.appendChild(el('span', 'rb-kind-words', t.kind_words));
    top.appendChild(nm);
    var sw = switchBox(t.enabled);
    explain(sw, t.enabled ? 'Backups go here. Switch off to stop sending, keeping everything set.' : 'Switched off: nothing is sent here.');
    sw._input.onchange = function () {
      api('rbackup', {action: 'save', id: t.id, target: {kind: t.kind, enabled: sw._get(), name: t.name, host: t.host, port: t.port, path: t.path, user: t.user, share: t.share, domain: t.domain, smb_encrypt: t.smb_encrypt, implicit: t.implicit, tls_check: t.tls_check, passive: t.passive}})
        .then(function () { loadRbackup(); }).catch(function (e) { oops(e); loadRbackup(); });
    };
    top.appendChild(sw);
    c.appendChild(top);
    c.appendChild(noI18n(el('div', 'rb-where mono', rbWhere(t))));
    var chips = el('div', 'rb-chips');
    var chip = function (w, cls, tip) { var x = el('span', 'tag ' + (cls || 'dim'), w); if (tip) x.title = tip; chips.appendChild(x); };
    if (t.has_password) chip('password', 'dim');
    if (t.has_key) chip('ssh key', 'violet');
    if (t.ssh_cert) chip('ssh certificate', 'violet');
    if (t.kind === 'sftp' || t.kind === 'scp') chip(t.hostkey ? 'host key trusted' : 'host key not trusted yet', t.hostkey ? 'ok' : 'warn', (t.hostkey_fp || []).join('\n'));
    if (t.kind === 'ftps') chip({system: 'certificate: system authorities', ca: 'certificate: own authority', pin: 'certificate pinned', none: 'certificate NOT checked'}[t.tls_check] || '', t.tls_check === 'none' ? 'warn' : 'ok');
    if (t.has_client_key) chip('client certificate', 'violet');
    if (t.kind === 'smb' && t.smb_encrypt) chip('SMB3 encrypted', 'ok');
    if (t.kind === 'ftp') chip('not encrypted on the way', 'warn');
    c.appendChild(chips);
    var last = t.last;
    var ls = el('div', 'rb-last ' + (last ? (last.ok ? 'good' : 'bad') : 'muted'));
    ls.textContent = last ? (last.ok ? '✓ last sent ' + ago(last.at) + ' · ' + rbBytes(last.bytes) : '✗ ' + ago(last.at) + ': ' + (last.error || 'failed')) : 'nothing sent here yet';
    c.appendChild(ls);
    var acts = el('div', 'rb-acts');
    var tr = cmdButton('Try it', 'play', 'small');
    tr.onclick = function () { rbTry(t, null, tr); };
    acts.appendChild(tr);
    var ed = cmdButton('Edit', 'edit', 'small');
    ed.onclick = function () { rbEdit(t); };
    acts.appendChild(ed);
    var ls2 = cmdButton('Backups there', 'list', 'small');
    ls2.onclick = function () { rbListThere(t); };
    acts.appendChild(ls2);
    var del = iconButton('trash', 'Take this destination away');
    del.onclick = function () {
      confirmThen('Take the destination ' + htmlText(t.name) + ' away?', 'Nothing is deleted on the server; backups simply stop going there, and its keys and certificates set here are forgotten.', 'Take it away', function () {
        api('rbackup', {action: 'delete', id: t.id}).then(function (x) { toast(x.message, 'good'); loadRbackup(); }).catch(oops);
      });
    };
    acts.appendChild(del);
    c.appendChild(acts);
    grid.appendChild(c);
  });
  host.appendChild(grid);
}
function drawRbRuns() {
  var host = $('rb-runs');
  clear(host);
  var runs = RB.runs || [];
  /* The list can be emptied, or a line taken off (1.0.110) - the backups
     themselves stay where they went. */
  var tools = $('rb-runs-tools');
  if (tools) {
    clear(tools);
    if (runs.length) {
      var wipe = cmdButton('Clear the list', 'trash', 'small');
      wipe.onclick = function () {
        confirmThen('Clear the list of backups sent?', 'Every line goes from this list (for both nodes). <b>The backups themselves stay where they went</b> - delete them under <i>Backups there</i> on a destination. Events keeps a line saying who cleared it.', 'Clear the list', function () {
          api('rbackup', {action: 'runs_forget', all: 1}).then(function (d) { toast(d.message, 'good'); RB.runs = d.runs || []; drawRbRuns(); }).catch(oops);
        }, true);
      };
      tools.appendChild(wipe);
    }
  }
  if (!runs.length) { host.appendChild(el('p', 'note', 'No backup sent yet.')); return; }
  host.appendChild(listTable(['When', 'Node', 'File', 'Size', 'Where it went', 'Who', ''], runs, function (r) {
    var tr = el('tr');
    tr.appendChild(el('td', 'muted', new Date(r.at * 1000).toLocaleString(numLang())));
    tr.appendChild(noI18n(el('td', '', r.node || '')));
    var f = el('td', 'mono small');
    f.appendChild(noI18n(el('span', '', r.file || '–')));
    if (r.file && !r.encrypted) { f.appendChild(document.createTextNode(' ')); f.appendChild(el('span', 'tag bad', 'not locked')); }
    tr.appendChild(f);
    tr.appendChild(el('td', 'num', r.bytes ? rbBytes(r.bytes) : '–'));
    var w = el('td');
    if (r.error) w.appendChild(el('span', 'small bad', r.error));
    (r.targets || []).forEach(function (x) {
      var s = el('span', 'tag namepill ' + (x.ok ? 'ok' : 'crit'), (x.ok ? '✓ ' : '✗ ') + x.name);
      s.title = x.ok ? (x.secs + ' s' + ((x.taken_away || []).length ? ' · taken away: ' + x.taken_away.join(', ') : '')) : (x.error || '');
      noI18n(s);
      w.appendChild(s);
      w.appendChild(document.createTextNode(' '));
    });
    tr.appendChild(w);
    tr.appendChild(noI18n(el('td', 'muted small', r.by || '')));
    var a = el('td', 'rowtools');
    var del = iconButton('trash', 'Take it off the list');
    del.onclick = function () {
      api('rbackup', {action: 'runs_forget', at: r.at, file: r.file || ''}).then(function (d) { toast(d.message, 'good'); RB.runs = d.runs || []; drawRbRuns(); }).catch(oops);
    };
    a.appendChild(del);
    tr.appendChild(a);
    return tr;
  }, 'plain'));
}
function rbPickKind() {
  modal('Where should the backups go?', function (body) {
    var g = el('div', 'rb-kinds');
    (RB.kinds || []).forEach(function (k) {
      var b = el('button', 'rb-kind-tile');
      b.type = 'button';
      var ic = el('span', 'rb-kind k-' + k.kind);
      ic.innerHTML = iconMarkup(RB_KIND_ICON[k.kind] || 'db', 20);
      b.appendChild(ic);
      b.appendChild(el('b', '', k.words));
      b.appendChild(el('span', 'small muted', RB_KIND_SAYS[k.kind] || ''));
      var need = {sftp: ['ssh', 'sftp'], scp: ['ssh', 'scp'], smb: ['smbclient']}[k.kind] || [];
      var missing = need.filter(function (x) { return !RB.tools[x]; });
      if (missing.length) {
        b.appendChild(el('span', 'small bad', 'missing here: ' + missing.join(', ') + (k.kind === 'smb' ? ' (dnf install samba-client)' : ' (dnf install openssh-clients)')));
      }
      b.onclick = function () { closeModal(); setTimeout(function () { rbEdit({kind: k.kind, enabled: 1, port: k.port}); }, 30); };
      if (hsOn('backup:ftp') && k.kind === 'ftp') { b.disabled = true; b.appendChild(el('span', 'small hs-note', 'not under high security')); }
      g.appendChild(b);
    });
    body.appendChild(g);
  }, [{words: 'Close', close: true}], 'medium');
}
/* The editor of one destination. A new one is saved before a key or a
   certificate is made for it - they are kept with it. */
function rbEdit(t) {
  t = t || {};
  var isNew = !t.id;
  var cur = {id: t.id};
  modal(isNew ? 'A new destination: ' + (t.kind_words || (RB.kinds.filter(function (k) { return k.kind === t.kind; })[0] || {}).words || t.kind) : t.name, function (body) {
    body.classList.add('rb-ed');
    var f = {};
    var sec = function (title, says) {
      var s = el('div', 'rb-sec');
      s.appendChild(el('h4', '', title));
      if (says) s.appendChild(el('p', 'small muted', says));
      var g = el('div', 'formgrid');
      s.appendChild(g);
      body.appendChild(s);
      return g;
    };
    var g0 = sec('What it is called', '');
    f.name = textBox(t.name || '', 'NAS in the server room');
    g0.appendChild(formField('Name', f.name));
    f.enabled = switchBox(t.enabled === undefined ? 1 : t.enabled);
    g0.appendChild(formField('Backups go here', f.enabled));
    var g1 = sec('Where', t.kind === 'folder' ? 'A whole path on this machine; the upsmon account must be able to write into it.' : '');
    if (t.kind === 'folder') {
      f.path = textBox(t.path || '', '/mnt/backup/upsmon', 'mono');
      var fp = formField('The folder', f.path);
      fp.classList.add('wide');
      g1.appendChild(fp);
    } else {
      f.host = textBox(t.host || '', 'backup.example.cz', 'mono');
      g1.appendChild(formField('The server', f.host));
      f.port = textBox(t.port || '', String({ftp: 21, ftps: t.implicit ? 990 : 21, sftp: 22, scp: 22, smb: 445}[t.kind] || ''), 'mono');
      g1.appendChild(formField('Port', f.port));
      if (t.kind === 'smb') {
        f.share = textBox(t.share || '', 'backup', 'mono');
        g1.appendChild(formField('The share', f.share));
        f.path = textBox(t.path || '', 'upsmon\\nightly', 'mono');
        g1.appendChild(formField('The folder in it', f.path, 'Made if it is not there.'));
      } else {
        f.path = textBox(t.path || '', t.kind === 'ftp' || t.kind === 'ftps' ? 'upsmon/backups' : '/home/backup/upsmon', 'mono');
        g1.appendChild(formField('The folder there', f.path, 'Made if it is not there. Without / at the start: under the account’s home.'));
      }
    }
    if (t.kind !== 'folder') {
      var g2 = sec('Signing in', t.kind === 'sftp' || t.kind === 'scp' ? 'A key (below) or a password - or both.' : '');
      f.user = textBox(t.user || '', t.kind === 'smb' ? 'backup' : 'upsmon-backup', 'mono');
      g2.appendChild(formField('Account', f.user));
      f.password = maskBox(t.password || '', t.has_password ? '' : '(none)', 'mono');
      g2.appendChild(formField('Password', f.password, t.has_password ? 'Kept, sealed. Type a new one to change it.' : ''));
      if (t.kind === 'smb') {
        f.domain = textBox(t.domain || '', 'CORP', 'mono');
        g2.appendChild(formField('Domain (workgroup)', f.domain));
        f.smb_encrypt = switchBox(t.smb_encrypt === undefined ? 1 : t.smb_encrypt);
        if (hsOn('backup:smb') && f.smb_encrypt._get()) f.smb_encrypt._input.disabled = true;
        g2.appendChild(formField('SMB3 encryption required', f.smb_encrypt, 'Everything on the wire encrypted; a server that cannot is refused.'));
      }
      if (t.kind === 'ftp' || t.kind === 'ftps') {
        f.passive = switchBox(t.passive === undefined ? 1 : t.passive);
        g2.appendChild(formField('Passive mode', f.passive, 'The usual one, through firewalls and NAT.'));
      }
    }
    if (t.kind === 'ftps') rbFtpsBlock(body, t, f, cur);
    if (t.kind === 'sftp' || t.kind === 'scp') rbSshBlock(body, t, f, cur);
    var out = el('div', 'rb-try-out');
    out.id = 'rb-try-out';
    body.appendChild(out);
    rbEdit.form = f;
  }, [
    {words: 'Close', close: true},
    {words: 'Try it', icon: 'play', go: function (b) { rbTry(cur.id ? rbTarget(cur.id) || t : t, rbFormData(t.kind), b, true); }},
    {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
      busy(b, true);
      rbSaveForm(t.kind, cur).then(function () { busy(b, false); toast('saved', 'good'); closeModal(); loadRbackup(); })
        .catch(function (e) { busy(b, false); oops(e); });
    }}], 'large');
}
function rbTarget(id) { return (RB.targets || []).filter(function (x) { return x.id === id; })[0]; }
function rbFormData(kind) {
  var f = rbEdit.form || {};
  var v = function (k) { return f[k] ? (f[k]._get ? f[k]._get() : f[k].value) : undefined; };
  var d = {kind: kind};
  ['name', 'enabled', 'host', 'port', 'path', 'user', 'password', 'share', 'domain', 'smb_encrypt', 'passive', 'implicit', 'tls_check', 'ca', 'pin', 'ssh_cert'].forEach(function (k) {
    var x = v(k);
    if (x !== undefined) d[k] = typeof x === 'string' ? x.trim() : x;
  });
  if (f.password) d.password = f.password.value;
  return d;
}
function rbSaveForm(kind, cur) {
  return api('rbackup', {action: 'save', id: cur.id || '', target: rbFormData(kind)}).then(function (x) {
    cur.id = x.target.id;
    var i = (RB.targets || []).map(function (t) { return t.id; }).indexOf(x.target.id);
    if (i >= 0) RB.targets[i] = x.target; else RB.targets.push(x.target);
    return x.target;
  });
}
function rbNeedSaved(kind, cur) {
  return cur.id ? Promise.resolve(rbTarget(cur.id)) : rbSaveForm(kind, cur);
}
function rbKeyBox(text) {
  var w = el('div', 'rb-keybox');
  var pre = noI18n(el('pre', 'mono', text));
  w.appendChild(pre);
  var c = cmdButton('Copy', 'copy', 'small');
  c.onclick = function () { copyText(text, c, 'Copied'); };
  w.appendChild(c);
  return w;
}
/* The key and the certificates, as isemon has them (1.0.109): one box each,
   a line saying what it is, the same row of buttons always there (Make,
   Use my own, Download, Forget - the last two greyed until there is one),
   Try it at the end of the row, and below it the half to copy - a click on
   it copies it. */
function rbConfirm(title, words, yes, go, danger) {
  /* Over the editor, which stays as it is underneath. */
  modalOver(function () { confirmThen(title, words, yes, go, danger); });
}
function rbCopyme(text, said) {
  var code = noI18n(el('code', 'copyme', text));
  explain(code, 'Click to copy.');
  code.onclick = function () { copyText(text, code, said || 'Copied'); };
  return code;
}
function rbPanel(note) {
  var box = el('div', 'subpanel rb-panel');
  var p = el('p', 'note');
  p.innerHTML = note;
  box.appendChild(p);
  var row = el('div', 'btnrow');
  box.appendChild(row);
  var below = el('div', 'rb-below');
  box.appendChild(below);
  return {box: box, row: row, below: below};
}
function rbTryButton(t, cur) {
  var b = cmdButton('Try reaching it', 'pulse', 'primary');
  explain(b, 'Sign in, write a small file, find it in the list and take it away again - with what is typed above, saved or not.');
  b.onclick = function () { rbTry(cur.id ? (rbTarget(cur.id) || t) : t, rbFormData(t.kind), b, true); };
  return b;
}
function rbSshBlock(body, t, f, cur) {
  var s = el('div', 'rb-sec');
  s.appendChild(el('h4', '', 'The SSH key'));
  var P = rbPanel('A key is better than a password: made here, it never leaves this machine except when you download it, and the server holds only its <b>public</b> half - in <code>~/.ssh/authorized_keys</code> of the account.');
  if (!RB.tools['ssh-keygen']) {
    var miss = el('p', 'note');
    miss.style.color = 'var(--warn)';
    miss.textContent = 'ssh-keygen is not on this machine, so a key cannot be made or read here: dnf install openssh-clients. A password still works.';
    P.box.insertBefore(miss, P.row);
  }
  var mk = cmdButton('Make a key', 'key', '');
  explain(mk, 'Make a fresh ed25519 pair here. The private half stays on this machine, sealed; the public half is shown below for you to put on the server. Any key already kept is replaced.');
  var own = cmdButton('Use my own', 'upload', '');
  explain(own, 'Use a private key you already have. Paste it whole, with its BEGIN and END lines; its public half is worked out here.');
  var dl = cmdButton('Download it', 'download', '');
  explain(dl, 'The private half as a file, for keeping somewhere safe. That it was downloaded, and by whom, is written into Events.');
  var fg = cmdButton('Forget it', 'forget', 'danger');
  explain(fg, 'Delete the private key from this machine. Unless the server takes a password instead, nothing here reaches it until a new key is made and put on it.');
  [mk, own, dl, fg].forEach(function (b) { P.row.appendChild(b); });
  P.row.appendChild(el('span', 'spacer'));
  P.row.appendChild(rbTryButton(t, cur));
  var state = {pub: t.pub, has: !!t.has_key, pass: t.key_pass || ''};
  var paint = function () {
    clear(P.below);
    dl.disabled = !state.has;
    fg.disabled = !state.has;
    mk.disabled = own.disabled = !RB.tools['ssh-keygen'];
    if (!state.has || !state.pub) {
      P.below.appendChild(el('p', 'btnhelp', 'No key yet — make one, or let it sign in with a password.'));
      return;
    }
    if (state.pass) {
      var kp = el('p', 'btnhelp', 'Its passphrase is kept, sealed: ');
      kp.appendChild(noI18n(el('span', 'mono', state.pass)));
      P.below.appendChild(kp);
    }
    P.below.appendChild(el('p', 'btnhelp', 'The public half. Click it to copy.'));
    P.below.appendChild(rbCopyme(state.pub, 'the public key is on the clipboard'));
    var u = (f.user && f.user.value) || 'the account';
    P.below.appendChild(el('p', 'btnhelp', 'On the server, as ' + u + ':'));
    P.below.appendChild(rbCopyme("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '" + state.pub + "' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"));
  };
  mk.onclick = function () {
    rbConfirm('Make a key for ' + ((f.name && f.name.value) || t.name || 'this destination'),
      'A fresh ed25519 pair is made here. The private half stays on this machine and the public half is shown for you to put on the server.' + (state.has ? '<br><br><b>The key kept now is replaced</b>, so until the new public half is on the server, backups cannot sign in there.' : ''),
      'Make one', function () {
        rbNeedSaved(t.kind, cur).then(function () { return api('rbackup', {action: 'keygen', id: cur.id}); })
          .then(function (x) { state.pub = x.pub; state.has = true; state.pass = ''; paint(); toast('a new key was made — put the public half on the server', 'good'); })
          .catch(oops);
      }, false);
  };
  own.onclick = function () {
    modalOver(function () {
      modal('Use my own key', function (body2) {
        var p = el('p', 'note');
        p.innerHTML = 'An OpenSSH private key, whole, including its <code>BEGIN</code> and <code>END</code> lines. It is kept in this machine’s database, sealed, and never shown back. Its public half is worked out here, so you do not have to hand that over as well.';
        body2.appendChild(p);
        var area = el('textarea', 'mono');
        area.rows = 11;
        area.id = 'rb-paste-area';
        area.spellcheck = false;
        area.placeholder = '-----BEGIN OPENSSH PRIVATE KEY-----';
        body2.appendChild(area);
        var pp = maskBox('', '', 'mono');
        pp.id = 'rb-paste-pp';
        body2.appendChild(formField('Its passphrase, if it has one', pp));
        setTimeout(function () { area.focus(); }, 60);
      }, [{words: 'Cancel', close: true},
          {words: 'Keep this key', cls: 'primary', close: true, go: function () {
            var key = $('rb-paste-area').value, pass = $('rb-paste-pp').value;
            rbNeedSaved(t.kind, cur).then(function () { return api('rbackup', {action: 'key_paste', id: cur.id, key: key, passphrase: pass}); })
              .then(function (x) { state.pub = x.pub; state.has = true; state.pass = x.key_pass || ''; paint(); toast('the key was stored', 'good'); })
              .catch(oops);
          }}]);
    });
  };
  dl.onclick = function () {
    rbConfirm('Download the private key', 'The private half leaves this machine as a file. Anybody holding it can sign in to the server as <code>' + htmlText((f.user && f.user.value) || 'that account') + '</code>. That it was downloaded, and by whom, is written into Events.', 'Download it', function () {
      api('rbackup', {action: 'key_download', id: cur.id}).then(function (x) {
        var a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([x.pem], {type: 'application/octet-stream'}));
        a.download = x.file;
        document.body.appendChild(a); a.click(); a.remove();
      }).catch(oops);
    }, false);
  };
  fg.onclick = function () {
    rbConfirm('Forget the key', 'The private key is deleted from this machine. Unless the server takes a password instead, backups will not reach it until a new key is made and put on it.', 'Forget it', function () {
      api('rbackup', {action: 'key_forget', id: cur.id}).then(function () { state.has = false; state.pub = ''; paint(); toast('the key is gone'); }).catch(oops);
    });
  };
  paint();
  s.appendChild(P.box);
  f.ssh_cert = el('textarea', 'mono rb-area small');
  f.ssh_cert.value = t.ssh_cert || '';
  f.ssh_cert.placeholder = 'ssh-ed25519-cert-v01@openssh.com AAAA…';
  var cf = formField('SSH certificate of the key (only if the server wants one)', f.ssh_cert);
  cf.style.marginTop = '12px';
  s.appendChild(cf);
  body.appendChild(s);
  var h = el('div', 'rb-sec');
  h.appendChild(el('h4', '', 'The server’s host key'));
  var H = rbPanel('The key the server proves itself with. Trusted once, after comparing its fingerprint with the server’s own (<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on it); a server answering with any other is refused - somebody in between, or the server reinstalled.');
  var hf = cmdButton('Forget it', 'forget', 'danger');
  H.row.appendChild(hf);
  H.row.appendChild(el('span', 'spacer'));
  H.row.appendChild(rbTryButton(t, cur));
  var paintHost = function (fps) {
    clear(H.below);
    hf.disabled = !(fps && fps.length);
    if (fps && fps.length) {
      H.below.appendChild(el('p', 'btnhelp ro', 'Trusted. Click to copy.'));
      fps.forEach(function (x) { H.below.appendChild(rbCopyme(x)); });
    } else {
      H.below.appendChild(el('p', 'btnhelp', 'Not trusted yet — Try reaching it shows the fingerprint to trust.'));
    }
  };
  hf.onclick = function () {
    rbConfirm('Forget the host key', 'Backups stop going there until it is trusted again.', 'Forget it', function () {
      api('rbackup', {action: 'hostkey_forget', id: cur.id}).then(function () { paintHost([]); }).catch(oops);
    });
  };
  paintHost(t.hostkey_fp);
  rbSshBlock.paintHost = paintHost;
  h.appendChild(H.box);
  body.appendChild(h);
}
function rbFtpsBlock(body, t, f, cur) {
  var s = el('div', 'rb-sec');
  s.appendChild(el('h4', '', 'TLS'));
  var g = el('div', 'formgrid');
  f.implicit = selectBox([['0', 'explicit - AUTH TLS on port 21'], ['1', 'implicit - TLS from the start, port 990']], t.implicit ? '1' : '0');
  f.implicit._get = function () { return f.implicit.value === '1' ? 1 : 0; };
  f.implicit.onchange = function () { if (f.port && (!f.port.value || f.port.value === '21' || f.port.value === '990')) f.port.value = f.implicit.value === '1' ? '990' : '21'; };
  g.appendChild(formField('TLS', f.implicit));
  f.tls_check = selectBox([['system', 'against the authorities this machine trusts'], ['ca', 'against an authority of my own'], ['pin', 'pinned: exactly this certificate'], ['none', 'not checked (not safe)']], t.tls_check || 'system');
  hsOptions(f.tls_check, ['none'], 'backup:ftps');
  g.appendChild(formField('The server’s certificate is checked', f.tls_check));
  s.appendChild(g);
  f.ca = el('textarea', 'mono rb-area small');
  f.ca.value = t.ca || '';
  f.ca.placeholder = '-----BEGIN CERTIFICATE-----';
  var caf = formField('The authority (PEM)', f.ca, t.ca_info ? 'Now: ' + (t.ca_info.subject || '') + ' · ' + rbWhen(t.ca_info.not_after) : 'The certificate of the authority that signed the server’s.');
  s.appendChild(caf);
  f.pin = textBox(t.pin || '', '64 hex digits - Try reaching it shows the server’s', 'mono');
  var pinf = formField('Pinned SHA-256 fingerprint', f.pin);
  s.appendChild(pinf);
  var show = function () { caf.hidden = f.tls_check.value !== 'ca'; pinf.hidden = f.tls_check.value !== 'pin'; };
  f.tls_check.onchange = show;
  show();
  rbFtpsBlock.pin = f.pin;
  rbFtpsBlock.check = f.tls_check;
  body.appendChild(s);
  var cc = el('div', 'rb-sec');
  cc.appendChild(el('h4', '', 'Client certificate'));
  var P = rbPanel('Only for a server that asks for one. Made here, its key never leaves this machine except when you download it; the server gets the <b>certificate</b> - give it to its administrator.');
  var mk = cmdButton('Make one', 'key', '');
  explain(mk, 'A key and a certificate for it, made here (EC P-256, five years). Any one kept is replaced.');
  var own = cmdButton('Use my own', 'upload', '');
  explain(own, 'A certificate and its key you have: PEM (both, in any order) or a PFX / PKCS#12 file with its password.');
  var dl = cmdButton('Download it', 'download', '');
  explain(dl, 'The certificate as a file (not its key), for the server’s administrator.');
  var fg = cmdButton('Forget it', 'forget', 'danger');
  [mk, own, dl, fg].forEach(function (b) { P.row.appendChild(b); });
  P.row.appendChild(el('span', 'spacer'));
  P.row.appendChild(rbTryButton(t, cur));
  var state = {cert: t.client_cert, info: t.client_cert_info};
  var paint = function () {
    clear(P.below);
    dl.disabled = fg.disabled = !state.cert;
    if (!state.cert) {
      P.below.appendChild(el('p', 'btnhelp', 'No client certificate — most servers want none.'));
      return;
    }
    if (state.info) P.below.appendChild(noI18n(el('p', 'btnhelp ro', (state.info.subject || '') + ' · ' + rbWhen(state.info.not_after))));
    P.below.appendChild(el('p', 'btnhelp', 'The certificate. Click it to copy.'));
    P.below.appendChild(rbCopyme(state.cert, 'the certificate is on the clipboard'));
  };
  mk.onclick = function () {
    rbConfirm('Make a client certificate', 'A key and a certificate for it are made here; the key stays on this machine.' + (state.cert ? '<br><br><b>The one kept now is replaced</b>: the server has to be given the new certificate.' : ''), 'Make one', function () {
      rbNeedSaved(t.kind, cur).then(function () { return api('rbackup', {action: 'cert_make', id: cur.id, cn: 'upsmon-backup-' + (RB.node || '')}); })
        .then(function (x) { state.cert = x.cert; state.info = x.info; paint(); toast('made — give the certificate to the server', 'good'); }).catch(oops);
    }, false);
  };
  own.onclick = function () {
    modalOver(function () {
      modal('Use my own client certificate', function (body2) {
        var p = el('p', 'note');
        p.innerHTML = 'The certificate and its private key, as PEM - pasted, in any order - or a <code>.pfx</code> / <code>.p12</code> file. The key is kept sealed and never shown back.';
        body2.appendChild(p);
        var area = el('textarea', 'mono');
        area.rows = 11;
        area.id = 'rb-cert-area';
        area.spellcheck = false;
        area.placeholder = '-----BEGIN CERTIFICATE-----\n…\n-----BEGIN PRIVATE KEY-----';
        body2.appendChild(area);
        var file = el('input');
        file.type = 'file';
        file.accept = '.pem,.crt,.key,.pfx,.p12';
        file.onchange = function () {
          var fl = file.files[0];
          if (!fl) return;
          if (/\.(pfx|p12)$/i.test(fl.name)) fl.arrayBuffer().then(function (buf) {
            var b = new Uint8Array(buf), s2 = '';
            for (var i = 0; i < b.length; i++) s2 += String.fromCharCode(b[i]);
            area.value = btoa(s2);
          });
          else fl.text().then(function (x) { area.value = (area.value ? area.value + '\n' : '') + x; });
        };
        body2.appendChild(formField('Or a file', file));
        var pw = maskBox('', '', 'mono');
        pw.id = 'rb-cert-pw';
        body2.appendChild(formField('The password of the key or of the PFX, if it has one', pw));
      }, [{words: 'Cancel', close: true},
          {words: 'Keep this certificate', cls: 'primary', close: true, go: function () {
            var text = $('rb-cert-area').value, pass = $('rb-cert-pw').value;
            rbNeedSaved(t.kind, cur).then(function () { return api('rbackup', {action: 'cert_given', id: cur.id, text: text, password: pass}); })
              .then(function (x) { state.cert = x.cert; state.info = x.info; paint(); toast('the certificate was stored', 'good'); }).catch(oops);
          }}]);
    });
  };
  dl.onclick = function () {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([state.cert], {type: 'application/x-pem-file'}));
    a.download = 'upsmon-backup-client.crt';
    document.body.appendChild(a); a.click(); a.remove();
  };
  fg.onclick = function () {
    rbConfirm('Forget the client certificate', 'Its key is deleted from this machine. A server that asks for one will refuse backups until another is made and given to it.', 'Forget it', function () {
      api('rbackup', {action: 'cert_forget', id: cur.id}).then(function () { state.cert = ''; state.info = null; paint(); }).catch(oops);
    });
  };
  paint();
  cc.appendChild(P.box);
  body.appendChild(cc);
}
function rbTry(t, data, button, inEditor) {
  if (button) busy(button, true);
  var ask = {action: 'try', id: t.id || ''};
  if (data) ask.target = data;
  api('rbackup', ask).then(function (x) {
    if (button) busy(button, false);
    var show = function (host) {
      clear(host);
      if (x.hostkey_needed) {
        host.appendChild(el('p', 'note warn', 'The server shows this host key. Compare it with the server’s own fingerprint before you trust it:'));
        (x.fingerprints || []).forEach(function (fp) { host.appendChild(noI18n(el('div', 'mono small', fp))); });
        var tb = cmdButton('Trust it', 'check', 'small primary');
        tb.onclick = function () {
          var save = (inEditor && rbEdit.form) ? rbSaveForm(t.kind, {id: t.id}) : Promise.resolve(t);
          save.then(function (saved) {
            return api('rbackup', {action: 'hostkey_trust', id: saved.id, hostkey: x.hostkey}).then(function (y) {
              toast('trusted', 'good');
              if (rbSshBlock.paintHost) rbSshBlock.paintHost(y.fingerprints);
              t.id = saved.id;
              rbTry(saved, inEditor ? rbFormData(t.kind) : null, button, inEditor);
            });
          }).catch(oops);
        };
        host.appendChild(tb);
        return;
      }
      var box = el('div', 'note ' + (x.ok ? 'good' : 'bad'));
      box.appendChild(el('b', '', x.ok ? 'It works (' + x.secs + ' s)' : 'It does not work'));
      var ul = el('ul', 'rb-steps');
      (x.steps || []).forEach(function (s) { ul.appendChild(el('li', '', '✓ ' + s)); });
      if (x.error) ul.appendChild(el('li', 'bad', '✗ ' + x.error));
      box.appendChild(ul);
      var sc = x.server_cert;
      if (sc && sc.fingerprint) {
        var p = el('div', 'small');
        p.appendChild(el('span', '', 'The server’s certificate: '));
        p.appendChild(noI18n(el('span', 'mono', ((sc.cert || {}).subject || '') + ' · SHA-256 ' + sc.fingerprint)));
        box.appendChild(p);
        if (inEditor && rbFtpsBlock.pin) {
          var pin = cmdButton('Pin this certificate', 'pin', 'small');
          pin.onclick = function () { rbFtpsBlock.check.value = 'pin'; rbFtpsBlock.check.onchange(); rbFtpsBlock.pin.value = sc.fingerprint; toast('pinned - Save to keep it', 'good'); };
          box.appendChild(pin);
        }
      }
      host.appendChild(box);
      if (inEditor) host.appendChild(hideBar(function () { clear(host); }));
    };
    var host = inEditor ? $('rb-try-out') : null;
    if (host) show(host);
    else modal('Trying ' + (t.name || ''), function (body) { var h = el('div'); body.appendChild(h); show(h); }, [{words: 'Close', close: true}], 'medium');
    if (!inEditor) loadRbackup();
  }).catch(function (e) { if (button) busy(button, false); oops(e); });
}
function rbListThere(t) {
  modal('Backups at ' + t.name, function (body) {
    var host = el('div');
    host.appendChild(el('p', 'center muted', 'Asking…'));
    body.appendChild(host);
    api('rbackup', {action: 'list', id: t.id}).then(function (x) {
      clear(host);
      var files = x.files || [];
      if (!files.length) { host.appendChild(el('p', 'note', 'No backup of upsmon there.')); return; }
      host.appendChild(listTable(['Made', 'Node', 'Size', '', ''], files, function (fl) {
        var tr = el('tr');
        var w = el('td');
        w.appendChild(el('div', '', new Date(fl.when * 1000).toLocaleString(numLang())));
        w.appendChild(noI18n(el('div', 'mono small muted', fl.name)));
        tr.appendChild(w);
        var n = el('td');
        n.appendChild(noI18n(el('span', '', fl.node)));
        if (fl.mine) { n.appendChild(document.createTextNode(' ')); n.appendChild(el('span', 'tag info', 'this node')); }
        tr.appendChild(n);
        var sz = el('td', 'num');
        sz.textContent = rbBytes(fl.bytes);
        if (!fl.encrypted) { sz.appendChild(document.createTextNode(' ')); sz.appendChild(el('span', 'tag bad', 'not locked')); }
        tr.appendChild(sz);
        var a = el('td', 'rowtools');
        var dl = iconButton('download', 'Download it');
        dl.onclick = function () { window.location.href = '?api=rbackup-download&id=' + encodeURIComponent(t.id) + '&name=' + encodeURIComponent(fl.name); };
        a.appendChild(dl);
        var pb = iconButton('undo', 'Put this back…');
        pb.onclick = function () { rbPutBackConfirm({id: t.id, name: fl.name, encrypted: fl.encrypted, when: fl.when, node: fl.node}); };
        a.appendChild(pb);
        var del = iconButton('trash', 'Delete it there');
        del.onclick = function () {
          confirmThen('Delete ' + htmlText(fl.name) + '?', 'It is deleted at ' + htmlText(t.name) + ', with its checksum and its RESTORE.md.', 'Delete it', function () {
            api('rbackup', {action: 'delete_file', id: t.id, name: fl.name}).then(function () { toast('deleted', 'good'); rbListThere(t); }).catch(oops);
          });
        };
        a.appendChild(del);
        tr.appendChild(a);
        return tr;
      }, 'plain'));
    }).catch(function (e) { clear(host); host.appendChild(el('p', 'note bad', String(e.message || e))); });
  }, [{words: 'Close', close: true}], 'large');
}
function rbPutBackConfirm(what) {
  modal('Put this backup back?', function (body) {
    var facts = [];
    if (what.when) facts.push(['Made', new Date(what.when * 1000).toLocaleString(numLang())]);
    if (what.node) facts.push(['On', what.node]);
    if (what.manifest) {
      var m = what.manifest;
      facts = [['Made', m.made_words], ['On', m.node + ' (' + (m.host || '') + ')'], ['upsmon', m.upsmon], ['Tokens', String(m.tokens)], ['Database', m.engine_words || m.engine]];
    }
    if (facts.length) body.appendChild(peekFacts(facts));
    body.appendChild(el('p', 'note warn', 'Everything in the database is replaced with what the backup holds - tokens, accounts, settings, certificates, logs, and who is signed in: you sign in again afterwards, with an account the backup has. A copy of what is here now is made first (Settings → The database → Copies). In a cluster it goes over to the other node too.'));
    var pw = maskBox('', what.encrypted === false ? '(not locked)' : 'the password of the backups - empty: the one set here', 'mono');
    body.appendChild(formField('Its password', pw, 'Only when it was locked with another password than the one set here now.'));
    rbPutBackConfirm.pw = pw;
  }, [{words: 'No, leave it', close: true},
      {words: 'Put it back', cls: 'danger', icon: 'undo', close: true, go: function () {
        var ask = {action: 'restore', password: rbPutBackConfirm.pw.value};
        if (what.upload) ask.upload = what.upload; else { ask.id = what.id; ask.name = what.name; }
        api('rbackup', ask).then(function (x) {
          toast(x.message, 'good');
          rbRestoreWatch();
        }).catch(oops);
      }}], 'medium');
}
function rbRestoreWatch(title) {
  modal(title || 'Putting the backup back', function (body) {
    var bar = el('div', 'going wide');
    bar.innerHTML = '<div class="bar"><span id="rbr-fill"></span></div><div class="says" id="rbr-says"></div>';
    body.appendChild(bar);
  }, [{words: 'Close', close: true}], 'medium');
  var step = function () {
    api('db', {action: 'job'}).then(function (d) {
      var j = d.job || {};
      if ($('rbr-fill')) $('rbr-fill').style.width = (j.whole ? Math.round(100 * j.done / j.whole) : 5) + '%';
      if ($('rbr-says')) $('rbr-says').textContent = (j.what || '') + (j.says ? ' — ' + j.says : '');
      if (j.running) { setTimeout(step, 1000); return; }
      if (!j.what && !j.result && !j.error) { setTimeout(step, 1000); return; }
      if (j.error) { if ($('rbr-says')) $('rbr-says').textContent = j.error; toast('putting it back failed: ' + j.error, 'bad'); return; }
      var r = j.result || {};
      if ($('rbr-says')) {
        var said = $('rbr-says');
        clear(said);
        said.appendChild(el('div', '', 'Put back.'));
        (r.said || []).concat(r.key ? [r.key] : []).forEach(function (x) { said.appendChild(el('div', 'small', x)); });
        if (r.safety) said.appendChild(el('div', 'small muted', 'What was here is kept as ' + r.safety));
      }
      toast(title ? 'the database is back' : 'the backup is back', 'good');
      if (title) setTimeout(function () { location.reload(); }, 4000);
    }).catch(function (e) {
      /* Who was signed in is what the backup says now: the sign-in page. */
      if (/signed in|401/i.test(String(e && e.message || e))) {
        if ($('rbr-says')) $('rbr-says').textContent = 'Put back. Sign in again - with an account the backup has.';
        setTimeout(function () { location.reload(); }, 3500);
        return;
      }
      setTimeout(step, 2000);
    });
  };
  setTimeout(step, 500);
}
function rbPutBackFile() {
  var file = el('input');
  file.type = 'file';
  file.accept = '.enc,.gz';
  file.onchange = function () {
    var fl = file.files[0];
    if (!fl) return;
    toast('sending ' + fl.name + '…', 'good');
    bigFetch('?api=rbackup-upload', fl).then(function (r) {
      return r.json().then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('the server said ' + r.status));
        return d;
      });
    }).then(function (d) {
      if (d.said) toast(d.said, 'bad');
      rbPutBackConfirm({upload: d.upload, encrypted: d.locked, manifest: d.manifest});
    }).catch(oops);
  };
  file.click();
}

/* A button busy with something slow, the seconds counted beside its words
   (1.0.109). Returns the function that ends it. */
function busyCount(button) {
  busy(button, true);
  var began = Date.now();
  var tag = el('span', 'busy-secs', '');
  button.appendChild(tag);
  var tick = setInterval(function () { tag.textContent = ' · ' + Math.round((Date.now() - began) / 1000) + ' s'; }, 500);
  return function () { clearInterval(tick); tag.remove(); busy(button, false); };
}


/* ======== restart and power off (OTP admin.js 12494-12648) ======== */
/* ---- Settings → Restart and power off (1.0.119) ------------------------------- */
var PW = {d: null, poll: null, failSince: 0, mine: false, reload: false};
function loadPower() {
  api('power').then(function (d) { PW.d = d; PW.failSince = 0; drawPower(); pwPollFor(); }).catch(oops);
}
function pwPollFor() {
  var live = PW.d && PW.d.plan && PW.d.plan.id && !pwAllDone(PW.d);
  if (live && !PW.poll) PW.poll = setInterval(pwPoll, 2000);
  if (!live && PW.poll) { clearInterval(PW.poll); PW.poll = null; }
}
function pwPoll() {
  if (TAB !== 'settings' || PANE !== 'power') { clearInterval(PW.poll); PW.poll = null; return; }
  api('power').then(function (d) {
    var wasAway = !!PW.failSince;
    PW.d = d; PW.failSince = 0;
    drawPower(true);
    if (pwAllDone(d)) {
      clearInterval(PW.poll); PW.poll = null;
      toast(d.plan.how === 'reboot' ? 'every node is up again' : 'switched off', 'good');
      if (wasAway || PW.reload) setTimeout(function () { location.reload(); }, 2500);
    }
  }).catch(function () { if (!PW.failSince) PW.failSince = Date.now(); drawPowerAway(); });
}
function pwStateOf(d, n) {
  var r = n.row || {};
  var plan = d.plan || {};
  if (!r.state) return {k: 'wait', w: plan.order === 'rolling' ? 'waits its turn' : 'asked'};
  if (r.state === 'failed') return {k: 'bad', w: 'failed: ' + (r.said || '')};
  if (r.state === 'back') return {k: 'ok', w: 'up again'};
  if (r.state === 'going') {
    if (plan.how === 'poweroff') return n.alive && (d.now - (r.down_at || 0)) < 20 ? {k: 'going', w: 'switching off'} : {k: 'ok', w: 'switched off'};
    if (n.alive && (n.started || 0) > (r.down_at || 0)) return {k: 'going', w: 'starting'};
    if (n.alive && d.now < (r.down_at || 0) + 15) return {k: 'going', w: 'going down'};
    return {k: 'going', w: 'restarting'};
  }
  return {k: 'wait', w: r.state};
}
function pwAllDone(d) {
  if (!d.plan || !d.plan.id) return true;
  return d.nodes.filter(function (n) { return (d.plan.targets || []).indexOf(n.name) >= 0; })
    .every(function (n) { var s = pwStateOf(d, n); return s.k === 'ok' || s.k === 'bad'; });
}
function drawPower(live) {
  var real = $('pw-host');
  if (!real || !PW.d) return;
  liveFill(real, function (host) {
  var d = PW.d;
  if (d.plan && d.plan.id) host.appendChild(pwProgress(d));
  var grid = el('div', 'pw-grid');
  d.nodes.forEach(function (n) {
    var c = el('div', 'card pw-node');
    var h = el('div', 'pw-head');
    h.appendChild(el('span', 'dot ' + (n.alive ? 'ok' : 'bad')));
    h.appendChild(noI18n(el('b', '', n.name)));
    if (n.me) h.appendChild(el('span', 'tag info', 'this page'));
    c.appendChild(h);
    c.appendChild(netFacts([
      ['State', n.alive ? 'answering' : 'not answering'],
      ['Address', n.address || '', true],
      ['Running for', n.started ? span(d.now - n.started) : ''],
      ['Version', n.version || '', true]
    ]));
    var row = el('div', 'btnrow');
    var rb = cmdButton('Restart', 'refresh', '');
    var off = cmdButton('Power off', 'power', 'danger');
    rb.disabled = off.disabled = !!d.busy || !n.alive;
    rb.onclick = function () { pwAsk('reboot', [n.name], 'one', n); };
    off.onclick = function () { pwAsk('poweroff', [n.name], 'one', n); };
    row.appendChild(rb); row.appendChild(off);
    c.appendChild(row);
    grid.appendChild(c);
  });
  host.appendChild(grid);
  if (d.cluster) {
    var both = el('div', 'card full');
    both.appendChild(el('h2', '', 'Both nodes'));
    var all = d.nodes.map(function (n) { return n.name; });
    var row2 = el('div', 'btnrow');
    var r1 = cmdButton('Restart one after the other', 'refresh', 'primary');
    explain(r1, 'The other node first, then this one - each in maintenance while it restarts, so the VIP address and the service never stop.');
    var r2 = cmdButton('Restart both at once', 'refresh', '');
    var r3 = cmdButton('Power off both', 'power', 'danger');
    [r1, r2, r3].forEach(function (b) { b.disabled = !!d.busy; });
    r1.onclick = function () { pwAsk('reboot', all, 'rolling'); };
    r2.onclick = function () { pwAsk('reboot', all, 'together'); };
    r3.onclick = function () { pwAsk('poweroff', all, 'together'); };
    row2.appendChild(r1); row2.appendChild(r2); row2.appendChild(r3);
    both.appendChild(row2);
    host.appendChild(both);
  }
  }, live, function () { explainWhatWasDrawn(real); });
}
function pwAsk(how, targets, order, n) {
  var d = PW.d;
  var who = targets.join(', ');
  var words;
  if (how === 'poweroff') words = targets.length > 1 ? 'Both nodes are switched off. Nothing answers - the dashboard, the pages - until somebody switches them on again at the machines.'
    : (d.cluster ? n.name + ' is switched off; the VIP address moves to the other node, which goes on answering alone. It has to be switched on again at the machine.' : 'The server is switched off. Nothing answers until somebody switches it on again at the machine.');
  else if (order === 'rolling') words = 'One after the other: each goes into maintenance, the VIP address moves to the other node, it restarts and comes back into service - then the next. RADIUS and the pages go on answering all the time.';
  else if (targets.length > 1) words = 'Both restart at the same moment: for a minute or two nothing answers - the dashboard and the pages.';
  else words = d.cluster ? n.name + ' goes into maintenance, the VIP address moves to the other node, and it restarts; back up, it comes back into service by itself.' : 'The server restarts: for a minute or two nothing answers.';
  confirmThen((how === 'reboot' ? 'Restart ' : 'Power off ') + who + '?', htmlText(words), how === 'reboot' ? 'Restart' : 'Power off', function () {
    api('power', {how: how, targets: targets, order: order}).then(function (r) {
      toast(r.message, 'good');
      PW.reload = targets.indexOf(((d.nodes.filter(function (x) { return x.me; })[0]) || {}).name) >= 0;
      loadPower();
    }).catch(oops);
  }, how === 'poweroff');
}
function pwProgress(d) {
  var plan = d.plan;
  var card = el('div', 'card full net-job');
  var done = pwAllDone(d);
  card.appendChild(el('h2', '', (plan.how === 'reboot' ? 'Restart' : 'Power-off') + (done ? ' - done' : ' under way')));
  var ol = el('ol', 'net-steps done');
  d.nodes.filter(function (n) { return (plan.targets || []).indexOf(n.name) >= 0; })
    .sort(function (a, b) { return plan.targets.indexOf(a.name) - plan.targets.indexOf(b.name); })
    .forEach(function (n) {
      var st = pwStateOf(d, n);
      var li = el('li', st.k === 'ok' ? 'good' : (st.k === 'bad' ? 'bad' : ''));
      li.appendChild(el('span', 'mark', st.k === 'ok' ? '✓' : (st.k === 'bad' ? '✗' : '…')));
      li.appendChild(noI18n(el('b', '', n.name + ' ')));
      li.appendChild(el('span', '', st.w));
      var r = n.row || {};
      if (st.k === 'going' && r.down_at) {
        var t = Math.max(0, d.now - r.down_at);
        var bar = el('div', 'going wide');
        bar.innerHTML = '<div class="bar"><span></span></div>';
        bar.querySelector('span').style.width = Math.min(100, Math.round(t / 120 * 100)) + '%';
        li.appendChild(el('span', 'muted small', ' ' + span(t)));
        li.appendChild(bar);
      }
      ol.appendChild(li);
    });
  card.appendChild(ol);
  if (done) card.appendChild(hideBar(function () {
    return api('power', {action: 'hide'}).then(function (x) { PW.d = x; drawPower(); });
  }, 'Hidden by itself half an hour after it began.'));
  return card;
}
function drawPowerAway() {
  var host = $('pw-host');
  if (!host) return;
  var box = $('pw-away');
  if (!box) { box = el('div', 'card full net-job'); box.id = 'pw-away'; host.insertBefore(box, host.firstChild); }
  clear(box);
  var away = Math.round((Date.now() - PW.failSince) / 1000);
  box.appendChild(el('h2', '', 'This page\'s server is restarting'));
  var bar = el('div', 'going wide');
  bar.innerHTML = '<div class="bar"><span></span></div>';
  bar.querySelector('span').style.width = Math.min(100, Math.round(away / 120 * 100)) + '%';
  box.appendChild(bar);
  box.appendChild(el('p', 'note', 'Not answering for ' + span(away) + ' - asked again every two seconds; the page comes back by itself.'));
}


/* ======== the time (OTP admin.js 12649-12904) ======== */
/* ---- Settings → Time (1.0.120) -------------------------------------------------
   Each node's clock as chrony sees it, its sources, and the time servers for the
   whole cluster. */
var NTP = {d: null, poll: null, draft: null, node: ''};
function loadNtp() {
  api('ntp').then(function (d) {
    NTP.d = d;
    if (!NTP.node) NTP.node = (d.nodes[0] || {}).name;
    drawNtp();
    if (!NTP.poll) NTP.poll = setInterval(function () {
      if (TAB !== 'settings' || PANE !== 'time') { clearInterval(NTP.poll); NTP.poll = null; return; }
      api('ntp').then(function (x) { NTP.d = x; drawNtp(true); }).catch(function () {});
    }, 10000);
  }).catch(oops);
}
function ntpMs(s) {
  if (s === undefined || s === null || isNaN(s)) return '–';
  var ms = s * 1000;
  var a = Math.abs(ms);
  return (ms >= 0 ? '+' : '−') + (a >= 1000 ? (a / 1000).toFixed(2) + ' s' : (a >= 10 ? a.toFixed(1) : a.toFixed(3)) + ' ms');
}
function ntpHealth(n) {
  var d = (n.now || {}).data || {};
  var t = d.tracking || {};
  if (!d.time) return {k: 'bad', w: n.alive ? 'not read yet' : 'not answering'};
  if (!d.chrony) return {k: d.ntpsynchronized === 'yes' ? 'ok' : 'bad', w: d.ntpsynchronized === 'yes' ? 'synchronised (not chrony)' : 'chrony is not installed'};
  if (t.leap === 'Not synchronised' || !t.stratum) return {k: 'bad', w: 'not synchronised'};
  var off = Math.abs(t.offset || 0);
  if (off > 1) return {k: 'bad', w: 'synchronised, but off'};
  if (off > 0.1) return {k: 'warn', w: 'synchronised'};
  return {k: 'ok', w: 'synchronised'};
}
function drawNtp(quiet) {
  var real = $('ntp-host');
  if (!real || !NTP.d) return;
  /* What the server has, until something is changed here. */
  if (!NTP.draft || !PENDING.ntp) NTP.draft = JSON.parse(JSON.stringify(NTP.d.conf));
  liveFill(real, function (host) {
  var d = NTP.d;
  var grid = el('div', 'pw-grid');
  d.nodes.forEach(function (n) {
    var nd = (n.now || {}).data || {};
    var t = nd.tracking || {};
    var h = ntpHealth(n);
    var c = el('div', 'card ntp-node');
    var head = el('div', 'pw-head');
    head.appendChild(el('span', 'dot ' + (h.k === 'ok' ? 'ok' : (h.k === 'warn' ? 'warn' : 'bad'))));
    head.appendChild(noI18n(el('b', '', n.name)));
    if (n.me) head.appendChild(el('span', 'tag info', 'this page'));
    head.appendChild(el('span', 'tag ' + (h.k === 'ok' ? 'ok' : (h.k === 'warn' ? 'warn' : 'crit')), h.w));
    c.appendChild(head);
    var big = el('div', 'ntp-big');
    big.appendChild(noI18n(el('span', 'ntp-off', ntpMs(t.offset))));
    big.appendChild(el('span', 'muted small', ' off the time servers'));
    c.appendChild(big);
    var clock = '';
    if (nd.time) {
      var dt = new Date((nd.time + (d.now - (n.now.at || d.now))) * 1000);
      clock = dt.toLocaleString(numLang());
    }
    c.appendChild(netFacts([
      ['Follows', t.ref || t.ref_id || '', true],
      ['Stratum', t.stratum !== undefined ? String(t.stratum) : '', true],
      ['Last correction', ntpMs(t.last_offset), true],
      ['Frequency', t.freq !== undefined ? t.freq.toFixed(3) + ' ppm' : '', true],
      ['Root delay / dispersion', t.root_delay !== undefined ? ntpMs(t.root_delay).replace('+', '') + ' / ' + ntpMs(t.root_disp).replace('+', '') : '', true],
      ['Leap status', t.leap || ''],
      ['Time zone', nd.timezone || '', true],
      ['Its time', clock],
      ['Read', n.now && n.now.at ? ago(n.now.at) : '']
    ]));
    var ap = n.applied || {};
    if (ap.at) {
      var st = el('p', 'small ' + (ap.ok ? 'muted' : 'bad'));
      st.textContent = (ap.ok ? 'Time servers set ' : 'Time servers NOT set ') + ago(ap.at) + (ap.said ? ': ' + ap.said : '');
      c.appendChild(st);
    }
    var row = el('div', 'btnrow');
    var re = cmdButton('Read it again', 'refresh', 'small');
    re.onclick = function () { api('ntp', {action: 'read', node: n.name}).then(function (r) { toast(r.message, 'good'); setTimeout(loadNtp, 4000); }).catch(oops); };
    var sy = cmdButton('Step it now', 'clock', 'small');
    explain(sy, 'The clock set to the time servers at once (chronyc makestep), not slewed slowly - for a clock that is far off.');
    sy.onclick = function () {
      confirmThen('Step the clock of ' + n.name + ' now?', htmlText('The clock jumps to the time servers\' time at once. Codes and logs written in that moment may look out of order.'), 'Step it', function () {
        api('ntp', {action: 'sync', node: n.name}).then(function (r) { toast(r.message, 'good'); setTimeout(loadNtp, 6000); }).catch(oops);
      }, false);
    };
    row.appendChild(re); row.appendChild(sy);
    c.appendChild(row);
    grid.appendChild(c);
  });
  host.appendChild(grid);
  if (d.cluster && d.nodes.length > 1) {
    var a = ((d.nodes[0].now || {}).data || {}).tracking || {};
    var b = ((d.nodes[1].now || {}).data || {}).tracking || {};
    if (a.offset !== undefined && b.offset !== undefined) {
      var diff = Math.abs(a.offset - b.offset);
      host.appendChild(el('p', 'note ' + (diff > 1 ? 'bad' : (diff > 0.1 ? 'warn' : 'good')), 'Between the two nodes: ' + ntpMs(diff).replace('+', '') + (diff > 1 ? ' - codes right on one node may be refused on the other' : '')));
    }
  }
  /* Sources, per node. */
  var sc = el('div', 'card full');
  var sh = el('h2', '', 'Where the time comes from');
  sc.appendChild(sh);
  if (d.cluster) {
    var seg = el('div', 'seg');
    d.nodes.forEach(function (n) {
      var bt = el('button', n.name === NTP.node ? 'on' : '', n.name);
      bt.type = 'button';
      noI18n(bt);
      bt.onclick = function () { NTP.node = n.name; drawNtp(false); };
      seg.appendChild(bt);
    });
    sc.appendChild(seg);
  }
  var sn = d.nodes.filter(function (x) { return x.name === NTP.node; })[0] || d.nodes[0];
  var srcs = (((sn || {}).now || {}).data || {}).sources || [];
  var STATES = {'*': ['ok', 'followed'], '+': ['ok', 'combined'], '-': ['', 'not combined'], '?': ['crit', 'unreachable'],
                'x': ['crit', 'false ticker'], '~': ['warn', 'too variable']};
  if (!srcs.length) sc.appendChild(el('p', 'note', 'No source - chrony has none, or is not installed.'));
  else sc.appendChild(listTable(['State', 'Source', 'Stratum', 'Asked every', 'Reached', 'Last heard', 'Offset'], srcs, function (s) {
    var tr = el('tr');
    var stt = STATES[s.state] || ['', s.state];
    var td = el('td');
    td.appendChild(el('span', 'tag ' + stt[0], stt[1]));
    if (s.mode === '=') td.appendChild(el('span', 'muted small', ' peer'));
    tr.appendChild(td);
    tr.appendChild(noI18n(el('td', 'mono', s.name)));
    tr.appendChild(el('td', 'num', String(s.stratum)));
    tr.appendChild(el('td', 'num', span(Math.pow(2, s.poll || 0))));
    var r = el('td');
    var bits = el('span', 'reach');
    for (var i = 7; i >= 0; i--) bits.appendChild(el('i', (s.reach >> i) & 1 ? 'on' : ''));
    bits.title = (s.reach || 0).toString(2).padStart(8, '0') + ' - the last 8 tries';
    r.appendChild(bits);
    tr.appendChild(r);
    tr.appendChild(el('td', 'muted', s.last_rx === null || s.last_rx === undefined ? '–' : span(s.last_rx) + ' ago'));
    tr.appendChild(noI18n(el('td', 'num mono', ntpMs(s.offset) + ' ± ' + ntpMs(s.error).replace('+', ''))));
    return tr;
  }, 'plain'));
  var own = (((sn || {}).now || {}).data || {}).own || [];
  if (own.length && !(((sn || {}).now || {}).data || {}).managed) {
    sc.appendChild(el('p', 'muted small', 'Its own /etc/chrony.conf: '));
    sc.appendChild(noI18n(el('pre', 'mono small', own.join('\n'))));
  }
  host.appendChild(sc);
  host.appendChild(ntpForm());
  }, !!quiet, function () { explainWhatWasDrawn(real); });
}
function ntpForm() {
  var d = NTP.d;
  var dr = NTP.draft;
  var card = el('div', 'card full');
  card.id = 'ntp-form';
  /* Anything changed here waits for the save bar at the bottom. */
  ['input', 'change'].forEach(function (ev) { card.addEventListener(ev, function () { ntpDirty(); }); });
  card.addEventListener('click', function (e) { if (e.target.closest && e.target.closest('button')) ntpDirty(); });
  card.appendChild(el('h2', '', 'The time servers'));
  var on = switchBox(dr.manage);
  var g0 = el('div', 'formgrid');
  g0.appendChild(formField('upsmon sets the time servers', on, 'Off: each machine keeps its own /etc/chrony.conf (AlmaLinux\'s pool, or what you set by hand) - shown and checked here, not changed. On: the servers below, the same on every node; the file\'s own server and pool lines are commented out, and put back when switched off again.'));
  card.appendChild(g0);
  var body = el('div');
  card.appendChild(body);
  var draw = function () {
    clear(body);
    body.hidden = !dr.manage;
    var list = el('div', 'ntp-servers');
    (dr.servers || []).forEach(function (s, i) {
      var row = el('div', 'ntp-srv');
      var hostIn = textBox(s.host, 'ntp.example.cz', 'mono');
      hostIn.oninput = function () { s.host = hostIn.value.trim(); };
      var kind = selectBox([['server', 'one server'], ['pool', 'a pool (several addresses)']], s.pool ? 'pool' : 'server');
      kind.onchange = function () { s.pool = kind.value === 'pool'; };
      row.appendChild(hostIn); row.appendChild(kind);
      [['iburst', 'iburst', 'Four quick questions at the start: synchronised in seconds, not minutes.'],
       ['prefer', 'preferred', 'Followed before the others when it is good.'],
       ['nts', 'NTS', 'Network Time Security: the server proves who it is (time.cloudflare.com, ptbtime1.ptb.de, nts.netnod.se…). Needs TCP 4460 out.']].forEach(function (o) {
        var l = el('label', 'check small');
        var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!s[o[0]];
        cb.onchange = function () { s[o[0]] = cb.checked; };
        l.appendChild(cb); l.appendChild(el('span', '', o[1]));
        explain(l, o[2]);
        row.appendChild(l);
      });
      var x = iconButton('trash', 'Take it away');
      x.onclick = function () { dr.servers.splice(i, 1); draw(); };
      row.appendChild(x);
      list.appendChild(row);
    });
    body.appendChild(list);
    var adds = el('div', 'btnrow');
    var add = cmdButton('Add a server', 'add', 'small');
    add.onclick = function () { dr.servers.push({host: '', pool: false, iburst: true, prefer: false, nts: false}); draw(); };
    adds.appendChild(add);
    [['cz.pool.ntp.org', true, false], ['pool.ntp.org', true, false], ['time.cloudflare.com', false, true], ['tik.cesnet.cz', false, false], ['tak.cesnet.cz', false, false]].forEach(function (p) {
      var b = cmdButton('+ ' + p[0], '', 'small');
      noI18n(b);
      b.onclick = function () {
        if (dr.servers.some(function (s) { return s.host === p[0]; })) return;
        dr.servers.push({host: p[0], pool: p[1], iburst: true, prefer: false, nts: p[2]}); draw();
      };
      adds.appendChild(b);
    });
    body.appendChild(adds);
    var g = el('div', 'formgrid');
    g.style.marginTop = '14px';
    if (d.cluster) {
      var peers = switchBox(dr.peers);
      peers._input.onchange = function () { dr.peers = !!peers._get(); };
      g.appendChild(formField('The nodes take each other too', peers, 'Each node is one more source for the other: if the servers above are out of reach, the two nodes at least keep one time - which is what codes need.'));
    }
    var stepS = textBox(String((dr.makestep || [1, 3])[0]), '1', 'mono');
    stepS.oninput = function () { dr.makestep = [stepS.value, (dr.makestep || [1, 3])[1]]; };
    var stepN = textBox(String((dr.makestep || [1, 3])[1]), '3', 'mono');
    stepN.oninput = function () { dr.makestep = [(dr.makestep || [1, 3])[0], stepN.value]; };
    g.appendChild(formField('Step when off by more than (s)', stepS, 'Further off than this, the clock jumps to the right time instead of being slowed or sped up gently.'));
    g.appendChild(formField('…in the first updates', stepN, 'How many updates after chronyd starts may step it: 3 is after a boot; -1 any time.'));
    var mins = textBox(String(dr.minsources || 1), '1', 'mono');
    mins.oninput = function () { dr.minsources = mins.value; };
    g.appendChild(formField('Sources that have to agree', mins, 'The clock is set only when at least this many sources agree. 1 with one server; 2 or 3 with several.'));
    var allow = textBox((dr.allow || []).join(', '), '192.0.2.0/24', 'mono');
    /* A list, as it came (1.0.146): kept as the typed text, the next drawing
       of the pane broke on .join and it stopped refreshing. */
    allow.oninput = function () { dr.allow = allow.value.split(/[\s,;]+/).filter(Boolean); };
    g.appendChild(formField('Serve the time to', allow, 'Networks that may ask these nodes for the time (UDP 123) - for the VPN concentrators, say. Empty: nobody. The firewall opens it by itself.'));
    body.appendChild(g);
  };
  on._input.onchange = function () { dr.manage = !!on._get(); draw(); };
  draw();
  var zones = d.zones || [];
  var tz = selectBox([['', '- as each machine has it -']].concat(zones.map(function (z) { return [z, z]; })), dr.timezone || '');
  tz.onchange = function () { dr.timezone = tz.value; };
  var g2 = el('div', 'formgrid');
  g2.style.marginTop = '14px';
  g2.appendChild(formField('Time zone', tz, 'Of the machines: the logs and the times on these pages. Codes do not depend on it.'));
  card.appendChild(g2);
  card.appendChild(el('p', 'muted small', 'Saved with the bar at the bottom; each node then puts them in by itself within seconds.'));
  return card;
}
function ntpDirty() {
  pendingSet('ntp', {pane: 'time', save: ntpSave, reset: function () {
    NTP.draft = JSON.parse(JSON.stringify(NTP.d.conf)); drawNtp(false);
  }});
}
function ntpSave() {
  var dr = NTP.draft;
  if (!dr) return Promise.resolve(true);
  var c = {manage: dr.manage, servers: (dr.servers || []).filter(function (s) { return s.host; }), peers: dr.peers,
           allow: dr.allow, step_s: (dr.makestep || [1, 3])[0], step_n: (dr.makestep || [1, 3])[1],
           minsources: dr.minsources, timezone: dr.timezone};
  return api('ntp', {action: 'save', conf: c}).then(function (r) {
    toast(r.message, 'good'); NTP.draft = null; setTimeout(loadNtp, 5000); return true;
  });
}


/* ======== the updates of the system (OTP admin.js 13215-13460) ======== */
/* ---- Settings → System updates (1.0.158) ----------------------------------------
   What each node has waiting, the update one node at a time - out of service,
   dnf or apt, back in service - with its output as it comes, and the restart
   it needs offered at the end. */
var OU = {d: null, poll: null, node: '', hide: false, reboot: 'ask', asked: 0};
try { OU.hide = localStorage.getItem('upsmon-ou-hide') === '1'; } catch (e) { /* only a convenience */ }
var OU_STATE = {waiting: ['waits its turn', 'dim'], draining: ['out of service', 'warn'],
                updating: ['updating', 'info'], rebooting: ['restarting', 'warn'],
                done: ['done', 'good'], failed: ['failed', 'bad'], skipped: ['left out', 'dim']};
function loadOsup() {
  api('osup').then(function (d) { OU.d = d; drawOsup(); ouPoll(ouLive(d)); }).catch(oops);
}
function ouLive(d) {
  d = d || OU.d || {};
  /* Just asked: the node has not begun yet, followed until it says (1.0.159). */
  if (Date.now() - OU.asked < 30000) return true;
  return (d.plan && d.plan.state === 'running') || (d.nodes || []).some(function (n) { return (n.check || {}).state === 'running'; }) || !!(d.power && d.power.id);
}
function ouPoll(on) {
  if (on && !OU.poll) {
    OU.poll = setInterval(function () {
      if (TAB !== 'settings' || PANE !== 'osup') { ouPoll(false); return; }
      api('osup').then(function (d) { OU.d = d; OU.away = 0; drawOsup(true); if (!ouLive(d)) ouPoll(false); })
        .catch(function () { OU.away = OU.away || Date.now(); drawOsup(true); });
    }, 2500);
  }
  if (!on && OU.poll) { clearInterval(OU.poll); OU.poll = null; }
}
/* Something asked of the nodes: followed from now on. */
function ouAsked() { OU.asked = Date.now(); ouPoll(true); }
/* A button clicked keeps the focus, and a live redraw leaves alone what has
   it - the window that was clicked in stayed as it was (1.0.159). */
function liveLetGo(host) {
  if (!host || host._letGo) return;
  host._letGo = true;
  host.addEventListener('click', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('button') : null;
    if (b && host.contains(b)) setTimeout(function () { if (document.activeElement === b) b.blur(); }, 0);
  });
}
function ouPercent(r) {
  var st = (r || {}).state;
  if (st === 'done' || st === 'failed') return 100;
  if (st === 'draining') return Math.min(8, 3 + Math.round((Date.now() / 1000 - Number(r.drain_at || r.at || 0)) / 3));
  if (st === 'updating') return Math.max(8, Math.min(95, Number(r.pct || 0)));
  if (st === 'rebooting') return 96;
  return 0;
}
function drawOsup(live) {
  var real = $('ou-host');
  if (!real || !OU.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = OU.d, plan = d.plan || {}, nodes = d.nodes || [];
    var running = plan.state === 'running';
    if (OU.away) host.appendChild(el('p', 'note warn', 'This page\'s server is not answering for ' + span(Math.round((Date.now() - OU.away) / 1000)) + ' - restarting, or the VIP address moving; asked again every few seconds.'));
    /* A restart the update left to do. */
    var need = nodes.filter(function (n) { return n.reboot; });
    if (need.length && !(d.power && d.power.id)) {
      var rb = el('div', 'card full notice warn ou-reboot');
      rb.appendChild(el('h2', '', need.length > 1 ? 'The nodes need a restart' : need[0].name + ' needs a restart'));
      rb.appendChild(el('p', 'note', 'A new kernel or libraries are in that only a restart brings into use. ' + (d.cluster ? 'Restarted one after the other, each in maintenance while it is, the service never stops.' : 'For a minute or two the dashboard is away.')));
      var go = cmdButton(need.length > 1 ? 'Restart them, one at a time' : 'Restart ' + need[0].name, 'refresh', 'primary');
      go.onclick = function () {
        confirmThen('Restart after the update', 'Restarted now: ' + htmlText(need.map(function (n) { return n.name; }).join(', ')) + (need.length > 1 ? ', one after the other.' : '.'), 'Restart', function () {
          api('osup', {action: 'reboot', nodes: need.map(function (n) { return n.name; })}).then(function (x) { toast(x.message, 'good'); ouAsked(); }).catch(oops);
        }, false);
      };
      rb.appendChild(go);
      host.appendChild(rb);
    }
    if (d.power && d.power.id) host.appendChild(el('p', 'note', 'Restarting: ' + (d.power.targets || []).join(', ') + ' - followed on Restart and power off.'));
    /* What each node has waiting. */
    var grid = el('div', 'pw-grid');
    nodes.forEach(function (n) {
      var c = el('div', 'card pw-node');
      var hd = el('div', 'pw-head');
      hd.appendChild(el('span', 'dot ' + (n.alive ? 'ok' : 'bad')));
      hd.appendChild(noI18n(el('b', '', n.name)));
      if (n.me) hd.appendChild(el('span', 'tag info', 'this page'));
      var ck = n.check || {};
      if (ck.state === 'running') hd.appendChild(el('span', 'tag info', 'looking…'));
      else if (ck.checked && ck.state === 'done') hd.appendChild(el('span', 'tag ' + (ck.count ? 'warn' : 'good'), ck.count ? num(ck.count) + ' waiting' : 'up to date'));
      if (n.reboot || (ck.reboot_after && ck.count)) hd.appendChild(el('span', 'pw-break'));
      if (n.reboot) hd.appendChild(el('span', 'tag warn', 'restart needed'));
      else if (ck.reboot_after && ck.count) hd.appendChild(el('span', 'tag info', 'restart after the update'));
      c.appendChild(hd);
      c.appendChild(netFacts([
        ['Updates waiting', ck.checked ? num(ck.count || 0) : 'not looked yet'],
        ['Of them security', ck.security !== undefined && ck.security !== null ? num(ck.security) : ''],
        ['A restart', !ck.checked ? '' : (ck.reboot_now ? 'needed now, before any update'
          : (ck.reboot_after && ck.count ? 'needed after the update - ' + (ck.reboot_why || []).join(', ') : 'not needed by these updates'))],
        ['Looked', ck.checked ? ago(ck.checked) : ''],
        ['Updated by', ck.pm || '', true]
      ]));
      if (ck.error) c.appendChild(el('p', 'note bad', ck.error));
      if ((ck.packages || []).length) {
        var more = el('details', 'fold');
        more.appendChild(el('summary', '', 'what is waiting'));
        more.appendChild(noI18n(el('pre', 'lines', ck.packages.slice(0, 300).join('\n') + (ck.packages.length > 300 ? '\n…' : ''))));
        OU.pkOpen = OU.pkOpen || {};
        if (OU.pkOpen[n.name]) more.open = true;
        more.ontoggle = function () { OU.pkOpen[n.name] = more.open; };
        c.appendChild(more);
      }
      var row = el('div', 'btnrow');
      var look = cmdButton('Look for updates', 'search', '');
      look.disabled = !n.alive || ck.state === 'running' || running;
      look.onclick = function () { busy(look, true); api('osup', {action: 'check', nodes: [n.name]}).then(function (x) { toast(x.message); OU.node = n.name; ouAsked(); }).catch(function (e) { busy(look, false); oops(e); }); };
      row.appendChild(look);
      c.appendChild(row);
      grid.appendChild(c);
    });
    host.appendChild(grid);
    /* The update itself. */
    if (!running) {
      var uc = el('div', 'card full');
      uc.appendChild(el('h2', '', d.cluster ? 'Update the nodes' : 'Update this server'));
      uc.appendChild(el('p', 'note', d.cluster
        ? 'The other node first, then this one - each out of service while it is updated, the VIP address on the other, RADIUS answered there; back in service before the next one starts.'
        : 'dnf (or apt) updates every package. The UPS goes on being watched meanwhile; a restart it needs is offered at the end.'));
      var segb = el('div', 'seg');
      [['ask', 'Ask me when a restart is needed'], ['auto', 'Restart by itself when needed' + (d.cluster ? ', one at a time' : '')]].forEach(function (o) {
        var b = el('button', OU.reboot === o[0] ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () { OU.reboot = o[0]; drawOsup(); };
        segb.appendChild(b);
      });
      var after = nodes.filter(function (n) { var k = n.check || {}; return k.reboot_after && k.count; });
      if (after.length) {
        var an = el('p', 'note warn', (after.length === nodes.length && nodes.length > 1 ? 'Both nodes need' : after.map(function (n) { return n.name; }).join(', ') + (after.length > 1 ? ' need' : ' needs'))
          + ' a restart after this update: ' + after.map(function (n) { return (n.check.reboot_why || []).join(', '); }).filter(function (x, i, a) { return x && a.indexOf(x) === i; }).join('; ') + '.');
        uc.appendChild(an);
      }
      var seg2 = el('div', 'seg');
      [['all', 'Every update'], ['security', 'Only the security updates']].forEach(function (o) {
        var b = el('button', (OU.what || 'all') === o[0] ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () { OU.what = o[0]; drawOsup(); };
        seg2.appendChild(b);
      });
      uc.appendChild(formField('Which', seg2));
      uc.appendChild(formField('After the update', segb));
      var row2 = el('div', 'btnrow');
      var start = cmdButton(d.cluster ? 'Update them, one at a time' : 'Update it now', 'download', 'primary');
      start.disabled = !d.helper || nodes.some(function (n) { return !n.alive; }) || !!(d.power && d.power.id);
      start.onclick = function () {
        confirmThen(d.cluster ? 'Update the nodes' : 'Update this server', 'Every package of the system is updated' + (d.cluster ? ', on ' + htmlText(nodes.map(function (n) { return n.name; }).join(' and then ')) + ', each out of service while it is.' : '.')
          + (OU.reboot === 'auto' ? '<br><br>A node that needs it is <b>restarted by itself</b>.' : '<br><br>A restart it needs is offered when it is done.'),
          'Update', function () {
            api('osup', {action: 'start', reboot: OU.reboot, security: OU.what === 'security'}).then(function (x) { toast(x.message, 'good'); OU.node = ''; ouAsked(); loadOsup(); }).catch(oops);
          }, false);
      };
      var lookAll = cmdButton('Look on every node', 'search', '');
      lookAll.onclick = function () { busy(lookAll, true); api('osup', {action: 'check'}).then(function (x) { toast(x.message); ouAsked(); }).catch(function (e) { busy(lookAll, false); oops(e); }); };
      row2.appendChild(start); row2.appendChild(lookAll);
      uc.appendChild(row2);
      if (!d.helper) uc.appendChild(el('p', 'note bad', 'The root helper of this node is not installed (install.sh --upgrade puts it in).'));
      host.appendChild(uc);
    }
    /* How far it is. */
    if (plan.id) {
      var pc = el('div', 'card full');
      var ph = el('h2', '', 'The update');
      if (running) {
        var stop = cmdButton('Stop it', 'cancel', 'small danger');
        explain(stop, 'The nodes not begun stay as they are; a node being updated finishes.');
        stop.onclick = function () { confirmThen('Stop the update', 'The nodes not yet begun stay as they are; one being updated finishes.', 'Stop it', function () { api('osup', {action: 'cancel'}).then(function (x) { toast(x.message); loadOsup(); }).catch(oops); }, true); };
        var tl = el('span', 'right'); tl.appendChild(stop); ph.appendChild(tl);
      }
      pc.appendChild(ph);
      pc.appendChild(el('p', 'note', 'Started by ' + (plan.by || '?') + ' · ' + ago(plan.at) + ' · ' + ({running: 'going on', done: 'done', failed: 'failed', cancelled: 'stopped'})[plan.state || 'running']
        + (plan.reboot === 'auto' ? ' · restarted where needed' : '') + (plan.security ? ' · security updates only' : '')));
      var steps = (plan.order || []).map(function (nm) {
        var n = nodes.filter(function (x) { return x.name === nm; })[0] || {name: nm};
        return {name: nm, row: n.row || {}};
      });
      var all = steps.length ? Math.round(steps.reduce(function (m, s) { return m + ouPercent(s.row); }, 0) / steps.length) : 0;
      pc.appendChild(upBar(all, plan.state === 'failed' ? 'bad' : (plan.state === 'done' ? 'good' : ''),
        num(all) + ' % · ' + steps.filter(function (s) { return s.row.state === 'done'; }).length + ' of ' + steps.length + ' node(s) done', true));
      var t = listTable(['Node', 'Step', 'How far', 'What happened', 'When'], steps, function (s) {
        var tr = el('tr');
        tr.appendChild(noI18n(el('td', 'mono', s.name)));
        var w = OU_STATE[s.row.state] || OU_STATE.waiting;
        var c = el('td'); c.appendChild(el('span', 'tag ' + w[1], w[0])); tr.appendChild(c);
        var b2 = el('td', 'up-how');
        var p2 = ouPercent(s.row);
        b2.appendChild(upBar(p2, s.row.state === 'failed' ? 'bad' : (s.row.state === 'done' ? 'good' : ''), num(p2) + ' %' + (s.row.state === 'updating' && s.row.phase ? ' · ' + txT(s.row.phase) : '')));
        tr.appendChild(b2);
        tr.appendChild(el('td', 'small', s.row.said || ''));
        tr.appendChild(el('td', 'muted', s.row.at ? ago(s.row.at) : '–'));
        return tr;
      }, 'plain');
      (t.querySelector('table') || t).classList.add('up-plan-table');
      pc.appendChild(t);
      if (!running) pc.appendChild(hideBar(function () { return api('osup', {action: 'hide'}).then(function (x) { OU.d = x; drawOsup(); }); }));
      host.appendChild(pc);
    }
    /* What the package manager says, a node at a time. */
    var have = nodes.filter(function (n) { return ((n.row || {}).lines || []).length || ((n.check || {}).lines || []).length; });
    if (have.length) {
      if (!OU.node || !have.some(function (n) { return n.name === OU.node; })) {
        var busyOne = have.filter(function (n) { return (n.row || {}).state === 'updating' || (n.check || {}).state === 'running'; })[0];
        OU.node = (busyOne || have[0]).name;
      }
      var lc = el('div', 'card full');
      var lh = el('h2', '', 'What it says');
      var lt = el('span', 'right');
      var hb = cmdButton(OU.hide ? 'Show it' : 'Hide it', OU.hide ? 'unfold' : 'fold', 'small');
      hb.onclick = function () { OU.hide = !OU.hide; try { localStorage.setItem('upsmon-ou-hide', OU.hide ? '1' : '0'); } catch (e) { /* only a convenience */ } drawOsup(); };
      var cb = cmdButton('Clear the window', 'broom', 'small');
      explain(cb, 'Empty the window of every node - for every page, and after a reload too; what comes after is shown.');
      lt.appendChild(hb); lt.appendChild(cb);
      lh.appendChild(lt);
      lc.appendChild(lh);
      if (have.length > 1) {
        var sg = el('div', 'seg');
        sg.style.marginBottom = '10px';
        have.forEach(function (n) {
          var b3 = noI18n(el('button', OU.node === n.name ? 'on' : '', n.name));
          b3.type = 'button';
          b3.onclick = function () { OU.node = n.name; OU.picked = Date.now(); drawOsup(); };
          sg.appendChild(b3);
        });
        lc.appendChild(sg);
      }
      var one = have.filter(function (n) { return n.name === OU.node; })[0];
      var lines = (one.row || {}).lines && (one.row || {}).lines.length ? one.row.lines : ((one.check || {}).lines || []);
      var from = 0;
      cb.onclick = function () {
        busy(cb, true);
        api('osup', {action: 'clear'}).then(function (x) { OU.d = x; drawOsup(); toast('the window is empty'); })
          .catch(function (e) { busy(cb, false); oops(e); });
      };
      if (!OU.hide) {
        var pre = noI18n(el('pre', 'lines ou-log', lines.slice(from).join('\n') || '–'));
        lc.appendChild(pre);
        setTimeout(function () { pre.scrollTop = pre.scrollHeight; }, 0);
      } else {
        lc.appendChild(el('p', 'muted small', 'Hidden - ' + num(lines.length) + ' line(s).'));
      }
      host.appendChild(lc);
    }
  }, live);
}



/* ======== automatic certificates (OTP admin.js 14225-14570) ======== */
/* ---- Settings → Automatic certificates (1.0.169) -------------------------------
   One card a certificate - the VIP address's, each node's - who orders it, what
   it has now, the last try; port 80 tried as the CA will try it. */
var AC = {d: null, probe: {}, poll: null};
function loadAcme() {
  api('acme').then(function (d) { AC.d = d; drawAcme(); acPoll(d.work && d.work.busy); }).catch(oops);
}
function acPoll(on) {
  if (on && !AC.poll) AC.poll = setInterval(function () {
    if (TAB !== 'settings' || PANE !== 'acme') { acPoll(false); return; }
    api('acme').then(function (d) { AC.d = d; drawAcme(); if (!(d.work && d.work.busy)) acPoll(false); }).catch(function () {});
  }, 2000);
  if (!on && AC.poll) { clearInterval(AC.poll); AC.poll = null; }
}
function drawAcme() {
  var real = $('ac-host');
  if (!real || !AC.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = AC.d;
    if (!d.on) host.appendChild(el('p', 'note', 'Off - switch it on below, say which certificates and the CA, and save.'));
    if (d.work && d.work.busy) {
      var g = el('div', 'going wide');
      g.innerHTML = '<div class="bar"><span style="width:60%"></span></div>';
      /* Which certificate, and what is being waited for now (1.0.176). */
      var w = el('div', 'says');
      if (d.work.target) {
        w.appendChild(el('b', '', d.work.target === 'vip' ? 'the VIP address' : d.work.target));
        w.appendChild(document.createTextNode(': '));
      }
      w.appendChild(el('span', '', d.work.says || 'ordering…'));
      g.appendChild(w);
      host.appendChild(g);
    }
    /* By hand (DNS-01): the record to put in, and the order waiting for it. */
    if (d.manual) {
      var mc = el('div', 'card full ac-manual');
      mc.appendChild(el('h2', '', 'Put this TXT record in DNS'));
      mc.appendChild(el('p', 'note warn', 'The order waits for it - up to an hour. Put it in, wait until DNS carries it, then say so. Take it away again once the certificate has come.'));
      mc.appendChild(netFacts([['Name', d.manual.rr, true], ['Type', 'TXT', true], ['Value', d.manual.txt, true], ['TTL', '60', true]]));
      var mr = el('div', 'btnrow');
      var cp = cmdButton('Copy the value', 'copy', 'small');
      cp.onclick = function () { copyText(d.manual.txt); };
      var dn = cmdButton('It is in DNS', 'check', 'small primary');
      dn.disabled = !!d.manual.done;
      dn.onclick = function () { api('acme', {action: 'manual_done'}).then(function (x) { AC.d = x; drawAcme(); acPoll(true); }).catch(oops); };
      var gv = cmdButton('Give the order up', 'close', 'small');
      gv.onclick = function () { api('acme', {action: 'manual_drop'}).then(function (x) { AC.d = x; drawAcme(); }).catch(oops); };
      mr.appendChild(cp); mr.appendChild(dn); mr.appendChild(gv);
      mc.appendChild(mr);
      host.appendChild(mc);
    }
    var grid = nodeGrid();
    (d.targets || []).forEach(function (t) {
      var st = t.state || {};
      var left = t.not_after ? Math.floor((t.not_after - Date.now() / 1000) / 86400) : null;
      var acme = t.how === 'ACME';
      var dot = !acme ? 'dim' : (st.ok === false ? 'warn' : (left !== null && left < 14 ? 'warn' : 'ok'));
      var c = nodeCard({node: t.target === 'vip' ? 'the VIP address' : t.target, me: t.target === d.node}, dot,
        acme ? (st.ok === false ? 'the last try failed' : 'from the CA') : (t.how ? 'not from the CA' : 'no certificate'),
        acme ? (st.ok === false ? 'warn' : 'ok') : 'dim');
      /* Who looks after it (1.0.170): ACME, or the certificate put in on
         Certificates and TLS is kept as it is. */
      var care = el('span', 'tag ' + (t.care && t.wanted ? 'info' : 'dim'),
        !t.wanted ? 'not asked for' : (t.care ? 'ACME renews it' : 'its own certificate is kept'));
      explain(care, !t.wanted ? 'For (Settings below) does not take this one in.'
        : (t.care ? 'Renewed by ACME before it runs out. A certificate put in by hand on Certificates and TLS takes it out of ACME’s care.'
          : 'The certificate put in on Certificates and TLS (uploaded, from a request, self-signed) stays: ACME does not replace it. Look after it, or Order it now, gives it to ACME.'));
      c.querySelector('.pw-head') ? c.querySelector('.pw-head').appendChild(care) : c.appendChild(care);
      nodeBig(c, left !== null ? num(left) : '–', left !== null ? 'days left' : '');
      c.appendChild(netFacts([
        ['For', t.name || '', true], ['Issued by', t.issuer || '', true], ['Keys', t.keys || '', true],
        ['Good until', t.not_after ? new Date(t.not_after * 1000).toLocaleDateString(numLang()) : ''],
        ['Last ordered', st.ordered_at ? ago(st.ordered_at) : 'never'],
        ['Ordered by', t.target === 'vip' ? 'the first node by name' : t.target]
      ]));
      if (st.ok === false && st.said) c.appendChild(nodeSaid({ok: false, error: st.said, at: st.failed_at}, ''));
      /* What the last order did, step by step (1.0.175). */
      if ((st.steps || []).length) {
        var det = el('details', 'acme-steps-done');
        det.appendChild(el('summary', 'small muted', 'What the last order did'));
        var t0 = st.steps[0][0];
        st.steps.forEach(function (x) {
          var r = el('div', 'si-row small');
          r.appendChild(noI18n(el('span', 'muted mono', '+' + Math.round(x[0] - t0) + ' s')));
          r.appendChild(el('span', '', x[1]));
          det.appendChild(r);
        });
        c.appendChild(det);
      }
      var pr = AC.probe[t.target];
      if (pr) c.appendChild(nodeSaid({ok: pr.ok, at: pr.at, error: pr.ok ? '' : pr.said}, 'Port 80 answers as the CA will ask it'));
      var row = el('div', 'btnrow');
      var probe = cmdButton('Try port 80', 'play', 'small');
      probe.hidden = d.challenge === 'dns-01';
      explain(probe, t.name ? 'http://' + t.name + '/.well-known/acme-challenge/ asked from this node, as the CA will ask it - whether it reaches upsmon. A firewall in front of the servers may still stop the CA from outside.'
        : 'The name of this certificate is not known yet: give it in Settings below (This node’s DNS name, on that node) - or wait until that node says its own full name.');
      probe.disabled = !t.name;
      probe.onclick = function () {
        busy(probe, true);
        api('acme', {action: 'probe', target: t.target}).then(function (x) {
          busy(probe, false); x.at = Date.now() / 1000; AC.probe[t.target] = x; drawAcme();
        }).catch(function (e) { busy(probe, false); oops(e); });
      };
      var order = cmdButton('Order it now', 'download', 'small primary');
      order.disabled = !d.on || !t.name || (d.work && d.work.busy);
      explain(order, !d.on ? 'Switch it on below first.' : (!t.name ? 'Give its name first (Its name…).'
        : 'Ordered from the CA now - from this node for any of them: the CA’s question and the certificate are kept in the database, and ' + (t.target === 'vip' ? 'every node' : t.target) + ' puts it in. ACME renews it from then on.'));
      order.onclick = function () {
        var go = function () {
          busy(order, true);
          api('acme', {action: 'order', target: t.target}).then(function (x) { busy(order, false); toast(x.message, 'good'); AC.d = x; drawAcme(); acPoll(true); })
            .catch(function (e) { busy(order, false); oops(e); });
        };
        if (t.how && !acme) {
          confirmThen('Replace the certificate of ' + (t.target === 'vip' ? 'the VIP address' : t.target) + '?',
            'It has one put in on Certificates and TLS (' + t.how + (t.issuer ? ', ' + t.issuer.replace(/^CN=/, '').split(',')[0] : '') + '). The one from the CA takes its place once it comes, and ACME renews it from then on. Its TLS settings stay as they are.',
            'Order it', go, false);
        } else go();
      };
      var cb = cmdButton(t.care ? 'Leave it alone' : 'Look after it', t.care ? 'cancel' : 'refresh', 'small');
      cb.disabled = !t.wanted;
      explain(cb, t.care ? 'ACME stops renewing this one; the certificate it has stays.'
        : 'ACME renews this one from now on - at the next look (within the hour) if it is not from the CA yet.');
      cb.onclick = function () {
        busy(cb, true);
        api('acme', {action: 'care', target: t.target, on: !t.care}).then(function (x) { AC.d = x; drawAcme(); })
          .catch(function (e) { busy(cb, false); oops(e); });
      };
      /* Every certificate's name from here (1.0.170) - the other node's and
         the VIP address's too. */
      var nm = cmdButton('Its name…', 'edit', 'small');
      explain(nm, t.target === 'vip' ? 'The DNS name of the VIP address - the one people type. It is the VIP address’s own (Settings → High availability) and its certificate is for it.'
        : 'The DNS name the certificate of ' + t.target + ' is for. Empty: the full host name of ' + t.target + '.');
      nm.onclick = function () { acmeNameAsk(t); };
      row.appendChild(probe); row.appendChild(order); row.appendChild(cb); row.appendChild(nm);
      if (t.before && !t.before.ran_out) row.appendChild(acmePutBackButton(t.target, t.before, function (x) { AC.d = x; drawAcme(); }));
      c.appendChild(row);
      grid.appendChild(c);
    });
    host.appendChild(grid);
    if (d.on && d.dns_guide) host.appendChild(acmeDnsGuide(d));
    setTimeout(function () { acmeNamesInSettings(d); }, 0);
    if (d.account && d.account.kid) {
      var a = el('p', 'muted small', 'The account at the CA: ');
      a.appendChild(noI18n(el('span', 'mono', d.account.kid)));
      if (d.account.key) a.appendChild(noI18n(el('span', '', ' · ' + d.account.key)));
      host.appendChild(a);
    }
  });
}

/* The certificate from before ACME (1.0.172): kept when ACME replaced it,
   put back with its key as it was; ACME then leaves it alone. */
function acmePutBackButton(target, before, then) {
  var b = cmdButton('Back to the one before…', 'undo', 'small');
  var words = (before.issuer || '').replace(/^CN=/, '').split(',')[0];
  explain(b, 'The certificate it had before ACME replaced it' + (words ? ' - from ' + words : '') + (before.not_after ? ', good until ' + new Date(before.not_after * 1000).toLocaleDateString(numLang()) : '') + '. Put back as it was; ACME no longer renews this one. The TLS settings stay.');
  b.onclick = function () {
    confirmThen('Put the certificate from before ACME back?', 'The one from the CA is taken out and the one it had before - ' + (words || before.how || '') + ' - put back, on every node that serves it. ACME no longer renews this one (Look after it gives it back).', 'Put it back', function () {
      busy(b, true);
      api('acme', {action: 'put_back', target: target}).then(function (x) { toast(x.message, 'good'); then(x); })
        .catch(function (e) { busy(b, false); oops(e); });
    }, false);
  };
  return b;
}

/* The names of the certificates beside their box (1.0.170): what each node's
   certificate is for now when its box is empty, and the VIP address's name -
   it is the VIP address's own (High availability), changed from here too. */
function acmeNamesInSettings(d) {
  var item = document.querySelector('.set-item[data-key="acme_node_name"]');
  if (!item) return;
  var now = {};
  (d.targets || []).forEach(function (t) { now[t.target] = t.name || ''; });
  var input = $('set-acme_node_name');
  if (input && now[d.node]) input.placeholder = now[d.node];
  Array.prototype.forEach.call(item.querySelectorAll('.node-other[data-node]'), function (row) {
    /* An empty one says the name it stands for, in the place of "(empty)"
       (1.0.172): the words did not fit in a narrow box. */
    var n = row.dataset.node;
    var empty = row.querySelector('.node-empty');
    if (empty && now[n]) {
      var v = noI18n(el('span', 'mono small muted', now[n]));
      v.title = 'none of its own: the name of its certificate, else its full host name';
      row.replaceChild(v, empty);
      var note = row.querySelector('span.muted:not(.mono)');
      if (note) note.textContent = 'by itself';
    }
  });
  var vip = (d.targets || []).filter(function (t) { return t.target === 'vip'; })[0];
  var box = item.querySelector('.node-others');
  var vr = item.querySelector('.node-other.vip');
  if (vr) vr.remove();
  if (!vip) return;
  if (!box) {
    box = el('div', 'node-others small');
    (item.querySelector('.set-tail') || item).appendChild(box);
  }
  vr = el('div', 'node-other vip');
  vr.appendChild(el('span', 'tag dim', 'VIP'));
  vr.appendChild(vip.name ? noI18n(el('span', 'mono small', vip.name)) : el('span', 'node-empty small', '(empty)'));
  vr.appendChild(el('span', 'muted', 'High availability'));
  if (ADMIN) {
    var eb = iconButton('edit', 'Change the name of the VIP address');
    eb.onclick = function () { acmeNameAsk({target: 'vip', name: vip.name}); };
    vr.appendChild(eb);
  }
  box.appendChild(vr);
}
function acmeNameAsk(t) {
  askInModal(t.target === 'vip' ? 'The name of the VIP address' : 'The name of ' + t.target,
    'The full DNS name its certificate is for - it goes into the certificate as its name (CN) and in its alternative names (SAN). The CA gives it only for a name that points at it (HTTP-01) or whose TXT record can be put in (DNS-01).',
    [{label: 'DNS name', placeholder: t.target === 'vip' ? 'upsmon.example.cz' : t.target + '.example.cz', mono: true, value: t.name || '',
      says: t.target === 'vip' ? 'Empty: the VIP address has no name.' : 'Empty: its full host name, as ' + t.target + ' says it.'}],
    'Keep it', 'save', function (v, b) {
      busy(b, true);
      api('acme', {action: 'name', target: t.target, name: v[0].trim()}).then(function (x) {
        closeModal(); AC.d = x; drawAcme(); toast('kept', 'good');
        if (t.target !== 'vip') loadSettings();
      }).catch(function (e) { busy(b, false); oops(e); });
    });
}

/* In your DNS (1.0.170): what each certificate asked for needs there - by the
   way the CA checks it - the steps of the way chosen, and a check that looks
   each record up from this node. */
var AC_DNS = (function () {
  try { var k = JSON.parse(sessionStorage.getItem('upsmon-acme-dns') || 'null'); if (k && k.rows) return k; } catch (e) {}
  return {at: 0, rows: null};
})();
var ACME_DNS_STEPS = {
  'http-01': ['Each name points at the address that reaches port 80 of its node (or of the VIP address) - from the internet, or from your own CA.',
              'Port 80 is open to it - the firewall in front of the servers, and Firewall and access here.',
              'Try port 80 on each card, then Order it now.'],
  desec: ['Sign up at desec.io (free) and confirm the mail.',
          'Add a domain there: a free one - yourname.dedyn.io - or one of your own whose DNS is at deSEC.',
          'Token management: make a token. Give it below as The deSEC API token, with The domain at deSEC, and save.',
          'In the DNS of your own domain put the CNAME records below - once; they stay for every renewal.',
          'Check DNS here, then Order it now. Renewals go by themselves.'],
  cloudflare: ['A token at Cloudflare (My Profile → API Tokens) with Zone - DNS - Edit for the zone, given below.',
               'Where the DNS of your domain is not at Cloudflare: a zone that is, as The TXT records go into, and the CNAME records below in your DNS.',
               'Order it now. Renewals go by themselves.'],
  rfc2136: ['A TSIG key the DNS server lets update the _acme-challenge records (tsig-keygen), given below with the server and the zone.',
            'With The TXT records go into: the CNAME records below in your DNS, and the key allowed in that zone.',
            'Order it now. Renewals go by themselves.'],
  acmedns: ['Register at the acme-dns server (POST /register) - it gives a user, a key and a subdomain; give them below.',
            'In your DNS put the CNAME records below - once.',
            'Check DNS here, then Order it now. Renewals go by themselves.'],
  manual: ['At every order - renewals too - the TXT record is shown here: put it in your DNS, then say It is in DNS.',
           'Better: a CNAME once in your DNS to a zone upsmon can write to (deSEC is free) - then nothing is by hand any more.']
};
function acmeDnsGuide(d) {
  var g = d.dns_guide;
  var key = g.challenge === 'http-01' ? 'http-01' : g.dns;
  var card = el('div', 'card full acme-dns');
  var h = el('h2', '', 'In your DNS');
  card.appendChild(h);
  card.appendChild(el('p', 'note', g.challenge === 'http-01'
    ? 'HTTP-01: the CA asks port 80 of each name - so each name points at the node, or the VIP address, and port 80 is open to the CA.'
    : (g.dns === 'manual' ? 'DNS-01 by hand: the CA reads a TXT record you put in at every order.'
      : 'DNS-01: the CA reads a TXT record upsmon puts in. What has to be in your DNS for it - once - is below.')));
  var ol = el('ol', 'acme-steps');
  (ACME_DNS_STEPS[key] || []).forEach(function (w) { ol.appendChild(el('li', '', w)); });
  card.appendChild(ol);
  var checked = AC_DNS.rows && Date.now() / 1000 - AC_DNS.at < 600 ? AC_DNS.rows : null;
  var rows = (g.rows || []).map(function (r, i) {
    var c = checked && checked[i] && checked[i].record === r.record ? checked[i] : {};
    return Object.assign({}, r, {ok: c.ok, said: c.said});
  });
  var t = listTable(['Certificate', 'DNS record', '', 'Type', 'Points at / value', '', 'In DNS now'], rows, function (r) {
    var tr = el('tr');
    tr.appendChild(r.target === 'vip' ? el('td', '', 'the VIP address') : (r.type === 'NS' ? el('td', '', 'its zone at deSEC') : noI18n(el('td', '', r.target))));
    var rec = el('td', 'mono small dns-txt');
    var recb = el('td', 'dns-copy');
    if (r.record) {
      rec.appendChild(noI18n(el('span', '', r.record)));
      var cp = iconButton('copy', 'Copy');
      cp.onclick = function () { copyText(r.record, cp); };
      recb.appendChild(cp);
    } else rec.appendChild(el('span', 'muted', r.why || ''));
    tr.appendChild(rec);
    tr.appendChild(recb);
    tr.appendChild(noI18n(el('td', 'mono small', r.type || '')));
    var val = el('td', 'mono small dns-txt');
    var valb = el('td', 'dns-copy');
    if (r.type === 'CNAME' || r.type === 'NS' || (r.type === 'A' && r.value)) {
      val.appendChild(noI18n(el('span', '', r.value)));
      var cv = iconButton('copy', 'Copy');
      cv.onclick = function () { copyText(r.value, cv); };
      valb.appendChild(cv);
      if (r.type === 'A') val.appendChild(el('div', 'muted', 'or the public address in front of it'));
    } else val.appendChild(el('span', 'muted', r.type === 'TXT' ? (r.value || r.why) : ''));
    tr.appendChild(val);
    tr.appendChild(valb);
    var st = el('td', 'small');
    if (r.check) {
      if (r.ok === undefined) st.appendChild(el('span', 'muted', 'not checked yet'));
      else {
        var tag = el('span', 'tag ' + (r.ok ? 'ok' : 'warn'), r.ok ? 'there' : 'not yet');
        st.appendChild(tag);
        if (r.said && !r.ok) st.appendChild(el('div', 'muted', r.said));
      }
    } else st.appendChild(el('span', 'muted', r.type === 'TXT' && !r.value ? 'upsmon puts it in' : '–'));
    tr.appendChild(st);
    return tr;
  });
  card.appendChild(t);
  var row = el('div', 'btnrow');
  var chk = cmdButton('Check DNS', 'search', 'small');
  explain(chk, 'Each record looked up from this node now, through its DNS servers - as the CA will look. A record just put in may take a while to show (its TTL).');
  chk.disabled = !(g.rows || []).some(function (r) { return r.check; });
  chk.onclick = function () {
    busy(chk, true);
    api('acme', {action: 'dns_check'}).then(function (x) {
      AC_DNS = {at: Date.now() / 1000, rows: x.rows, own: x.own_resolvers};
      try { sessionStorage.setItem('upsmon-acme-dns', JSON.stringify(AC_DNS)); } catch (e) {}
      busy(chk, false); drawAcme();
    }).catch(function (e) { busy(chk, false); oops(e); });
  };
  row.appendChild(chk);
  if (checked && AC_DNS.own === false) {
    card.appendChild(el('p', 'note warn small', 'Checked with this machine’s DNS servers - inside your network they may see what the internet does not. Set DNS servers for ACME (below) to public ones, 1.1.1.1, 9.9.9.9, to see what the CA sees.'));
  }
  if (checked) {
    var when = el('span', 'muted small');
    when.appendChild(el('span', '', 'checked'));
    when.appendChild(document.createTextNode(' '));
    when.appendChild(el('span', '', ago(AC_DNS.at)));
    row.appendChild(when);
  }
  card.appendChild(row);
  return card;
}


/* ---- a certificate exported, in the format asked for (upsmon 4.1) ----------------
   PEM with its chain, the certificate alone (PEM or DER), with its private key
   (PEM, the key locked with a password or not), the key alone, or PFX / PKCS#12 -
   AES-256, or 3DES for older Windows and Java. A password is typed unseen. */
var CERT_FORMATS = [
  {fmt: 'pem', name: 'PEM with the chain', ext: '.pem', key: false, icon: 'lock',
   says: 'The certificate and the certificates between it and the root - what nginx, Apache and most servers take.'},
  {fmt: 'crt', name: 'The certificate, PEM', ext: '.crt', key: false, icon: 'lock',
   says: 'The certificate alone, without its chain.'},
  {fmt: 'der', name: 'The certificate, DER', ext: '.der', key: false, icon: 'lock',
   says: 'The certificate alone, binary - for Windows and Java tools that want DER.'},
  {fmt: 'pfx', name: 'PFX / PKCS#12', ext: '.pfx', key: true, pw: 'need', icon: 'key',
   says: 'The certificate, its chain and its private key in one file, locked with a password (AES-256) - for Windows, IIS, Exchange, a load balancer.'},
  {fmt: 'pfx_legacy', name: 'PFX, compatible', ext: '.pfx', key: true, pw: 'need', icon: 'key',
   says: 'The same, locked the old way (3DES, SHA-1) - for Windows Server 2016 and older, Java 8, appliances that refuse the new one.'},
  {fmt: 'pem_key', name: 'PEM with the private key', ext: '-with-key.pem', key: true, pw: 'may', icon: 'key',
   says: 'The certificate, its chain and its private key as text; the key locked with the password when one is given.'},
  {fmt: 'key', name: 'The private key alone', ext: '.key', key: true, pw: 'may', icon: 'key',
   says: 'The key alone, PEM; locked with the password when one is given.'}
];
function certExport(target, prof) {
  var base = /^[A-Za-z0-9*.-]{1,100}$/.test(String((prof.info || {}).cn || '')) ? String(prof.info.cn).replace('*', '_') : (target === 'vip' ? 'web-address' : target);
  var info = prof.info || {};
  var hasKey = !!prof.has_key;
  var pick = 'pem';
  /* A dual certificate (4.3.3): the RSA one, its ECDSA twin, or both in a .zip. */
  var twin = prof.alt && prof.alt.info ? prof.alt.info : null;
  var which = 'main', whichTiles = {};
  var WHICH = twin ? [
    {w: 'main', name: (info.key || 'RSA') , says: 'The first certificate - the one served by default.', tag: ''},
    {w: 'alt', name: (twin.key || 'ECDSA'), says: 'Its twin beside it - for the clients that take ECDSA.', tag: '-ecdsa'},
    {w: 'both', name: 'Both', says: 'The two in one .zip, each a file of its own in the format chosen, each with its own key.', tag: '-dual'}] : [];
  var p1 = secretBox('', '8 characters at least', 'mono');
  var p2 = secretBox('', 'the same again', 'mono');
  p1.autocomplete = p2.autocomplete = 'new-password';
  var tiles = {}, pwBox, keyWarn, nameLine, meter, pwWhy;
  function strength(s) {
    var n = 0;
    if (s.length >= 8) n++;
    if (s.length >= 14) n++;
    if (/[a-z]/.test(s) && /[A-Z]/.test(s)) n++;
    if (/\d/.test(s)) n++;
    if (/[^A-Za-z0-9]/.test(s)) n++;
    return s ? Math.max(1, Math.min(4, n)) : 0;
  }
  function paint() {
    var f = CERT_FORMATS.filter(function (x) { return x.fmt === pick; })[0];
    Object.keys(tiles).forEach(function (k) { tiles[k].classList.toggle('on', k === pick); });
    pwBox.hidden = !f.key;
    keyWarn.hidden = !f.key;
    pwWhy.textContent = f.pw === 'need' ? 'A PFX file is always locked: whoever opens it needs this password.'
      : 'Optional: without a password the private key is written in the clear.';
    clear(nameLine);
    nameLine.appendChild(document.createTextNode('The file: '));
    Object.keys(whichTiles).forEach(function (k) { whichTiles[k].classList.toggle('on', k === which); });
    var wt = WHICH.filter(function (x) { return x.w === which; })[0];
    nameLine.appendChild(noI18n(el('b', 'mono', base + (wt ? wt.tag : '') + (which === 'both' ? '.zip' : f.ext))));
    var s = strength(p1.value);
    meter.className = 'cx-meter s' + s;
    meter.title = ['', 'weak', 'fair', 'good', 'strong'][s];
  }
  modal('Download the certificate', function (body) {
    var head = el('div', 'cx-head');
    head.appendChild(noI18n(el('div', 'cx-cn mono', info.cn || info.subject || target)));
    var sub = [];
    if (info.issuer) sub.push('issued by ' + (String(info.issuer).match(/CN=([^,]+)/) || [0, info.issuer])[1]);
    if (info.not_after) sub.push('good until ' + new Date(info.not_after * 1000).toLocaleDateString(window.OTP_LANG === 'cs' ? 'cs-CZ' : undefined));
    head.appendChild(el('div', 'muted small', sub.join(' · ')));
    body.appendChild(head);
    if (twin) {
      body.appendChild(el('h4', 'cx-h', 'Which certificate'));
      var wg = el('div', 'cx-grid');
      WHICH.forEach(function (x) {
        var t = el('button', 'cx-tile');
        t.type = 'button';
        var top = el('div', 'cx-top');
        top.appendChild(noI18n(el('span', 'cx-name', x.name)));
        if (x.w === 'both') top.appendChild(el('span', 'tag info', '.zip'));
        t.appendChild(top);
        t.appendChild(el('div', 'cx-says', x.says));
        t.onclick = function () { which = x.w; paint(); };
        whichTiles[x.w] = t;
        wg.appendChild(t);
      });
      body.appendChild(wg);
    }
    body.appendChild(el('h4', 'cx-h', 'The format'));
    var grid = el('div', 'cx-grid');
    CERT_FORMATS.forEach(function (f) {
      var t = el('button', 'cx-tile');
      t.type = 'button';
      var top = el('div', 'cx-top');
      top.appendChild(el('span', 'cx-name', f.name));
      top.appendChild(el('span', 'tag ' + (f.key ? 'warn' : 'info'), f.key ? 'with the key' : 'public'));
      t.appendChild(top);
      t.appendChild(el('div', 'cx-says', f.says));
      t.appendChild(noI18n(el('div', 'cx-ext mono', f.ext)));
      if (f.key && !hasKey) {
        t.disabled = true;
        t.title = 'The private key of this certificate is not kept here.';
      }
      t.onclick = function () { pick = f.fmt; paint(); if (f.key) setTimeout(function () { p1.focus(); }, 30); };
      tiles[f.fmt] = t;
      grid.appendChild(t);
    });
    body.appendChild(grid);
    pwBox = el('div', 'cx-pw');
    var g = el('div', 'formgrid');
    g.appendChild(formField('Password', p1));
    g.appendChild(formField('The password again', p2));
    pwBox.appendChild(g);
    var row = el('div', 'cx-row');
    meter = el('span', 'cx-meter s0');
    for (var i = 0; i < 4; i++) meter.appendChild(el('i'));
    row.appendChild(meter);
    pwWhy = el('span', 'muted small', '');
    row.appendChild(pwWhy);
    pwBox.appendChild(row);
    body.appendChild(pwBox);
    keyWarn = el('p', 'note warn cx-warn', 'The private key leaves the server: whoever has the file and its password can be this server. Every export with the key is written into Events.');
    body.appendChild(keyWarn);
    nameLine = el('p', 'btnhelp');
    body.appendChild(nameLine);
    p1.addEventListener('input', paint);
    paint();
  }, [{words: 'Cancel', close: true},
      {words: 'Download', cls: 'primary', icon: 'download', go: function (b) {
        var f = CERT_FORMATS.filter(function (x) { return x.fmt === pick; })[0];
        var pw = f.key ? p1.value : '';
        if (f.key && (pw || f.pw === 'need')) {
          if (pw.length < 8) { toast('a password of 8 characters at least', 'bad'); p1.focus(); return; }
          if (pw !== p2.value) { toast('the two passwords are not the same', 'bad'); p2.focus(); return; }
        }
        busy(b, true);
        api('web', {action: 'tls_export', target: target, format: pick, password: pw, which: which}).then(function (x) {
          var raw = atob(x.data), bytes_ = new Uint8Array(raw.length);
          for (var i = 0; i < raw.length; i++) bytes_[i] = raw.charCodeAt(i);
          var a = el('a');
          a.href = URL.createObjectURL(new Blob([bytes_], {type: x.mime || 'application/octet-stream'}));
          a.download = x.name;
          document.body.appendChild(a);
          a.click();
          setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
          closeModal();
          toast(x.with_key ? x.name + ' - with the private key; keep it, and its password, safe' : x.name, 'good');
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}

/* ---- Settings → Proxy (4.2.1), from OTP 1.0.197 ---- */

var PX = {poll: null};
function drawProxy() {
  var host = $('px-host');
  if (!host) return;
  clear(host);
  var c = el('div', 'card full');
  c.appendChild(el('h2', '', 'Try it'));
  c.appendChild(el('p', 'note', 'An address asked from this node the way upsmon asks the web: through the proxy as it is saved, or straight where none is set or the address is in the list. Each step is shown. Empty: where the new versions are looked for.'));
  var row = el('div', 'btnrow');
  var url = el('input');
  url.type = 'text';
  url.placeholder = 'https://github.com/';
  url.style.flex = '1';
  url.style.minWidth = '260px';
  var go = cmdButton('Try it', 'play', 'primary');
  var said = el('div', 'px-out');
  /* Tried on every node (1.0.169): each node's card fills in as it answers. */
  go.onclick = function () {
    busy(go, true);
    clear(said);
    if (PX.poll) { clearInterval(PX.poll); PX.poll = null; }
    api('proxy', {action: 'try', url: url.value.trim()}).then(function (x) {
      var nodes = x.nodes || [];
      var cards = {};
      var grid = nodeGrid();
      nodes.forEach(function (n) {
        var cd = nodeCard({node: n, me: !!(STATUS && n === STATUS.node)}, 'dim', 'being tried', 'info');
        var body = el('div', 'px-out');
        body.appendChild(pxPath(null, n));
        cd.appendChild(body);
        grid.appendChild(cd);
        cards[n] = {body: body, done: false, card: cd};
      });
      said.appendChild(grid);
      var began = Date.now();
      var look = function () {
        api('proxy', {action: 'result', id: x.id}).then(function (r) {
          var left = 0;
          nodes.forEach(function (n) {
            var got = (r.nodes || {})[n];
            if (cards[n].done) return;
            if (!got) { left++; return; }
            cards[n].done = true;
            var hd = cards[n].card.querySelector('.pw-head');
            hd.querySelector('.dot').className = 'dot ' + (got.ok ? 'ok' : 'bad');
            var tg = hd.querySelector('.tag:last-child');
            hd.replaceChild(el('span', 'tag ' + (got.ok ? 'ok' : 'crit'), got.ok ? (got.mode === 'proxy' ? 'through the proxy' : 'straight') : 'not reached'), tg);
            clear(cards[n].body);
            if (got.error) { cards[n].body.appendChild(el('p', 'note bad', got.error)); return; }
            cards[n].body.appendChild(pxPath(got));
            cards[n].body.appendChild(pxSteps(got));
          });
          if (!left || Date.now() - began > 60000) {
            clearInterval(PX.poll); PX.poll = null; busy(go, false);
            nodes.forEach(function (n) {
              if (!cards[n].done) { clear(cards[n].body); cards[n].body.appendChild(el('p', 'note warn', 'This node did not answer in a minute - is it running?')); }
            });
          }
        }).catch(function () {});
      };
      PX.poll = setInterval(look, 1000);
      setTimeout(look, 300);
    }).catch(function (e) { busy(go, false); oops(e); });
  };
  url.addEventListener('keydown', function (e) { if (e.key === 'Enter') go.click(); });
  row.appendChild(url); row.appendChild(go);
  c.appendChild(row);
  c.appendChild(said);
  host.appendChild(c);
}
/* The way it went, drawn: this node, the proxy (when it went through one),
   the address - each link green, red, or still being tried. */
function pxPath(x, nodeName) {
  var box = el('div', 'px-path' + (x ? (x.ok ? ' ok' : ' bad') : ' going'));
  var steps = (x && x.steps) || [];
  var failAt = steps.filter(function (s) { return !s.ok; })[0];
  var stop = function (icon, title, sub, cls) {
    var n = el('div', 'px-stop ' + (cls || ''));
    var ic = el('span', 'px-ic');
    ic.innerHTML = iconMarkup(icon, 22);
    n.appendChild(ic);
    n.appendChild(noI18n(el('b', 'mono', title)));
    if (sub) n.appendChild(el('span', 'muted small', sub));
    return n;
  };
  var link = function (state, words) {
    var l = el('div', 'px-link ' + state);
    l.appendChild(el('span', 'px-wire'));
    if (words) l.appendChild(el('span', 'px-lw small', words));
    return l;
  };
  if (!x) {
    box.appendChild(stop('router', nodeName || (STATUS && STATUS.node) || 'upsmon', 'the node', 'me'));
    box.appendChild(link('going', 'trying…'));
    box.appendChild(stop('globe', '…', '', ''));
    return box;
  }
  var reached = function (re) { return steps.some(function (s) { return s.ok && re.test(s.what); }); };
  box.appendChild(stop('router', x.node, 'the node', 'me'));
  if (x.mode === 'proxy') {
    var toProxy = reached(/^connected to the proxy/) ? 'ok' : 'bad';
    box.appendChild(link(toProxy, toProxy === 'ok' ? 'connected' : 'not reached'));
    box.appendChild(stop('wall', x.proxy, x.proxy_auth ? 'the proxy · with a password' : 'the proxy', toProxy === 'ok' ? 'good' : 'bad'));
    var through = x.ok ? 'ok' : (toProxy === 'ok' ? 'bad' : 'off');
    box.appendChild(link(through, through === 'ok' ? 'through the proxy' : (through === 'bad' ? 'stopped here' : '')));
  } else {
    var st = x.ok ? 'ok' : 'bad';
    box.appendChild(link(st, 'straight'));
  }
  box.appendChild(stop(x.tls ? 'lock' : 'globe', x.host + ':' + x.port, x.tls ? x.tls.version + ' · ' + (x.tls.issuer || '') : '', x.ok ? 'good' : 'bad'));
  var top = el('div', 'px-verdict ' + (x.ok ? 'ok' : 'bad'));
  top.appendChild(el('span', 'dot ' + (x.ok ? 'ok' : 'bad')));
  var words = x.ok
    ? (x.mode === 'proxy' ? 'Reached through the proxy' : 'Reached straight') + ' - HTTP ' + x.status + ', ' + x.ms + ' ms'
    : 'Not reached: ' + ((failAt && failAt.said) || '?');
  top.appendChild(el('b', '', words));
  if (x.mode === 'direct' && x.why_direct) top.appendChild(el('span', 'muted small', 'straight because ' + x.why_direct));
  var wrap = el('div', 'px-result');
  wrap.appendChild(top);
  wrap.appendChild(box);
  return wrap;
}
function pxSteps(x) {
  var ul = el('div', 'px-steps');
  var plan = x.mode === 'proxy'
    ? ['the proxy looked up', 'connected to the proxy'].concat(/^https/.test(x.url) ? ['a tunnel through the proxy', 'TLS'] : []).concat(['asked for'])
    : ['looked up', 'connected to'].concat(/^https/.test(x.url) ? ['TLS'] : []).concat(['asked for']);
  var done = x.steps || [];
  done.forEach(function (s) {
    var r = el('div', 'px-step ' + (s.ok ? 'ok' : 'bad'));
    r.appendChild(el('span', 'px-n', s.ok ? '✓' : '✗'));
    var t = el('div', 'px-st');
    t.appendChild(el('b', '', s.what));
    if (s.said) t.appendChild(noI18n(el('div', 'muted small mono', s.said)));
    r.appendChild(t);
    r.appendChild(el('span', 'px-ms small muted', s.ms + ' ms'));
    ul.appendChild(r);
  });
  for (var i = done.length; i < plan.length; i++) {
    var r = el('div', 'px-step off');
    r.appendChild(el('span', 'px-n', '○'));
    var t = el('div', 'px-st');
    t.appendChild(el('b', '', 'not tried - the step before stopped it'));
    r.appendChild(t);
    ul.appendChild(r);
  }
  return ul;
}

/* ---- Certificates from acme (1.0.58): acme push, the receiving end ---------- */
var PUSH = {};
function loadPush() {
  if (!ADMIN || !$('web-push')) return;
  api('acme-push').then(drawPush).catch(function () { /* the card stays as it was */ });
}
function pushDo(body, then) {
  return api('acme-push', body).then(function (d) {
    if (d.message) toast(d.message, 'good');
    drawPush(d);
    if (then) then(d);
    return d;
  }).catch(oops);
}
/* The tiles of the card and of the code (1.0.60): a click copies what is in
   it - the code, the address for acme, the id, the key - for acme's Target. */
function pushTiles(box, values) {
  Array.prototype.forEach.call(box.querySelectorAll('.fact'), function (cell, i) {
    if (values[i]) copyOnClick(cell, values[i], 'copied: ' + cell.querySelector('.k').textContent);
  });
  return box;
}
function pushCode(code, until) {
  modal('Pair with an acme', function (body) {
    body.appendChild(el('p', 'note', 'In acme: Targets → add An application of ours (acme push), its address below, and this code in Pairing code - then Try. The code is shown this once, works once, for 15 minutes; five wrong tries end it.'));
    var big = noI18n(el('div', 'push-code mono', code));
    copyOnClick(big, code, 'the pairing code is copied');
    body.appendChild(big);
    body.appendChild(pushTiles(peekFacts([['The address for acme', noI18n(el('span', 'mono', location.origin + '/'))],
      ['Valid until', new Date(until * 1000).toLocaleTimeString(numLang())]]), [location.origin + '/']));
    body.appendChild(el('p', 'btnhelp', 'A click on the code or the address copies it.'));
  }, [{words: 'Close', close: true}], true);
}
/* What is changed on the card and not saved yet (1.0.59): the two switches
   and the acmes to forget wait for the save bar at the bottom, as every other
   setting does; Put them back throws them away. */
var PUSH_WANT = {forget: {}};
function pushWanted() {
  var w = PUSH_WANT, d = PUSH || {};
  var any = (w.on !== undefined && w.on !== d.on) || (w.other_names !== undefined && w.other_names !== d.other_names)
    || Object.keys(w.forget).length;
  if (!any) { PUSH_WANT = {forget: {}}; delete PENDING.push; markDirtyCount(); return; }
  pendingSet('push', {pane: 'web', save: pushSave, reset: function () { PUSH_WANT = {forget: {}}; drawPush(PUSH); }});
}
function pushSave() {
  var w = PUSH_WANT, d = PUSH || {}, chain = Promise.resolve();
  var step = function (body) { chain = chain.then(function () { return api('acme-push', body); }); };
  /* Forgotten first, while it is still on; switched off last. */
  Object.keys(w.forget).forEach(function (kid) { step({action: 'key_forget', key_id: kid}); });
  if (w.on === true && !d.on) step({action: 'switch', on: true});
  if (w.other_names !== undefined && w.other_names !== d.other_names) step({action: 'other_names', on: w.other_names});
  if (w.on === false && d.on) step({action: 'switch', on: false});
  return chain.then(function () {
    PUSH_WANT = {forget: {}};
    toast('Certificates from acme: saved', 'good');
    loadPush();
    return true;
  });
}
function drawPush(d) {
  PUSH = d || {};
  var W = PUSH_WANT;
  var host = $('web-push');
  if (!host) return;
  clear(host);
  var st = $('web-push-state');
  if (st) { clear(st); st.appendChild(el('span', 'tag ' + (d.on ? (d.keys.length ? 'ok' : 'warn') : 'dim'), d.on ? (d.keys.length ? 'on - paired' : 'on - not paired yet') : 'off')); }
  var g = el('div', 'set-grid');
  var sw = switchBox(W.on !== undefined ? W.on : d.on);
  sw._input.onchange = function () { PUSH_WANT.on = !!sw._get(); pushWanted(); };
  g.appendChild(formField('Take certificates from acme', sw, 'Off: hello says only that it is off, and nothing is taken.'));
  if (d.on) {
    var sw2 = switchBox(W.other_names !== undefined ? W.other_names : d.other_names);
    sw2._input.onchange = function () { PUSH_WANT.other_names = !!sw2._get(); pushWanted(); };
    g.appendChild(formField('Take certificates of other names', sw2, 'Off: a certificate must hold the name of this server (' + ((d.slots || [])[0] || {names: ['?']}).names.join(', ') + '). On: acme may say not to check it.'));
  }
  host.appendChild(g);
  if (!d.on) return;
  host.appendChild(pushTiles(peekFacts([
    ['The address for acme', noI18n(el('span', 'mono', location.origin + '/'))],
    ['This server’s id', noI18n(el('span', 'mono', d.app_id || ''))],
    ['Its sealing key (X25519)', noI18n(el('span', 'mono small', d.enc_key || ''))]]),
    [location.origin + '/', d.app_id, d.enc_key]));
  /* pairing */
  var row = el('div', 'btnrow');
  var pair = cmdButton('Pair with an acme', 'key', 'primary');
  pair.onclick = function () { pushDo({action: 'pair'}, function (x) { if (x.code) pushCode(x.code, x.pairing.until); }); };
  row.appendChild(pair);
  if (d.pairing) {
    var back = cmdButton('Take it back', 'undo', '');
    back.onclick = function () { pushDo({action: 'pair_stop'}); };
    row.appendChild(back);
    row.appendChild(el('span', 'small muted', 'A code waits until ' + new Date(d.pairing.until * 1000).toLocaleTimeString(numLang()) + ' (' + num(d.pairing.tries) + ' wrong so far).'));
  }
  var paste = cmdButton('Or paste acme’s key…', 'edit', '');
  paste.onclick = function () {
    var ta, nm;
    modal('Paste acme’s key', function (body) {
      body.appendChild(el('p', 'note', 'acme’s own Certificates from acme card shows This acme’s own key: acme-push-ed25519 AAAA… acme then pins this server when it first sees it - keep Check the application’s certificate on there.'));
      ta = el('textarea', 'mono'); ta.rows = 3; ta.placeholder = 'acme-push-ed25519 …';
      body.appendChild(formField('acme’s key', ta));
      nm = textBox('', 'acme1', '');
      body.appendChild(formField('A name for it', nm));
    }, [{words: 'Close', close: true}, {words: 'Take this key', cls: 'primary', icon: 'key', go: function (b) {
      busy(b, true);
      api('acme-push', {action: 'key_add', key: ta.value.trim(), name: nm.value.trim()})
        .then(function (x) { toast(x.message, 'good'); closeModal(); drawPush(x); })
        .catch(function (e) { busy(b, false); oops(e); });
    }}], true);
  };
  row.appendChild(paste);
  host.appendChild(row);
  /* the acmes paired */
  if ((d.keys || []).length) {
    host.appendChild(el('h4', '', 'Paired with'));
    host.appendChild(listTable(['acme', 'Key', 'Since', 'How', {words: '', cls: 'act'}], d.keys, function (k) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', '', k.name || k.comment || '–')));
      tr.appendChild(noI18n(el('td', 'mono small', k.key_id)));
      tr.appendChild(stampCell(k.at));
      tr.appendChild(el('td', 'muted', k.how || ''));
      var act = el('td', 'rowtools');
      if (W.forget[k.key_id]) {
        tr.classList.add('push-gone');
        var keep = cmdButton('Keep it', 'undo', 'small');
        keep.onclick = function () { delete PUSH_WANT.forget[k.key_id]; pushWanted(); drawPush(PUSH); };
        act.appendChild(el('span', 'small muted', 'forgotten when saved'));
        act.appendChild(keep);
      } else {
        var f = cmdButton('Forget it', 'trash', 'small danger');
        explain(f, 'Nothing more is taken from it once saved; the certificate it put in stays until another one replaces it.');
        f.onclick = function () { PUSH_WANT.forget[k.key_id] = true; pushWanted(); drawPush(PUSH); };
        act.appendChild(f);
      }
      tr.appendChild(act);
      return tr;
    }));
  }
  /* what acme sees here */
  host.appendChild(el('h4', '', 'What acme sees here'));
  host.appendChild(listTable(['Slot', 'Names', 'Now', 'Until', 'Looked after by'], d.slots || [], function (s) {
    var tr = el('tr');
    tr.appendChild(noI18n(el('td', 'mono small', s.id)));
    tr.appendChild(noI18n(el('td', 'mono small', (s.names || []).join(', '))));
    var c = s.current || {};
    tr.appendChild(el('td', 'small', c.fingerprint ? (c.issuer || '') + (c.alt ? ' + ' + (c.alt.key_type || '') : '') : 'none'));
    tr.appendChild(c.not_after ? stampCell(c.not_after) : el('td', 'muted', '–'));
    tr.appendChild(el('td', '', {none: 'nobody (none)', manual: 'by hand', 'own-acme': 'Automatic certificates', 'acme-push': 'acme push'}[s.managed_by] || s.managed_by));
    return tr;
  }));
  if (d.last) {
    var l = el('p', 'note good');
    l.textContent = 'The last push: ' + (d.last.acme || '') + ' · ' + ago(d.last.at) + ' · ' + (d.last.said || '');
    host.appendChild(l);
  }
  dressButtons(host);
}

/* ---- passkeys: Face ID, Touch ID, Windows Hello (upsmon 4.4.0, as ai has them) ------
   Your account → Passkeys: added from this device, listed, taken away; a full
   administrator sees anybody's from the row of the account. */
function pkDeviceName() {
  var ua = navigator.userAgent || '';
  if (/iPad/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return 'iPad';
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/Mac/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows';
  if (/Android/.test(ua)) return 'Android';
  return 'this device';
}
function pkCan() {
  return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext
    && !/^[0-9.]+$|^\[/.test(location.hostname));
}
function pkTable(host, rows, then) {
  clear(host);
  if (!rows.length) { host.appendChild(el('p', 'muted small', 'No passkey yet.')); return; }
  host.appendChild(listTable(['Passkey', 'For', 'Added', 'Last used', {words: '', cls: 'act'}], rows, function (p) {
    var tr = el('tr');
    var n = el('td');
    n.appendChild(noI18n(el('span', '', p.name || '–')));
    if (p.backed_up) { n.appendChild(document.createTextNode(' ')); n.appendChild(el('span', 'tag dim', 'synced')); }
    tr.appendChild(n);
    tr.appendChild(noI18n(el('td', 'mono small', p.host || '')));
    tr.appendChild(stampCell(p.created));
    tr.appendChild(p.last_used ? stampCell(p.last_used) : el('td', 'muted', 'never'));
    var act = el('td', 'rowtools');
    var x = cmdButton('Take it away', 'trash', 'small danger');
    x.onclick = function () {
      confirmThen('Take this passkey away?', 'It signs nobody in here any more. It stays on the device until it is taken away there (Settings → Passwords).', 'Take it away', function () {
        api('passkeys', {do: 'delete', id: p.id}).then(function (d) { toast(d.message, 'good'); then(d.passkeys || []); }).catch(oops);
      }, true);
    };
    act.appendChild(x);
    tr.appendChild(act);
    return tr;
  }, 'plain'));
}
function pkAdd(button, then) {
  busy(button, true);
  api('passkey-register', {step: 'begin'}).then(function (d) {
    var o = d.publicKey;
    o.challenge = pkBytes(o.challenge);
    o.user.id = pkBytes(o.user.id);
    o.excludeCredentials = (o.excludeCredentials || []).map(function (c) { return {type: c.type, id: pkBytes(c.id)}; });
    return navigator.credentials.create({publicKey: o});
  }).then(function (cr) {
    return api('passkey-register', {step: 'finish', name: pkDeviceName() + ' · ' + new Date().toLocaleDateString(numLang()),
      clientDataJSON: pkText(cr.response.clientDataJSON), attestationObject: pkText(cr.response.attestationObject)});
  }).then(function (d) {
    toast(d.message, 'good');
    then(d.passkeys || []);
  }).catch(function (e) {
    if (e && e.name === 'InvalidStateError') toast('this device has a passkey for this account already', 'warn');
    else if (!e || (e.name !== 'NotAllowedError' && e.name !== 'AbortError')) oops(e);
  }).then(function () { busy(button, false); });
}
/* The section of Your account. */
function pkMeSection(body) {
  var sec = el('div', 'me-sec');
  sec.appendChild(el('h3', '', 'Passkeys - Face ID, Touch ID'));
  sec.appendChild(el('p', 'note', 'A passkey signs you in with a face, a finger or the PIN of this device - no name, no password to type. It is kept on the device (on an iPad and an iPhone in the iCloud Keychain, so on your other Apple devices too); the server has only its public half.'));
  var list = el('div', 'pk-list');
  sec.appendChild(list);
  var row = el('div', 'btnrow');
  var add = cmdButton('Add a passkey of this device', 'key', 'primary');
  var why = el('span', 'small muted', '');
  row.appendChild(add);
  row.appendChild(why);
  sec.appendChild(row);
  body.appendChild(sec);
  var draw = function (rows) { pkTable(list, rows, draw); };
  api('passkeys').then(function (d) {
    draw(d.passkeys || []);
    if (!d.on) { add.disabled = true; why.textContent = 'Passkeys are switched off on this server (Settings → Accounts).'; }
    else if (!pkCan()) { add.disabled = true; why.textContent = 'A passkey is added on the pages opened by a name over HTTPS (https://name/), not by an address.'; }
    add.onclick = function () { pkAdd(add, draw); };
  }).catch(function (e) { list.appendChild(el('p', 'note bad', String((e && e.message) || e))); });
}
/* A full administrator: anybody's passkeys, from the row of the account. */
function pkOf(name) {
  modal('Passkeys of ' + name, function (body) {
    body.appendChild(el('p', 'note', 'The passkeys this account signs in with. Taken away here, one signs nobody in - for a lost iPad, say. Only the account itself can add one, from Your account.'));
    var list = el('div', 'pk-list');
    body.appendChild(list);
    var draw = function (rows) { pkTable(list, rows, draw); };
    api('passkeys&name=' + encodeURIComponent(name)).then(function (d) { draw(d.passkeys || []); }).catch(oops);
  }, [{words: 'Close', close: true}], 'medium');
}

/* ---- the load of the server in the header (upsmon 4.4.0, ai 1.0.72-1.0.76 as it is) ----
   Off until Settings → About → The load of the server in the header; a full
   administrator only. Its look and the style of its details are the account's
   own (Your account), kept on the server with the account. */
function prefs() { return (typeof ME !== 'undefined' && ME && ME.prefs) || {}; }
function savePrefs(change) {
  return api('prefs', change).then(function (d) {
    if (typeof ME !== 'undefined' && ME) ME.prefs = d.prefs || {};
    return ME.prefs;
  });
}
/* How busy the server is, in the header of the page (from ai 1.0.72-1.0.76).
   Plain JavaScript, no library. Needs the few helpers of helpers.js ($, el, clear,
   noI18n, bytes, api, prefs, savePrefs, LIVE, toast, oops) - or your own of the same names.

   Start it:     hloadLoop();          (polls every 3 s while the page is shown)
   The header:   <div class="hload" id="hload" hidden aria-live="off"></div>
   My account:   hloadPickers(host)    (the two rows of cards to choose the looks)
*/
/* How busy the server is, beside running (1.0.72): every 3 s while the page
   is shown and live, nothing while it is hidden; the daemon reads /proc only
   when asked. CPU, memory, the disks, the network. */
var HLOAD = {timer: null, busy: false};
function hloadRate(n) {
  if (n === null || n === undefined) return '–';
  if (n < 1024) return Math.round(n) + ' B/s';
  if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' kB/s';
  return (n / 1048576).toFixed(n < 10485760 ? 1 : 0) + ' MB/s';
}
/* Four looks to choose from (1.0.72): pills with a bar, one plain line,
   small graphs of the last two minutes, rings. */
var HLOAD_KEEP = 40;
function hloadSpark(vals, max, cls) {
  var w = 56, h = 18, n = vals.length;
  var svg = '<svg class="hl-spark ' + (cls || '') + '" viewBox="0 0 ' + w + ' ' + h + '" width="' + w + '" height="' + h + '" preserveAspectRatio="none" aria-hidden="true">';
  if (n > 1) {
    var top = Math.max(max || 0, 1);
    var pts = vals.map(function (v, i) { return (i * w / (HLOAD_KEEP - 1)).toFixed(1) + ',' + (h - 1 - (h - 2) * Math.min(1, (v || 0) / top)).toFixed(1); });
    svg += '<polyline points="' + pts.join(' ') + '" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>';
  }
  return svg + '</svg>';
}
function hlVal(v) {
  var s = noI18n(el('span', 'hl-v'));
  if (v.indexOf('<span') === 0) s.innerHTML = v; else s.textContent = v;
  return s;
}
/* How wide a bar is: exactly what it says - nothing at 0 %, at least a
   hairline for anything that rounds to 1 % or more. */
function hlWidth(pct) {
  pct = Number(pct) || 0;
  if (pct < 0.5) return 0;
  return Math.max(1, Math.min(100, pct));
}
function hloadRing(pct) {
  var r = 7, c = 2 * Math.PI * r, p = hlWidth(pct);
  return '<svg class="hl-ring" viewBox="0 0 18 18" width="18" height="18" aria-hidden="true"><circle cx="9" cy="9" r="' + r + '" class="hl-ring-bg"/>'
    + '<circle cx="9" cy="9" r="' + r + '" class="hl-ring-fg" stroke-dasharray="' + (c * p / 100).toFixed(1) + ' ' + c.toFixed(1) + '" transform="rotate(-90 9 9)"/></svg>';
}
function hloadDraw(d, into, asLook) {
  /* into/asLook: a preview of a look drawn elsewhere (My account), from the
     sample numbers; it touches nothing of the real header (1.0.75) */
  var preview = !!into;
  var host = into || $('hload');
  if (!host) return;
  var hist;
  var mp = d.mem_total ? 100 * d.mem_used / d.mem_total : null;
  if (preview) hist = hpSample().hist;
  else {
    HLOAD.last = d;
    hist = HLOAD.hist || (HLOAD.hist = {cpu: [], mem: [], disk: [], net: []});
    var push = function (k, v) { hist[k].push(v || 0); if (hist[k].length > HLOAD_KEEP) hist[k].shift(); };
    if (d.cpu !== undefined && !HLOAD.noPush) { push('cpu', d.cpu); push('mem', mp); push('disk', (d.disk_rd || 0) + (d.disk_wr || 0)); push('net', (d.net_rx || 0) + (d.net_tx || 0)); hloadKeep(); }
  }
  var look = asLook || HLOAD.look || 'graphs';
  host.className = 'hload look-' + look + (preview ? ' hl-preview' : '');
  clear(host);
  var tips = {
    cpu: 'The processor, busy over the last ' + (d.over_s || 3) + ' s, all ' + d.cores + ' core(s) together' + (d.load ? ' · load ' + d.load.join(' / ') : ''),
    mem: 'Memory in use (without what the kernel keeps as cache and gives back)' + (d.swap_used ? ' · swap in use ' + bytes(d.swap_used) : ''),
    disk: 'The disks: read ↓ and written ↑, every disk together',
    net: 'The network cards: down ↓ (in) and up ↑ (out), every card together - not the loopback nor the bridges of containers'
  };
  var cpuV = d.cpu === undefined ? '…' : Math.round(d.cpu) + ' %';
  var memV = d.mem_total ? bytes(d.mem_used) + ' / ' + bytes(d.mem_total) : '–';
  // fixed places for each number, so nothing beside them moves as they change (1.0.73)
  var two = function (a, b) { return '<span class="hl-r">↓' + hloadRate(a) + '</span><span class="hl-r">↑' + hloadRate(b) + '</span>'; };
  var diskV = two(d.disk_rd, d.disk_wr);
  var netV = two(d.net_rx, d.net_tx);
  var heat = function (c, pct) { if (pct === null || pct === undefined) return; c.classList.toggle('hot', pct >= 90); c.classList.toggle('warm', pct >= 70 && pct < 90); };
  if (look === 'line') {
    var line = el('span', 'hl-line');
    [['CPU', cpuV, 'cpu', d.cpu], ['RAM', memV, 'mem', mp], ['Disk', diskV, 'disk'], ['Net', netV, 'net']].forEach(function (x, i) {
      if (i) line.appendChild(el('span', 'hl-sep', '·'));
      var part = el('span', 'hl-part hl-' + x[2]);
      part.appendChild(el('span', 'hl-k', x[0]));
      part.appendChild(hlVal(x[1]));
      heat(part, x[3]);
      if (hpStyle() === 'off') part.title = tips[x[2]];
      part.dataset.k = x[2];
      part.tabIndex = 0;
      part.setAttribute('role', 'button');
      if (!preview) hloadPanelHooks(part, x[2]);
      line.appendChild(part);
    });
    host.appendChild(line);
  } else {
    [['CPU', cpuV, 'cpu', d.cpu, 100], ['RAM', memV, 'mem', mp, 100], ['Disk', diskV, 'disk', null, null], ['Net', netV, 'net', null, null]].forEach(function (x) {
      var c = el('span', 'hl hl-' + x[2]);
      c.title = tips[x[2]];
      if (look === 'rings' && x[3] !== null && x[3] !== undefined) {
        var ring = el('span', 'hl-ringbox'); ring.innerHTML = hloadRing(x[3]); c.appendChild(ring);
      }
      c.appendChild(el('span', 'hl-k', x[0]));
      c.appendChild(hlVal(x[1]));
      if (look === 'pills' && x[3] !== null && x[3] !== undefined) {
        var bar = el('span', 'hl-bar'), fill = el('span', '');
        fill.style.width = hlWidth(x[3]) + '%';
        bar.appendChild(fill); c.appendChild(bar);
      }
      if (look === 'graphs') {
        var g = el('span', 'hl-g');
        var vals = hist[x[2]], max = x[4] || Math.max.apply(null, vals.concat([1024]));
        g.innerHTML = hloadSpark(vals, max);
        c.appendChild(g);
      }
      heat(c, x[3]);
      c.dataset.k = x[2];
      c.tabIndex = 0;
      c.setAttribute('role', 'button');
      if (hpStyle() !== 'off') c.removeAttribute('title');
      if (!preview) hloadPanelHooks(c, x[2]);
      host.appendChild(c);
    });
  }
  host.hidden = false;
  if (!preview && HLOAD.open) hloadPanelDraw();
}
/* Sample numbers for the previews in My account: a server with sensors, so
   every part shows (1.0.75). */
function hpSample() {
  if (HLOAD.sample) return HLOAD.sample;
  var h = {cpu: [], mem: [], disk: [], net: []};
  for (var i = 0; i < HLOAD_KEEP; i++) {
    h.cpu.push(48 + 28 * Math.sin(i / 4)); h.mem.push(30 + i * 0.15);
    h.disk.push((1 + Math.sin(i / 4 + 1)) * 9e7); h.net.push((1 + Math.sin(i / 4 + 2)) * 7e6);
  }
  var cores = [[96, 3900, 71], [12, 1200, 48], [88, 3800, 69], [4, 800, 46], [61, 3400, 62], [9, 1100, 47], [100, 4100, 84], [22, 2000, 51]]
    .map(function (c, n) { return {n: n, busy: c[0], mhz: c[1], temp: c[2]}; });
  HLOAD.sample = {hist: h,
    last: {cpu: 49, mem_used: 9.8e9, mem_total: 33.5e9, disk_rd: 190e6, disk_wr: 48e6, net_rx: 12.6e6, net_tx: 1.5e6, cores: 8, load: [3.92, 3.1, 2.71], over_s: 3},
    detail: {cores: cores, model: 'AMD Ryzen 7 5800X 8-Core Processor', temps: {cpu: [['Tctl', 73]], cores: {}, other: []},
      disks: [{name: 'nvme0n1', size: 1e12, model: 'Samsung SSD 980 PRO', rd: 190e6, wr: 48e6, util: 38, temp: 44},
              {name: 'sda', size: 4e12, model: 'WDC WD40EFRX', rd: 2.2e6, wr: 0, util: 3, temp: 36}],
      filesystems: [{mount: '/', kind: 'ext4', total: 984e9, used: 212e9}, {mount: '/srv', kind: 'xfs', total: 3.6e12, used: 3.1e12}],
      nics: [{name: 'eno1', state: 'up', speed: 1000, rx: 12.6e6, tx: 1.5e6, rx_all: 812e9, tx_all: 96e9}],
      top_cpu: [{name: 'node', pid: 1201, cpu: 187}, {name: 'claude', pid: 1302, cpu: 96}, {name: 'postgres', pid: 812, cpu: 41}],
      top_mem: [{name: 'node', pid: 1201, rss: 2.1e9}, {name: 'claude', pid: 1302, rss: 1.4e9}],
      uptime: 1051200, mem: {total: 33.5e9, available: 21.6e9, cached: 6.1e9, buffers: 0.3e9, swap_total: 8.6e9, swap_free: 8.6e9, shared: 120e6}, procs: 312}};
  return HLOAD.sample;
}
/* A picker as the terminal colours: a card for each choice with what it
   really looks like, drawn by the same code from the sample numbers. */
function hlPicker(choices, now, draw, pick) {
  var box = el('div', 'pal-pick hl-pick' + (draw === hlPreviewPanel ? ' hl-pick-p' : ''));
  choices.forEach(function (n) {
    var b = el('button', 'pal-card hl-card' + (n[0] === now ? ' on' : ''));
    b.type = 'button';
    b.dataset.v = n[0];
    var sw = el('div', 'pal-sw hl-sw');
    draw(sw, n[0]);
    b.appendChild(sw);
    b.appendChild(el('span', 'pal-name', n[1]));
    b.onclick = function () {
      box.querySelectorAll('.pal-card').forEach(function (x) { x.classList.toggle('on', x === b); });
      pick(n[0]);
    };
    box.appendChild(b);
  });
  return box;
}
function hlPreviewLook(sw, look) {
  if (look === 'off') { sw.appendChild(el('span', 'muted small hl-none', 'nothing in the header')); return; }
  var inner = el('div', 'hl-scale');
  var host = el('div', 'hload');
  inner.appendChild(host);
  hloadDraw(hpSample().last, host, look);
  sw.appendChild(inner);
}
function hlPreviewPanel(sw, st) {
  if (st === 'off') {
    var t = el('div', 'hl-tipbox');
    t.appendChild(el('span', 'hl-tipchip', 'CPU 49 %'));
    t.appendChild(el('span', 'hl-tip small', 'The processor, busy over the last 3 s, all 8 core(s) together'));
    sw.appendChild(t);
    return;
  }
  var smp = hpSample(), keep = [HLOAD.last, HLOAD.detail, HLOAD.hist, HLOAD.open];
  HLOAD.last = smp.last; HLOAD.detail = smp.detail; HLOAD.hist = smp.hist; HLOAD.open = 'cpu';
  var p = el('div', 'hl-panel hp-' + st + ' hl-prevpanel');
  p.style.width = (st === 'wide' ? 1180 : (st === 'table' ? 420 : 470)) + 'px';
  try {
    if (st === 'table') hpTable(p, 'cpu'); else if (st === 'map') hpMap(p, 'cpu'); else if (st === 'wide') hpWide(p); else hpTiles(p, 'cpu');
  } finally { HLOAD.last = keep[0]; HLOAD.detail = keep[1]; HLOAD.hist = keep[2]; HLOAD.open = keep[3]; }
  var inner = el('div', 'hl-scale hl-scale-p' + (st === 'wide' ? ' wide' : ''));
  inner.appendChild(p);
  sw.appendChild(inner);
}
/* The panel of one chip (1.0.73): pointed at (or tapped on an iPad), what is
   behind the number - each core with its frequency and temperature, the
   disks and the filesystems, the cards, the processes taking most, and the
   last two minutes larger. Read from the daemon only while it is open. */
function hloadPanelHooks(c, k) {
  c.onmouseenter = function () { if (matchMedia('(hover: hover)').matches) hloadPanelOpen(k, c); };
  c.onmouseleave = function () { if (matchMedia('(hover: hover)').matches) hloadPanelSoon(); };
  c.onclick = function (e) { e.stopPropagation(); if (HLOAD.open === k) hloadPanelClose(); else hloadPanelOpen(k, c); };
  c.onkeydown = function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); c.onclick(e); } if (e.key === 'Escape') hloadPanelClose(); };
}
function hloadPanelOpen(k, chip) {
  clearTimeout(HLOAD.shut);
  if (hpStyle() === 'off') return;
  HLOAD.open = k;
  HLOAD.chip = k;
  var p = $('hload-panel');
  if (!p) {
    p = el('div', 'hl-panel');
    p.id = 'hload-panel';
    p.onmouseenter = function () { clearTimeout(HLOAD.shut); };
    p.onmouseleave = function () { if (matchMedia('(hover: hover)').matches) hloadPanelSoon(); };
    p.onclick = function (e) { e.stopPropagation(); };
    document.body.appendChild(p);
    document.addEventListener('click', function () { if (HLOAD.open) hloadPanelClose(); });
    window.addEventListener('resize', function () { if (HLOAD.open) hloadPanelPlace(); });
  }
  p.hidden = false;
  hloadPanelDraw();
  hloadPanelPlace(chip);
  if (!HLOAD.detail || Date.now() - (HLOAD.detailAt || 0) > 2500) hloadTick(true);
}
function hloadPanelSoon() { clearTimeout(HLOAD.shut); HLOAD.shut = setTimeout(hloadPanelClose, 350); }
function hloadPanelClose() {
  HLOAD.open = null;
  var p = $('hload-panel');
  if (p) p.hidden = true;
  document.querySelectorAll('#hload .hl-open').forEach(function (c) { c.classList.remove('hl-open'); });
}
function hloadPanelPlace(chip) {
  var p = $('hload-panel');
  chip = chip || document.querySelector('#hload [data-k="' + HLOAD.chip + '"]');
  if (!p || !chip) return;
  var r = chip.getBoundingClientRect(), st = hpStyle();
  var w = Math.min(st === 'wide' ? 1180 : (st === 'table' ? 420 : 470), window.innerWidth - 16);
  var left = r.left;
  if (st === 'wide') { var hr = $('hload').getBoundingClientRect(); left = hr.left; r = {bottom: hr.bottom, left: hr.left}; }
  p.style.width = w + 'px';
  p.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, left)) + 'px';
  p.style.top = Math.round(r.bottom + 6) + 'px';
  p.style.maxHeight = Math.max(200, window.innerHeight - r.bottom - 20) + 'px';
}
function hlBar(pct, cls) {
  var b = el('span', 'hp-bar ' + (cls || ''));
  var f = el('span', '');
  f.style.width = hlWidth(pct) + '%';
  if (pct >= 90) b.classList.add('hot'); else if (pct >= 70) b.classList.add('warm');
  b.appendChild(f);
  return b;
}
function hlTemp(t) {
  if (t === null || t === undefined) return null;
  return el('span', 'hp-temp' + (t >= 85 ? ' hot' : (t >= 70 ? ' warm' : '')), Math.round(t) + ' °C');
}
function hlUp(sec) {
  sec = Math.round(sec || 0);
  var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return (d ? d + ' d ' : '') + (d || h ? h + ' h ' : '') + m + ' min';
}
/* Four ways to show the details (1.0.74), chosen in My account: tiles, a
   table (as htop, good for many cores), a map of the cores with rings, or one
   wide panel with all four at once. */
var HP_STYLES = [['tiles', 'tiles - a card for each core'], ['table', 'a table - a row for each core (as htop)'],
                 ['map', 'a map of the cores with rings'], ['wide', 'one wide panel with everything at once'],
                 ['off', 'no details - only a short tip']];
function hpStyle() { var v = prefs().hpanel; return HP_STYLES.some(function (x) { return x[0] === v; }) ? v : 'tiles'; }
function hloadPanelDraw() {
  var p = $('hload-panel'), k = HLOAD.open;
  if (!p || !k) return;
  var st = hpStyle();
  clear(p);
  p.className = 'hl-panel hp-' + st;
  document.querySelectorAll('#hload [data-k]').forEach(function (c) { c.classList.toggle('hl-open', st !== 'wide' ? c.dataset.k === k : true); });
  if (st === 'table') hpTable(p, k);
  else if (st === 'map') hpMap(p, k);
  else if (st === 'wide') hpWide(p);
  else hpTiles(p, k);
}
var HP_TITLE = {cpu: 'The processor', mem: 'Memory', disk: 'The disks', net: 'The network'};
function hpMax(k) {
  var vals = (HLOAD.hist || {})[k] || [];
  return (k === 'cpu' || k === 'mem') ? 100 : Math.max.apply(null, vals.concat([1024]));
}
/* a filled graph of the last two minutes, as wide as its box */
function hpArea(k, h, grid) {
  var vals = (HLOAD.hist || {})[k] || [], w = 400, top = Math.max(hpMax(k), 1);
  var box = el('div', 'hp-area hl-' + k);
  var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" width="100%" height="' + h + '" preserveAspectRatio="none" aria-hidden="true">';
  if (grid) [0.25, 0.5, 0.75].forEach(function (g) { svg += '<line x1="0" x2="' + w + '" y1="' + h * g + '" y2="' + h * g + '" class="hp-grid" vector-effect="non-scaling-stroke"/>'; });
  if (vals.length > 1) {
    var pts = vals.map(function (v, i) { return (i * w / (HLOAD_KEEP - 1)).toFixed(1) + ',' + (h - 1 - (h - 3) * Math.min(1, (v || 0) / top)).toFixed(1); });
    var last = ((vals.length - 1) * w / (HLOAD_KEEP - 1)).toFixed(1);
    svg += '<polygon points="0,' + h + ' ' + pts.join(' ') + ' ' + last + ',' + h + '" fill="currentColor" opacity=".16"/>';
    svg += '<polyline points="' + pts.join(' ') + '" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" vector-effect="non-scaling-stroke"/>';
  }
  box.innerHTML = svg + '</svg>';
  return box;
}
function hpRing(pct, label, cls, size) {
  size = size || 78;
  var r = size / 2 - 7, c = 2 * Math.PI * r, v = hlWidth(pct);
  var col = cls || (v >= 90 ? 'hot' : (v >= 70 ? 'warm' : ''));
  var box = el('span', 'hp-ring ' + col);
  box.innerHTML = '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" aria-hidden="true">'
    + '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" class="hp-ring-bg"/>'
    + '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" class="hp-ring-fg" stroke-dasharray="' + (c * v / 100).toFixed(1) + ' ' + c.toFixed(1) + '" transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')"/></svg>';
  box.appendChild(noI18n(el('span', 'hp-ring-v', label)));
  return box;
}
function hpTempCls(t) { return t >= 85 ? 'hot' : (t >= 70 ? 'warm' : 'ok'); }
function hpSec(p, title) { var s = el('div', 'hp-sec'); if (title) s.appendChild(el('div', 'hp-h', title)); p.appendChild(s); return s; }
function hpTd(tr, v, cls) { var td = el('td', cls || ''); if (v && v.nodeType) td.appendChild(v); else if (v !== null && v !== undefined) td.appendChild(noI18n(el('span', '', String(v)))); tr.appendChild(td); return td; }
function hpGHz(m) { return m ? (m >= 1000 ? (m / 1000).toFixed(1) + ' GHz' : m + ' MHz') : ''; }
function hpPct(v) { return v === null || v === undefined ? '…' : Math.round(v) + ' %'; }
function hpCpuTemp(x) { var t = ((x.temps || {}).cpu || [])[0]; return t ? t[1] : null; }
function hpNoTemp(host, x) {
  var tps = x.temps || {};
  if (!(tps.cpu || []).length && !Object.keys(tps.cores || {}).length)
    host.appendChild(el('p', 'muted small', 'No temperature: this machine has no sensors the kernel reads (a virtual machine has none).'));
}
function hpWait(p) { p.appendChild(el('p', 'muted small', 'reading…')); }
/* the same rows for memory and the network in every style but the tiles */
function hpMemRows(host, x) {
  var m = x.mem || {}, used = (m.total || 0) - (m.available || 0);
  var t = el('table', 'hp-t hp-kvt');
  [['In use', bytes(used)], ['Free for programs', bytes(m.available || 0)], ['Cache (given back when needed)', bytes((m.cached || 0) + (m.buffers || 0))],
   ['Shared', bytes(m.shared || 0)], ['Swap', m.swap_total ? bytes(m.swap_total - (m.swap_free || 0)) + ' / ' + bytes(m.swap_total) : null], ['Altogether', bytes(m.total || 0)]].forEach(function (r) {
    var tr = el('tr', ''); hpTd(tr, el('span', 'muted', r[0])); hpTd(tr, r[1] === null ? el('span', 'muted', 'none') : r[1], 'num'); t.appendChild(tr);
  });
  host.appendChild(t);
}
function hpProcs(host, list, what) {
  /* the bar is the real share: of one core (or of the busiest process past
     100 %), of the memory in use - not of the busiest process */
  var t = el('table', 'hp-t'), top = 100;
  var memAll = (HLOAD.last && (HLOAD.last.mem_used || HLOAD.last.mem_total)) || 0;
  list.forEach(function (q) { if (what === 'cpu') top = Math.max(top, q.cpu || 0); });
  list.slice(0, 5).forEach(function (q) {
    var tr = el('tr', ''), v = what === 'cpu' ? q.cpu : q.rss;
    var share = what === 'cpu' ? 100 * (v || 0) / top : (memAll ? 100 * (v || 0) / memAll : 0);
    hpTd(tr, q.name, 'mono hp-name'); hpTd(tr, hlBar(share, 'hp-info'), 'hp-barc');
    hpTd(tr, what === 'cpu' ? Math.round(v) + ' %' : bytes(v), 'num');
    t.appendChild(tr);
  });
  host.appendChild(t);
  if (!list.length) host.appendChild(el('p', 'muted small', 'nothing busy just now'));
}
function hpNicRows(host, x) {
  var t = el('table', 'hp-t');
  (x.nics || []).forEach(function (n) {
    var tr = el('tr', '');
    hpTd(tr, el('b', 'mono', n.name)); hpTd(tr, (n.state || '') + (n.speed ? ' · ' + (n.speed >= 1000 ? n.speed / 1000 + ' Gb/s' : n.speed + ' Mb/s') : ''), 'muted small');
    hpTd(tr, '↓' + hloadRate(n.rx) + ' ↑' + hloadRate(n.tx), 'num'); t.appendChild(tr);
    var tr2 = el('tr', 'hp-sub'); hpTd(tr2, ''); hpTd(tr2, noI18n(el('span', 'muted small', '↓' + bytes(n.rx_all) + ' ↑' + bytes(n.tx_all))), 'hp-span2');
    tr2.lastChild.colSpan = 2; t.appendChild(tr2);
  });
  host.appendChild(t);
  if (!(x.nics || []).length) host.appendChild(el('p', 'muted small', 'no card'));
}
function hpDisks(x) { return (x.disks || []).filter(function (dk) { return dk.size > 64 * 1048576; }); }
function hpHead(p, k, extra) {
  var head = el('div', 'hp-head');
  head.appendChild(el('b', '', HP_TITLE[k]));
  if (extra) head.appendChild(extra);
  p.appendChild(head);
}
/* B - the table */
function hpTable(p, k) {
  var d = HLOAD.last || {}, x = HLOAD.detail;
  var sum = {cpu: hpPct(d.cpu), mem: d.mem_total ? bytes(d.mem_used) + ' / ' + bytes(d.mem_total) : '',
             disk: '↓' + hloadRate(d.disk_rd) + ' ↑' + hloadRate(d.disk_wr), net: '↓' + hloadRate(d.net_rx) + ' ↑' + hloadRate(d.net_tx)}[k];
  var ex = el('span', 'muted small');
  ex.appendChild(noI18n(el('b', 'hp-sum', sum)));
  if (k === 'cpu' && x) { ex.appendChild(noI18n(el('span', '', ' · load ' + (d.load || []).join(' / ')))); var ct = hpCpuTemp(x); if (ct !== null) { ex.appendChild(noI18n(el('span', '', ' · '))); ex.appendChild(hlTemp(ct)); } }
  hpHead(p, k, ex);
  p.appendChild(hpArea(k, 38));
  if (!x) return hpWait(p);
  if (k === 'cpu') {
    var t = el('table', 'hp-t hp-cores-t');
    (x.cores || []).forEach(function (c) {
      var tr = el('tr', '');
      hpTd(tr, 'cpu' + c.n, 'mono muted'); hpTd(tr, hlBar(c.busy), 'hp-barc'); hpTd(tr, hpPct(c.busy), 'num');
      hpTd(tr, hpGHz(c.mhz), 'num muted'); hpTd(tr, hlTemp(c.temp), 'num'); t.appendChild(tr);
    });
    p.appendChild(t);
    hpNoTemp(p, x);
    hpProcs(hpSec(p, 'Taking most of the processor'), x.top_cpu || [], 'cpu');
  } else if (k === 'mem') {
    hpMemRows(hpSec(p, ''), x);
    hpProcs(hpSec(p, 'Taking most memory'), x.top_mem || [], 'mem');
  } else if (k === 'disk') {
    var td = el('table', 'hp-t'), hr = el('tr', 'hp-th');
    ['disk', 'read', 'written', 'busy', '°C'].forEach(function (h, i) { hpTd(hr, el('span', '', h), i ? 'num' : ''); });
    td.appendChild(hr);
    hpDisks(x).forEach(function (dk) {
      var tr = el('tr', '');
      hpTd(tr, dk.name, 'mono'); hpTd(tr, hloadRate(dk.rd), 'num'); hpTd(tr, hloadRate(dk.wr), 'num'); hpTd(tr, hpPct(dk.util), 'num'); hpTd(tr, hlTemp(dk.temp), 'num');
      td.appendChild(tr);
    });
    p.appendChild(td);
    var s2 = hpSec(p, 'Filesystems'), tf = el('table', 'hp-t');
    (x.filesystems || []).forEach(function (f) {
      var pct = f.total ? 100 * f.used / f.total : 0, tr = el('tr', '');
      hpTd(tr, f.mount, 'mono hp-name'); hpTd(tr, hlBar(pct), 'hp-barc'); hpTd(tr, bytes(f.used) + ' / ' + bytes(f.total), 'num muted small'); hpTd(tr, Math.round(pct) + ' %', 'num');
      tf.appendChild(tr);
    });
    s2.appendChild(tf);
  } else hpNicRows(hpSec(p, ''), x);
}
/* C - the map of the cores and rings */
function hpMap(p, k) {
  var d = HLOAD.last || {}, x = HLOAD.detail;
  var top = el('div', 'hp-top');
  var info = el('div', 'hp-info-col');
  info.appendChild(el('b', '', HP_TITLE[k]));
  if (k === 'cpu') {
    top.appendChild(hpRing(d.cpu, hpPct(d.cpu)));
    var ct = x ? hpCpuTemp(x) : null;
    if (ct !== null) top.appendChild(hpRing(ct, Math.round(ct) + '°', hpTempCls(ct) === 'ok' ? '' : hpTempCls(ct)));
    if (x) {
      if (x.model) info.appendChild(noI18n(el('div', 'muted small', x.model)));
      info.appendChild(noI18n(el('div', 'muted small', 'load ' + (d.load || []).join(' / ') + ' · ' + hlUp(x.uptime))));
    }
  } else if (k === 'mem') {
    var mp = d.mem_total ? 100 * d.mem_used / d.mem_total : 0;
    top.appendChild(hpRing(mp, Math.round(mp) + ' %'));
    info.appendChild(noI18n(el('div', 'muted small', d.mem_total ? bytes(d.mem_used) + ' / ' + bytes(d.mem_total) : '')));
  } else {
    var a = k === 'disk' ? [d.disk_rd, d.disk_wr] : [d.net_rx, d.net_tx];
    info.appendChild(noI18n(el('div', 'hp-big', '↓' + hloadRate(a[0]) + '  ↑' + hloadRate(a[1]))));
  }
  top.appendChild(info);
  p.appendChild(top);
  p.appendChild(hpArea(k, 60, true));
  if (!x) return hpWait(p);
  if (k === 'cpu') {
    var s = hpSec(p, 'Map of the cores (colour = how busy, number = temperature)');
    var g = el('div', 'hp-heat');
    (x.cores || []).forEach(function (c) {
      var b = el('div', 'hp-cell'), v = c.busy || 0;
      b.style.background = 'hsl(' + Math.round(120 - 1.2 * v) + ',62%,' + Math.round(20 + v * 0.17) + '%)';
      b.appendChild(noI18n(el('span', 'hp-cell-n', String(c.n))));
      b.appendChild(noI18n(el('b', '', c.busy === null || c.busy === undefined ? '…' : Math.round(v) + '%')));
      b.appendChild(noI18n(el('span', 'hp-cell-t', c.temp !== null && c.temp !== undefined ? Math.round(c.temp) + '°' : hpGHz(c.mhz))));
      b.title = 'CPU ' + c.n + ' · ' + hpGHz(c.mhz);
      g.appendChild(b);
    });
    s.appendChild(g);
    hpNoTemp(s, x);
    var s3 = hpSec(p, 'Taking most of the processor'), w = el('div', 'hp-pills');
    (x.top_cpu || []).slice(0, 6).forEach(function (q) { var c = el('span', 'hp-pill'); c.appendChild(noI18n(el('span', 'mono', q.name))); c.appendChild(noI18n(el('b', '', Math.round(q.cpu) + ' %'))); w.appendChild(c); });
    s3.appendChild(w);
  } else if (k === 'mem') {
    hpMemRows(hpSec(p, ''), x);
    hpProcs(hpSec(p, 'Taking most memory'), x.top_mem || [], 'mem');
  } else if (k === 'disk') {
    var cards = el('div', 'hp-cards');
    hpDisks(x).forEach(function (dk) {
      var c = el('div', 'hp-card'), t = el('div', 'hp-card-top');
      t.appendChild(noI18n(el('b', 'mono', dk.name)));
      if (dk.temp !== null && dk.temp !== undefined) t.appendChild(hlTemp(dk.temp));
      c.appendChild(t);
      c.appendChild(noI18n(el('div', 'muted small hp-ell', bytes(dk.size) + (dk.model ? ' · ' + dk.model : ''))));
      c.appendChild(noI18n(el('div', 'hp-big', hpPct(dk.util))));
      c.appendChild(hlBar(dk.util));
      c.appendChild(noI18n(el('div', 'muted small', '↓' + hloadRate(dk.rd) + ' ↑' + hloadRate(dk.wr))));
      cards.appendChild(c);
    });
    p.appendChild(cards);
    var s2 = hpSec(p, 'Filesystems'), rings = el('div', 'hp-rings');
    (x.filesystems || []).forEach(function (f) {
      var pct = f.total ? 100 * f.used / f.total : 0, one = el('div', 'hp-fsring');
      one.appendChild(hpRing(pct, Math.round(pct) + '%', null, 64));
      one.appendChild(noI18n(el('div', 'mono hp-ell', f.mount)));
      one.appendChild(noI18n(el('div', 'muted small', bytes(f.used) + ' / ' + bytes(f.total))));
      rings.appendChild(one);
    });
    s2.appendChild(rings);
  } else {
    var nc = el('div', 'hp-cards');
    (x.nics || []).forEach(function (n) {
      var c = el('div', 'hp-card'), t = el('div', 'hp-card-top');
      t.appendChild(noI18n(el('b', 'mono', n.name)));
      t.appendChild(noI18n(el('span', 'muted small', (n.state || '') + (n.speed ? ' · ' + (n.speed >= 1000 ? n.speed / 1000 + ' Gb/s' : n.speed + ' Mb/s') : ''))));
      c.appendChild(t);
      c.appendChild(noI18n(el('div', 'hp-big', '↓' + hloadRate(n.rx))));
      c.appendChild(noI18n(el('div', 'hp-big', '↑' + hloadRate(n.tx))));
      c.appendChild(noI18n(el('div', 'muted small', '↓' + bytes(n.rx_all) + ' ↑' + bytes(n.tx_all))));
      nc.appendChild(c);
    });
    p.appendChild(nc);
    if (!(x.nics || []).length) p.appendChild(el('p', 'muted small', 'no card'));
  }
}
/* D - one wide panel, the four side by side */
function hpWide(p) {
  var d = HLOAD.last || {}, x = HLOAD.detail;
  var grid = el('div', 'hp-wide-grid');
  ['cpu', 'mem', 'disk', 'net'].forEach(function (k) {
    var col = el('div', 'hp-col' + (k === HLOAD.open ? ' hp-col-on' : ''));
    var head = el('div', 'hp-head');
    head.appendChild(el('b', '', HP_TITLE[k]));
    var sum = {cpu: hpPct(d.cpu), mem: d.mem_total ? bytes(d.mem_used) + ' / ' + bytes(d.mem_total) : '',
               disk: '↓' + hloadRate(d.disk_rd) + ' ↑' + hloadRate(d.disk_wr), net: '↓' + hloadRate(d.net_rx) + ' ↑' + hloadRate(d.net_tx)}[k];
    var ex = el('span', 'small');
    ex.appendChild(noI18n(el('span', 'hp-sum', sum)));
    if (k === 'cpu' && x) { var ct = hpCpuTemp(x); if (ct !== null) { ex.appendChild(noI18n(el('span', '', ' '))); ex.appendChild(hlTemp(ct)); } }
    head.appendChild(ex);
    col.appendChild(head);
    col.appendChild(hpArea(k, 34));
    if (!x) { hpWait(col); grid.appendChild(col); return; }
    if (k === 'cpu') {
      var t = el('table', 'hp-t');
      (x.cores || []).forEach(function (c) {
        var tr = el('tr', '');
        hpTd(tr, 'cpu' + c.n, 'mono muted'); hpTd(tr, hlBar(c.busy), 'hp-barc'); hpTd(tr, hpPct(c.busy), 'num'); hpTd(tr, hlTemp(c.temp), 'num');
        t.appendChild(tr);
      });
      col.appendChild(t);
      if (x.model) col.appendChild(noI18n(el('div', 'muted small hp-ell', x.model)));
      col.appendChild(noI18n(el('div', 'muted small', 'load ' + (d.load || []).join(' / ') + ' · ' + hlUp(x.uptime))));
    } else if (k === 'mem') {
      hpMemRows(col, x);
      hpProcs(hpSec(col, 'Taking most memory'), (x.top_mem || []).slice(0, 4), 'mem');
    } else if (k === 'disk') {
      var td = el('table', 'hp-t');
      hpDisks(x).forEach(function (dk) {
        var tr = el('tr', '');
        hpTd(tr, dk.name, 'mono hp-name'); hpTd(tr, hlBar(dk.util), 'hp-barc'); hpTd(tr, hpPct(dk.util), 'num'); hpTd(tr, hlTemp(dk.temp), 'num');
        td.appendChild(tr);
        var tr2 = el('tr', 'hp-sub'); hpTd(tr2, ''); hpTd(tr2, noI18n(el('span', 'muted small', '↓' + hloadRate(dk.rd) + ' ↑' + hloadRate(dk.wr))));
        tr2.lastChild.colSpan = 3; td.appendChild(tr2);
      });
      col.appendChild(td);
      var s2 = hpSec(col, 'Filesystems'), tf = el('table', 'hp-t');
      (x.filesystems || []).forEach(function (f) {
        var pct = f.total ? 100 * f.used / f.total : 0, tr = el('tr', '');
        hpTd(tr, f.mount, 'mono hp-name'); hpTd(tr, hlBar(pct), 'hp-barc'); hpTd(tr, Math.round(pct) + ' %', 'num'); tf.appendChild(tr);
      });
      s2.appendChild(tf);
    } else {
      var tn = el('table', 'hp-t');
      (x.nics || []).forEach(function (n) {
        var tr = el('tr', '');
        hpTd(tr, el('b', 'mono', n.name), 'hp-name');
        hpTd(tr, (n.state || '') + (n.speed ? ' · ' + (n.speed >= 1000 ? n.speed / 1000 + ' Gb/s' : n.speed + ' Mb/s') : ''), 'num muted small');
        tn.appendChild(tr);
        var tr2 = el('tr', 'hp-sub'); hpTd(tr2, noI18n(el('span', '', '↓' + hloadRate(n.rx) + ' ↑' + hloadRate(n.tx)))); tr2.lastChild.colSpan = 2; tn.appendChild(tr2);
        var tr3 = el('tr', 'hp-sub'); hpTd(tr3, noI18n(el('span', 'muted small', '↓' + bytes(n.rx_all) + ' ↑' + bytes(n.tx_all)))); tr3.lastChild.colSpan = 2; tn.appendChild(tr3);
      });
      col.appendChild(tn);
      if (!(x.nics || []).length) col.appendChild(el('p', 'muted small', 'no card'));
    }
    grid.appendChild(col);
  });
  p.appendChild(grid);
  if (x) {
    var s = hpSec(p, 'Taking most of the processor'), w = el('div', 'hp-pills');
    (x.top_cpu || []).slice(0, 8).forEach(function (q) { var c = el('span', 'hp-pill'); c.appendChild(noI18n(el('span', 'mono', q.name))); c.appendChild(noI18n(el('b', '', Math.round(q.cpu) + ' %'))); w.appendChild(c); });
    s.appendChild(w);
  }
}
/* A - the tiles */
function hpTiles(p, k) {
  var d = HLOAD.last || {}, x = HLOAD.detail;
  var head = el('div', 'hp-head');
  head.appendChild(el('b', '', {cpu: 'The processor', mem: 'Memory', disk: 'The disks', net: 'The network'}[k]));
  var big = el('div', 'hp-graph');
  var vals = (HLOAD.hist || {})[k] || [];
  var max = (k === 'cpu' || k === 'mem') ? 100 : Math.max.apply(null, vals.concat([1024]));
  big.innerHTML = hloadSpark(vals, max).replace('width="56" height="18"', 'width="100%" height="54"');
  big.classList.add('hl-' + k);
  var scale = el('span', 'hp-scale muted small', k === 'cpu' || k === 'mem' ? '100 %' : hloadRate(max));
  head.appendChild(scale);
  p.appendChild(head);
  p.appendChild(big);
  p.appendChild(el('div', 'hp-span muted small', 'the last two minutes'));
  var sec = function (title) { var s = el('div', 'hp-sec'); if (title) s.appendChild(el('div', 'hp-h', title)); p.appendChild(s); return s; };
  var row = function (host, cells) { var r = el('div', 'hp-row'); cells.forEach(function (c) { if (c === null || c === undefined) { r.appendChild(el('span', '')); return; } r.appendChild(c.nodeType ? c : noI18n(el('span', '', String(c)))); }); host.appendChild(r); return r; };
  if (!x) { p.appendChild(el('p', 'muted small', 'reading…')); return; }
  var tps = x.temps || {};
  if (k === 'cpu') {
    var s1 = sec('');
    row(s1, [el('span', 'muted', 'Now'), noI18n(el('b', '', d.cpu === undefined ? '…' : Math.round(d.cpu) + ' %')), el('span', 'muted', 'load'), noI18n(el('span', '', (d.load || []).join(' / ')))]).classList.add('hp-kv');
    if (x.model) row(s1, [noI18n(el('span', 'hp-wide muted small', x.model))]);
    row(s1, [el('span', 'muted', 'Up for'), noI18n(el('span', '', hlUp(x.uptime))), el('span', 'muted', 'processes'), noI18n(el('span', '', String(x.procs || '')))]).classList.add('hp-kv');
    (tps.cpu || []).forEach(function (t) { row(s1, [noI18n(el('span', 'muted', t[0])), hlTemp(t[1])]).classList.add('hp-kv'); });
    var s2 = sec('Each core');
    var grid = el('div', 'hp-cores');
    (x.cores || []).forEach(function (c) {
      var one = el('div', 'hp-core');
      var top = el('div', 'hp-core-top');
      top.appendChild(noI18n(el('b', '', 'CPU ' + c.n)));
      top.appendChild(noI18n(el('span', '', c.busy === null || c.busy === undefined ? '…' : Math.round(c.busy) + ' %')));
      one.appendChild(top);
      one.appendChild(hlBar(c.busy));
      var bot = el('div', 'hp-core-bot muted small');
      bot.appendChild(noI18n(el('span', '', c.mhz ? (c.mhz >= 1000 ? (c.mhz / 1000).toFixed(1) + ' GHz' : c.mhz + ' MHz') : '')));
      var t = hlTemp(c.temp);
      if (t) bot.appendChild(t);
      one.appendChild(bot);
      grid.appendChild(one);
    });
    s2.appendChild(grid);
    if (!(tps.cpu || []).length && !Object.keys(tps.cores || {}).length) s2.appendChild(el('p', 'muted small', 'No temperature: this machine has no sensors the kernel reads (a virtual machine has none).'));
    var s3 = sec('Taking most of the processor');
    (x.top_cpu || []).slice(0, 5).forEach(function (q) { row(s3, [noI18n(el('span', 'mono', q.name)), noI18n(el('span', 'muted small', 'pid ' + q.pid)), noI18n(el('span', 'num', Math.round(q.cpu) + ' %'))]); });
    if (!(x.top_cpu || []).length) s3.appendChild(el('p', 'muted small', 'nothing busy just now'));
  } else if (k === 'mem') {
    var m = x.mem || {}, used = (m.total || 0) - (m.available || 0);
    var s1m = sec('');
    s1m.appendChild(hlBar(m.total ? 100 * used / m.total : 0));
    [['In use', used], ['Free for programs', m.available], ['Cache (given back when needed)', (m.cached || 0) + (m.buffers || 0)], ['Shared', m.shared], ['Altogether', m.total]].forEach(function (r) {
      row(s1m, [el('span', 'muted', r[0]), noI18n(el('span', 'num', bytes(r[1] || 0)))]).classList.add('hp-kv2');
    });
    if (m.swap_total) {
      var su = m.swap_total - (m.swap_free || 0);
      row(s1m, [el('span', 'muted', 'Swap'), noI18n(el('span', 'num', bytes(su) + ' / ' + bytes(m.swap_total)))]).classList.add('hp-kv2');
    } else row(s1m, [el('span', 'muted', 'Swap'), el('span', 'num muted', 'none')]).classList.add('hp-kv2');
    var s2m = sec('Taking most memory');
    (x.top_mem || []).slice(0, 5).forEach(function (q) { row(s2m, [noI18n(el('span', 'mono', q.name)), noI18n(el('span', 'muted small', 'pid ' + q.pid)), noI18n(el('span', 'num', bytes(q.rss)))]); });
  } else if (k === 'disk') {
    var s1d = sec('Each disk');
    (x.disks || []).filter(function (dk) { return dk.size > 64 * 1048576; }).forEach(function (dk) {
      var r = row(s1d, [noI18n(el('b', 'mono', dk.name)), noI18n(el('span', 'muted small', bytes(dk.size) + (dk.model ? ' · ' + dk.model : ''))),
        noI18n(el('span', 'num', '↓' + hloadRate(dk.rd) + ' ↑' + hloadRate(dk.wr))), hlTemp(dk.temp)]);
      r.classList.add('hp-disk');
      var u = el('div', 'hp-util');
      u.appendChild(el('span', 'muted small', 'busy'));
      u.appendChild(hlBar(dk.util));
      u.appendChild(noI18n(el('span', 'small num', dk.util === undefined ? '…' : Math.round(dk.util) + ' %')));
      s1d.appendChild(u);
    });
    var s2d = sec('Filesystems');
    (x.filesystems || []).forEach(function (f) {
      var pct = f.total ? 100 * f.used / f.total : 0;
      var r = row(s2d, [noI18n(el('span', 'mono', f.mount)), noI18n(el('span', 'muted small', f.kind)), noI18n(el('span', 'num', bytes(f.used) + ' / ' + bytes(f.total)))]);
      r.classList.add('hp-fs');
      var b = el('div', 'hp-util');
      b.appendChild(hlBar(pct));
      b.appendChild(noI18n(el('span', 'small num', Math.round(pct) + ' %')));
      s2d.appendChild(b);
    });
  } else {
    var s1n = sec('Each card');
    (x.nics || []).forEach(function (n) {
      row(s1n, [noI18n(el('b', 'mono', n.name)), noI18n(el('span', 'muted small', (n.state || '') + (n.speed ? ' · ' + (n.speed >= 1000 ? n.speed / 1000 + ' Gb/s' : n.speed + ' Mb/s') : ''))),
        noI18n(el('span', 'num', '↓' + hloadRate(n.rx) + ' ↑' + hloadRate(n.tx)))]).classList.add('hp-nic');
      row(s1n, [el('span', ''), noI18n(el('span', 'muted small', 'since start ↓' + bytes(n.rx_all) + ' ↑' + bytes(n.tx_all)))]).classList.add('hp-nic2');
    });
    if (!(x.nics || []).length) s1n.appendChild(el('p', 'muted small', 'no card'));
  }
  var oth = tps.other || [];
  if (k === 'cpu' && oth.length) {
    var s4 = sec('Other sensors');
    oth.forEach(function (t) { row(s4, [noI18n(el('span', 'muted', t[0])), hlTemp(t[1])]).classList.add('hp-kv'); });
  }
}
function hloadTick(now) {
  if (!$('hload') || (HLOAD.busy && !now) || document.hidden || !LIVE) return;
  HLOAD.look = prefs().hload || 'graphs';
  if (HLOAD.look === 'off') { $('hload').hidden = true; return; }
  HLOAD.busy = true;
  var withDetail = !!HLOAD.open;
  api('load' + (withDetail ? '&detail=1' : '')).then(function (d) {
    if (d.detail) { HLOAD.detail = d.detail; HLOAD.detailAt = Date.now(); }
    hloadDraw(d);
  }).catch(function () { }).then(function () { HLOAD.busy = false; });
}
/* The graphs kept across a reload (upsmon 4.4.0): F5 draws what was there at
   once and goes on from it, rather than starting again empty. This tab only
   (sessionStorage), at most the last two minutes; the time the page was away
   is drawn as a gap. */
var HLOAD_STORE = 'upsmon-hload';
function hloadKeep() {
  try { sessionStorage.setItem(HLOAD_STORE, JSON.stringify({at: Date.now(), hist: HLOAD.hist, last: HLOAD.last})); } catch (e) { }
}
function hloadRestore() {
  var k = null;
  try { k = JSON.parse(sessionStorage.getItem(HLOAD_STORE) || 'null'); } catch (e) { k = null; }
  if (!k || !k.hist || !k.last || !(k.at > 0)) return;
  var away = (Date.now() - k.at) / 1000;
  if (away < 0 || away > 3 * HLOAD_KEEP) return;
  var gap = Math.floor(away / 3);
  ['cpu', 'mem', 'disk', 'net'].forEach(function (x) {
    var v = (k.hist[x] || []).slice();
    for (var i = 0; i < gap; i++) v.push(0);
    k.hist[x] = v.slice(-HLOAD_KEEP);
  });
  HLOAD.hist = k.hist;
  HLOAD.look = prefs().hload || 'graphs';
  if (HLOAD.look === 'off') return;
  /* drawn as it was, without adding a point: the next reading adds it */
  HLOAD.noPush = true;
  try { hloadDraw(k.last); } finally { HLOAD.noPush = false; }
}
function hloadLoop() {
  if (!$('hload')) return;
  clearInterval(HLOAD.timer);
  if (!HLOAD.hist) hloadRestore();
  hloadTick();
  setTimeout(hloadTick, 1200);      /* the first rate needs a second reading */
  HLOAD.timer = setInterval(hloadTick, 3000);
}
document.addEventListener('visibilitychange', function () { if (!document.hidden) hloadTick(); });

/* The two pickers of My account (1.0.75): cards drawn by the same code from sample numbers. */
function hloadPickers(lsec) {
  if (!$('hload')) return;
  var HL_LOOKS = [['graphs', 'with a graph of the last two minutes'], ['pills', 'pills with a bar'], ['line', 'one plain line'],
                  ['rings', 'with rings'], ['off', 'not shown']];
  var g3 = el('div', 'hl-pickers');
  g3.appendChild(el('div', 'hl-pick-h', 'The load of the server in the header (CPU, RAM, the disks, the network)'));
  g3.appendChild(hlPicker(HL_LOOKS, prefs().hload || 'graphs', hlPreviewLook, function (v) {
    savePrefs({hload: v}).then(function () {
      HLOAD.look = v;
      if (v === 'off') { hloadPanelClose(); $('hload').hidden = true; } else if (HLOAD.last) hloadDraw(HLOAD.last); else hloadTick();
      toast('kept', 'good');
    }).catch(oops);
  }));
  /* and how its details look when a number is pointed at (1.0.74) */
  g3.appendChild(el('div', 'hl-pick-h', 'Its details, when a number is pointed at (or tapped)'));
  g3.appendChild(hlPicker(HP_STYLES, hpStyle(), hlPreviewPanel, function (v) {
    savePrefs({hpanel: v}).then(function () {
      if (v === 'off') hloadPanelClose(); else if (HLOAD.open) { hloadPanelDraw(); hloadPanelPlace(); }
      if (HLOAD.last) hloadDraw(HLOAD.last);
      toast('kept', 'good');
    }).catch(oops);
  }));
  lsec.appendChild(g3);
}

/* ======== helpers of the panes above, from OTP admin.js ======== */
var MODAL_GO = null;

var QS = {
  tokens: qSuggest($('tk-q'), 'tokens'),
  mailq: qSuggest($('mq-q'), 'mailq'),
  requests: qSuggest($('rq-q'), 'radius', function () { return 'hours=' + $('rq-hours').value; }),
  events: qSuggest($('ev-q'), 'events'),
  enrolment: qSuggest($('en-q'), 'enrolment', function () {
    /* The picker's own window (1.0.94): it is no <select> with a value. */
    var r = $('en-since') && $('en-since')._range ? $('en-since')._range() : null;
    var s = r && r.from ? Math.max(0, Date.now() / 1000 - r.from) : Number(($('en-since') || {}).value);
    return s ? 'hours=' + Math.ceil(s / 3600) : '';
  })
};

/** A question in the page's own popup - never the browser's. `fields` are
    {label, type, placeholder, says}; `go(values, button)` gets what was typed. */
function askInModal(title, lede, fields, words, icon, go) {
  var boxes = [];
  modal(title, function (body) {
    if (lede) body.appendChild(el('p', 'note', lede));
    var g = el('div', 'formgrid');
    fields.forEach(function (f) {
      var input = f.type === 'password' ? maskBox('', '', '') : el('input');
      if (f.type !== 'password') input.type = f.type || 'text';
      input.placeholder = f.placeholder || '';
      input.autocomplete = 'off';
      if (f.value && f.type !== 'password') input.value = f.value;
      if (f.mono) input.className = 'mono';
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); $('modal-foot').querySelector('.btn.primary').click(); }
      });
      boxes.push(input);
      g.appendChild(formField(f.label, input, f.says));
      if (f.people) personSuggest(input, f.people);
    });
    body.appendChild(g);
    setTimeout(function () { if (boxes[0]) boxes[0].focus(); }, 60);
  }, [{words: 'Close', close: true}, {words: words, cls: 'primary', icon: icon, go: function (b) {
    go(boxes.map(function (x) { return x.value; }), b);
  }}], 'medium');
}

/** Kept certificates as a table: who, signed by whom, from when to when, the
    whole fingerprint, and a button to take each out (1.0.20: shared by the
    directories and the mail server). */
function certTable(list, drop) {
  return listTable(['It is', 'Signed by', 'Good from', 'Good until', 'Fingerprint (SHA-256)', ''], list, function (c) {
    var tr = el('tr');
    tr.appendChild(noI18n(el('td', '', c.subject || '–')));
    var by = el('td');
    if (c.self_signed) by.appendChild(el('span', 'tag info', 'itself - a root'));
    else by.appendChild(noI18n(el('span', '', c.issuer || '–')));
    tr.appendChild(by);
    var when = function (t) { var ms = Date.parse(t || ''); return isNaN(ms) ? (t || '–') : dayWords(new Date(ms)); };
    tr.appendChild(el('td', 'muted small', when(c.from)));
    var left = c.until ? (Date.parse(c.until) - Date.now()) / 86400000 : null;
    var tone = left === null || isNaN(left) ? '' : (left < 0 ? 'bad' : (left < 60 ? 'warn' : 'good'));
    tr.appendChild(el('td', 'small ' + tone, when(c.until)));
    var fp = noI18n(el('td', 'mono small muted fp-full'));
    var hex = (c.fingerprint || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    var half = Math.ceil(hex.length / 4) * 2;
    [hex.slice(0, half), hex.slice(half)].forEach(function (part) {
      if (part) fp.appendChild(el('div', '', part.replace(/(..)(?=.)/g, '$1:')));
    });
    fp.title = hex.replace(/(..)(?=.)/g, '$1:');
    tr.appendChild(fp);
    var tools = el('td', 'rowtools');
    if (ADMIN && drop) {
      var x = iconButton('trash', 'Take this certificate out');
      x.onclick = function () { drop(c); };
      tools.appendChild(x);
    }
    tr.appendChild(tools);
    return tr;
  });
}

function ensureOption(sel, value) {
  if (!Array.prototype.some.call(sel.options, function (o) { return o.value === value; })) {
    var o = el('option', '', value); o.value = value; sel.appendChild(o);
  }
}

/** opts: {dir: () => directory name, buttons: [{words, icon, on(g), toggle(g)}]} -
    a box to type part of a name into, Find the groups, and the list with a
    button per role beside every group, lit where the group has it. */
function groupBrowser(opts) {
  var box = el('div', 'groupbrowser');
  var bar = el('div', 'btnrow');
  bar.style.alignItems = 'center';
  var like = el('input');
  like.type = 'search';
  like.placeholder = 'part of a group’s name (empty: all)';
  like.style.maxWidth = '420px';
  like.style.minWidth = '320px';
  var go = cmdButton('Find the groups', 'search', 'small');
  bar.appendChild(like);
  bar.appendChild(go);
  box.appendChild(bar);
  var list = el('div');
  list.style.marginTop = '10px';
  box.appendChild(list);
  var st = {groups: [], q: '', page: 0, per: 15};
  function paint() {
    Array.prototype.forEach.call(list.querySelectorAll('tr.dgroup'), function (tr) {
      var any = false;
      opts.buttons.forEach(function (b, i) {
        var on = !!b.on(tr._g);
        any = any || on;
        var btn = tr.querySelectorAll('.rowtools .btn')[i];
        if (btn) btn.classList.toggle('on', on);
      });
      tr.classList.toggle('is-read', any);
    });
  }
  function draw() {
    clear(list);
    if (!st.groups.length) { list.appendChild(el('p', 'note', 'The directory has no groups under that base matching that.')); return; }
    var low = st.q.toLowerCase();
    var rows = !low ? st.groups : st.groups.filter(function (g) {
      return (g.cn + ' ' + g.dn + ' ' + (g.description || '')).toLowerCase().indexOf(low) >= 0;
    });
    var fb = el('div', 'btnrow');
    fb.style.alignItems = 'center';
    var f = el('input');
    f.type = 'search';
    f.placeholder = 'narrow this list…';
    f.value = st.q;
    f.style.maxWidth = '420px';
    f.style.minWidth = '320px';
    f.oninput = function () {
      st.q = f.value; st.page = 0;
      var at = f.selectionStart;
      draw();
      var again = list.querySelector('input[type=search]');
      if (again) { again.focus(); try { again.setSelectionRange(at, at); } catch (e) { } }
    };
    fb.appendChild(f);
    fb.appendChild(el('span', 'muted small', num(rows.length) + ' of ' + num(st.groups.length)));
    list.appendChild(fb);
    var pages = Math.max(1, Math.ceil(rows.length / st.per));
    if (st.page >= pages) st.page = pages - 1;
    list.appendChild(listTable(['Group', 'What it is for', ''], rows.slice(st.page * st.per, st.page * st.per + st.per), function (g) {
      var tr = el('tr', 'dgroup');
      tr._g = g;
      var n = el('td');
      n.appendChild(noI18n(el('div', '', g.cn)));
      n.appendChild(noI18n(el('div', 'mono small muted', g.dn)));
      tr.appendChild(n);
      tr.appendChild(noI18n(el('td', 'muted small', g.description || '')));
      var t = el('td', 'rowtools');
      opts.buttons.forEach(function (b) {
        var btn = cmdButton(b.words, b.icon, 'small');
        btn.onclick = function (e) { e.stopPropagation(); b.toggle(g); paint(); };
        t.appendChild(btn);
      });
      tr.appendChild(t);
      return tr;
    }, 'rows'));
    if (pages > 1) {
      var nav = el('div', 'btnrow');
      nav.style.marginTop = '8px';
      var prev = cmdButton('Back', 'prev', 'small');
      prev.disabled = st.page === 0;
      prev.onclick = function () { st.page--; draw(); };
      var next = cmdButton('Next', 'next', 'small');
      next.disabled = st.page >= pages - 1;
      next.onclick = function () { st.page++; draw(); };
      nav.appendChild(prev);
      nav.appendChild(el('span', 'muted small', 'page ' + (st.page + 1) + ' of ' + pages));
      nav.appendChild(next);
      list.appendChild(nav);
    }
    paint();
    explainWhatWasDrawn(list);
  }
  function find() {
    var d = opts.dir();
    if (!d) { toast('choose the directory first', 'bad'); return; }
    busy(go, true);
    api('directories', {action: 'groups', name: d, like: like.value.trim()}).then(function (r) {
      st.groups = r.groups || []; st.q = ''; st.page = 0;
      draw();
      toast(num(st.groups.length) + ' group(s) found', 'good');
    }).catch(function (e) {
      /* The groups of the directory asked before must not stay to be added
         to a realm of another one (1.0.36). */
      st.groups = []; st.q = ''; st.page = 0; draw(); oops(e);
    }).then(function () { busy(go, false); });
  }
  go.onclick = find;
  like.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); find(); } });
  box._paint = paint;
  return box;
}

function hideBar(go, words) {
  var row = el('div', 'actions hide-row');
  row.appendChild(hideButton(go));
  if (words) row.appendChild(el('span', 'muted small', words));
  return row;
}

/* In a cluster, which node a line of a log was written on (1.0.45). */
function manyNodes() {
  return !!(STATUS && ((STATUS.nodes || []).length > 1 || (STATUS.replication || {}).mode));
}

/* ---- a person as the directory knows them (1.0.19, isemon's person card) ---- */
function meInitials(name, display) {
  var words = String(display || name || '?').replace(/[^\p{L}\p{N}\s._-]/gu, ' ')
    .split(/[\s._@-]+/).filter(Boolean);
  var two = words.length > 1 ? words[0][0] + words[words.length - 1][0] : String(words[0] || name || '?').slice(0, 2);
  return two.toUpperCase();
}

function netFacts(rows) {
  var dl = el('div', 'net-facts');
  rows.forEach(function (r) {
    if (r[1] === undefined) return;
    var one = el('div', 'net-fact');
    one.appendChild(el('span', 'k', r[0]));
    var v = el('span', 'v' + (r[2] ? ' mono' : ''));
    if (r[1] instanceof Node) v.appendChild(r[1]); else v.textContent = r[1] === '' || r[1] === null ? '–' : String(r[1]);
    if (r[2]) noI18n(v);
    one.appendChild(v);
    dl.appendChild(one);
  });
  return dl;
}

function nodeCell(n) {
  var td = el('td', 'small');
  if (n) td.appendChild(noI18n(el('span', 'tag dim node-tag', n)));
  else td.appendChild(el('span', 'muted', '–'));
  return td;
}

function nodeEdit(s, node, current, then) {
  var box;
  var who = node === '*' ? 'the cluster (every node without its own)' : node + ' only';
  modal(s.name + ' · ' + (node === '*' ? 'the cluster' : node), function (body) {
    if (s.says) body.appendChild(saysBlock(s.says));
    box = textBox(current === null || current === undefined ? '' : String(current),
                  node === '*' ? String(s.default) : String(s.shared), 'mono');
    /* What empty means, once - "((empty))" said it twice (1.0.170). */
    var bare = function (v) { return nodeValWords(s, v).replace(/^\((.*)\)$/, '$1'); };
    body.appendChild(formField('For ' + who, box, node === '*' ? 'Empty: the built-in default (' + bare(s.default) + ').'
                                                     : 'Empty: the cluster’s value (' + bare(s.shared) + ').'));
  }, [{words: 'Close', close: true}, {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
    if (b && b.disabled) return;
    if (b) busy(b, true);
    var raw = box.value.trim();
    var val = raw === '' ? (node === '*' ? s.default : s.shared) : raw;
    nodeSave(s, node, val, function () { closeModal(); then(); }).then(function () { if (b) busy(b, false); });
  }}], true);
}

/* What a test found, in a node's card. */
function nodeSaid(got, words) {
  var p = el('div', 'node-said ' + (got.ok ? 'ok' : 'bad'));
  p.appendChild(el('span', 'dot ' + (got.ok ? 'ok' : 'bad')));
  var t = el('div');
  t.appendChild(el('b', '', got.error ? 'It did not go' : words));
  if (got.error) t.appendChild(noI18n(el('div', 'small muted', got.error)));
  t.appendChild(el('div', 'small muted', ago(got.at)));
  p.appendChild(t);
  return p;
}

function nodeSave(s, node, value, then) {
  var want = {};
  want[s.key] = typeof s.default === 'number' ? Number(value)
    : (typeof s.default === 'boolean' ? (value === true || value === 'true' || value === '1' || value === 1) : value);
  return api('settings', {settings: want, node: node}).then(function (r) { toast(r.message, 'good'); then(); }).catch(oops);
}

function nodeValEl(s, v, cls) {
  var words = nodeValWords(s, v);
  /* A value as it is; the words for an empty one in the page's language
     (not .mono: that is never translated). */
  if (v === '' || v === null || v === undefined)
    return el('span', String(cls).replace(/\bmono\b/, 'node-empty'), words);
  return noI18n(el('span', cls, words));
}

function nodeValWords(s, v) {
  if (isBool(s)) return (v === true || v === 1 || v === '1' || v === 'true') ? 'on' : 'off';
  if (v === '' || v === null || v === undefined) return NODE_EMPTY[s.key] || '(empty)';
  return String(v);
}

/** A certificate file read into a box: PEM as it is, a DER .cer written out as PEM. */
function readCertFile(file, box) {
  var reader = new FileReader();
  reader.onload = function () {
    var bytes = new Uint8Array(reader.result || new ArrayBuffer(0));
    var text = '';
    try { text = new TextDecoder('utf-8').decode(bytes); } catch (e) { text = ''; }
    if (text.indexOf('-----BEGIN CERTIFICATE-----') < 0 && bytes.length && bytes[0] === 0x30) {
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      text = '-----BEGIN CERTIFICATE-----\n' + btoa(bin).replace(/(.{64})/g, '$1\n').replace(/\n$/, '')
        + '\n-----END CERTIFICATE-----';
    }
    var ok = text.indexOf('-----BEGIN CERTIFICATE-----') >= 0;
    box.value = ok ? text.trim() : '';
    box.dispatchEvent(new Event('input'));
    toast(ok ? 'read ' + file.name + ' - Save the changes adds it' : file.name + ' is not a certificate', ok ? 'good' : 'bad');
  };
  reader.readAsArrayBuffer(file);
}

function saveBarPlace() {
  var bar = $('save-bar');
  if (!bar) return;
  var ed = PANE === 'texts' && TAB === 'settings' ? document.querySelector('.tx-shell.split > .tx-ed') : null;
  if (!ed) { saveBarHome(); return; }
  if (!SAVE_BAR_HOME) SAVE_BAR_HOME = {parent: bar.parentNode, next: bar.nextSibling};
  if (bar.parentNode !== ed || ed.lastChild !== bar) { ed.appendChild(bar); bar.classList.add('in-editor'); }
}

/* ---- export and import ---------------------------------------------------- */
function saveFile(name, text) {
  var a = el('a');
  a.href = URL.createObjectURL(new Blob([text], {type: 'application/json'}));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

function txT(s) {
  var got = typeof i18nText === 'function' ? i18nText(String(s)) : null;
  return got == null ? String(s) : got;      /* untranslated, or English: as it is */
}

function whoisPeek(name, kind) {
  peek(name + ' in the directory', function () { return api('directories', {action: 'whois', user: name, kind: kind}); }, function (body, d) {
    if (!d.entry) { body.appendChild(el('p', 'note', d.directory + ' has nobody by that name.')); return; }
    personCard(body, d, name);
  });
  $('modal-box').className = 'box medium';
}

/* ======== helpers of the panes above, from OTP admin.js ======== */
var NODE_EMPTY = {isemon_hostname: 'the machine’s own name', mail_helo: 'the machine’s own name',
                  radius_bind: 'every address', siem_hostname: 'the machine’s own name',
                  acme_node_name: 'the name of its certificate, else its full host name'};

/* The save bar where the page scrolls (1.0.131): at the end of the pane - or,
   on Message texts, where only the editor scrolls, at the end of the editor.
   Either way it is below the last thing until something is changed, and
   then sticks to the bottom. Moved back home before the editor is drawn
   again, or it would go with it. */
var SAVE_BAR_HOME = null;

/* "Hide this" on what is over and only says how it went (1.0.123): a
   change of network, a restart, an upgrade, a job on the database, a test
   mail. `go` hides it - a promise when the server is told. */
function hideButton(go) {
  var b = cmdButton('Hide this', 'close', 'small');
  b.classList.add('hide-this');
  b.onclick = function (e) {
    if (e) e.stopPropagation();
    busy(b, true);
    Promise.resolve(go()).catch(oops).then(function () { busy(b, false); });
  };
  return b;
}

/** One person's card out of a whois answer: who, the state, where, what. */
function personCard(body, d, name) {
  var e = d.entry;
  var head = el('div', 'me-head');
  var ava = el('div', 'me-ava' + (d.role === 'fulladmin' ? ' admin' : ''), meInitials(e.sam || name, e.display));
  ava.setAttribute('aria-hidden', 'true');
  noI18n(ava);
  head.appendChild(ava);
  var who = el('div', 'me-who');
  who.appendChild(noI18n(el('div', 'me-n', e.display || e.sam || name)));
  who.appendChild(noI18n(el('div', 'me-d mono', e.upn || name)));
  var tags = el('div', 'me-tags');
  tags.appendChild(el('span', 'tag ' + (e.disabled ? 'crit' : 'ok'), e.disabled ? 'switched off in the directory' : 'active in the directory'));
  if (e.locked) tags.appendChild(el('span', 'tag crit', 'locked out'));
  if (e.expires) tags.appendChild(el('span', 'tag ' + (e.expires * 1000 < Date.now() ? 'crit' : 'warn'),
                                     (e.expires * 1000 < Date.now() ? 'expired ' : 'expires ') + stamp(e.expires)));
  if (d.role) tags.appendChild(el('span', 'tag ' + roleTone(d.role), roleWords(d.role)));
  if (d.realm) tags.appendChild(noI18n(el('span', 'tag info', d.realm)));
  if (d.token_state) tags.appendChild(el('span', 'tag ' + (d.token_state === 'active' ? 'ok' : 'warn'),
                                         d.token_state === 'active' ? 'has a token' : 'token: ' + d.token_state));
  who.appendChild(tags);
  head.appendChild(who);
  body.appendChild(head);
  var sec = el('div', 'me-sec');
  sec.appendChild(el('h3', '', 'In the directory'));
  var kv = el('div', 'me-kv');
  var row = function (k, v) {
    if (!v) return;
    kv.appendChild(el('div', 'k', k));
    var c = el('div', 'v');
    if (v.nodeType) c.appendChild(v); else c.appendChild(noI18n(el('span', 'mono', v)));
    kv.appendChild(c);
  };
  row('Account name', e.sam);
  row('User principal name', e.upn);
  row('Mail', e.mail);
  row('Department', e.department);
  row('Title', e.title);
  if (e.dn) row('Where', placeSteps(e.dn, e.sam || name));
  var asked = el('span', 'muted', d.directory + ' · ' + num(d.took_ms) + ' ms');
  noI18n(asked);
  row('Asked', asked);
  sec.appendChild(kv);
  body.appendChild(sec);
  var gs = el('div', 'me-sec');
  var list = (d.group_list || (d.groups || []).map(function (g) { return {name: g, dn: '', gives: []}; }));
  var h3 = el('h3', '', 'Groups, those inside groups as well');
  h3.appendChild(noI18n(el('span', 'me-count', ' (' + num(list.length) + ')')));
  gs.appendChild(h3);
  gs.appendChild(personGroups(list));
  body.appendChild(gs);
}

function saveBarHome() {
  var bar = $('save-bar');
  if (!bar) return;
  if (!SAVE_BAR_HOME) SAVE_BAR_HOME = {parent: bar.parentNode, next: bar.nextSibling};
  if (bar.parentNode !== SAVE_BAR_HOME.parent) {
    SAVE_BAR_HOME.parent.insertBefore(bar, SAVE_BAR_HOME.next && SAVE_BAR_HOME.next.parentNode === SAVE_BAR_HOME.parent ? SAVE_BAR_HOME.next : null);
    bar.classList.remove('in-editor');
  }
}

/* ======== helpers of the panes above, from OTP admin.js ======== */
/** The groups: the ones that give something here as cards that say what,
    the rest as one wrapping line of names, past a few rows behind "and N more". */
function personGroups(list) {
  var cell = el('div');
  var key = list.filter(function (g) { return (g.gives || []).length; });
  var rest = list.filter(function (g) { return !(g.gives || []).length; });
  if (!list.length) { cell.appendChild(el('span', 'muted', 'in no group')); return cell; }
  if (key.length) {
    var cards = el('div', 'me-groups');
    key.forEach(function (g) {
      var role = (g.gives || []).filter(function (x) { return x.role; })[0];
      var card = el('div', 'me-group gives' + (role && role.role === 'readonly' ? ' ro' : (role ? '' : ' realm')));
      (g.gives || []).forEach(function (x) {
        card.appendChild(el('span', 'gwhy', x.role ? 'makes an administrator: ' + roleWords(x.role)
          : 'lets into the realm ' + x.realm));
      });
      card.appendChild(noI18n(el('span', 'gn', g.name)));
      var where = dnPlace(g.dn);
      var bits = where.path.slice(); if (where.domain) bits.push(where.domain);
      if (bits.length) card.appendChild(noI18n(el('span', 'gp', bits.join(' › '))));
      card.title = g.dn || '';
      cards.appendChild(card);
    });
    cell.appendChild(cards);
  }
  if (rest.length) {
    var line = el('div', 'me-chips'), SHOW = 24;
    rest.forEach(function (g, i) {
      var chip = noI18n(el('span', 'me-chip', g.name));
      chip.title = g.dn || '';
      if (i >= SHOW) chip.hidden = true;
      line.appendChild(chip);
    });
    if (rest.length > SHOW) {
      var more = el('button', 'me-chip me-chip-more', 'and ' + num(rest.length - SHOW) + ' more');
      more.type = 'button';
      more.onclick = function () {
        Array.prototype.forEach.call(line.querySelectorAll('.me-chip[hidden]'), function (c) { c.hidden = false; });
        more.remove();
      };
      line.appendChild(more);
    }
    cell.appendChild(line);
  }
  return cell;
}

/** Where somebody lives in the directory, as steps: the domain, each OU, them. */
function placeSteps(dn, own) {
  var place = dnPlace(dn);
  var steps = el('div', 'me-place');
  var step = function (words, cls) {
    if (steps.children.length) steps.appendChild(el('span', 'sep', '›'));
    steps.appendChild(noI18n(el('span', 'step' + (cls ? ' ' + cls : ''), words)));
  };
  if (place.domain) step(place.domain, 'dom');
  place.path.forEach(function (ou) { step(ou); });
  step(place.name || own, 'me');
  var wrap = el('div');
  wrap.appendChild(steps);
  wrap.appendChild(noI18n(el('div', 'me-dn mono', dn)));
  return wrap;
}

/* ======== helpers of the panes above, from OTP admin.js ======== */
function dnPlace(dn) {
  var parts = dnParts(dn), name = parts.length ? parts[0][1] : '', ous = [], dcs = [];
  parts.slice(1).forEach(function (p) { if (p[0] === 'dc') dcs.push(p[1]); else if (p[1]) ous.push(p[1]); });
  return {name: name, path: ous.reverse(), domain: dcs.join('.')};
}

/* ======== helpers of the panes above, from OTP admin.js ======== */
function dnParts(dn) {
  var out = [], cur = '', i, c;
  dn = String(dn || '');
  for (i = 0; i < dn.length; i++) {
    c = dn[i];
    if (c === '\\' && i + 1 < dn.length) { cur += dn[i + 1]; i++; continue; }
    if (c === ',') { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (cur) out.push(cur);
  return out.map(function (one) {
    var at = one.indexOf('=');
    return at < 0 ? ['', one.trim()] : [one.slice(0, at).trim().toLowerCase(), one.slice(at + 1).trim()];
  });
}

/* ======== starting (OTP admin.js 6893-6913) ======== */
/* ---- starting ------------------------------------------------------------ */
(function start() {
  var h = (location.hash || '#settings').slice(1).split('/');
  if (h[1]) PANE = h[1];
  if (STATUS) paintHeader(STATUS);
  showTab(h[0] || 'settings');
  setInterval(tick, 5000);
  if (typeof hloadLoop === 'function') hloadLoop();
  explainWhatWasDrawn(document);
  /* A link to #settings/dir, or Back: the page follows the address. */
  window.addEventListener('hashchange', function () {
    var g = (location.hash || '#settings').slice(1).split('/');
    if (TABS.indexOf(g[0]) < 0) return;
    if (g[0] === 'settings' && g[1] && g[1] !== PANE && typeof showPane === 'function'
        && TAB === 'settings') { showPane(g[1]); return; }
    if (g[1]) PANE = g[1];
    if (g[0] !== TAB) showTab(g[0]);
  });
}());


