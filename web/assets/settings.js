/* settings.js - the Settings of upsmon: the pages of OTP (its admin.js, 1.0.187),
   their Accounts, Certificates and TLS, Automatic certificates, Upgrades and About,
   drawn by core.js the way OTP draws them, over the upsmon daemon's settings API. */

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
  if (name === 'acme') loadAcme(); else acPoll(false);
  if (name === 'about') drawAbout();
  if (name === 'upgrade') loadUpgrade();
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


/* ======== about (OTP admin.js 5939-6104) ======== */
/* ---- about ---------------------------------------------------------------- */
function drawAbout() {
  var s = STATUS || {};
  var host = $('about-state');
  clear(host);
  host.appendChild(el('h2', '', 'upsmon ' + (s.version || '')));
  host.appendChild(peekFacts([['Running for', span(s.uptime || 0)], ['RADIUS', ((s.radius || {}).listening || []).join(', ') || 'not listening'],
                              ['Clients', num(s.clients)], ['Realms', num(s.realms)], ['Directories', num(s.directories)],
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
      ? 'This is the only server: while it is in maintenance nobody can sign in to the VPN. Its pages go on working.'
      : 'It stops answering RADIUS and its /healthz says 503: the VPN and the load balancer go to the other node. Its pages go on working.';
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
          + (many ? 'the nodes are upgraded one at a time - each in maintenance while it is, so the service never stops.' : 'this server is upgraded: for a minute nobody can sign in to the VPN.')), 'Upgrade', function () {
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
    : ' - for a minute nobody can sign in to the VPN.') + ' The database stays as it is. What came in the newer versions is gone until you upgrade again.'),
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
             : 'This server is the only one: while it is put in and restarted - a minute or two - nobody can sign in to the VPN, and these pages stop answering for a moment.',
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
                 ['Key', info.key || '–']];
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
      dl.title = 'The certificate and its chain, as PEM - without the key';
      dl.onclick = function () {
        api('web', {action: 'tls_pem', target: target}).then(function (x) {
          saveFile((target === 'vip' ? 'web-address' : target) + '.pem', x.pem);
        }).catch(oops);
      };
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
        if (/-----BEGIN /.test(head) || /-----BEGIN /.test(new TextDecoder().decode(bytesArr))) {
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
    body.appendChild(el('p', 'note', 'PEM files - the certificate, its key, the chain, the root, in any order or all in one - or one PFX / PKCS#12 file. ' +
      (prof && prof.pending ? 'A request waits here: the certificate the authority sent back is enough, its key is here.' : 'The key has to come with it.')));
    var drop = el('div', 'drop');
    var inp = el('input'); inp.type = 'file'; inp.multiple = true; inp.hidden = true;
    inp.accept = '.pem,.crt,.cer,.key,.pfx,.p12,.chain,.ca,.txt';
    var says = el('span', '', 'Drop the files here, or press to choose them');
    drop.appendChild(inp); drop.appendChild(says);
    var list = el('div', 'cert-files');
    function take(files) {
      readCertFiles(files).then(function (r) {
        got = got.concat(r);
        clear(list);
        got.forEach(function (x) { list.appendChild(noI18n(el('span', 'cchip', x.name + (x.pfx ? ' (PFX)' : ' (PEM)')))); });
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
        if (pfx.length > 1) { toast('one PFX / PKCS#12 file at a time', 'bad'); return; }
        if (!pfx.length && !/-----BEGIN /.test(pem)) { toast('choose the files first, or paste the PEM', 'bad'); return; }
        busy(b, true);
        api('web', {action: 'tls_upload', target: target, cert: pem, pfx: pfx.length ? pfx[0].pfx : '',
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
        ['For', t.name || '', true], ['Issued by', t.issuer || '', true],
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
var AC_DNS = {at: 0, rows: null};
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
  var t = listTable(['Certificate', 'Record', 'Type', 'Points at / value', 'In DNS now'], rows, function (r) {
    var tr = el('tr');
    tr.appendChild(r.target === 'vip' ? el('td', '', 'the VIP address') : (r.type === 'NS' ? el('td', '', 'its zone at deSEC') : noI18n(el('td', '', r.target))));
    var rec = el('td', 'mono small dns-cell');
    if (r.record) {
      rec.appendChild(noI18n(el('span', '', r.record)));
      var cp = iconButton('copy', 'Copy');
      cp.onclick = function () { copyText(r.record, cp); };
      rec.appendChild(cp);
    } else rec.appendChild(el('span', 'muted', r.why || ''));
    tr.appendChild(rec);
    tr.appendChild(noI18n(el('td', 'mono small', r.type || '')));
    var val = el('td', 'mono small dns-cell');
    if (r.type === 'CNAME' || r.type === 'NS' || (r.type === 'A' && r.value)) {
      val.appendChild(noI18n(el('span', '', r.value)));
      var cv = iconButton('copy', 'Copy');
      cv.onclick = function () { copyText(r.value, cv); };
      val.appendChild(cv);
      if (r.type === 'A') val.appendChild(el('div', 'muted', 'or the public address in front of it'));
    } else val.appendChild(el('span', 'muted', r.type === 'TXT' ? (r.value || r.why) : ''));
    tr.appendChild(val);
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
    /* The text and its button in one box: the button at the column's edge. */
    Array.prototype.forEach.call(tr.querySelectorAll('td.dns-cell'), function (td) {
      var box = el('div', 'dns-val');
      while (td.firstChild) box.appendChild(td.firstChild);
      td.appendChild(box);
    });
    return tr;
  });
  card.appendChild(t);
  /* The copy buttons right after the text, one under the other: the text of
     a column as wide as its longest (1.0.172). */
  setTimeout(function () {
    [1, 3].forEach(function (col) {
      var spans = Array.prototype.map.call(t.querySelectorAll('tbody tr'), function (tr) {
        var td = tr.children[col];
        return td && td.querySelector('.dns-val > span:first-child');
      }).filter(Boolean);
      var w = 0;
      spans.forEach(function (sp) { sp.style.width = ''; w = Math.max(w, sp.getBoundingClientRect().width); });
      spans.forEach(function (sp) { sp.style.width = Math.ceil(w) + 'px'; });
    });
  }, 0);
  var row = el('div', 'btnrow');
  var chk = cmdButton('Check DNS', 'search', 'small');
  explain(chk, 'Each record looked up from this node now, through its DNS servers - as the CA will look. A record just put in may take a while to show (its TTL).');
  chk.disabled = !(g.rows || []).some(function (r) { return r.check; });
  chk.onclick = function () {
    busy(chk, true);
    api('acme', {action: 'dns_check'}).then(function (x) {
      AC_DNS = {at: Date.now() / 1000, rows: x.rows, own: x.own_resolvers};
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

function whoisPeek(name, kind) {
  peek(name + ' in the directory', function () { return api('directories', {action: 'whois', user: name, kind: kind}); }, function (body, d) {
    if (!d.entry) { body.appendChild(el('p', 'note', d.directory + ' has nobody by that name.')); return; }
    personCard(body, d, name);
  });
  $('modal-box').className = 'box medium';
}

/* ======== helpers of the panes above, from OTP admin.js ======== */
/* A big file goes to /admin/upload/ (1.0.98): there nginx asks whether a
   full administrator sends it before it takes a byte. Where that place is
   not set up (an nginx without auth_request) it answers 404, and the file
   goes the old way. */
var BIG_PATH = true;

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


