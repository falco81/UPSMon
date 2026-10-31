/* core.js - what every page of upsmon is drawn with.
   Taken from isemon's dashboard, function for function where it could be: the
   same elements, the same popups, the same panel that says what a thing does,
   the same tables and the same pager - so that the two look and behave alike. */
'use strict';
function $(id) { return document.getElementById(id); }

/** An element holding a name or a value rather than words of the page's
    own: never translated, whatever language the page is in. (1.10.155) */
function noI18n(node) {
  if (node && node.setAttribute) node.setAttribute('data-no-i18n', '');
  return node;
}

function el(kind, cls, text) {
  var node = document.createElement(kind);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function clear(node) {
  while (node && node.firstChild) node.removeChild(node.firstChild);
  /* ...and it forgets what it had drawn. `sameAsDrawn` remembers the last
     answer drawn into a host so an identical one is not redrawn; a host
     that has since been EMPTIED and given a placeholder still remembered
     the old answer, so when the same answer came back it was "already
     drawn" and the placeholder stayed - a door card stuck on "Counting…"
     until the numbers happened to change. */
  if (node) node._drew = undefined;
}

/* ---- time, said the way a person reads it ------------------------------
   One format, written out rather than left to the browser: dd-mm-yyyy and a
   24-hour clock, the same on every machine that opens this page. The browser's
   own idea of a date is whatever its language happens to be - 09/23 in one
   place, 23/09 in the next, and an afternoon written as 05:49 PM - and a
   column of times that means something different depending on who is looking
   at it is worse than no column at all. The date is on every one of them,
   today's included: the only question these columns are ever asked is WHEN,
   and a bare clock time cannot answer it a day later or across midnight. */
function pad2(n) { return (n < 10 ? '0' : '') + n; }
function dayWords(d) {
  return pad2(d.getDate()) + '-' + pad2(d.getMonth() + 1) + '-' + d.getFullYear();
}
function clockWords(d, seconds) {
  return pad2(d.getHours()) + ':' + pad2(d.getMinutes())
    + (seconds === false ? '' : ':' + pad2(d.getSeconds()));
}
function stamp(ts) {
  if (!ts) return '–';
  var d = new Date(ts * 1000);
  return dayWords(d) + ' ' + clockWords(d);
}
function shortStamp(ts) { return stamp(ts); }
/** The same moment with the date in its own dimmer piece, for a table cell:
    the day is the part that repeats down a column and the time is the part
    being read, so they are not given the same weight. */
function stampCell(ts, cls) {
  var td = el('td', cls || '');
  if (!ts) { td.textContent = '\u2013'; return td; }
  var d = new Date(ts * 1000);
  /* The row's own moment, written on the cell that says it. Anything else
     in the row - an address in a column nothing knew about when it was
     drawn - can then be asked what it was called THEN rather than now,
     which on an address handed out by DHCP is a different machine. */
  td.dataset.ts = String(Math.round(ts));
  td.appendChild(el('span', 'day', dayWords(d) + ' '));
  td.appendChild(el('span', '', clockWords(d)));
  return td;
}
function ago(ts) {
  if (!ts) return 'never';
  var s = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (s < 90) return s + ' s ago';
  if (s < 5400) return Math.round(s / 60) + ' min ago';
  if (s < 172800) return Math.round(s / 3600) + ' h ago';
  return Math.round(s / 86400) + ' days ago';
}
function span(s) {
  s = Math.max(0, Math.round(s || 0));
  /* Every part cut off rather than rounded, exactly as the command line's
     own human_span does it. Rounding the smaller half of a span is how
     "5 h 60 min" happens, and how the same number comes out differently
     here and in `isemon --status`, which is worse than either. */
  if (s < 60) return s + ' s';
  if (s < 3600) return Math.floor(s / 60) + ' min';
  if (s < 86400) return Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min';
  /* One day is a day, not "1 days" - here and on the command line. */
  var days = Math.floor(s / 86400);
  return (days === 1 ? '1 day ' : days + ' days ') + Math.floor((s % 86400) / 3600) + ' h';
}
/* Numbers as the page's language writes them (1.10.168): in Czech
   `404 327` and `45,8 GB` - written the English way, a Czech reader took the
   comma for a decimal point and `404,327` for four hundred and four. One way
   per language whatever the browser is set to, as the dates are; the tables
   read them back with `shownNumber`. */
function numLang() {
  return (typeof I18N !== 'undefined' && I18N.on && I18N.code) ? I18N.code : 'en-US';
}
var NUM_FMT = {lang: null, dec: '.'};
function numDecimal() {
  var lang = numLang();
  if (NUM_FMT.lang !== lang) {
    var said = '.';
    try { said = (1.5).toLocaleString(lang).replace(/[0-9]/g, '').charAt(0) || '.'; }
    catch (e) { said = '.'; }
    NUM_FMT = {lang: lang, dec: said === ',' ? ',' : '.'};
  }
  return NUM_FMT.dec;
}
/** A number read back off the page, written either way. */
function shownNumber(text) {
  var t = String(text === null || text === undefined ? '' : text);
  t = numDecimal() === ',' ? t.replace(/[\s\u00a0\u202f]/g, '').replace(',', '.')
    : t.replace(/[\s,\u00a0\u202f]/g, '');
  return parseFloat(t);
}
function bytes(n) {
  n = Number(n || 0);
  var units = ['B', 'kB', 'MB', 'GB', 'TB'], i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  var said = i === 0 ? n.toFixed(0) : n.toFixed(1);
  if (numDecimal() === ',') said = said.replace('.', ',');
  return said + ' ' + units[i];
}
/* One grouping whatever the browser is set to, as the dates are: the
   browser's own gave 1’234’567 in one place and 1.2 MB beside it, and the
   tables sorted those by their first group. (1.10.160) */
function num(n) {
  var lang = numLang();
  try { return Number(n || 0).toLocaleString(lang); }
  catch (e) { return Number(n || 0).toLocaleString('en-US'); }
}

/* Text to the clipboard (1.0.46): the browser's own way where the page is
   secure, the old one where not; said either way, and the element it came
   from flashes green. */
function copyText(text, node, words) {
  text = String(text || '');
  if (!text) return;
  function done() {
    try { window.getSelection().removeAllRanges(); } catch (e) { }
    if (node) {
      node.classList.add('copied');
      setTimeout(function () { node.classList.remove('copied'); }, 1200);
    }
    toast(words || 'copied', 'good');
  }
  function old() {
    var t = document.createElement('textarea');
    t.value = text; t.setAttribute('readonly', '');
    t.style.position = 'fixed'; t.style.opacity = '0';
    document.body.appendChild(t); t.select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { }
    t.remove();
    if (ok) done(); else toast('it could not be copied', 'bad');
  }
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, old);
  else old();
}
/* A node that copies `text` when clicked, and says so as it is pointed at. */
function copyOnClick(node, text, words) {
  node.classList.add('copyable');
  node.title = 'Click to copy';
  node.setAttribute('role', 'button');
  node.tabIndex = 0;
  node.onclick = function (ev) { ev.stopPropagation(); copyText(text, node, words); };
  node.onkeydown = function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); node.onclick(ev); } };
  return node;
}

function toast(words, kind) {
  var node = $('toast');
  /* A page without one - the sign-in page (1.0.127) - gets one. */
  if (!node) {
    node = el('div', 'toast');
    node.id = 'toast';
    node.setAttribute('role', 'status');
    document.body.appendChild(node);
  }
  node.textContent = words;
  node.className = 'toast show' + (kind ? ' ' + kind : '');
  clearTimeout(node._away);
  node._away = setTimeout(function () { node.className = 'toast' + (kind ? ' ' + kind : ''); },
                          kind === 'bad' ? 6500 : 3200);
}
/* Only the newest answer of a list is drawn (1.0.57): a slow answer to the
   last filter landed after the fast one to the new filter and drew rows that
   did not match what was asked. An older one ends as "stopped". */
var LATEST = {};
function apiLatest(key, what, body) {
  var n = LATEST[key] = (LATEST[key] || 0) + 1;
  return api(what, body).then(function (d) {
    if (LATEST[key] !== n) { var e = new Error('superseded'); e.stopped = true; throw e; }
    return d;
  });
}
function oops(e) {
  if (e && e.stopped) return;           /* somebody stopped it: not a fault */
  /* An account that must set its own password first: every page answers
     "change your password first" - said once, by its own form (1.0.103). */
  if (typeof ME === 'object' && ME && ME.must_change && e && e.status === 403) return;
  toast(String(e && e.message || e), 'bad');
}

function busy(button, on) {
  if (!button) return;
  button.disabled = !!on;
  button.classList.toggle('busy', !!on);
}

/* ---- the popup ---------------------------------------------------------- */
var MODAL_CLOSE = null;
/* Which opening of the popup is the current one. Every open and every close
   is a new number, and anything that put up a placeholder and then went to
   ask the daemon holds the number it got; when the answer comes back, it is
   drawn only if that number is still the current one. Without this an
   answer arriving late - press address A, close it, press address B - drew
   A's story over B's, or reopened a popup somebody had just closed. */
var MODAL_GEN = 0;
function modalTicket() { return MODAL_GEN; }
function modalStill(ticket) { return ticket === MODAL_GEN && !$('modal').hidden; }

function modal(title, build, buttons, narrow) {
  if (MODAL_OVER_WANTED) modalOverNow();
  MODAL_GEN += 1;
  $('modal-title').textContent = title;
  /* `narrow` is true for the small popup, or the name of another size. */
  $('modal-box').className = 'box' + (typeof narrow === 'string' ? ' ' + narrow
    : (narrow ? ' narrow' : ''));
  var body = $('modal-body');
  clear(body);
  if (typeof build === 'function') build(body); else if (build) body.appendChild(build);
  var foot = $('modal-foot');
  clear(foot);
  (buttons || [{words: 'Close', close: true}]).forEach(function (b) {
    if (b.spacer) { var s = el('span', 'left'); foot.appendChild(s); return; }
    if (b.admin && !ADMIN) return;
    var button = el('button', 'btn cmd' + (b.cls ? ' ' + b.cls : ''), b.words);
    setButtonIcon(button, b.icon || iconForWords(b.words), b.words);
    if (b.left) button.classList.add('left');
    var run = function () {
      var was = MODAL_GEN;
      if (b.go) b.go(button);
      /* ...unless what the button did was open another popup in this one's
         place: closing then closed that one. (1.10.168) */
      if (b.close && MODAL_GEN === was) closeModal();
    };
    button.onclick = run;
    /* Anything that destroys is asked twice (1.0.52): the first click turns
       the buttons into "Really?", the second does it. Everything typed in
       the popup stays where it is. */
    if (/\bdanger\b/.test(b.cls || '') && b.go && !b.once) {
      button.onclick = function () {
        var strip = el('div', 'sure-strip');
        strip.appendChild(el('span', 'sure-q', 'Really? This cannot be taken back.'));
        var no = el('button', 'btn cmd', 'No, leave it');
        setButtonIcon(no, 'close', 'No, leave it');
        var yes = el('button', 'btn cmd danger', b.words);
        setButtonIcon(yes, b.icon || iconForWords(b.words), b.words);
        strip.appendChild(no);
        strip.appendChild(yes);
        var kept = Array.prototype.slice.call(foot.children);
        kept.forEach(function (c) { c.hidden = true; });
        foot.appendChild(strip);
        no.onclick = function () { strip.remove(); kept.forEach(function (c) { c.hidden = false; }); no.blur(); };
        yes.onclick = function () { strip.remove(); kept.forEach(function (c) { c.hidden = false; }); run(); };
        setTimeout(function () { try { no.focus(); } catch (e) { } }, 0);
      };
    }
    foot.appendChild(button);
  });
  /* Focus goes into the popup - its first box, or its main button - and
     back to where it came from when it closes. It stayed behind the popup,
     so Enter did nothing and Tab walked the page underneath. (1.10.159) */
  var opened = !$('modal').hidden;
  if (!opened) MODAL_FROM = document.activeElement;
  $('modal').hidden = false;
  var first = body.querySelector('input:not([type=hidden]):not([disabled]), select:not([disabled]), '
                                 + 'textarea:not([disabled])')
    /* ...never a button that destroys something: a second Enter would
       press it. In a popup asking "erase all this?" it is the way out. */
    || foot.querySelector('.btn.primary:not(.danger)')
    || foot.querySelector('.btn:not(.danger)');
  if (first) setTimeout(function () { try { first.focus(); } catch (e) { } }, 0);
  return {body: $('modal-body'), foot: foot};
}
var MODAL_FROM = null;
/* A popup over a popup (1.0.22): what `open` puts up goes on top of the one
   open now, which stays where it is underneath; closing the top one goes
   back to it. `back`, if given, runs once it is the one on top again - to
   draw it afresh after what was done over it. */
var MODAL_STACK = [];
var MODAL_IDS = ['modal', 'modal-box', 'modal-title', 'modal-x', 'modal-body', 'modal-foot'];
/* The popup underneath is put aside only when the new one really opens
   (1.0.44): an `open` that opens nothing - an API call that failed, an
   action that needs no popup - left the page under a hidden popup on top,
   where nothing could be clicked. */
var MODAL_OVER_WANTED = null;
function modalOver(open, back) {
  var cur = $('modal');
  if (!cur || cur.hidden) { open(); return; }
  MODAL_OVER_WANTED = {back: back, at: Date.now()};
  /* Opened at once, or a moment later once its data came - or never, and
     then the popup open now simply stays as it is. */
  open();
}
function modalOverNow() {
  var want = MODAL_OVER_WANTED;
  MODAL_OVER_WANTED = null;
  var cur = $('modal');
  if (!want || !cur || cur.hidden || Date.now() - want.at > 20000) return;
  var back = want.back;
  var n = MODAL_STACK.length;
  var oldX = $('modal-x');
  MODAL_IDS.forEach(function (id) { var e = $(id); if (e) e.id = id + '-under' + n; });
  cur.classList.add('under');
  var wrap = document.createElement('div');
  wrap.innerHTML = '<div class="modal over" id="modal" hidden><div class="box" id="modal-box">'
    + '<div class="head"><h3 id="modal-title"></h3><button class="xbtn" id="modal-x" '
    + 'aria-label="Close"></button></div><div class="body" id="modal-body"></div>'
    + '<div class="foot" id="modal-foot"></div></div></div>';
  var fresh = wrap.firstChild;
  document.body.appendChild(fresh);
  if (oldX) $('modal-x').innerHTML = oldX.innerHTML;
  $('modal-x').onclick = closeModal;
  /* A click beside a popup does not close it (1.0.25): only its buttons do. */
  MODAL_STACK.push({el: cur, n: n, from: MODAL_FROM, close: MODAL_CLOSE, back: back});
  MODAL_CLOSE = null;
  MODAL_FROM = document.activeElement;
}
function closeModal() {
  MODAL_OVER_WANTED = null;
  /* A time picker's list goes with the popup it was in (1.0.57). */
  Array.prototype.forEach.call(document.querySelectorAll('#modal .tp'), function (t) { if (t._close) t._close(); });
  MODAL_GEN += 1;
  $('modal').hidden = true;
  /* What the popup showed goes with it (1.0.101) - a token's key, its QR
     code, recovery codes stayed in the page, hidden, until another popup
     opened. Emptied a moment later, once nothing opened in its place. */
  var shutGen = MODAL_GEN, shut = $('modal');
  setTimeout(function () {
    if (MODAL_GEN !== shutGen || !shut.isConnected || !shut.hidden) return;
    ['modal-body', 'modal-foot'].forEach(function (id) {
      var n = shut.querySelector('#' + id);
      if (n) clear(n);
    });
  }, 60);
  /* The lists a popup's boxes floated over the page go with the popup. */
  setTimeout(function () {
    Array.prototype.forEach.call(document.querySelectorAll('.qs-float'), function (d) {
      if (!d._input || !d._input.isConnected || d._input.closest('#modal[hidden]')) d.remove();
    });
  }, 0);
  if (MODAL_CLOSE) { var f = MODAL_CLOSE; MODAL_CLOSE = null; f(); }
  var back = MODAL_FROM;
  MODAL_FROM = null;
  /* Over another popup: this one goes, and the one under it is the popup
     again - ids, focus and all. */
  var under = null;
  if (MODAL_STACK.length) {
    var top = $('modal');
    if (top) top.remove();
    under = MODAL_STACK.pop();
    MODAL_IDS.forEach(function (id) {
      var e = document.getElementById(id + '-under' + under.n);
      if (e) e.id = id;
    });
    under.el.classList.remove('under');
    MODAL_CLOSE = under.close;
    MODAL_FROM = under.from;
  }
  if (back && back.isConnected && back.focus) { try { back.focus(); } catch (e) { } }
  if (under && under.back) setTimeout(under.back, 0);
}
/* Tab and Shift+Tab go round inside the popup while it is open. */
document.addEventListener('keydown', function (e) {
  if (e.key !== 'Tab' || !$('modal') || $('modal').hidden) return;
  var inside = Array.prototype.filter.call(
    $('modal-box').querySelectorAll('button, input, select, textarea, a[href], [tabindex]'),
    function (n) { return !n.disabled && n.tabIndex >= 0 && n.getClientRects().length; });
  if (!inside.length) return;
  var at = inside.indexOf(document.activeElement);
  if (e.shiftKey && at <= 0) { e.preventDefault(); inside[inside.length - 1].focus(); }
  else if (!e.shiftKey && (at < 0 || at === inside.length - 1)) {
    e.preventDefault();
    inside[0].focus();
  }
});
if ($('modal-x')) {
  $('modal-x').onclick = closeModal;
  /* A click beside the popup leaves it open (1.0.25): a stray click lost a
     half-filled form. It closes by its own buttons, its x, or Escape. */
}
document.addEventListener('keydown', function (e) {
  /* A help popup open is the first thing Escape closes. (1.10.159) */
  if (e.key === 'Escape' && typeof SETHELP !== 'undefined' && SETHELP
      && SETHELP.style.display !== 'none') {
    hideHelp();
    return;                              /* the help first, the popup next time */
  }
  if (e.key !== 'Escape' || !$('modal') || $('modal').hidden) return;
  /* Escape closes what is on top, and only that: the column menu or the
     find box opened over the popup used to take the popup with them.
     (1.10.155) */
  if (typeof COLS_MENU !== 'undefined' && COLS_MENU) return;
  closeModal();
});

/* What icon a button deserves when nobody has said. Read off the words on
   it, because the words are chosen to say what it does: everything that lets
   go of something gets the same mark, everything that asks a machine gets
   another, and a button nobody thought about gets a plain tick rather than
   nothing at all. */
function iconForWords(words) {
  var w = String(words || '').toLowerCase();
  if (/\bno,|cancel|not now|leave it|leave the router|close$/.test(w)) return 'close';
  if (/erase|forget|delete|remove|take .* off|empty/.test(w)) return 'forget';
  if (/unfold|undo|put .* back|back in/.test(w)) return 'undo';
  if (/ban\b|ban /.test(w)) return 'ban';
  if (/whitelist|never ban/.test(w)) return 'shield';
  if (/fold/.test(w)) return 'fold';
  if (/fill|countr/.test(w)) return 'globe';
  if (/router|sync/.test(w)) return 'router';
  if (/key/.test(w)) return 'key';
  if (/download/.test(w)) return 'download';
  if (/load|import|paste|use my own/.test(w)) return 'upload';
  if (/fetch/.test(w)) return 'download';
  if (/password|sign/.test(w)) return 'lock';
  if (/make|add|new/.test(w)) return 'add';
  if (/end them|stop/.test(w)) return 'cancel';
  if (/everything about|look/.test(w)) return 'search';
  if (/save|set it|keep/.test(w)) return 'save';
  return 'check';
}

/** Ask before doing something that cannot be taken back. */
function confirmThen(title, words, buttonWords, go, danger) {
  modal(title, function (body) {
    var p = el('p', 'note');
    p.innerHTML = words;
    p.style.marginBottom = '0';
    body.appendChild(p);
  }, [
    {words: 'No, leave it', close: true},
    {words: buttonWords, cls: danger === false ? 'primary' : 'danger', close: true, go: go}
  ], true);
}
var ICONS = {
  /* An envelope: mail (1.0.20). */
  /* An open book: a guide to read (1.0.110). */
  book: '<path d="M12 6.5C10 5 7 4.5 3.5 5v13.5C7 18 10 18.5 12 20c2-1.5 5-2 8.5-1.5V5C17 4.5 14 5 12 6.5z"/><path d="M12 6.5V20"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  /* A phone: a code by SMS (1.0.76). */
  phone: '<rect x="7" y="2.5" width="10" height="19" rx="2.2"/><path d="M11 18.5h2"/>',
  /* A pencil: change it. Used for every Edit in the pages (1.0.8). */
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
  shield: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>',
  /* A socket, a radio, and a plug with nothing behind it: the three doors
     that are the network rather than somebody signing in to something. */
  ethernet: '<rect x="4" y="9" width="16" height="10" rx="2"/>'
    + '<path d="M8 9V6h8v3M9 19v-4M12 19v-4M15 19v-4"/>',
  wifi: '<path d="M4 9a13 13 0 0 1 16 0"/><path d="M7 12.5a8.5 8.5 0 0 1 10 0"/>'
    + '<path d="M10 16a4 4 0 0 1 4 0"/><circle cx="12" cy="19" r="1"/>',
  plug: '<path d="M9 3v6M15 3v6"/><path d="M7 9h10v3a5 5 0 0 1-10 0z"/>'
    + '<path d="M12 17v4"/>',
  /* The switch every appliance has: the ring broken at the top, with the
     stroke standing in the gap. "Turn this one on." */
  power: '<path d="M12 3.5v7"/><path d="M7.8 6.3a7 7 0 1 0 8.4 0"/>',
  /* A token: the little fob with a number on it, whether it is a fob or an
     app pretending to be one. */
  token: '<rect x="3" y="7" width="18" height="10" rx="2.5"/>'
    + '<path d="M7.5 12h1.4M11.3 12h1.4M15.1 12h1.4"/>',
  ban: '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
  cancel: '<circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/>',
  check: '<path d="M20 6 9 17l-5-5"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  spray: '<path d="M7 20h6v-9H7z"/><path d="M8 11V7h4v4"/><path d="M14 5h2M14 8h3"/>'
    + '<path d="M14 11h2M18 6h.01M19 10h.01"/>',
  in: '<path d="M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/>'
    + '<path d="M14 12h7"/><path d="M18 9l3 3-3 3"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
  refresh: '<path d="M21 12a9 9 0 1 1-2.6-6.4"/><path d="M21 3v5h-5"/>',
  save: '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/>'
    + '<path d="M17 21v-8H7v8"/><path d="M7 3v5h8"/>',
  undo: '<path d="M9 14L4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 0 12h-3"/>',
  down: '<path d="M12 4v12"/><path d="M7 11l5 5 5-5"/><path d="M5 20h14"/>',
  /* Move a row up a place. Used where a list has an order that decides
     something - which name server is asked first, and so which zone wins. */
  up: '<path d="M12 20V8"/><path d="M7 13l5-5 5 5"/>',
  lower: '<path d="M12 4v12"/><path d="M7 11l5 5 5-5"/>',
  trash: '<path d="M4 7h16"/><path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>'
    + '<path d="M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13"/><path d="M10 11v6M14 11v6"/>',
  forget: '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/>'
    + '<path d="M9 11l6 6M15 11l-6 6"/>',
  download: '<path d="M12 4v12"/><path d="M7 11l5 5 5-5"/><path d="M4 20h16"/>',
  /* Two sheets, one behind the other: what "copy this" looks like
     everywhere. */
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/>'
    + '<path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
  upload: '<path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 20h16"/>',
  key: '<circle cx="8" cy="12" r="3.2"/><path d="M11.2 12H21"/><path d="M17 12v3"/>'
    + '<path d="M20 12v2.4"/>',
  router: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01"/>'
    + '<path d="M8 7l3 3 5-6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/>'
    + '<path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3"/>'
    + '<path d="M12.5 15H17"/>',
  history: '<path d="M3.5 12a8.5 8.5 0 1 0 2.6-6.1"/><path d="M3 4v4h4"/>'
    + '<path d="M12 7.5V12l3 2"/>',
  wall: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9.3h18M3 14.7h18"/>'
    + '<path d="M9 4v5.3M15 9.3v5.4M9 14.7V20"/>',
  fold: '<path d="M4 5c5 0 6 7 8 7"/><path d="M4 12h8"/><path d="M4 19c5 0 6-7 8-7"/>'
    + '<path d="M12 12h8"/><path d="M17 9l3 3-3 3"/>',
  net: '<rect x="3" y="5" width="18" height="14" rx="2"/>'
    + '<path d="M7 12h.01M10.5 12h.01M14 12h.01M17.5 12h.01"/>',
  list: '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="4" cy="6" r="1"/>'
    + '<circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>',
  person: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20c0-3.6 3.1-5.5 7-5.5s7 1.9 7 5.5"/>',
  people: '<circle cx="9" cy="8" r="3.2"/><path d="M2.5 20c0-3.4 2.9-5.2 6.5-5.2s6.5 1.8 6.5 5.2"/>'
    + '<path d="M16.5 5.2a3.2 3.2 0 0 1 0 5.6"/><path d="M18 14.9c2.1.6 3.5 2.2 3.5 5.1"/>',
  archive: '<rect x="3" y="4" width="18" height="5" rx="1"/><path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9"/><path d="M10 13h4"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  db: '<ellipse cx="12" cy="6" rx="7" ry="3"/><path d="M5 6v12c0 1.7 3.1 3 7 3s7-1.3 7-3V6"/>'
    + '<path d="M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3"/>',
  gear: '<circle cx="12" cy="12" r="3"/>'
    + '<path d="M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3'
    + 'M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  chart: '<path d="M4 19h16"/><path d="M5 15l4-5 4 3 6-8"/>',
  log: '<path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5"/><path d="M9 13h7M9 17h5"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6"/><path d="M12 7.5h.01"/>',
  add: '<circle cx="12" cy="12" r="9"/><path d="M12 8v8M8 12h8"/>',
  play: '<path d="M7 5v14l11-7z"/>',
  next: '<path d="M9 18l6-6-6-6"/>',
  unfold: '<path d="M6 9l6 6 6-6"/>',
  prev: '<path d="M15 18l-6-6 6-6"/>',
  last: '<path d="M7 18l6-6-6-6M17 6v12"/>',
  first: '<path d="M17 18l-6-6 6-6M7 6v12"/>',
  eye: '<path d="M2 12s3.8-6.5 10-6.5S22 12 22 12s-3.8 6.5-10 6.5S2 12 2 12z"/>'
    + '<circle cx="12" cy="12" r="2.8"/>',
  out: '<path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4"/><path d="M10 16l4-4-4-4"/>'
    + '<path d="M14 12H3"/>',
  pulse: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  bell: '<path d="M6 16V11a6 6 0 1 1 12 0v5l1.5 2h-15L6 16z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
  flag: '<path d="M5 21V4"/><path d="M5 5h11l-2 3.5L16 12H5z"/>',
  pin: '<path d="M9 4h6l-1 6 3 3H7l3-3z"/><path d="M12 13v7"/>',
  broom: '<path d="M14 3l7 7"/><path d="M12.5 5.5L18.5 11.5"/>'
    + '<path d="M11 7L4 14v6h6l7-7z"/><path d="M8 12l4 4"/>'
};

function iconMarkup(key, size) {
  return '<svg viewBox="0 0 24 24" width="' + (size || 17) + '" height="' + (size || 17)
    + '" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"'
    + ' stroke-linejoin="round" aria-hidden="true">' + (ICONS[key] || '') + '</svg>';
}

/** Put an icon on a button that is already on the page, keeping its words. */
function setButtonIcon(button, key, label) {
  var words = label !== undefined ? label : button.textContent;
  button.innerHTML = iconMarkup(key) + (words ? '<span></span>' : '');
  if (words) button.querySelector('span').textContent = words;
  return button;
}

/** A button with an icon and a word. */
function cmdButton(label, key, cls) {
  var b = el('button', 'btn cmd' + (cls ? ' ' + cls : ''));
  b.type = 'button';
  return setButtonIcon(b, key, label);
}

/** A button that is only an icon, for a row that has no width to spare. */
function iconButton(key, title) {
  var b = el('button', 'btn iconbtn small');
  b.type = 'button';
  /* Red on hover is for what takes something away; the rest go blue (1.0.15). */
  if (['trash', 'close', 'power', 'off', 'remove', 'delete'].indexOf(key) < 0) b.classList.add('go');
  if (title) b.title = title;
  return setButtonIcon(b, key, '');
}
var SETHELP = null;
/* Something a machine said, shown the way it said it. The text is put in as
   text and never as markup, and it is drawn in a box that scrolls rather than
   one that wraps, so a long line from a router stays one line. */
function saidBox(text) {
  var box = el('div', 'joblines said');
  var line = el('div');
  line.textContent = String(text === undefined || text === null ? '' : text);
  box.appendChild(line);
  return box;
}
function helpBox() {
  if (!SETHELP) {
    SETHELP = el('div', 'sethelp');
    document.body.appendChild(SETHELP);
  }
  return SETHELP;
}
/** A value put inside the words `explain` and `richText` escape themselves:
    without anything that could be read as a tag, and NOT escaped here -
    escaped twice, "R&D" showed as "R&amp;D" (1.10.176). */
function wordsIn(text) {
  return String(text === undefined || text === null ? '' : text).replace(/[<>]/g, '');
}

function richText(text) {
  var safe = String(text === undefined || text === null ? '' : text)
    .replace(/[&<>"']/g, function (c) {
      /* The apostrophe as well. Every one of these lands in element content
         today, where it would not matter - but this reads as the page's
         escaper, and the first use of it inside an attribute would be an
         injection nobody looked for. */
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
    });
  /* A short list of tags that mean something in a sentence, and a line
     break, which is what a newline in one of these strings is asking for.
     Everything else stays as the characters somebody typed. */
  return safe.replace(/&lt;(\/?)(code|i|b|br|kbd)\s*\/?&gt;/g, '<$1$2>')
    .replace(/\n/g, '<br>');
}
/** What a setting says about itself, drawn rather than spelled out. These
    strings carry <code> around the thing somebody would type and <b> around
    the word that matters; printed as text they read as markup, which is what
    they looked like until now. */
function saysBlock(words) {
  var box = el('div', 'says');
  box.innerHTML = richText(words);
  return box;
}

function helpAt(over, html, at) {
  /* Nothing to say is not the same as an empty box. An element whose words
     have been folded into the one around it asks for nothing here. */
  if (!html) return;
  var box = helpBox();
  box._over = over;
  box.innerHTML = html;
  box.style.display = 'block';
  /* Where the pointer was when this opened. A redraw that takes the row away
     must not take the panel with it while somebody is holding still. */
  var mouse = MOUSE_AT || {x: -1, y: -1};
  box._mouseAt = (at && typeof at.clientX === 'number')
    ? {x: at.clientX, y: at.clientY} : {x: mouse.x, y: mouse.y};
  /* `at` is the mouse event that opened it, where there was one. */
  at = at || over;
  var wide = box.getBoundingClientRect();
  /* Where a pointer is, when there is one. A panel of a dozen lines anchored
     to a table row is a panel the size of a card, and wherever it is put it
     lands on something: over the row it covers the row, beside the row it
     covers the card next to it. Next to the POINTER is the one place that
     reads as deliberate, because it is where every tooltip anybody has ever
     used appears. The element is still the anchor when this was reached by
     keyboard, where there is no pointer to speak of. */
  if (at && typeof at.clientX === 'number' && (at.clientX || at.clientY)) {
    var x = at.clientX + 16;
    var y = at.clientY + 18;
    if (x + wide.width > window.innerWidth - 8) x = at.clientX - wide.width - 16;
    if (x < 8) x = 8;
    if (y + wide.height > window.innerHeight - 8) y = at.clientY - wide.height - 14;
    if (y < 8) y = Math.max(8, window.innerHeight - wide.height - 8);
    box.style.left = Math.round(x) + 'px';
    box.style.top = Math.round(y) + 'px';
    return;
  }
  at = (at && at.getBoundingClientRect) ? at.getBoundingClientRect()
                                        : over.getBoundingClientRect();
  var left = Math.min(Math.max(8, at.left), window.innerWidth - wide.width - 12);
  var top = at.bottom + 8;
  /* A row of a door card says a dozen things about itself, and a panel of a
     dozen things is half the height of the window. Under the row it runs off
     the bottom; over the row it lands on the header and the tabs and covers
     the very row somebody is pointing at. So a TALL panel goes BESIDE the
     thing where there is room for it, level with it, and nothing is covered
     at all. Small ones are left exactly where they always were. */
  var tall = wide.height > window.innerHeight / 3;
  var level = Math.max(8, Math.min(at.top, window.innerHeight - wide.height - 8));
  if (top + wide.height > window.innerHeight - 8) {
    if (tall && at.right + 8 + wide.width <= window.innerWidth - 8) {
      left = at.right + 8;
      top = level;
    } else if (tall && at.left - wide.width - 8 >= 8) {
      left = at.left - wide.width - 8;
      top = level;
    } else if (at.top - wide.height - 8 >= 8) {
      top = at.top - wide.height - 8;
    } else {
      top = level;
    }
  }
  box.style.left = left + 'px';
  box.style.top = top + 'px';
}
function hideHelp(e) {
  if (!SETHELP) return;
  /* A row that a redraw is taking away fires `mouseleave` on its way out,
     with the pointer exactly where it was. Closing on that is what made a
     panel disappear while somebody was reading it. The panel stays; the
     sweeper below takes it away once they actually move. */
  var from = e && e.currentTarget;
  if (from && from.nodeType === 1 && !from.isConnected) return;
  SETHELP.style.display = 'none';
}

/** Hold a box at the height it already has, while what is in it is replaced.

    A card redrawn by the live update empties and fills again inside one
    frame. The page is shorter in between, the browser moves the scroll to
    match, and what somebody sees is the whole column jumping every few
    seconds. Holding the height across the swap takes the jump away; letting
    go afterwards lets the card be whatever size it should now be. An open
    panel goes with it, because it was pointing at a row that no longer
    exists. */
function steady(host) {
  if (!host) return;
  /* Where the page is, so it can be put back. Holding the box at its old
     height and then letting go two frames later was worse than the thing it
     was meant to fix: the new content is rarely the same height as the old,
     so every refresh ended with a visible jump as the height was released.
     The scroll position is the thing that actually has to stay still. */
  host._wasAt = window.scrollY || window.pageYOffset || 0;
  hideHelp();
}

function settle(host) {
  if (!host || host._wasAt === undefined) return;
  var back = host._wasAt;
  host._wasAt = undefined;
  var now = window.scrollY || window.pageYOffset || 0;
  /* Only when the swap actually moved it, and without a smooth scroll -
     this is putting something back, not going somewhere. */
  if (Math.abs(now - back) > 1) window.scrollTo(0, back);
}

/** Whether an answer is the one already on the page.

    The live update asks every few seconds and most of the time nothing has
    changed. Redrawing a card that is the same card is a clear-and-rebuild
    for nothing, and on a page somebody has scrolled down it is a visible
    flicker every few seconds. */
/** Is somebody pointing at something inside this?

    A panel is open and it belongs to a row in here. Redrawing now takes that
    row out of the page, the panel is left pointing at nothing, and a second
    later it disappears - which from the other side of the screen is a popup
    that closes by itself while you are reading it. */
/** Whether somebody is doing something inside a part of the page that a
    refresh would draw again: typing into a box drawn there (the boxes the
    page is built with have names of their own, and stay where they are), or
    words selected in it a moment ago. Never for long: past half a minute the
    list is drawn again whatever, so that a selection left lying about never
    stops it for good. (1.10.168) */
var HOLD_SINCE = 0, SELECTED_AT = 0;
document.addEventListener('selectionchange', function () { SELECTED_AT = Date.now(); });
function userHolds(host) {
  if (!host) return false;
  var held = false;
  var on = document.activeElement;
  if (on && on !== document.body && host.contains(on) && !on.id && liveControl(on)
      && !(on.closest && on.closest('.modal, #modal'))) {
    /* A list open or a box typed in holds it as long as it is (1.0.123). */
    return true;
  }
  if (LIVE_PRESS && LIVE_PRESS.isConnected && host.contains(LIVE_PRESS)) return true;
  if (!held && Date.now() - SELECTED_AT < 15000) {
    try {
      var sel = window.getSelection ? window.getSelection() : null;
      if (sel && !sel.isCollapsed && sel.anchorNode && host.contains(sel.anchorNode)) held = true;
    } catch (e) { /* no selection to ask about */ }
  }
  if (!held) { HOLD_SINCE = 0; return false; }
  if (!HOLD_SINCE) HOLD_SINCE = Date.now();
  if (Date.now() - HOLD_SINCE > 30000) { HOLD_SINCE = 0; return false; }
  return true;
}

function pointerBusy(host) {
  if (!host || !SETHELP || SETHELP.style.display !== 'block') return false;
  var over = SETHELP._over;
  return !!(over && host.contains && host.contains(over));
}

function sameAsDrawn(host, d) {
    /* Whatever has changed can wait for the pointer to move. Deliberately
       WITHOUT writing down what would have been drawn, so that the moment
       the panel closes the next pass draws it. */
    if (pointerBusy(host)) return true;
    var said;
    try {
      /* The minute goes into the key. Anything drawn with "2 min ago" in
         it is a different picture a minute later even when the data is
         not, and a card that said "2 min ago" for an hour because nothing
         new arrived was a card that was lying. */
      said = JSON.stringify(d) + '@' + Math.floor(Date.now() / 60000);
    } catch (e) {
      return false;
    }
    if (host._drew === said) return true;
    host._drew = said;
    return false;
}

function explain(over, words, extra) {
  if (!over || !words) return over;
  var html = '<div>' + richText(words) + '</div>' + (extra || '');
  /* One thing pointed at, one panel - and it says what THAT thing is.
     Until 1.10.156 an element inside another that explains itself was
     folded into it, both ways: a row of the Traffic list took in what every
     address, name and mark in it said, so pointing anywhere at a row showed
     a column of a dozen paragraphs, the same ones twice where both ends were
     private or both had no name. Now each keeps its own words; the panel is
     always the innermost one under the pointer, and moving back out of it
     onto the row shows the row's again. One panel at a time, as before. */
  /* The browser's own tooltip is taken away rather than left beside this one:
     both showing at once is what somebody actually sees, a white box sitting
     on top of the page's own dark one saying the same thing twice. */
  if (over.getAttribute && over.getAttribute('title')) {
    over.removeAttribute('title');
  }
  if (!over.getAttribute('aria-label')) {
    /* Only the tags richText knows taken out (1.0.101): a path such as
       /var/log/remote/<host>/ kept its <host>. */
    /* In the page's language (1.0.103): cut to 300 characters or with its
       tags taken out, the English never matched a translation. */
    var spoken = String(words).replace(/<\/?(?:b|i|em|strong|code|kbd|br)\s*\/?>/gi, '');
    if (typeof i18nText === 'function') {
      var tr = i18nText(String(words));
      if (tr && tr !== String(words)) spoken = String(tr).replace(/<[^>]*>/g, '');
    }
    over.setAttribute('aria-label', spoken.slice(0, 300));
  }
  over.dataset.explains = '1';
  /* The words may change while the listeners stay: they are put on once, and
     what they show is read fresh each time. */
  over._explainHtml = html;
  if (over._explained) return over;
  over._explained = true;
  /* Every one of these asks whether there is anything to say: words taken
     off later leave the listeners in place, saying nothing and hiding
     nothing. */
  over.addEventListener('mouseenter', function (e) {
    if (over._explainHtml) helpAt(over, over._explainHtml, e);
  });
  over.addEventListener('mouseleave', function (e) {
    if (!over._explainHtml) return;
    /* Back out onto something around it that says something of its own:
       that is what is pointed at now. */
    var to = e && e.relatedTarget;
    for (var up = over.parentNode; up && up.nodeType === 1 && up !== document.body;
         up = up.parentNode) {
      if (up._explainHtml && to && up.contains(to)) {
        helpAt(up, up._explainHtml, e);
        return;
      }
    }
    hideHelp(e);
  });
  over.addEventListener('focus', function () {
    if (over._explainHtml) helpAt(over, over._explainHtml);
  });
  over.addEventListener('blur', function (e) {
    if (over._explainHtml) hideHelp(e);
  });
  return over;
}
var MOUSE_AT = {x: -1, y: -1};
document.addEventListener('mousemove', function (e) {
  MOUSE_AT = {x: e.clientX, y: e.clientY};
}, true);

/* A panel left open over something that has since been redrawn away points at
   nothing - but only once somebody has MOVED. A list that redraws itself
   every few seconds used to take the row out from under a still pointer, and
   this closed the panel a second later: a popup that vanishes by itself
   while it is being read. Nothing redraws under a pointer any more (see
   `pointerBusy`); this is what catches the rest. */
setInterval(function () {
  if (!SETHELP || SETHELP.style.display !== 'block') return;
  var over = SETHELP._over;
  if (!over || over.isConnected) return;
  var was = SETHELP._mouseAt;
  if (was && Math.abs(was.x - MOUSE_AT.x) < 4 && Math.abs(was.y - MOUSE_AT.y) < 4) {
    return;                      // the pointer has not moved; leave it be
  }
  hideHelp();
}, 1000);
window.addEventListener('scroll', hideHelp, true);
function peek(title, ask, draw, jump) {
  var mine = ++PEEK;
  var buttons = [{words: 'Close', close: true}];
  /* ...but not when it is the page they are already on. Pressing it there
     closed the popup and did nothing whatever, which reads as a button that
     is broken rather than as one that had nowhere to go. */
  if (jump && jump.tab !== TAB) {
    buttons.unshift({words: jump.words, cls: 'primary', icon: jump.icon, close: true,
                     go: function () {
                       /* A jump that carries its own way there - the Log with
                          its filter set (1.0.103) - takes it. */
                       if (typeof jump.go === 'function') { jump.go(); return; }
                       /* To the very page meant, not only its tab (1.0.37):
                          Open Upgrades opened whichever settings page was last. */
                       if (jump.pane && typeof PANE !== 'undefined') PANE = jump.pane;
                       showTab(jump.tab);
                       if (jump.pane && typeof showPane === 'function') setTimeout(function () { showPane(jump.pane); }, 0);
                     }});
  }
  modal(title, function (body) {
    body.appendChild(el('p', 'center muted', 'Asking…'));
  }, buttons);
  var ticket = modalTicket();
  Promise.resolve(ask()).then(function (d) {
    if (mine !== PEEK || !modalStill(ticket)) return;  /* they moved on */
    var body = $('modal-body');
    clear(body);
    draw(body, d);
    explainWhatWasDrawn(body);
  }).catch(function (e) {
    if (mine !== PEEK || !modalStill(ticket)) return;
    var body = $('modal-body');
    clear(body);
    body.appendChild(el('p', 'center bad', String((e && e.message) || e)));
  });
}

/** The line of plain facts a popup opens with. */
function peekFacts(pairs) {
  var box = el('div', 'facts');
  pairs.forEach(function (one) {
    if (!one) return;
    var cell = el('div', 'fact');
    /* A long value - an address, a version - gets two columns (1.0.37). */
    var vtext = one[1] && one[1].nodeType ? (one[1].textContent || '') : String(one[1] === undefined || one[1] === null ? '' : one[1]);
    if (vtext.length > 22) cell.className = 'fact wide';
    cell.appendChild(el('span', 'k', one[0]));
    var v = el('span', 'v');
    if (one[1] && one[1].nodeType) v.appendChild(one[1]); else { v.textContent = one[1]; v.title = String(one[1] === undefined || one[1] === null ? '' : one[1]); }
    cell.appendChild(v);
    box.appendChild(cell);
  });
  return box;
}

function pageSays(label, page, pages) {
  var where = ' You are on page ' + (page + 1) + ' of ' + pages + '.';
  if (label === 'First' || label === 'Newest') {
    return 'Back to the first page of this list.' + where;
  }
  if (label === 'Back') return 'The page before this one.' + where;
  if (label === 'On' || label === 'Next') return 'The next page of this list.' + where;
  return 'The last page of this list.' + where;
}

/** Headers into cells: words, or {words, cls} for a column that is not drawn
    flush left, or an array of either for a run of columns that belong
    together - an address, its name, its flag - handed in as one so that the
    headers and the cells can never drift apart. */
function headCells(headers) {
  var flat = [];
  (headers || []).forEach(function (h) {
    if (Array.isArray(h)) { flat.push.apply(flat, h); } else { flat.push(h); }
  });
  return flat.map(function (h) {
    return h && h.cls ? el('th', h.cls, h.words || '') : el('th', '', h);
  });
}

/* Every table of the pages (1.0.165): its rows scroll inside it under headings
   that stay, and past LT_PER rows it is paged - the same buttons as every
   list. The lists the daemon pages itself (`own`: the tokens, the log, the
   enrolments, the events, the outgoing mail) keep their own. The page a table
   is on is kept while it is drawn again by itself. */
var LT_PER = 50;
var LT_PAGE = {};
function listTable(headers, rows, cell, cls, opts) {
  opts = opts || {};
  rows = Array.isArray(rows) ? rows : [];
  if (!opts.own && rows.length > LT_PER) {
    var key = (cls || '') + '|' + headCells(headers).map(function (th) { return th.textContent; }).join('|');
    var box = el('div', 'lt-paged');
    var pages = Math.ceil(rows.length / LT_PER);
    var draw = function (page) {
      page = Math.max(0, Math.min(pages - 1, page || 0));
      LT_PAGE[key] = page;
      clear(box);
      var t = listTable(headers, rows.slice(page * LT_PER, (page + 1) * LT_PER),
                        function (r, n) { return cell(r, n + page * LT_PER); }, cls, {own: false, inner: true});
      box.appendChild(t);
      var pg = el('div', 'pager lt-pager');
      box.appendChild(pg);
      pager(pg, page, LT_PER, rows.length, function (p) { draw(p); t = null; });
    };
    draw(LT_PAGE[key] || 0);
    return box;
  }
  var wrap = el('div', 'scroll' + (opts.own ? '' : ' lt-held'));
  var table = el('table', cls || 'plain');
  var thead = el('thead'), tr = el('tr');
  /* A header is its words, or {words, cls} when the column it names is not
     drawn flush left - a number, a mark - so that the word above a column
     sits over the column and not beside it. */
  headCells(headers).forEach(function (th) { tr.appendChild(th); });
  thead.appendChild(tr);
  table.appendChild(thead);
  var body = el('tbody');
  /* An empty list says so in one row rather than leaving a bare header
     (1.0.15). `cls` may carry an `empty` text after a '|': 'plain|Nothing yet'. */
  var words = 'Nothing here';
  if (cls && cls.indexOf('|') >= 0) { words = cls.slice(cls.indexOf('|') + 1); cls = cls.slice(0, cls.indexOf('|')); table.className = cls || 'plain'; }
  if (!rows.length) {
    var tr0 = el('tr', 'empty-row'), td0 = el('td', 'muted', words);
    td0.colSpan = Math.max(1, headers.length);
    tr0.appendChild(td0);
    body.appendChild(tr0);
  }
  rows.forEach(function (r, n) {
    var line = cell(r, n);
    if (line && line.nodeType === 1 && line.tagName === 'TR' && !line._rec
        && r && typeof r === 'object' && !Array.isArray(r)) {
      line._rec = r;
    }
    body.appendChild(line);
  });
  table.appendChild(body);
  table._cell = cell;
  wrap.appendChild(table);
  /* ...and whatever else its records hold that has a name, as columns out
     of sight until somebody asks for them (1.10.156). */
  return wrap;
}

/* ---- paging, once, for every table that needs it ------------------------- */
function pager(id, page, per, total, go, capped) {
  var host = typeof id === 'string' ? $(id) : id;
  clear(host);
  var pages = Math.max(1, Math.ceil((total || 0) / per));
  /* A page past the end - the window rolled on, or rows were erased - is
     an empty table with no way back (1.10.176): taken to the last page. */
  if (total > 0 && page >= pages && go && !capped) {
    setTimeout(function () { go(pages - 1); }, 0);
    return;
  }
  if (pages <= 1) return;
  /* A total the daemon stopped counting at is not the end of the list:
     "Last" then would be a page from the middle of it, said to be the last.
     It says "more than", and Last is left to the order turned round.
     (1.10.168) */
  capped = !!capped;
  function button(words, key, to, off, says) {
    var b = cmdButton(words, key, 'small');
    b.disabled = !!off;
    explain(b, says);
    b.onclick = function () { go(to); };
    host.appendChild(b);
  }
  /* The same four buttons as every other list on the page (1.10.160): the
     lists paged here can be ordered by any of their headings, so "newer" and
     "older" said something that was only true of one order. */
  button('First', 'first', 0, page === 0, pageSays('First', page, pages));
  button('Back', 'prev', Math.max(0, page - 1), page === 0, pageSays('Back', page, pages)
         + ' The filters above stay as they are.');
  var says = el('span', 'muted', capped
    ? 'page ' + (page + 1) + ' of more than ' + num(pages) + ' · more than ' + num(total)
      + ' row(s)'
    : 'page ' + (page + 1) + ' of ' + pages + ' · ' + num(total) + ' row(s)');
  explain(says, 'How many rows match the filters above, and where in them this page is. '
    + 'How many are shown at a time is the last box in the filter row.');
  host.appendChild(says);
  button('Next', 'next', Math.min(pages - 1, page + 1), page >= pages - 1,
         pageSays('Next', page, pages) + ' The filters above stay as they are.');
  button('Last', 'last', pages - 1, page >= pages - 1 || capped, capped
    ? 'The list goes on past what was counted. To reach its other end, make the time window '
      + 'shorter or the search narrower - or, in a list whose headings sort, order it the other '
      + 'way round by its heading.' : pageSays('Last', page, pages));
}

function debounce(fn, ms) {
  var t = null;
  return function () {
    var args = arguments, self = this;
    clearTimeout(t);
    t = setTimeout(function () { fn.apply(self, args); }, ms);
  };
}

/* ==========================================================================
   What is upsmon's own from here on: the state the helpers above expect, the
   one way the pages ask the daemon, and the sweep that turns every `title`
   into the page's own panel.
   ========================================================================== */
var ADMIN = false;           /* set by the page: may this sign-in change things */
var TAB = '';
var PEEK = 0;
function showTab(name) { if (typeof window.optShowTab === 'function') window.optShowTab(name); }

/** Ask the daemon, through this page's PHP. A body makes it a POST. */
/* Every question has a deadline (1.0.66): behind the VIP address, an answer
   on its way when the address moved to the other node never came, the
   connection waited for good, and a page that asks again only after an
   answer - the upgrade's progress among them - stood still until F5.
   Aborted, the browser drops that connection and the next question goes to
   whichever node holds the address now. `wait` (seconds) for the slow ones. */
var API_WAIT_GET = 20, API_WAIT_POST = 150;
/* Whether the session is really gone (1.0.73): asked three times, two
   seconds apart; one answer that knows the session is enough. */
var SIGNED_OUT_CHECK = null;
function signedOutForSure() {
  if (SIGNED_OUT_CHECK) return SIGNED_OUT_CHECK;
  var admin = /\/admin\//.test(location.pathname);
  var ask = function () {
    return fetch('?api=' + (admin ? 'whoami' : 'me'), {credentials: 'same-origin'}).then(function (r) {
      if (r.status === 401) return 'gone';
      if (!r.ok) return 'unknown';
      return r.json().then(function (d) { return (admin ? d.who : d.me) ? 'here' : 'gone'; });
    }).catch(function () { return 'unknown'; });
  };
  var wait = function (ms) { return new Promise(function (ok) { setTimeout(ok, ms); }); };
  var tries = 0, gone = 0;
  var round = function () {
    return wait(tries ? 2000 : 600).then(ask).then(function (said) {
      tries++;
      if (said === 'here') return false;
      if (said === 'gone') gone++;
      if (gone >= 3) return true;
      if (tries >= 8) return gone >= 2;
      return round();
    });
  };
  SIGNED_OUT_CHECK = round().then(function (v) { SIGNED_OUT_CHECK = null; return v; });
  return SIGNED_OUT_CHECK;
}
function signedOutNow() {
  /* Changes not saved: said, not reloaded - the reload asked "leave the
     page?" every five seconds, for good (1.0.57). */
  var unsaved = (typeof DIRTY === 'object' && DIRTY && Object.keys(DIRTY).length) ||
                (typeof PENDING === 'object' && PENDING && Object.keys(PENDING).length);
  if (!unsaved) location.reload();
  else if (!window.SIGNED_OUT_SAID) {
    window.SIGNED_OUT_SAID = true;
    toast('signed out - the changes not saved are lost; reload the page to sign in again', 'bad');
  }
  throw new Error('signed out');
}
function api(what, body, wait) {
  var opts = {credentials: 'same-origin'};
  if (body !== undefined && body !== null) {
    opts.method = 'POST';
    opts.headers = {'Content-Type': 'application/json'};
    opts.body = JSON.stringify(body || {});
  }
  var limit = wait || (opts.method ? API_WAIT_POST : API_WAIT_GET), timer = null, late = false;
  if (typeof AbortController === 'function') {
    var ac = new AbortController();
    opts.signal = ac.signal;
    timer = setTimeout(function () { late = true; ac.abort(); }, limit * 1000);
  }
  return fetch('?api=' + what, opts).catch(function (e) {
    clearTimeout(timer);
    var err = new Error(late ? 'the server did not answer in ' + limit + ' s'
                             : 'the server could not be reached');
    err.unreachable = true;
    throw err;
  }).then(function (r) {
    clearTimeout(timer);
    if (r.status === 401 && !/^(login|portal-login)/.test(what)) {
      /* Asked again before the page is left (1.0.73): behind the VIP address
         a node that is restarting, or that has just got the address, may say
         401 for a moment - and reloading then broke the page in the middle
         of an upgrade. Meanwhile the answer is "not reached", so whatever
         asks every few seconds asks again. */
      return signedOutForSure().then(function (gone) {
        if (!gone) {
          var err = new Error('the server could not be reached');
          err.unreachable = true;
          throw err;
        }
        return signedOutNow();
      });
    }
    return r.text().then(function (text) {
      var data;
      try { data = JSON.parse(text); }
      catch (e) {
        /* nginx's own pages, not the daemon's answer (1.0.36). */
        if (r.status === 429 || r.status === 503 && /limit/i.test(text)) throw new Error('too many attempts - wait a minute and try again');
        if (r.status === 502 || r.status === 503 || r.status === 504) {
          var down = new Error('the server is not answering just now - try again in a moment');
          down.unreachable = true;     /* nginx with nothing behind it - a restart */
          throw down;
        }
        if (r.status === 413) throw new Error('that is more than the server takes');
        throw new Error('the page got something that is not an answer');
      }
      if (!r.ok || data.ok === false) {
        var err = new Error(data.error || ('HTTP ' + r.status));
        err.status = r.status;
        err.detail = data.detail || '';
        throw err;
      }
      return data;
    });
  });
}

/** Every `title` already drawn, given the page's own panel instead. */
/* No browser tooltip anywhere (1.0.157): whatever gets a title - drawn now or
   later, by any part of the pages - says it in the page's own panel instead,
   and a picture's <title> becomes its aria-label. A title put on after
   explain() had run, or on something drawn later without explainWhatWasDrawn,
   showed the browser's white box - beside the page's own one, too. */
function nativeTipsAway(root) {
  if (!root || !root.querySelectorAll) return;
  var one = function (el) {
    if (!el.getAttribute || el.tagName === 'IFRAME') return;       /* an iframe's title is for screen readers */
    var said = el.getAttribute('title');
    if (!said) return;
    if (el.closest && el.closest('.sethelp')) return;
    if (el.dataset && el.dataset.explains) {
      el.removeAttribute('title');
      el._explainHtml = '<div>' + richText(said) + '</div>';
      return;
    }
    explain(el, said);
  };
  if (root.nodeType === 1) one(root);
  Array.prototype.forEach.call(root.querySelectorAll('[title]'), one);
  Array.prototype.forEach.call(root.querySelectorAll('svg title'), function (t) {
    var svg = t.closest('svg');
    if (svg && !svg.getAttribute('aria-label')) svg.setAttribute('aria-label', (t.textContent || '').trim());
    if (svg && svg.getAttribute('aria-labelledby') === t.id) svg.removeAttribute('aria-labelledby');
    t.parentNode.removeChild(t);
  });
}
/* Long explaining paragraphs - a pane's lede, a card's note - in three lines
   (1.0.157): a click opens the rest in place, and the whole is in the page's
   panel on the pointer. Never a warning or an error, nor one with a link or a
   button in it, nor anything in a dialog: those are read whole. */
var FOLD_SEEN = null;
function longWordsFolded(root) {
  if (!root || !root.querySelectorAll || !document.body.classList.contains('fold-words')) return;
  var list = [];
  if (root.matches && root.matches('p.note, .ctl-lede')) list.push(root);
  Array.prototype.push.apply(list, root.querySelectorAll('p.note, .ctl-lede'));
  list.forEach(function (p) {
    if (p._folded || p.closest('.modal, .sethelp, .says') ||
        /(^|\s)(bad|warn|good|err|ok)(\s|$)/.test(p.className) ||
        p.querySelector('a, button, input, select, textarea')) return;
    p._folded = true;
    p.classList.add('fold');
    var mark = function () {
      if (!p.isConnected) return;
      if (!p.clientHeight || p.classList.contains('open')) return;
      var cut = p.scrollHeight > p.clientHeight + 2;
      p.classList.toggle('cut', cut);
      if (cut && !p.dataset.explains) {
        explain(p, p.textContent);
        p._explainHtml = '<div>' + p.innerHTML + '</div>';
      }
    };
    p.addEventListener('click', function () { p.classList.toggle('open'); });
    /* Measured when it is seen and whenever its size changes - a pane drawn
       hidden has nothing to measure yet, and the page's language makes a
       text longer or shorter. */
    if (typeof ResizeObserver === 'function') {
      if (!FOLD_SEEN) FOLD_SEEN = new ResizeObserver(function (rows) {
        rows.forEach(function (r) { if (r.target._foldMark) r.target._foldMark(); });
      });
      p._foldMark = mark;
      FOLD_SEEN.observe(p);
    } else {
      setTimeout(mark, 60);
      setTimeout(mark, 800);
    }
  });
}
(function () {
  if (typeof MutationObserver !== 'function' || typeof document === 'undefined') return;
  var go = function () {
    nativeTipsAway(document.body);
    longWordsFolded(document.body);
    new MutationObserver(function (list) {
      list.forEach(function (m) {
        if (m.type === 'attributes') { if (m.target.getAttribute('title')) nativeTipsAway(m.target); return; }
        Array.prototype.forEach.call(m.addedNodes, function (n) {
          if (n.nodeType === 1) { nativeTipsAway(n); longWordsFolded(n); }
        });
      });
    }).observe(document.body, {subtree: true, childList: true, attributes: true, attributeFilter: ['title']});
  };
  if (document.body) go(); else document.addEventListener('DOMContentLoaded', go);
})();

function explainWhatWasDrawn(where) {
  var host = where || document;
  Array.prototype.forEach.call(host.querySelectorAll('[title]'), function (one) {
    if (one.closest && one.closest('.sethelp')) return;
    if (one.dataset.explains) {
      var said = one.getAttribute('title');
      one.removeAttribute('title');
      if (said) one._explainHtml = '<div>' + richText(said) + '</div>';
      return;
    }
    explain(one, one.getAttribute('title'));
  });
}

/** A whole sentence of text for markup, escaped. */
function htmlText(t) {
  return String(t === undefined || t === null ? '' : t).replace(/[&<>"']/g, function (c) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
  });
}

/** A key/value table, the label column as wide as its longest label. */
function kvTable(pairs) {
  var t = el('table', 'plain tight');
  var b = el('tbody');
  pairs.forEach(function (p) {
    if (!p) return;
    var tr = el('tr');
    tr.appendChild(el('td', 'muted', p[0]));
    var td = el('td', p[2] || '');
    if (p[1] && p[1].nodeType) td.appendChild(p[1]); else td.textContent = p[1] === undefined
      || p[1] === null || p[1] === '' ? '–' : String(p[1]);
    tr.appendChild(td);
    b.appendChild(tr);
  });
  t.appendChild(b);
  return t;
}

/** A field of a form inside a popup: a label, the box, the words under it. */
var FORM_FIELD_N = 0;
function formField(label, input, says) {
  var item = el('div', 'set-item');
  var l = el('label', '', label);
  /* The label names its box: a click on it lands in the box, and a screen
     reader says what the box is (1.0.15). A switch is a label of its own
     around a checkbox; that checkbox is what the name points at. */
  var target = input && input._input ? input._input : input;
  if (target && target.nodeType === 1 && /^(INPUT|SELECT|TEXTAREA)$/.test(target.tagName)) {
    if (!target.id) target.id = 'ff-' + (++FORM_FIELD_N);
    l.htmlFor = target.id;
  }
  item.appendChild(l);
  item.appendChild(input);
  if (says) item.appendChild(saysBlock(says));
  return item;
}
function textBox(value, placeholder, cls) {
  var i = el('input', cls || '');
  i.type = 'text';
  i.value = value === undefined || value === null ? '' : String(value);
  if (placeholder) i.placeholder = placeholder;
  i.autocomplete = 'off';
  i.spellcheck = false;
  return i;
}
/** A box for a secret: typed unseen, never offered to a password manager
    as something to remember (1.0.15). `_show()` turns it into plain text. */
function secretBox(value, placeholder, cls) {
  return maskBox(value, placeholder, cls);
}
/** A password or a secret as isemon shows one (1.0.22): dots, and its last
    two characters in clear, so "the one I set" can be told from a typing
    mistake. One that is kept comes from the daemon already as dots and its
    last two; one typed here is masked the same way as it is typed. `value`
    is the real text, whatever the box shows. `_show()` shows it whole. */
var MASK_PROTO = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
function maskShown(real) {
  real = String(real || '');
  if (!real || real.charAt(0) === '\u2022') return real;
  /* Being typed (1.0.124): dots only. The last two characters show only on
     one that is kept - it comes from the daemon as dots and its last two. */
  return new Array(real.length + 1).join('\u2022');
}
function maskBox(value, placeholder, cls) {
  var i = textBox('', placeholder, cls);
  i.autocomplete = 'off';
  i.setAttribute('data-lpignore', 'true');
  i.setAttribute('data-1p-ignore', 'true');
  i.classList.add('masked');
  var real = '', open = false;
  var paint = function (caret) {
    MASK_PROTO.set.call(i, open ? real : maskShown(real));
    if (caret !== undefined && document.activeElement === i) {
      try { i.setSelectionRange(caret, caret); } catch (e) { }
    }
  };
  Object.defineProperty(i, 'value', {
    configurable: true,
    get: function () { return real; },
    set: function (v) { real = v === null || v === undefined ? '' : String(v); paint(); }
  });
  var changed = function (caret) {
    paint(caret);
    i.dispatchEvent(new Event('input', {bubbles: true}));
  };
  i.addEventListener('beforeinput', function (e) {
    if (open) return;
    var a = i.selectionStart, z = i.selectionEnd, t = e.inputType || '';
    if (a === null) return;
    e.preventDefault();
    /* What was kept is dots: anything typed into it starts it afresh. */
    if (real.charAt(0) === '\u2022') { real = ''; a = z = 0; }
    var data = e.data;
    if (data === null && e.dataTransfer) data = e.dataTransfer.getData('text/plain');
    if (t.indexOf('insert') === 0) {
      if (t === 'insertLineBreak' || t === 'insertParagraph') return;
      data = String(data || '').replace(/[\r\n]+/g, '');
      real = real.slice(0, a) + data + real.slice(z);
      changed(a + data.length);
    } else if (t.indexOf('delete') === 0) {
      if (a === z) {
        if (/Backward/.test(t)) a = /Word|Line/.test(t) ? 0 : Math.max(0, a - 1);
        else z = /Word|Line/.test(t) ? real.length : Math.min(real.length, z + 1);
      }
      real = real.slice(0, a) + real.slice(z);
      changed(a);
    }
  });
  /* Whatever got in without being typed - filled in by the browser -
     is taken as it is. */
  i.addEventListener('input', function (e) {
    if (!e.isTrusted || open) { if (open) real = MASK_PROTO.get.call(i); return; }
    var shown = MASK_PROTO.get.call(i);
    if (shown !== maskShown(real)) { real = shown.replace(/^\u2022+/, ''); paint(); }
  });
  /* Pressed, a kept one is chosen whole: what is typed replaces it. */
  i.addEventListener('focus', function () {
    if (real.charAt(0) === '\u2022') setTimeout(function () { try { i.select(); } catch (e) { } }, 0);
  });
  i.addEventListener('copy', function (e) { e.preventDefault(); });
  i.addEventListener('cut', function (e) { e.preventDefault(); });
  i._show = function () { open = true; paint(); };
  real = value === null || value === undefined ? '' : String(value);
  paint();
  return i;
}
function selectBox(pairs, value) {
  var s = el('select');
  pairs.forEach(function (p) {
    var o = el('option', '', p[1]);
    o.value = p[0];
    s.appendChild(o);
  });
  s.value = String(value === undefined || value === null ? '' : value);
  return s;
}
function switchBox(on) {
  var wrap = el('label', 'sw');
  var input = document.createElement('input');
  input.type = 'checkbox';
  input.checked = !!on && String(on) !== '0';
  wrap.appendChild(input);
  wrap.appendChild(el('span', 'knob'));
  wrap._get = function () { return input.checked ? 1 : 0; };
  wrap._input = input;
  return wrap;
}

/** The language picker: the person's own choice, kept where the page says. */
function langWords(code) {
  var one = (window.OTP_LANGS || []).filter(function (l) { return l.code === code; })[0];
  return one ? one.name : code;
}

/* Every icon a button was given by its `data-icon` in the markup, put on. */
function dressButtons(where) {
  Array.prototype.forEach.call((where || document).querySelectorAll('[data-icon]'),
    function (b) {
      if (b.dataset.dressed) return;
      b.dataset.dressed = '1';
      /* A count chip inside a tab goes back on after the icon rewrote it. */
      var keep = Array.prototype.slice.call(b.querySelectorAll('.count, .me-name'));
      keep.forEach(function (k) { k.remove(); });
      var words = b.textContent.trim();
      if (keep.length && keep[0].classList.contains('me-name')) {
        setButtonIcon(b, b.dataset.icon, '');
      } else {
        setButtonIcon(b, b.dataset.icon, b.dataset.icon === 'close' ? '' : words);
      }
      keep.forEach(function (k) { b.appendChild(k); });
    });
}


/* ---- 1.0.17: which long cards may take the whole window (from isemon) ----
   A card whose rows scroll inside it is the right shape for a list of a
   hundred thousand events: the search box and the pager stay where somebody
   left them. It is the wrong shape when another card is under it on the same
   page, because a card capped to the window puts that one below the fold for
   ever. The markup says which cards are long (`data-hold`); this says which
   of them may hold: only where the card is alone on its page - a card marked
   `aside` (the daemon's own log) is not counted, and stays reachable. Run
   once and again whenever a page is shown. */
function holdTheTallOnes() {
  Array.prototype.forEach.call(document.querySelectorAll('.holds-one'), function (one) {
    one.classList.remove('holds-one', 'has-aside');
  });
  Array.prototype.forEach.call(document.querySelectorAll('[data-hold]'), function (card) {
    var panel = card.closest ? card.closest('.panel') : null;
    var alone = true, aside = false;
    if (panel) {
      var cards = panel.querySelectorAll('.card.full');
      var others = Array.prototype.filter.call(cards, function (one) {
        return one !== card && !card.contains(one) && !isTuckedAway(one)
          && !(one.classList.contains('admin-only') && !window.ADMIN)
          && !(one.classList.contains('fulladmin-only') && !window.ADMIN);
      });
      aside = others.some(function (one) { return one.classList.contains('aside'); });
      alone = others.every(function (one) { return one.classList.contains('aside'); });
    }
    card.classList.toggle('held', alone);
    if (!alone || isTuckedAway(card)) return;
    for (var up = card.parentNode; up && up !== panel; up = up.parentNode) {
      if (up.classList) up.classList.add('holds-one');
    }
    if (panel) { panel.classList.add('holds-one'); panel.classList.toggle('has-aside', aside); }
    fitTheNotes(card);
  });
}
/** A paragraph of explanation cut to two lines, the rest one press away. */
function fitTheNotes(card) {
  Array.prototype.forEach.call(card.children, function (note) {
    if (!note.classList || !note.classList.contains('note')) return;
    if (!note.dataset.cuts) {
      note.dataset.cuts = '1';
      note.onclick = function () {
        note.classList.toggle('open');
        note.classList.toggle('cut', !note.classList.contains('open')
                              && note.scrollHeight > note.clientHeight + 2);
      };
    }
    if (!note.classList.contains('open')) note.classList.toggle('cut', note.scrollHeight > note.clientHeight + 2);
  });
}
function isTuckedAway(node) {
  for (var up = node; up && up.nodeType === 1; up = up.parentNode) {
    if (up.hidden) return true;
  }
  return false;
}
window.addEventListener('resize', function () {
  clearTimeout(window._heldSoon);
  window._heldSoon = setTimeout(function () { if (typeof holdTheTallOnes === 'function') holdTheTallOnes(); }, 120);
});

/* ==========================================================================
   Offering as one types (1.0.19, isemon's qSuggest)
   ==========================================================================
   Under a search box: the fields of the list as `field:`, and once a field
   is typed, what it holds, busiest first. Under a box for a person: people
   from the directory of the realm, and the realms after an @. ↑ ↓ choose,
   Tab or Enter take, Esc closes. What the box does when somebody types, it
   does when something is taken. */
function suggestBox(input) {
  var wrap = el('div', 'qs-wrap');
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);
  if (input.style.flex) { wrap.style.flex = input.style.flex; input.style.flex = ''; }
  if (input.style.minWidth) { wrap.style.minWidth = input.style.minWidth; input.style.minWidth = ''; }
  /* The list floats over the page, not inside the box's own card: in a
     popup that scrolls, a list inside it was cut to a sliver with
     scrollbars of its own (1.0.20). It is placed under the box each time
     it opens, and follows it while anything scrolls. */
  var drop = el('div', 't-suggest qs-drop qs-float');
  drop.hidden = true;
  drop._input = input;
  document.body.appendChild(drop);
  var said = el('div', 'qs-said');
  said.hidden = true;
  wrap.appendChild(said);
  input.setAttribute('autocomplete', 'off');
  input.setAttribute('spellcheck', 'false');
  var place = function () {
    if (drop.hidden) return;
    var r = input.getBoundingClientRect();
    var below = window.innerHeight - r.bottom - 12, above = r.top - 12;
    var up = below < 220 && above > below;
    drop.style.left = Math.max(8, Math.min(r.left, window.innerWidth - Math.max(r.width, 320) - 8)) + 'px';
    drop.style.minWidth = r.width + 'px';
    drop.style.maxHeight = Math.max(160, Math.min(440, up ? above : below)) + 'px';
    /* 'auto', never '' (1.0.35): emptied, the stylesheet's own top of 100%
       came back, and a list that had to open upwards - from a box low in a
       popup - was pushed below the screen. */
    if (up) { drop.style.top = 'auto'; drop.style.bottom = (window.innerHeight - r.top + 4) + 'px'; }
    else { drop.style.bottom = 'auto'; drop.style.top = (r.bottom + 4) + 'px'; }
  };
  /* Taken off again once the box is gone from the page (1.0.57): every
     token window added two that stayed for good, holding the window. */
  var onMove = function () {
    if (!input.isConnected) {
      window.removeEventListener('scroll', onMove, true);
      window.removeEventListener('resize', onMove);
      return;
    }
    place();
  };
  window.addEventListener('scroll', onMove, true);
  window.addEventListener('resize', onMove);
  return {wrap: wrap, drop: drop, said: said, place: place};
}
function suggestEngine(input, box, offer, foot) {
  var st = {items: [], at: -1, moved: false, asked: 0, hold: false, typed: false,
            /* a box that comes already filled in is as good as picked */
            taken: input.value ? input.value : null};
  function close() {
    box.drop.hidden = true;
    box.wrap.classList.remove('qs-open');
    st.items = []; st.at = -1; st.moved = false;
  }
  function mark(n) {
    st.at = n;
    Array.prototype.forEach.call(box.drop.querySelectorAll('.t-sug'), function (r, i) {
      r.classList.toggle('on', i === n);
      if (i === n && r.scrollIntoView) r.scrollIntoView({block: 'nearest'});
    });
  }
  function draw(title, items, about) {
    clear(box.drop);
    if (document.activeElement !== input) { box.drop.hidden = true; st.items = []; return; }
    st.items = items; st.at = items.length ? 0 : -1; st.moved = false;
    if (!items.length) { close(); return; }
    var head = el('div', 't-sug-head', title);
    if (about) { head.appendChild(document.createTextNode(' — ')); head.appendChild(el('span', '', about)); }
    box.drop.appendChild(head);
    items.forEach(function (it, n) {
      var row = el('div', 't-sug' + (n === 0 ? ' on' : ''));
      row.appendChild(noI18n(el('span', 't-sug-val' + (it.mono === false ? '' : ' mono'), it.show)));
      var note = el('span', 't-sug-note', it.note || '');
      if (it.data) noI18n(note);
      if (it.ex) { note.appendChild(document.createTextNode(' ')); note.appendChild(noI18n(el('span', 'mono qs-ex', it.ex))); }
      row.appendChild(note);
      row.appendChild(el('span', 't-sug-n', it.n ? num(it.n) : (it.tag || '')));
      row.onmousedown = function (e) { e.preventDefault(); take(n); };
      row.onmousemove = function () { mark(n); };
      box.drop.appendChild(row);
    });
    if (typeof hideHelp === 'function') hideHelp();
    if (foot) box.drop.appendChild(foot());
    box.drop.hidden = false;
    box.place();
    box.wrap.classList.add('qs-open');
  }
  function take(n) {
    var it = st.items[n];
    if (!it) return;
    var text = input.value;
    var before = text.slice(0, it.from), after = text.slice(it.to);
    var put = it.put, at = before.length + put.length;
    if (it.done && it.space !== false && !/^\s/.test(after)) { put += ' '; at += 1; }
    input.value = before + put + after.replace(/^"/, '');
    input.focus();
    try { input.setSelectionRange(at, at); } catch (e) { /* not a text box */ }
    close();
    /* Something whole was picked: nothing is offered again until the box
       is typed in or emptied - not when it is clicked or comes back into
       focus (1.0.22). */
    st.taken = it.done ? input.value : null;
    input.dispatchEvent(new Event('input', {bubbles: true}));
    if (it.picked) it.picked();
    if (!it.done) ask();
  }
  function ask() {
    if (st.hold || document.activeElement !== input) return;
    if (st.taken !== null && st.taken !== undefined && input.value === st.taken) return;
    var mine = ++st.asked;
    Promise.resolve(offer(st)).then(function (got) {
      if (mine !== st.asked) return;
      if (!got) { close(); return; }
      draw(got.title, got.items, got.about);
    }).catch(function () { close(); });
  }
  var soon = debounce(ask, 140);
  input.addEventListener('input', function () {
    if (st.taken !== null && st.taken !== undefined && input.value !== st.taken) st.taken = null;
    st.hold = false; soon();
  });
  input.addEventListener('focus', function () { st.hold = false; soon(); });
  input.addEventListener('click', function () { st.hold = false; soon(); });
  input.addEventListener('blur', function () { setTimeout(close, 150); });
  input.addEventListener('keydown', function (e) {
    var open = !box.drop.hidden && st.items.length;
    if (!open) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); st.moved = true; mark(Math.min(st.items.length - 1, st.at + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); st.moved = true; mark(Math.max(0, st.at - 1)); }
    else if (e.key === 'Tab' && (st.moved || st.typed)) { e.preventDefault(); take(st.at < 0 ? 0 : st.at); }
    else if (e.key === 'Enter' && st.moved) { e.preventDefault(); e.stopImmediatePropagation(); take(st.at); }
    else if (e.key === 'Enter') { st.hold = true; close(); }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
  }, true);
  return {close: close, ask: ask};
}

/** Where the caret is in `field:value` text: the term it is in, and the
    field and the value typed so far where it is one. */
function qCaret(input, known) {
  var text = input.value, at = input.selectionStart || 0, start = 0, inQuote = false;
  for (var i = 0; i < at; i += 1) {
    var c = text[i];
    if (c === '"') inQuote = !inQuote;
    else if (!inQuote && (c === ' ' || c === '(' || c === ')')) start = i + 1;
  }
  var end = at;
  while (end < text.length && !/[\s()]/.test(text[end])) end += 1;
  var term = text.slice(start, at);
  var lead = /^[-!]/.test(term) ? term[0] : '';
  var body = term.slice(lead.length);
  var out = {start: start, end: end, lead: lead, body: body};
  var m = body.match(/^([A-Za-z_][\w.-]*)(!=|>=|<=|[:~=<>])(.*)$/);
  if (m && known[m[1].toLowerCase()]) {
    out.field = m[1].toLowerCase();
    out.op = m[2];
    var v = m[3];
    out.valueAt = start + lead.length + m[1].length + m[2].length;
    if (v.charAt(0) === '"') { out.quoted = true; v = v.slice(1); out.valueAt += 1; }
    var comma = out.quoted ? -1 : v.lastIndexOf(',');
    if (comma >= 0) { out.valueAt += comma + 1; v = v.slice(comma + 1); }
    out.typed = v.replace(/"$/, '');
  }
  return out;
}

var Q_FIELDS = {};
/** A list's search box, as isemon's: `field:value` offered and narrowed as
    one types. `list` is the daemon's name for the list; `extra()` gives what
    else narrows the values (the window of hours). Returns {said(words)}. */
function qSuggest(input, list, extra) {
  if (!input || input._qs) return input && input._qs;
  var box = suggestBox(input);
  var me = {said: function (words) {
    box.said.textContent = words || '';
    box.said.hidden = !words;
    input.classList.toggle('qs-bad', !!words);
  }};
  input._qs = me;
  var fields = function () {
    if (Q_FIELDS[list]) return Promise.resolve(Q_FIELDS[list]);
    return api('suggest&list=' + list).then(function (d) { Q_FIELDS[list] = d.fields || []; return Q_FIELDS[list]; });
  };
  var foot = function () {
    var f = el('div', 't-sug-foot');
    [['field:a,b', 'any of them'], ['-field:value', 'not'], ['*', 'anything'], ['field~part', 'contains'],
     ['(a OR b)', 'either']].forEach(function (p) {
      f.appendChild(noI18n(el('code', 'qs-syn', p[0])));
      f.appendChild(el('span', 'qs-syn-says', p[1]));
    });
    f.appendChild(el('span', '', '↑ ↓ and Tab or Enter take one · Esc closes'));
    return f;
  };
  suggestEngine(input, box, function (st) {
    return fields().then(function (all) {
      var known = {};
      all.forEach(function (f) { known[f[0]] = f; });
      var where = qCaret(input, known);
      if (where.field) {
        st.typed = true;
        if (/^[<>]/.test(where.op) || /^[<>]/.test(where.typed || '')) return null;
        var more = extra ? extra() : '';
        return api('suggest&list=' + list + '&field=' + encodeURIComponent(where.field)
                   + '&typed=' + encodeURIComponent(where.typed || '') + (more ? '&' + more : '')).then(function (d) {
          var items = (d.values || []).map(function (v) {
            var quoted = /[\s(),"]/.test(v.val) || where.quoted;
            return {show: v.val, n: v.n, data: true,
                    put: quoted ? '"' + String(v.val).replace(/"/g, '') + '"' : v.val,
                    from: where.valueAt - (where.quoted ? 1 : 0), to: where.end, done: true};
          });
          return {title: 'What ' + where.field + ' holds, most first', items: items.slice(0, 30),
                  about: (known[where.field] || [])[1]};
        });
      }
      var typed = where.body.toLowerCase();
      st.typed = !!typed;
      if (/["]/.test(typed) || /[^a-z_-]/.test(typed)) return null;
      var items = [];
      var one = function (f) {
        items.push({show: f[0] + ':', note: f[1], ex: f[2] || '', put: where.lead + f[0] + ':',
                    from: where.start, to: where.end, done: false});
      };
      all.forEach(function (f) { if (!typed || f[0].indexOf(typed) === 0) one(f); });
      all.forEach(function (f) { if (typed && f[0].indexOf(typed) > 0) one(f); });
      return {title: typed ? 'Fields' : 'Fields - or type a word to find it anywhere', items: items};
    });
  }, foot);
  return me;
}

/** A box for a person's name: the realms after an @, and while a name is
    typed the people in the directory of its realm - with whether each has
    a token already. `opts.realm()` names the realm when the box itself
    does not; `opts.picked(person)` hears what was taken. */
function personSuggest(input, opts) {
  if (!input || input._ps) return;
  opts = opts || {};
  var box = suggestBox(input);
  input._ps = true;
  var realmsList = function () {
    if (window.REALMS_SEEN) return Promise.resolve(window.REALMS_SEEN);
    return api('realms').then(function (d) { window.REALMS_SEEN = (d.realms || []).filter(function (r) { return r.enabled; }); return window.REALMS_SEEN; });
  };
  suggestEngine(input, box, function (st) {
    var text = input.value.trim().toLowerCase();
    st.typed = !!text;
    return realmsList().then(function (realms) {
      var at = text.indexOf('@');
      if (at >= 0 && !text.slice(at + 1).match(/^[a-z0-9.-]*\.[a-z]{2,}$/)) {
        /* After the @: the realms. */
        var part = text.slice(at + 1);
        var items = realms.filter(function (r) { return r.suffix && r.suffix !== '*' && r.suffix.toLowerCase().indexOf(part) === 0; })
          .map(function (r) {
            return {show: '@' + r.suffix, note: r.name + (r.directory ? ' · ' + r.directory : ''), data: true,
                    put: text.slice(0, at) + '@' + r.suffix, from: 0, to: input.value.length, done: false, space: false};
          });
        return items.length ? {title: 'Realms', items: items} : null;
      }
      var bare = at >= 0 ? text.slice(0, at) : text;
      if (bare.length < 2) {
        if (!text) {
          var hint = realms.filter(function (r) { return r.suffix && r.suffix !== '*'; }).map(function (r) {
            return {show: '@' + r.suffix, note: r.name, data: true, put: '@' + r.suffix, from: 0,
                    to: input.value.length, done: false, space: false};
          });
          return hint.length ? {title: 'Realms - or type part of a name', items: hint} : null;
        }
        return null;
      }
      var realm = at >= 0 ? text.slice(at + 1) : (opts.realm ? opts.realm() : '');
      /* The realm by its name, which is what the daemon asks by - whether it
         came as the part after an @ or as a realm's name (1.0.34): by the
         part after the @, Move to found nobody. A realm unknown here asks
         every directory, as no realm at all does. */
      var named = realm ? realms.filter(function (r) {
        return r.directory && (String(r.suffix || '').toLowerCase() === realm || String(r.name).toLowerCase() === realm);
      }) : [];
      var asks = opts.directory ? ['']
        : (named.length ? named.map(function (r) { return r.name; })
           : realms.filter(function (r) { return r.directory; }).map(function (r) { return r.name; }));
      return Promise.all(asks.slice(0, 4).map(function (rn) {
        return api('directories', {action: 'people', like: bare, realm: rn, limit: 12,
                                   directory: opts.directory || ''})
          .catch(function () { return {people: []}; });
      })).then(function (all) {
        var items = [], seen = {};
        all.forEach(function (d) {
          (d.people || []).forEach(function (p) {
            if (!p.name || seen[p.name]) return;
            seen[p.name] = 1;
            items.push({show: p.name, note: (p.display || '') + (p.mail ? ' · ' + p.mail : '')
                          + (p.disabled ? ' · switched off in the directory' : ''), data: true,
                        tag: p.token ? (p.token === 'active' ? 'has a token' : 'token: ' + p.token) : '',
                        put: p.name, from: 0, to: input.value.length, done: true, space: false,
                        picked: opts.picked ? function () { opts.picked(p); } : null});
          });
        });
        return items.length ? {title: 'In the directory', items: items.slice(0, 20)} : null;
      });
    });
  }, null);
}

/* ---- The time picker (1.0.53) ------------------------------------------------------
   Every list with a time window gets the same one, as in isemon: quick
   ranges, "last N minutes/hours/days/weeks", or from - to by the calendar,
   and ‹ › that move the window back and forth by its own length. It stands
   in for the <select> it replaces, under the same id: `.value` is still the
   hours (or seconds) back to its start, `.onchange` still fires, and
   `._range()` says {from, to} in seconds since 1970 (to 0 = now). */
var TP_QUICK = [
  ['m15', 'last 15 minutes', 900], ['h1', 'last hour', 3600], ['h6', 'last 6 hours', 21600],
  ['h24', 'last 24 hours', 86400], ['d3', 'last 3 days', 259200], ['d7', 'last week', 604800],
  ['d30', 'last month', 2592000], ['d90', 'last 3 months', 7776000], ['y1', 'last year', 31536000]];
var TP_CAL = [['today', 'today'], ['yesterday', 'yesterday'], ['week', 'this week'],
  ['lastweek', 'last week (Mon-Sun)'], ['month', 'this month'], ['lastmonth', 'last month (calendar)']];
function tpCalendar(k) {
  /* By the calendar, not by 86 400 s (1.0.57): a day around a change of
     summer time is 23 or 25 hours. */
  var d = new Date(); d.setHours(0, 0, 0, 0);
  var at = function (y, m, dd) { return new Date(y, m, dd).getTime() / 1000; };
  var y = d.getFullYear(), m = d.getMonth(), dd = d.getDate();
  var mon = dd - ((d.getDay() + 6) % 7);
  return {today: [at(y, m, dd), 0], yesterday: [at(y, m, dd - 1), at(y, m, dd)],
          week: [at(y, m, mon), 0], lastweek: [at(y, m, mon - 7), at(y, m, mon)],
          month: [at(y, m, 1), 0], lastmonth: [at(y, m - 1, 1), at(y, m, 1)]}[k];
}
/* The calendar window `n` steps before or after (1.0.57). */
function tpCalShift(c, n) {
  var d = new Date(); d.setHours(0, 0, 0, 0);
  var y = d.getFullYear(), m = d.getMonth(), dd = d.getDate();
  var at = function (yy, mm, x) { return Math.round(new Date(yy, mm, x).getTime() / 1000); };
  var mon = dd - ((d.getDay() + 6) % 7);
  if (c === 'today' || c === 'yesterday') {
    var base = dd + (c === 'yesterday' ? -1 : 0) + n;
    return {k: 'abs', from: at(y, m, base), to: at(y, m, base + 1)};
  }
  if (c === 'week' || c === 'lastweek') {
    var w = mon + (c === 'lastweek' ? -7 : 0) + 7 * n;
    return {k: 'abs', from: at(y, m, w), to: at(y, m, w + 7)};
  }
  var mm = m + (c === 'lastmonth' ? -1 : 0) + n;
  return {k: 'abs', from: at(y, mm, 1), to: at(y, mm + 1, 1)};
}
function tpLocal(ts) {
  var d = new Date(ts * 1000), p = function (n) { return ('0' + n).slice(-2); };
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
}
function tpWords(st) {
  if (st.k === 'all') return 'all time';
  if (st.k === 'rel') {
    var q = TP_QUICK.filter(function (x) { return x[2] === st.s; })[0];
    if (q) return q[1];
    var u = [[604800, 'weeks'], [86400, 'days'], [3600, 'hours'], [60, 'minutes']].filter(function (x) { return st.s % x[0] === 0; })[0] || [60, 'minutes'];
    return 'last ' + Math.max(1, Math.round(st.s / u[0])) + ' ' + u[1];
  }
  if (st.k === 'cal') return (TP_CAL.filter(function (x) { return x[0] === st.c; })[0] || ['', st.c])[1];
  var f = stamp(st.from).slice(0, 16), t = st.to ? stamp(st.to).slice(0, 16) : 'now';
  return f + ' → ' + t;
}
function tpRange(st) {
  var now = Date.now() / 1000;
  if (st.k === 'all') return {from: 0, to: 0};
  if (st.k === 'rel') return {from: now - st.s, to: 0};
  if (st.k === 'cal') { var c = tpCalendar(st.c); return {from: c[0], to: c[1]}; }
  return {from: st.from, to: st.to || 0};
}
function timePicker(id, opts) {
  opts = opts || {};
  var old = $(id);
  var keep = 'upsmon.tp.' + id;
  var st = null;
  try { st = JSON.parse(localStorage.getItem(keep) || 'null'); } catch (e) { st = null; }
  if (!st || !st.k || (st.k === 'all' && !opts.all)) st = opts.start || {k: 'rel', s: 86400};
  var wrap = el('div', 'tp');
  var prev = el('button', 'tp-step', '‹'); prev.type = 'button'; prev.title = 'The window before this one';
  var main = el('button', 'tp-main'); main.type = 'button';
  var next = el('button', 'tp-step', '›'); next.type = 'button'; next.title = 'The window after this one';
  wrap.appendChild(prev); wrap.appendChild(main); wrap.appendChild(next);
  if (old && old.title) wrap.title = old.title;
  var pop = null;
  function fire() {
    try { localStorage.setItem(keep, JSON.stringify(st)); } catch (e) { /* not kept */ }
    paint();
    if (typeof wrap.onchange === 'function' && !wrap._quiet) wrap.onchange();
  }
  function paint() {
    clear(main);
    main.appendChild(setButtonIcon(el('span', 'tp-ico'), 'clock', ''));
    main.appendChild(el('span', 'tp-words', tpWords(st)));
    var r = tpRange(st);
    next.disabled = !r.to;
    prev.disabled = st.k === 'all';
  }
  function shift(dir) {
    var r = tpRange(st), now = Date.now() / 1000;
    if (st.k === 'cal' || (st.k === 'abs' && st.c)) {
      /* By whole days, weeks, months (1.0.57) - and still by them after the
         first step (1.0.61): the window remembers what it was stepped from,
         where a fixed length of seconds drifted off the 1st of the month. */
      var c = st.c, n = (st.k === 'cal' ? 0 : (st.n || 0)) + dir;
      if (n === 0 && (c === 'today' || c === 'week' || c === 'month')) {
        st = {k: 'cal', c: c};
      } else {
        var nx = tpCalShift(c, n);
        st = {k: 'abs', from: nx.from, to: nx.to >= now ? 0 : nx.to, c: c, n: n};
      }
      fire();
      return;
    }
    var to = r.to || now, len = Math.max(60, Math.round((to - r.from) / 60) * 60);
    var nf = Math.round(r.from + dir * len), nt = Math.round(to + dir * len);
    if (nt >= now - 30) {
      /* Back to "up to now" in the shape it had: a fixed start stays fixed. */
      st = st.k === 'rel' ? {k: 'rel', s: len} : {k: 'abs', from: nf, to: 0};
    } else st = {k: 'abs', from: nf, to: nt};
    fire();
  }
  prev.onclick = function () { shift(-1); };
  next.onclick = function () { shift(1); };
  function close() { if (pop) { pop.remove(); pop = null; document.removeEventListener('mousedown', outside, true); } }
  wrap._close = close;
  function outside(e) { if (pop && !pop.contains(e.target) && !wrap.contains(e.target)) close(); }
  main.onclick = function () {
    if (pop) { close(); return; }
    pop = el('div', 'tp-pop');
    var cols = el('div', 'tp-cols');
    var quick = el('div', 'tp-col');
    quick.appendChild(el('div', 'tp-h', 'Quick'));
    var grid = el('div', 'tp-quick');
    TP_QUICK.concat(opts.all ? [['all', 'all time', 0]] : []).forEach(function (q) {
      var b = el('button', 'tp-q', q[1]); b.type = 'button';
      if ((st.k === 'rel' && st.s === q[2]) || (q[0] === 'all' && st.k === 'all')) b.classList.add('on');
      b.onclick = function () { st = q[0] === 'all' ? {k: 'all'} : {k: 'rel', s: q[2]}; close(); fire(); };
      grid.appendChild(b);
    });
    quick.appendChild(grid);
    quick.appendChild(el('div', 'tp-h', 'By the calendar'));
    var cal = el('div', 'tp-quick');
    TP_CAL.forEach(function (c) {
      var b = el('button', 'tp-q', c[1]); b.type = 'button';
      if (st.k === 'cal' && st.c === c[0]) b.classList.add('on');
      b.onclick = function () { st = {k: 'cal', c: c[0]}; close(); fire(); };
      cal.appendChild(b);
    });
    quick.appendChild(cal);
    cols.appendChild(quick);
    var own = el('div', 'tp-col');
    own.appendChild(el('div', 'tp-h', 'The last…'));
    var rel = el('div', 'tp-row');
    var n = textBox('', '', 'tp-n'); n.inputMode = 'numeric';
    var unit = selectBox([['60', 'minutes'], ['3600', 'hours'], ['86400', 'days'], ['604800', 'weeks']], '3600');
    if (st.k === 'rel') {
      var u = [604800, 86400, 3600, 60].filter(function (x) { return st.s % x === 0; })[0] || 60;
      n.value = st.s / u; unit.value = String(u);
    } else n.value = '12';
    var go1 = cmdButton('Show', 'check', 'small primary');
    go1.onclick = function () {
      var v = Math.max(1, Math.round(Number(n.value) || 0));
      st = {k: 'rel', s: v * Number(unit.value)}; close(); fire();
    };
    n.onkeydown = function (e) { if (e.key === 'Enter') go1.onclick(); };
    rel.appendChild(n); rel.appendChild(unit); rel.appendChild(go1);
    own.appendChild(rel);
    own.appendChild(el('div', 'tp-h', 'From - to'));
    var r0 = tpRange(st), now = Date.now() / 1000;
    var f = el('input', 'tp-dt'); f.type = 'datetime-local'; f.value = tpLocal(r0.from || now - 86400);
    var t = el('input', 'tp-dt'); t.type = 'datetime-local'; t.value = r0.to ? tpLocal(r0.to) : '';
    var fr = el('label', 'tp-lab'); fr.appendChild(el('span', '', 'From')); fr.appendChild(f);
    var tr = el('label', 'tp-lab'); tr.appendChild(el('span', '', 'To')); tr.appendChild(t);
    own.appendChild(fr); own.appendChild(tr);
    own.appendChild(el('div', 'tp-s', 'An empty end means up to now.'));
    var go2 = cmdButton('Show this window', 'check', 'small primary');
    go2.onclick = function () {
      var a = f.value ? new Date(f.value).getTime() / 1000 : 0;
      var b = t.value ? new Date(t.value).getTime() / 1000 : 0;
      if (!a) { toast('give the start', 'bad'); return; }
      if (b && b <= a) { toast('the end is before the start', 'bad'); return; }
      st = b ? {k: 'abs', from: Math.round(a), to: Math.round(b)} : {k: 'rel', s: Math.max(60, Math.round(Date.now() / 1000 - a))};
      if (!b) st = {k: 'abs', from: Math.round(a), to: 0};
      close(); fire();
    };
    own.appendChild(go2);
    cols.appendChild(own);
    pop.appendChild(cols);
    document.body.appendChild(pop);
    var box = wrap.getBoundingClientRect();
    var w = Math.min(640, window.innerWidth - 16);
    pop.style.width = w + 'px';
    pop.style.left = Math.max(8, Math.min(box.right - w, window.innerWidth - w - 8)) + 'px';
    /* Kept inside the window (1.0.103): on a phone it was 700 px tall from
       halfway down, its lower half out of reach. Up over the box when there
       is more room above; scrolled inside itself when neither is enough. */
    var below = window.innerHeight - box.bottom - 14, above = box.top - 14;
    var h = pop.offsetHeight;
    if (h > below && above > below) {
      pop.style.maxHeight = above + 'px';
      pop.style.top = Math.max(8, box.top - 6 - Math.min(h, above)) + 'px';
    } else {
      pop.style.maxHeight = Math.max(160, below) + 'px';
      pop.style.top = (box.bottom + 6) + 'px';
    }
    pop.style.overflow = 'auto';
    setTimeout(function () { document.addEventListener('mousedown', outside, true); }, 0);
  };
  wrap._range = function () { var r = tpRange(st); return {from: Math.floor(r.from), to: Math.ceil(r.to), words: tpWords(st)}; };
  wrap._set = function (s) { st = s; fire(); };
  Object.defineProperty(wrap, 'value', {get: function () {
    var r = tpRange(st);
    if (st.k === 'all') return '0';
    var back = Date.now() / 1000 - r.from;
    return String(opts.unit === 's' ? Math.ceil(back) : Math.max(1, Math.ceil(back / 3600)));
  }});
  wrap.id = id;
  if (old) { wrap.className += ' ' + (old.className || ''); old.parentNode.replaceChild(wrap, old); }
  paint();
  return wrap;
}
/* The query part for the API: `from` and `to`, and `hours` back to the start
   for the endpoints that still want it. */
function tpQuery(id, fromName, toName) {
  var p = $(id);
  if (!p || !p._range) return '';
  var r = p._range();
  return (r.from ? '&' + (fromName || 'from') + '=' + r.from : '') + (r.to ? '&' + (toName || 'to') + '=' + r.to : '');
}

/* ---- drawn again by itself, under somebody working (1.0.123) -------------
   A part of a page that refreshes itself is drawn into a box of its own first
   and put in by `liveFill`. When nobody is working in it, it simply replaces
   what was there. When somebody is - a list open, a box being typed in, a
   switch just turned, the mouse held down - the card they are in stays as it
   is, the very same elements, never taken out of the page (a list taken out
   closes), and everything around it is drawn new. A card whose shape has
   changed under them waits, and is drawn the moment they leave it. What was
   changed in a card that is not being worked in any more but was not saved
   yet goes over into the new card. */
var LIVE_PRESS = null;
document.addEventListener('pointerdown', function (e) { LIVE_PRESS = e.target; }, true);
document.addEventListener('pointerup', function () { setTimeout(function () { LIVE_PRESS = null; liveOwed(); }, 0); }, true);
document.addEventListener('pointercancel', function () { LIVE_PRESS = null; }, true);
document.addEventListener('focusout', function () { setTimeout(liveOwed, 0); }, true);
document.addEventListener('keydown', function (e) { if (e.key === 'Escape' || e.key === 'Enter' || e.key === 'Tab') setTimeout(liveOwed, 0); }, true);

function liveControl(node) {
  if (!node || node === document.body || !node.tagName) return false;
  if (node.isContentEditable) return true;
  if (node.tagName === 'SELECT' || node.tagName === 'TEXTAREA') return true;
  if (node.tagName === 'INPUT') return !/^(button|submit|reset|image)$/i.test(node.type || '');
  return false;
}
/** The card in `host` somebody is working in now, or null. */
function liveWorkedIn(host) {
  if (!host) return null;
  var on = document.activeElement;
  var at = null;
  if (liveControl(on) && host.contains(on)) at = on;
  else if (LIVE_PRESS && LIVE_PRESS.isConnected && host.contains(LIVE_PRESS)) at = LIVE_PRESS;
  else if (Date.now() - SELECTED_AT < 15000 && liveSelectedIn(host)) at = liveSelectedIn(host);
  else if (typeof SETHELP !== 'undefined' && SETHELP && SETHELP.style.display === 'block' && SETHELP._over
           && SETHELP._over.isConnected && host.contains(SETHELP._over)) at = SETHELP._over;
  if (!at) return null;
  var unit = at.closest ? at.closest('.card, .modal-box, tr, .set-item') : null;
  if (unit && (unit === host || !host.contains(unit))) unit = null;
  if (!unit) {
    unit = at;
    while (unit.parentNode && unit.parentNode !== host) unit = unit.parentNode;
  }
  return unit;
}
function liveSelectedIn(host) {
  try {
    var sel = window.getSelection ? window.getSelection() : null;
    if (sel && !sel.isCollapsed && sel.anchorNode && host.contains(sel.anchorNode)) {
      return sel.anchorNode.nodeType === 1 ? sel.anchorNode : sel.anchorNode.parentNode;
    }
  } catch (e) { /* nothing selected */ }
  return null;
}
function livePath(host, node) {
  var path = [];
  while (node && node !== host) {
    var p = node.parentNode;
    if (!p) return null;
    path.unshift(Array.prototype.indexOf.call(p.childNodes, node));
    node = p;
  }
  return node === host ? path : null;
}
function liveAt(root, path) {
  var n = root;
  for (var i = 0; i < path.length; i++) {
    n = n && n.childNodes[path[i]];
    if (!n) return null;
  }
  return n;
}
function liveControls(root) {
  return root && root.querySelectorAll ? Array.prototype.slice.call(root.querySelectorAll('input, select, textarea')) : [];
}
function liveChanged(c) {
  if (c.tagName === 'SELECT') {
    return Array.prototype.some.call(c.options, function (o) { return o.selected !== o.defaultSelected; });
  }
  if (c.type === 'checkbox' || c.type === 'radio') return c.checked !== c.defaultChecked;
  if (c.type === 'file') return false;
  return c.value !== c.defaultValue;
}
/* What was changed and not saved, over into the new elements at the same
   place - by the controls' order, and only when the two have the same ones. */
function liveCarry(oldRoot, newRoot) {
  /* A fold opened stays open, one shut stays shut. */
  if (oldRoot && oldRoot.querySelectorAll && newRoot && newRoot.querySelectorAll) {
    var da = oldRoot.tagName === 'DETAILS' ? [oldRoot] : Array.prototype.slice.call(oldRoot.querySelectorAll('details'));
    var db = newRoot.tagName === 'DETAILS' ? [newRoot] : Array.prototype.slice.call(newRoot.querySelectorAll('details'));
    if (da.length && da.length === db.length) da.forEach(function (x, i) { if (db[i].open !== x.open) db[i].open = x.open; });
  }
  var a = liveControls(oldRoot), b = liveControls(newRoot);
  if (!a.length || a.length !== b.length) return;
  for (var i = 0; i < a.length; i++) {
    if (a[i].tagName !== b[i].tagName || (a[i].type || '') !== (b[i].type || '')) return;
  }
  a.forEach(function (c, i) {
    if (!liveChanged(c)) return;
    var n = b[i];
    if (c.type === 'checkbox' || c.type === 'radio') {
      if (n.checked === c.checked) return;
      n.checked = c.checked;
    } else {
      if (n.value === c.value) return;
      n.value = c.value;
      if (n.value !== c.value) return;          // a choice the new list does not have
    }
    /* No events: a change can be an action (a switch that saves at once),
       and a form that keeps a draft has drawn the same value anyway. */
  });
}
/* `fresh`'s children into `host`, keeping `keep` (found at `path`) as it is. */
function liveMerge(host, fresh, path, depth) {
  var k = path[depth];
  var kept = host.childNodes[k];
  var mine = fresh.childNodes[k];
  var before = Array.prototype.slice.call(fresh.childNodes, 0, k);
  var after = Array.prototype.slice.call(fresh.childNodes, k + 1);
  Array.prototype.slice.call(host.childNodes).forEach(function (c, i) {
    if (c === kept) return;
    var twin = i < k ? before[i] : after[i - k - 1];
    if (twin) liveCarry(c, twin);
    host.removeChild(c);
  });
  before.forEach(function (c) { host.insertBefore(c, kept); });
  after.forEach(function (c) { host.appendChild(c); });
  if (depth + 1 < path.length) {
    if (mine.nodeType === 1 && kept.nodeType === 1 && mine.className !== kept.className) kept.className = mine.className;
    liveMerge(kept, mine, path, depth + 1);
  }
}
var LIVE_OWED = [];
function liveOwed() {
  if (!LIVE_OWED.length) return;
  var owed = LIVE_OWED;
  LIVE_OWED = [];
  owed.forEach(function (o) {
    if (o.host.isConnected && o.host._liveGen === o.gen) liveFill(o.host, o.build, true, o.after);
  });
}
/** `build(box)` draws into an empty box; what it drew goes into `host`.
    `live`: drawn by a refresh, not by something the person did - only then
    is a card being worked in kept. `after()` runs once it is in. */
var LIVE_DRAW = false;
/** Draws whatever `fn` draws as a refresh - not something the person did. */
function liveRun(fn) {
  var was = LIVE_DRAW;
  LIVE_DRAW = true;
  try { return fn(); } finally { LIVE_DRAW = was; }
}
function liveFill(host, build, live, after) {
  if (!host) return;
  if (live === undefined) live = LIVE_DRAW;
  host._liveGen = (host._liveGen || 0) + 1;
  var box = document.createElement(host.tagName === 'TBODY' ? 'tbody' : 'div');
  build(box);
  var keep = live ? liveWorkedIn(host) : null;
  if (!keep) {
    if (live) {
      var old = Array.prototype.slice.call(host.childNodes);
      var neu = Array.prototype.slice.call(box.childNodes);
      if (old.length === neu.length) old.forEach(function (c, i) { liveCarry(c, neu[i]); });
    }
    clear(host);
    while (box.firstChild) host.appendChild(box.firstChild);
  } else {
    var path = livePath(host, keep);
    var twin = path && liveAt(box, path);
    if (!twin || twin.nodeType !== 1 || twin.tagName !== keep.tagName || (twin.id || '') !== (keep.id || '')) {
      /* Its shape changed: drawn once they leave it. */
      LIVE_OWED = LIVE_OWED.filter(function (o) { return o.host !== host; });
      LIVE_OWED.push({host: host, build: build, gen: host._liveGen, after: after});
      return;
    }
    liveMerge(host, box, path, 0);
  }
  if (after) after();
}

/* ---- the second step of signing in to the administration (1.0.125) -------
   On the sign-in page, after a right password: the code of the way the
   account set up - or, the first time, choosing a way and setting it up. */
function mfaStep() {
  var box = $('mfa-box');
  if (!box) return;
  box.hidden = false;
  /* Room for it (1.0.126): the picture and the welcome line go while the
     second step is asked. */
  document.body.classList.add('mfa-on');
  clear(box);
  box.appendChild(el('p', 'muted', 'Checking…'));
  api('mfa').then(function (d) { mfaDraw(box, d); }).catch(function (e) {
    clear(box);
    box.appendChild(el('p', 'said bad', String(e.message || e)));
    box.appendChild(mfaOut());
  });
}
var MFA_WORDS = {app: 'App', mail: 'E-mail', sms: 'SMS'};
function mfaOut() {
  var b = cmdButton('Sign out', 'out', 'ghost');
  b.type = 'button';
  b.onclick = function () { api('logout', {}).then(function () { location.reload(); }, function () { location.reload(); }); };
  return b;
}
function mfaCodeForm(box, d, action, words, after) {
  var f = el('form', 'mfa-form');
  var row = el('div', 'mfa-row');
  var code = textBox('', '123456', 'mono mfa-code');
  code.inputMode = 'numeric';
  code.autocomplete = 'one-time-code';
  code.maxLength = 10;
  row.appendChild(code);
  var go = cmdButton(words, 'check', 'primary');
  go.type = 'submit';
  row.appendChild(go);
  f.appendChild(row);
  var said = el('div', 'said');
  f.appendChild(said);
  f.addEventListener('submit', function (e) {
    e.preventDefault();
    if (!code.value.trim()) { code.focus(); return; }
    go.disabled = true;
    said.className = 'said';
    said.textContent = '';
    api('mfa', {action: action, code: code.value}).then(function (r) {
      said.className = 'said good';
      said.textContent = r.message || 'Welcome back.';
      setTimeout(function () { location.reload(); }, 400);
    }).catch(function (e) {
      go.disabled = false;
      said.className = 'said bad';
      said.textContent = String(e.message || e);
      code.value = '';
      code.focus();
    });
  });
  box.appendChild(f);
  setTimeout(function () { code.focus(); }, 30);
  if (after) after(f);
  return f;
}
function mfaDraw(box, d) {
  clear(box);
  var head = el('div', 'mfa-head');
  head.appendChild(el('b', '', d.stage === 'enrol' ? 'Set up the second step' : 'The second step'));
  head.appendChild(noI18n(el('span', 'muted small mono', ' ' + (d.name || ''))));
  box.appendChild(head);
  if (d.stage === 'check') {
    if (d.kind === 'app') {
      box.appendChild(el('p', 'lede', 'The code your authenticator app shows for these pages now.'));
      mfaCodeForm(box, d, 'check', 'Sign in');
    } else {
      var p = el('p', 'lede', d.kind === 'mail' ? 'A code is sent by e-mail to ' + d.dest + '.' : 'A code is sent by SMS to ' + d.dest + '.');
      box.appendChild(p);
      var send = cmdButton('Send the code', 'mail', 'primary');
      send.type = 'button';
      var sent = el('div', 'said');
      var form = null;
      send.onclick = function () {
        send.disabled = true;
        sent.className = 'said';
        sent.textContent = 'Sending…';
        api('mfa', {action: 'send'}).then(function (r) {
          sent.className = 'said good';
          sent.textContent = 'Sent to ' + r.sent_to + ' - write the code from it below.';
          setButtonIcon(send, 'mail', 'Send another');
          send.classList.remove('primary');
          setTimeout(function () { send.disabled = false; }, 30000);
          if (!form) form = mfaCodeForm(box, d, 'check', 'Sign in');
          else form.querySelector('input').focus();
        }).catch(function (e) { send.disabled = false; sent.className = 'said bad'; sent.textContent = String(e.message || e); });
      };
      box.appendChild(send);
      box.appendChild(sent);
    }
  } else {
    box.appendChild(el('p', 'lede small', 'After the password these pages ask for a code too - choose how (the account\'s own, not a VPN token).'));
    var seg = el('div', 'seg mfa-ways');
    var body = el('div', 'mfa-body');
    (d.methods || ['app']).forEach(function (k, i) {
      var b = el('button', 'mfa-way', MFA_WORDS[k] || k);
      b.type = 'button';
      b.onclick = function () {
        Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); });
        mfaWay(body, d, k);
      };
      seg.appendChild(b);
      if (i === 0) setTimeout(function () { b.click(); }, 0);
    });
    box.appendChild(seg);
    box.appendChild(body);
  }
  var foot = el('div', 'mfa-foot');
  foot.appendChild(mfaOut());
  box.appendChild(foot);
}
function mfaWay(body, d, kind) {
  clear(body);
  if (kind === 'app') {
    body.appendChild(el('p', 'small muted', 'Scan it with the app (Google or Microsoft Authenticator…) and write the six digits it shows.'));
    var pic = el('div', 'mfa-qr');
    pic.appendChild(el('span', 'muted small', 'Making it…'));
    body.appendChild(pic);
    api('mfa', {action: 'enrol_start', kind: 'app'}).then(function (r) {
      clear(pic);
      var img = el('img');
      img.src = r.qr;
      img.alt = 'QR code';
      pic.appendChild(img);
      var key = noI18n(el('div', 'mono small mfa-key', r.secret));
      key.title = 'Typed into the app instead of scanning';
      pic.appendChild(key);
      mfaCodeForm(body, d, 'enrol_confirm', 'Sign in');
    }).catch(function (e) { clear(pic); pic.appendChild(el('p', 'said bad', String(e.message || e))); });
    return;
  }
  body.appendChild(el('p', 'small muted', kind === 'mail' ? 'The address the codes go to - a code goes there now to prove it is yours.'
    : 'The phone number with its country code - a code goes there now to prove it is yours.'));
  var drow = el('div', 'mfa-row');
  var dest = textBox('', kind === 'mail' ? 'novak@example.cz' : '+420 603 123 456', 'mono');
  drow.appendChild(dest);
  var send = cmdButton('Send a code', kind === 'mail' ? 'mail' : 'phone', '');
  send.type = 'button';
  drow.appendChild(send);
  var sent = el('div', 'said');
  var form = null;
  send.onclick = function () {
    if (!dest.value.trim()) { dest.focus(); return; }
    send.disabled = true;
    sent.className = 'said';
    sent.textContent = 'Sending…';
    api('mfa', {action: 'enrol_start', kind: kind, dest: dest.value}).then(function (r) {
      sent.className = 'said good';
      sent.textContent = 'Sent to ' + r.sent_to + ' - write the code from it below.';
      setButtonIcon(send, kind === 'mail' ? 'mail' : 'phone', 'Send another');
      setTimeout(function () { send.disabled = false; }, 30000);
      if (!form) form = mfaCodeForm(body, d, 'enrol_confirm', 'Sign in');
      else form.querySelector('input').focus();
    }).catch(function (e) { send.disabled = false; sent.className = 'said bad'; sent.textContent = String(e.message || e); });
  };
  dest.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); send.click(); } });
  body.appendChild(drow);
  body.appendChild(sent);
}
