/* cols.js - the columns of every table, laid out by whoever is looking.
   Taken whole from isemon (1.10.146 - 1.10.159) for upsmon 1.0.9: the same
   switch under your name, the same grips, the same menu on the right
   button, the same layout kept with your account. */
'use strict';
/* ==========================================================================
   Columns laid out by whoever is looking
   --------------------------------------------------------------------------
   Every table with a heading can be laid out by hand: drag the edge of a
   heading to make that column wider or narrower, drag the heading itself to
   put the column somewhere else. What somebody sets is kept with their
   account (`user_cols`, saved as soon as the column is let go of) and comes
   back with the page wherever they sign in; the account popup under their
   name puts it back as it comes.

   Only while "Edit the columns" is switched on, in that same popup (from
   1.10.146). It is off whenever somebody signs in: the daemon holds the
   switch for one sign-in, in memory, so signing out, a sign-in running out
   and a restart of the service all turn it off again. Off, no heading can
   be sized or carried and nothing is saved - but the layout already kept is
   drawn just the same.

   Nothing changes for a table nobody has touched: it is laid out exactly as
   before. A table somebody has sized holds those widths whatever its rows
   say (`table-layout: fixed`), the last column taking whatever room is
   left over, so a refresh never moves it. Moving a column moves its cells
   in every row as the rows are drawn - before the browser paints them, so
   there is no frame of the old order - and the cells themselves, so what
   each one does when pressed goes with it. Ordering by a column, here or
   on the server, goes by the column and not by where it now stands.

   A table is known by where it is on the page (its own id, or the nearest
   one around it) and the words of its headings, so the same list keeps its
   layout from one visit to the next, and one with different columns - the
   Traffic tab's pages, say - keeps one of its own. A column is known by its
   heading's words, so a layout survives a column being added.
   ========================================================================== */
/** A layout as the page can use it: whatever a file or an older daemon
    sent that is not one is left out, and no width is absurd (1.0.15): one
    width of a thousand million shrank every other column to nothing. */
function colsSane(all) {
  var out = {};
  if (!all || typeof all !== 'object' || Array.isArray(all)) return out;
  Object.keys(all).forEach(function (k) {
    var one = all[k], got = {};
    if (!one || typeof one !== 'object' || Array.isArray(one)) return;
    ['o', 'h', 's', 'v'].forEach(function (f) {
      if (!Array.isArray(one[f])) return;
      var seen = {}, list = [];
      one[f].forEach(function (x) {
        if (typeof x !== 'string' || !x || x.length > 80 || seen[x]) return;
        seen[x] = 1; list.push(x);
      });
      if (list.length) got[f] = list;
    });
    if (one.w && typeof one.w === 'object' && !Array.isArray(one.w)) {
      var w = {};
      Object.keys(one.w).forEach(function (ck) {
        var n = Number(one.w[ck]);
        if (typeof ck === 'string' && ck.length <= 80 && isFinite(n) && n > 0) w[ck] = Math.min(5000, Math.max(COLS_LEAST, Math.round(n)));
      });
      if (Object.keys(w).length) got.w = w;
    }
    if (isFinite(Number(one.t))) got.t = Number(one.t);
    if (Object.keys(got).length) out[k] = got;
  });
  return out;
}
/** The layouts the daemon kept take the place of the ones here. */
function colsTake(kept) {
  var sane = colsSane(kept);
  Object.keys(COLS).forEach(function (k) { delete COLS[k]; });
  Object.keys(sane).forEach(function (k) { COLS[k] = sane[k]; });
}
var COLS_LEAST = 24;       /* no column narrower than this, in pixels */
var COLS = colsSane(ME && ME.cols);
var COLS_SOON = null;      /* the save under way, so saves go one after another */
var COLS_EDIT = !!(ME && ME.cols_edit);   /* this sign-in may change them */
var COLS_HUSH = 0;         /* a click straight after a drag is not a click */
var COLS_DRAG = null;      /* the heading being carried */

function colsLabel(th) {
  if (th.classList.contains('col-spacer')) return '';
  var said = '';
  Array.prototype.forEach.call(th.childNodes, function (n) {
    /* In English whatever language the page is shown in: a layout is kept
       under these words, and it is the same table in every language. */
    if (n.nodeType === 3) { said += srcText(n); return; }
    if (n.nodeType !== 1 || n.classList.contains('t-sort') || n.classList.contains('col-grip')
        || n.classList.contains('col-tools')) { return; }
    said += srcText(n);
  });
  return said.replace(/[⇅▲▼]/g, '').replace(/\s+/g, ' ').trim().toLowerCase()
    .slice(0, 60);
}

function colsHash(text) {
  var h = 5381;
  for (var i = 0; i < text.length; i++) h = ((h * 33) ^ text.charCodeAt(i)) >>> 0;
  return h.toString(36);
}

/** An empty column somebody put in for room (1.10.149): `~1`, `~2`... */
var COLS_SPACER = /^~\d{1,4}$/;
function colsIsSpacer(cell) { return cell.classList.contains('col-spacer'); }
function colsRealCells(row) {
  return Array.prototype.filter.call(row.cells, function (c) { return !colsIsSpacer(c); });
}

/** The heading row of a table that can be laid out, or null. One row of
    headings, two columns at least, none spread over two: anything else is
    a table whose shape this would only break. */
function colsHead(table) {
  if (!table || table.dataset.noCols || !table.tHead || table.tHead.rows.length !== 1) {
    return null;
  }
  if (table.closest && table.closest('.tip, .no-cols, .helpbox')) return null;
  var head = table.tHead.rows[0];
  var cells = head.cells;
  if (cells.length < 2) return null;
  for (var i = 0; i < cells.length; i++) if (cells[i].colSpan > 1) return null;
  return head;
}

/** Which table this is, for its layout; each heading learns which column
    it was first (`ci`) and what it is called (`ck`). A heading row drawn
    again from scratch starts again in its own order.

    A table is known by where it is and the words of its headings - or, for
    one that names itself (`data-cols-key`), by that name alone, so that a
    column added to it in a later version does not lose the layout somebody
    gave it. Such a table takes over a layout kept under its old name. */
function colsKey(table, head) {
  var cells = colsRealCells(head), fresh = false, i;
  for (i = 0; i < cells.length; i++) {
    if (cells[i].dataset.ci === undefined) { fresh = true; break; }
  }
  if (fresh) {
    Array.prototype.slice.call(head.cells).forEach(function (c) {
      if (colsIsSpacer(c)) c.remove();
    });
    for (i = 0; i < cells.length; i++) cells[i].dataset.ci = String(i);
    delete head.dataset.cop;
  }
  var byCi = cells.slice().sort(function (a, b) {
    return Number(a.dataset.ci) - Number(b.dataset.ci);
  });
  var seen = {}, names = [];
  byCi.forEach(function (th) {
    var k = colsLabel(th) || '#' + th.dataset.ci;
    if (seen[k]) k += '#' + th.dataset.ci;
    seen[k] = 1;
    th.dataset.ck = k;
    names.push(k);
  });
  var around = table.id ? table : (table.parentNode && table.parentNode.closest
    ? table.parentNode.closest('[id]') : null);
  var where = around ? around.id : 'page';
  if (!table.dataset.colsKey) {
    /* Named by the columns it shows as it comes. The ones kept out of sight
       until asked for are left out of the name (1.10.156), so that adding
       more of them - now or in a later version - never changes which table
       this is, and a layout somebody saved for it stays theirs. */
    var named = byCi.filter(function (th) { return !th.hasAttribute('data-cols-optional'); })
      .map(function (th) { return th.dataset.ck; });
    return where + ':' + colsHash(named.join('|'));
  }
  var key = 'k:' + table.dataset.colsKey;
  if (!COLS[key]) {
    var old = Object.keys(COLS).filter(function (k) { return k.indexOf(where + ':') === 0; })
      .sort(function (a, b) { return (COLS[b].t || 0) - (COLS[a].t || 0); })[0];
    if (old) { COLS[key] = COLS[old]; delete COLS[old]; }
  }
  return key;
}

/** How the columns are to stand: in which order (first positions, with the
    empty columns somebody added among them), which are put away, and one
    string that says all of it - empty for a table as it comes. A column
    the layout does not know (one added since) stays where it would have
    been. */
function colsPlan(head, mine) {
  var real = colsRealCells(head), n = real.length, i;
  var at = {};
  real.forEach(function (c) { at[c.dataset.ck] = Number(c.dataset.ci); });
  var spacers = ((mine && mine.s) || []).filter(function (k) { return COLS_SPACER.test(k); });
  var isSpacer = {};
  spacers.forEach(function (k) { isSpacer[k] = 1; });
  var seq = [], used = {}, usedS = {};
  ((mine && mine.o) || []).forEach(function (k) {
    if (isSpacer[k]) { if (!usedS[k]) { usedS[k] = 1; seq.push(k); } return; }
    if (at[k] === undefined || used[at[k]]) return;
    used[at[k]] = 1;
    seq.push(at[k]);
  });
  for (i = 0; i < n; i++) if (!used[i]) seq.splice(Math.min(i, seq.length), 0, i);
  spacers.forEach(function (k) { if (!usedS[k]) seq.push(k); });
  var hidden = {}, hid = [];
  ((mine && mine.h) || []).forEach(function (k) {
    if (at[k] !== undefined && !hidden[at[k]]) { hidden[at[k]] = 1; hid.push(at[k]); }
  });
  /* The columns a table offers but keeps out of sight until somebody asks
     for them (1.10.156): hidden unless this person's layout says shown. */
  var asked = {};
  ((mine && mine.v) || []).forEach(function (k) { asked[k] = 1; });
  real.forEach(function (c) {
    var ci = Number(c.dataset.ci);
    if (c.hasAttribute('data-cols-optional') && !asked[c.dataset.ck] && !hidden[ci]) {
      hidden[ci] = 1;
      hid.push(ci);
    }
  });
  /* Never every column away: one is always left to read. */
  if (hid.length >= n) { hidden = {}; hid = []; }
  var natural = !spacers.length && !hid.length;
  for (i = 0; natural && i < seq.length; i++) if (seq[i] !== i) natural = false;
  return {seq: seq, hidden: hidden, n: n,
          sig: natural ? '' : seq.join(',') + '|' + hid.sort().join(',')};
}

/** One row put into that order. A row drawn as it comes has its cells
    numbered first; a row of another shape (a message spread over the whole
    table, a fold under a row) is left as it is. Empty columns are cells of
    their own, made here and nowhere else. */
function colsRowTo(tr, plan, isHead) {
  if ((tr.dataset.cop || '') === plan.sig) return;
  var real = colsRealCells(tr), n = plan.n, i;
  if (real.length !== n) return;
  for (i = 0; i < n; i++) if (real[i].colSpan > 1) return;
  if (!tr.dataset.cop) {
    for (i = 0; i < n; i++) if (real[i].dataset.ci === undefined) real[i].dataset.ci = String(i);
  }
  var byCi = {};
  for (i = 0; i < n; i++) byCi[real[i].dataset.ci] = real[i];
  for (i = 0; i < plan.seq.length; i++) {
    if (typeof plan.seq[i] === 'number' && !byCi[plan.seq[i]]) return;
  }
  Array.prototype.slice.call(tr.cells).forEach(function (c) { if (colsIsSpacer(c)) c.remove(); });
  plan.seq.forEach(function (one) {
    if (typeof one === 'number') {
      var cell = byCi[one];
      cell.classList.toggle('col-hidden', !!plan.hidden[one]);
      tr.appendChild(cell);
      return;
    }
    var gap = document.createElement(isHead ? 'th' : 'td');
    gap.className = 'col-spacer';
    gap.dataset.ck = one;
    tr.appendChild(gap);
  });
  if (plan.sig) tr.dataset.cop = plan.sig; else delete tr.dataset.cop;
}

/** A table laid out as its owner left it: run whenever it is drawn. */
function colsApply(table) {
  var head = colsHead(table);
  if (!head) return;
  var key = colsKey(table, head);
  table._colsKey = key;
  if (!table.classList.contains('cols-able')) table.classList.add('cols-able');
  var mine = COLS[key] || null;
  var plan = colsPlan(head, mine);
  if (plan.sig || head.dataset.cop) {
    colsRowTo(head, plan, true);
    Array.prototype.forEach.call(table.tBodies, function (body) {
      /* Over a copy: moving cells inside the live collection made the
         browser walk it again at every step - two seconds for 8000 rows. */
      Array.prototype.slice.call(body.rows).forEach(function (tr) { colsRowTo(tr, plan, false); });
    });
    if (table.tFoot) {
      Array.prototype.slice.call(table.tFoot.rows).forEach(function (tr) {
        colsRowTo(tr, plan, false);
      });
    }
  }
  colsWire(table, head);
  colsWidths(table, head, mine);
}

/** The widths somebody set, or the table's own when there are none. Kept
    as shares of the table, not as pixels: the table always fills its card
    and never runs past it, on a wide screen and a narrow one alike, and the
    columns keep the proportions they were given. A column the layout does
    not know (one added since) gets the average; a column put away takes
    no room at all. */
function colsWidths(table, head, mine) {
  var widths = mine && mine.w;
  var cells = head.cells;
  if (!widths || !Object.keys(widths).length) {
    if (!table.classList.contains('cols-set')) return;
    table.classList.remove('cols-set');
    table.style.width = '';
    Array.prototype.forEach.call(cells, function (th) { th.style.width = ''; });
    return;
  }
  var px = [], known = 0, n = 0, sum = 0;
  Array.prototype.forEach.call(cells, function (th) {
    var w = Number(widths[th.dataset.ck]) || 0;
    px.push(w);
    if (w > 0) { known += w; n += 1; }
  });
  var avg = n ? known / n : 100;
  px = px.map(function (w, at) {
    if (cells[at].classList.contains('col-hidden')) return 0;
    return Math.max(COLS_LEAST, w > 0 ? w : avg);
  });
  px.forEach(function (w) { sum += w; });
  Array.prototype.forEach.call(cells, function (th, at) {
    th.style.width = px[at] ? (px[at] / sum * 100).toFixed(4) + '%' : '';
  });
  table.classList.add('cols-set');
  table.style.width = '';
}

/** How wide each column would like to be: its longest line, heading
    included, with nothing broken across lines. Asked of the table itself,
    laid out freely for a moment and put straight back - in the same breath,
    so the browser never paints it that way. */
function colsNatural(table, head) {
  table.classList.add('cols-measure');
  var got = Array.prototype.map.call(head.cells, function (th) {
    return th.getBoundingClientRect().width;
  });
  table.classList.remove('cols-measure');
  return got;
}

function colsSave() {
  if (!COLS_EDIT) return;
  /* Kept small: past a few hundred tables, the ones looked at longest ago
     go first. */
  var keys = Object.keys(COLS);
  if (keys.length > 300 || JSON.stringify(COLS).length > 50000) {
    keys.sort(function (a, b) { return (COLS[a].t || 0) - (COLS[b].t || 0); });
    while (keys.length && (keys.length > 300 || JSON.stringify(COLS).length > 50000)) {
      delete COLS[keys.shift()];
    }
  }
  /* Saved the moment a column is let go of, one save after another, so an
     older layout can never land after a newer one. */
  var send = function () {
    return api('columns', {cols: COLS}).catch(function (e) {
      if (e && e.status === 409) {
        /* Editing was switched off behind the page - the service restarted,
           or the sign-in is a new one. The page goes on believing it was on
           otherwise, rearranging tables that are put back at the next load:
           off here too, and the layout as it is kept. (1.10.155) */
        colsEditing(false);
        api('my-settings').then(function (now) {
          colsTake((now.settings || {}).columns || {});
          colsApplyAll();
        }).catch(function () { /* the next load draws it */ });
        toast('editing the columns has been switched off - the service restarted or this '
          + 'is a new sign-in - so that change was not kept. Switch it on again under your '
          + 'name.', 'bad');
        return;
      }
      toast('your columns could not be kept: ' + ((e && e.message) || e), 'bad');
    });
  };
  COLS_SOON = (COLS_SOON || Promise.resolve()).then(send, send);
}

/** Editing the columns switched on or off for this sign-in: the grips and
    the carrying come and go, the layout stays as it is. */
function colsEditing(on) {
  COLS_EDIT = !!on;
  if (!COLS_EDIT) colsMenuClose();
  document.body.classList.toggle('cols-editing', COLS_EDIT);
  Array.prototype.forEach.call(document.querySelectorAll('thead th'), function (th) {
    if (th._colsCarry) th.draggable = COLS_EDIT;
  });
  var me = $('me-btn');
  if (me) me.classList.toggle('editing', COLS_EDIT);
}

/** Every table on the page again, after a layout changed under it. */
function colsApplyAll() {
  Array.prototype.forEach.call(document.getElementsByTagName('table'), colsApply);
}

function colsMine(table) {
  var key = table._colsKey;
  if (!key) return null;
  var mine = COLS[key] || (COLS[key] = {});
  mine.t = Math.floor(Date.now() / 1000);
  return mine;
}

/** The grip on each heading's right edge, and the heading as something to
    carry. Once a heading: a heading drawn again gets them again. */
function colsWire(table, head) {
  if (!table._colsMenu) {
    table._colsMenu = true;
    /* The right button anywhere in the table, while editing - on a row as
       well as on its heading: the menu is about the column under the
       pointer (1.10.152). */
    table.addEventListener('contextmenu', function (e) {
      if (!COLS_EDIT || !e.target.closest) return;
      var cell = e.target.closest('td, th');
      var row = cell && cell.parentNode;
      var top = colsHead(table);
      if (!cell || !top || !row || cell.closest('table') !== table) return;
      if (row === top) return;                  /* the heading has its own */
      var th = row.cells.length === top.cells.length ? top.cells[cell.cellIndex] : null;
      if (!th) return;
      e.preventDefault();
      colsMenu(e.clientX, e.clientY, table, th);
    });
  }
  if (!table._colsHush) {
    table._colsHush = true;
    /* Caught on the way down, before the heading's own click: letting go
       of a grip or a carried heading must not also order the table by it. */
    table.addEventListener('click', function (e) {
      if (Date.now() - COLS_HUSH < 350 && e.target.closest && e.target.closest('thead')) {
        e.stopPropagation();
        e.preventDefault();
      }
    }, true);
  }
  Array.prototype.forEach.call(head.cells, function (th) {
    if (th._colsWired) return;
    th._colsWired = true;
    var grip = el('span', 'col-grip');
    grip.setAttribute('aria-hidden', 'true');
    grip.title = '';
    grip.addEventListener('pointerdown', function (e) { colsStretch(e, table, th, grip); });
    grip.addEventListener('dblclick', function (e) {
      if (!COLS_EDIT) return;
      e.stopPropagation();
      e.preventDefault();
      COLS_HUSH = Date.now();
      /* Twice on a grip: this table's widths as they come. */
      var mine = colsMine(table);
      if (!mine) return;
      delete mine.w;
      if (!mine.o && !mine.h && !mine.s) delete COLS[table._colsKey];
      colsApply(table);
      colsSave();
    });
    th.appendChild(grip);
    /* The right button, while editing: what can be done with the columns
       of this table - put one away, bring one back, add or take away an
       empty one. Otherwise the browser's own menu, as always. */
    th.addEventListener('contextmenu', function (e) {
      if (!COLS_EDIT) return;
      e.preventDefault();
      e.stopPropagation();
      colsMenu(e.clientX, e.clientY, table, th);
    });
    if (th.querySelector('input, select, button, textarea')) return;
    th._colsCarry = true;
    th.draggable = COLS_EDIT;
    th.addEventListener('dragstart', function (e) {
      if (th._stretching || !COLS_EDIT) { e.preventDefault(); return; }
      COLS_DRAG = {table: table, th: th};
      th.classList.add('col-carried');
      try {
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', colsLabel(th));
      } catch (x) { /* an old browser carries it anyway */ }
    });
    th.addEventListener('dragover', function (e) {
      if (!COLS_DRAG || COLS_DRAG.table !== table || COLS_DRAG.th === th) return;
      e.preventDefault();
      var box = th.getBoundingClientRect();
      var after = e.clientX > box.left + box.width / 2;
      th.classList.toggle('col-drop-after', after);
      th.classList.toggle('col-drop-before', !after);
    });
    th.addEventListener('dragleave', function () {
      th.classList.remove('col-drop-after', 'col-drop-before');
    });
    th.addEventListener('drop', function (e) {
      if (!COLS_DRAG || COLS_DRAG.table !== table || COLS_DRAG.th === th || !COLS_EDIT) return;
      e.preventDefault();
      var after = th.classList.contains('col-drop-after');
      th.classList.remove('col-drop-after', 'col-drop-before');
      var carried = COLS_DRAG.th;
      var order = Array.prototype.map.call(head.cells, function (c) { return c.dataset.ck; })
        .filter(function (k) { return k !== carried.dataset.ck; });
      var at = order.indexOf(th.dataset.ck) + (after ? 1 : 0);
      order.splice(at, 0, carried.dataset.ck);
      var mine = colsMine(table);
      if (!mine) return;
      mine.o = order;
      COLS_HUSH = Date.now();
      colsApply(table);
      colsSave();
    });
    th.addEventListener('dragend', function () {
      th.classList.remove('col-carried');
      Array.prototype.forEach.call(head.cells, function (c) {
        c.classList.remove('col-drop-after', 'col-drop-before');
      });
      COLS_DRAG = null;
      COLS_HUSH = Date.now();
    });
  });
}


/* ---- the menu on a heading's right button, while editing ---------------- */
var COLS_MENU = null;
function colsMenuClose() {
  if (COLS_MENU) { COLS_MENU.remove(); COLS_MENU = null; }
}
document.addEventListener('mousedown', function (e) {
  if (COLS_MENU && !COLS_MENU.contains(e.target)) colsMenuClose();
}, true);
document.addEventListener('keydown', function (e) {
  if (COLS_MENU && e.key === 'Escape') colsMenuClose();
});
window.addEventListener('resize', colsMenuClose);
document.addEventListener('scroll', function (e) {
  if (COLS_MENU && !COLS_MENU.contains(e.target)) colsMenuClose();
}, true);

/** What a column is called in the menu: its heading, or where it stands
    when it has none. */
function colsMenuName(th) {
  /* As the heading reads on the screen - in the language it is shown in,
     and spelt as it is (`MAC address`, not `Mac address`). The English one
     is what a layout is kept under; this is only what the menu says.
     (1.10.159) */
  var shown = '';
  Array.prototype.forEach.call(th.childNodes, function (n) {
    if (n.nodeType === 3) { shown += n.textContent; return; }
    if (n.nodeType !== 1 || n.classList.contains('t-sort') || n.classList.contains('col-grip')
        || n.classList.contains('col-tools')) { return; }
    shown += n.textContent;
  });
  shown = shown.replace(/[⇅▲▼]/g, '').replace(/\s+/g, ' ').trim();
  if (shown) return shown;
  var said = colsLabel(th);
  if (said) return said.charAt(0).toUpperCase() + said.slice(1);
  return 'Column ' + (Number(th.dataset.ci || 0) + 1) + ' (no heading)';
}

function colsMenu(x, y, table, th) {
  colsMenuClose();
  var head = colsHead(table);
  if (!head || !COLS_EDIT) return;
  var key = table._colsKey;
  var mine = COLS[key] || {};
  var hidden = {};
  (mine.h || []).forEach(function (k) { hidden[k] = 1; });
  var real = colsRealCells(head);
  var asked = {};
  (mine.v || []).forEach(function (k) { asked[k] = 1; });
  real.forEach(function (c) {
    if (c.hasAttribute('data-cols-optional') && !asked[c.dataset.ck]) hidden[c.dataset.ck] = 1;
  });
  var showing = real.filter(function (c) { return !hidden[c.dataset.ck]; }).length;
  var menu = el('div', 'cols-menu');
  menu.setAttribute('role', 'menu');
  var item = function (words, icon, go, off, cls) {
    var b = el('button', 'cols-mi' + (cls ? ' ' + cls : ''));
    b.type = 'button';
    b.setAttribute('role', 'menuitem');
    b.innerHTML = icon ? iconMarkup(icon, 14) : '<span class="cols-mi-blank"></span>';
    b.appendChild(el('span', '', words));
    b.disabled = !!off;
    b.onclick = function (ev) {
      ev.stopPropagation();
      go();
    };
    menu.appendChild(b);
    return b;
  };
  var again = function () { colsMenu(x, y, table, th.isConnected ? th : head.cells[0]); };
  if (colsIsSpacer(th)) {
    item('Take this empty column away', 'trash', function () {
      colsMenuClose();
      colsDropSpacer(table, th.dataset.ck);
    });
  } else {
    item('Hide “' + colsMenuName(th) + '”', 'eye', function () {
      colsMenuClose();
      colsHide(table, th.dataset.ck, true);
    }, showing <= 1);
  }
  item('Add an empty column to the left', 'add', function () {
    colsMenuClose();
    colsAddSpacer(table, th, false);
  });
  item('Add an empty column to the right', 'add', function () {
    colsMenuClose();
    colsAddSpacer(table, th, true);
  });
  menu.appendChild(el('div', 'cols-msep'));
  menu.appendChild(el('div', 'cols-mh', 'Columns of this table'));
  /* Every column, the hidden ones too: ticked is shown. Pressing one
     changes it and leaves the menu open, so several can be done at once. */
  real.slice().sort(function (a, b) { return Number(a.dataset.ci) - Number(b.dataset.ci); })
    .forEach(function (c) {
      var off = !!hidden[c.dataset.ck];
      item(colsMenuName(c), off ? '' : 'check', function () {
        colsHide(table, c.dataset.ck, !off);
        again();
      }, !off && showing <= 1, off ? 'off' : '');
    });
  menu.appendChild(el('div', 'cols-msep'));
  item('Put this table back as it comes', 'undo', function () {
    colsMenuClose();
    delete COLS[key];
    colsApply(table);
    colsSave();
  }, !COLS[key]);
  document.body.appendChild(menu);
  COLS_MENU = menu;
  var box = menu.getBoundingClientRect();
  menu.style.left = Math.max(8, Math.min(x, window.innerWidth - box.width - 8)) + 'px';
  menu.style.top = Math.max(8, Math.min(y, window.innerHeight - box.height - 8)) + 'px';
}

/** The widths as they stand now, for a table that has none kept yet: an
    empty column needs a width to be anything at all. */
function colsHoldWidths(table, head, mine) {
  if (mine.w && Object.keys(mine.w).length) return;
  mine.w = {};
  Array.prototype.forEach.call(head.cells, function (c) {
    var w = Math.round(c.getBoundingClientRect().width);
    if (w) mine.w[c.dataset.ck] = w;
  });
}

function colsHide(table, ck, away) {
  var mine = colsMine(table);
  if (!mine) return;
  var h = (mine.h || []).filter(function (k) { return k !== ck; });
  /* A column kept out of sight until asked for is shown by being asked for,
     and put away again by no longer being. */
  var head = colsHead(table);
  var optional = head && Array.prototype.some.call(head.cells, function (c) {
    return c.dataset.ck === ck && c.hasAttribute('data-cols-optional');
  });
  if (optional) {
    var v = (mine.v || []).filter(function (k) { return k !== ck; });
    if (!away) v.push(ck);
    if (v.length) mine.v = v; else delete mine.v;
  } else if (away) {
    h.push(ck);
  }
  if (h.length) mine.h = h; else delete mine.h;
  colsApply(table);
  colsSave();
}

function colsAddSpacer(table, th, after) {
  var head = colsHead(table);
  var mine = colsMine(table);
  if (!head || !mine) return;
  colsHoldWidths(table, head, mine);
  var order = Array.prototype.map.call(head.cells, function (c) { return c.dataset.ck; });
  var most = 0;
  (mine.s || []).forEach(function (k) { most = Math.max(most, Number(k.slice(1)) || 0); });
  var id = '~' + (most + 1);
  var at = order.indexOf(th.dataset.ck);
  order.splice(at < 0 ? order.length : at + (after ? 1 : 0), 0, id);
  mine.o = order;
  mine.s = (mine.s || []).concat([id]);
  mine.w[id] = 48;
  colsApply(table);
  colsSave();
}

function colsDropSpacer(table, id) {
  var mine = colsMine(table);
  if (!mine) return;
  mine.s = (mine.s || []).filter(function (k) { return k !== id; });
  if (!mine.s.length) delete mine.s;
  if (mine.o) mine.o = mine.o.filter(function (k) { return k !== id; });
  if (mine.w) delete mine.w[id];
  colsApply(table);
  colsSave();
}

/** Dragging a grip: this column wider or narrower, the others as they are. */
function colsStretch(e, table, th, grip) {
  if (!COLS_EDIT) return;
  if (e.button !== undefined && e.button !== 0) return;
  e.preventDefault();
  e.stopPropagation();
  var head = colsHead(table);
  var mine = colsMine(table);
  if (!head || !mine) return;
  var cells = Array.prototype.slice.call(head.cells);
  var at = cells.indexOf(th);
  if (at < 0) return;
  /* Where every column stands now, and how narrow each may go. The table
     keeps its width: what one column gains the columns to its right give
     up, and none of them more than it has spare - a column already as
     narrow as its longest line gives nothing, so once nothing to the right
     is spare the edge goes no further. Never a scroll bar under the table. */
  var base = cells.map(function (c) { return c.getBoundingClientRect().width; });
  var want = colsNatural(table, head);
  var least = cells.map(function (c, j) {
    return Math.max(COLS_LEAST, Math.min(base[j], Math.ceil(want[j])));
  });
  /* Only the columns to the right of it give room or take it back: what is
     to the left stays exactly where it was put, so a table is laid out from
     left to right, one edge at a time. The nearest gives first. */
  var order = [];
  for (var r = at + 1; r < cells.length; r++) {
    if (!cells[r].classList.contains('col-hidden')) order.push(r);
  }
  var from = e.clientX;
  th._stretching = true;
  /* Not carried while it is being sized: a heading that can be dragged
     would otherwise start being carried the moment the mouse moved. */
  var carried = th.draggable;
  th.draggable = false;
  grip.classList.add('on');
  document.body.classList.add('cols-stretching');
  try { grip.setPointerCapture(e.pointerId); } catch (x) { /* fine without */ }
  var put = function (w) {
    /* A column put away keeps the width it had, for when it comes back. */
    var kept = mine.w || {};
    mine.w = {};
    cells.forEach(function (c, j) {
      mine.w[c.dataset.ck] = c.classList.contains('col-hidden')
        ? (kept[c.dataset.ck] || 0) : Math.round(w[j]);
      if (!mine.w[c.dataset.ck]) delete mine.w[c.dataset.ck];
    });
    colsWidths(table, head, mine);
  };
  put(base);
  colsSizeSay(th, base[at]);
  var move = function (ev) {
    var dx = ev.clientX - from;
    var w = base.slice();
    if (dx > 0) {
      var need = dx;
      order.forEach(function (j) {
        var give = Math.min(need, Math.max(0, w[j] - least[j]));
        w[j] -= give;
        need -= give;
      });
      w[at] += dx - need;
    } else if (dx < 0) {
      /* Narrower: what it lets go of goes to the columns on its right -
         first those short of their longest line, then the rest. */
      var spare = Math.min(-dx, Math.max(0, w[at] - COLS_LEAST));
      w[at] -= spare;
      order.forEach(function (j) {
        var take = Math.min(spare, Math.max(0, want[j] - w[j]));
        w[j] += take;
        spare -= take;
      });
      /* ...and what is still over is shared by them, by how wide each
         already is - a narrow column (an arrow, a mark) gets next to
         nothing, so it is not suddenly the widest thing in the table. */
      if (spare > 0 && order.length) {
        var room = 0;
        order.forEach(function (j) { room += w[j]; });
        order.forEach(function (j) { w[j] += room ? spare * w[j] / room : spare / order.length; });
      } else if (spare > 0) {
        w[at] += spare;
      }
    }
    put(w);
    colsSizeSay(th, w[at]);
  };
  var done = function () {
    grip.removeEventListener('pointermove', move);
    grip.removeEventListener('pointerup', done);
    grip.removeEventListener('pointercancel', done);
    grip.classList.remove('on');
    document.body.classList.remove('cols-stretching');
    colsSizeSay(null);
    th._stretching = false;
    th.draggable = carried;
    COLS_HUSH = Date.now();
    colsSave();
  };
  grip.addEventListener('pointermove', move);
  grip.addEventListener('pointerup', done);
  grip.addEventListener('pointercancel', done);
}

/** While a column is being sized: how wide it is, in a pill at the foot of
    the window, so that two columns can be made the same width by eye and
    by number. Gone as soon as the column is let go of. */
function colsSizeSay(th, px) {
  var pill = $('cols-size');
  if (!th) { if (pill) pill.hidden = true; return; }
  if (!pill) {
    pill = el('div', 'cols-size');
    pill.id = 'cols-size';
    pill.setAttribute('role', 'status');
    pill.setAttribute('aria-live', 'polite');
    document.body.appendChild(pill);
  }
  clear(pill);
  pill.appendChild(el('span', 'cols-size-n', colsIsSpacer(th) ? 'empty column'
    : (colsLabel(th) || 'this column')));
  pill.appendChild(el('b', '', Math.round(px) + ' px'));
  pill.hidden = false;
}

/** Put every table back as it comes - this person's own, or (for a full
    admin) somebody else's. */
function colsReset(whose) {
  var mine = !whose || (ME && whose === ME.name);
  var asked = mine ? (COLS_SOON || Promise.resolve()).then(function () {
    return api('columns', {cols: {}, reset: true});
  })
    : api('users', {action: 'reset_cols', name: whose});
  return asked.then(function () {
    if (mine) {
      Object.keys(COLS).forEach(function (k) { delete COLS[k]; });
      colsApplyAll();
    }
    toast(mine ? 'Every table is back as it comes' : 'The columns of ' + whose
      + ' are back as they come; they see it at their next page load', 'good');
  });
}

/* Whenever anything is drawn: the tables in it laid out before they are
   painted. A mutation observer runs before the next frame, so a table is
   never seen in its old order first. */
(function () {
  if (!window.MutationObserver) return;
  var watch = new MutationObserver(function (records) {
    var tables = [];
    var note = function (t) { if (t && tables.indexOf(t) < 0) tables.push(t); };
    records.forEach(function (m) {
      var t = m.target;
      if (t && t.nodeType === 1) {
        var tag = t.tagName;
        if (tag === 'TBODY' || tag === 'THEAD' || tag === 'TFOOT' || tag === 'TR'
            || tag === 'TABLE') {
          note(tag === 'TABLE' ? t : t.closest('table'));
          return;
        }
      }
      Array.prototype.forEach.call(m.addedNodes, function (n) {
        if (n.nodeType !== 1) return;
        if (n.tagName === 'TABLE') { note(n); return; }
        if (n.tagName === 'TR' || n.tagName === 'TD' || n.tagName === 'TH') return;
        var inner = n.getElementsByTagName('table');
        for (var i = 0; i < inner.length; i++) note(inner[i]);
      });
    });
    tables.forEach(function (t) {
      try { colsApply(t); } catch (x) { /* a layout is never worth a broken page */ }
    });
  });
  watch.observe(document.body, {childList: true, subtree: true});
  document.addEventListener('DOMContentLoaded', colsApplyAll);
  colsEditing(COLS_EDIT);
  colsApplyAll();
})();

/** Which column a heading is, whatever position somebody has moved it to. */
function colOf(th, at) {
  var ci = th && th.dataset ? th.dataset.ci : undefined;
  return ci !== undefined && ci !== '' ? Number(ci) : at;
}
/** A row's cell for that column, wherever it now stands in the row. */
function cellOf(tr, col) {
  if (!tr || !tr.cells) return null;
  if (!tr.dataset.cop) return tr.cells[col];
  for (var i = 0; i < tr.cells.length; i++) {
    if (Number(tr.cells[i].dataset.ci) === col) return tr.cells[i];
  }
  return null;
}

