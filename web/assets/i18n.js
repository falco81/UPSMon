/* i18n.js - the page in another language. Taken whole from isemon (1.10.153 on):
   the page is written in English and a file in lang/ says what each piece is in
   another language; this swaps the words as they appear, before they are painted. */
/* ==========================================================================
   The page in another language (1.10.153)
   --------------------------------------------------------------------------
   The page is written in English and stays so in its code. A language file
   in web/lang/ (cs.json, en.json...) holds, under an ID each, the English a
   piece of the page shows (`source`) and what to show instead (`text`).
   When the person signed in has chosen a language, its file is handed to the
   page before anything is drawn (OTP_LANG_PACK) and this swaps the words
   as they appear - whatever drew them, whenever - before the browser paints
   them:
   - an element holding only words and bold, code, line breaks is swapped
     whole, so a sentence is translated as a sentence (`rich`);
   - otherwise each piece of text by itself (`strings`), or by a pattern with
     {0}, {1} where the page puts a number or a name (`patterns`);
   - and the titles, placeholders and labels the same way.
   Never data: nothing inside an input, code, a .mono, or anything marked
   data-no-i18n. Without a file, with a broken one, or with English as it
   comes, none of this runs at all and the page is exactly what its code
   draws. What the code reads back off the page - a heading it sorts by, the
   name a column is kept under - it reads in English (`srcText`).
   ========================================================================== */
var I18N = {on: false, code: 'en', exact: null, pats: [], rich: null, richPats: [],
            orig: (typeof WeakMap === 'function') ? new WeakMap() : null,
            attrs: (typeof WeakMap === 'function') ? new WeakMap() : null,
            richOrig: (typeof WeakMap === 'function') ? new WeakMap() : null};

function i18nFold(s) { return String(s).replace(/\s+/g, ' ').trim(); }
/** A word that changes with the number beside it, written in a translation
    as `{0:one|two to four|five and more}` - "1 pokus", "3 pokusy", "7 pokusů"
    - or with two forms, `{0:one|more}`. The number is the one in that slot.
    English writes "attempt(s)" and needs none of it. (1.10.160) */
function i18nPlural(text, slots, m) {
  if (text.indexOf(':') < 0) return text;
  return text.replace(/\{(\d+):([^}]*)\}/g, function (all, n, forms) {
    var at = slots.indexOf(Number(n));
    if (at < 0) return all;
    var said = String(m[at + 1] || '').replace(/[\s,\u00a0]/g, '');
    var count = /^-?\d+$/.test(said) ? Math.abs(parseInt(said, 10)) : NaN;
    var form = forms.split('|');
    if (isNaN(count)) return form[form.length - 1];
    if (form.length === 2) return count === 1 ? form[0] : form[1];
    if (count === 1) return form[0];
    if (count >= 2 && count <= 4) return form[1];
    return form[2] || form[form.length - 1];
  });
}
function i18nEsc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/** A pattern as a regular expression: the words as they are, each {n} any
    run of characters (but never across a tag, in a rich one). */
function i18nCompile(source, rich) {
  var slots = [];
  /* Empty is allowed: what the code adds after a number is often nothing.
     A slot never reaches across " · " or " — " either, unless the pattern
     itself has one: "{0} min ago" is not "fw1 · blocked · written 3 min
     ago" with everything before the last dot in its slot. (1.10.155) */
  var across = /\s[\u00b7\u2022|\u2014]\s/.test(source)
    /* ...or it is a long sentence of its own, specific enough that what
       fills it may be anything: " — last 3 min ago" at the end of one. */
    || source.replace(/\{\d+\}/g, '').length >= 25;
  var any = rich ? '([^<]*?)' : (across ? '(.*?)' : '((?:(?!\\s[\u00b7\u2022|\u2014]\\s).)*?)');
  var bits = source.split(/(\{\d+\})/);
  /* A slot never starts or ends in the middle of a word: "{0} ever{1}" is
     not to be found inside "everything". */
  var body = bits.map(function (bit, i) {
    var m = /^\{(\d+)\}$/.exec(bit);
    if (!m) return i18nEsc(bit);
    slots.push(Number(m[1]));
    var before = i > 0 ? bits[i - 1] : '', after = i < bits.length - 1 ? bits[i + 1] : '';
    return (/[A-Za-z]$/.test(before) ? '(?![A-Za-z])' : '') + any
      + (/^[A-Za-z]/.test(after) ? '(?<![A-Za-z])' : '');
  }).join('');
  /* "— this one and {0} other(s)" is written after a number by the code,
     in the same piece of text: whatever stands before such a dash or comma
     is kept as it is, in front. */
  var pre = !rich && /^[\u2014\u2013\u00b7,;:(]\s/.test(source);
  if (pre) {
    body = '(?:(.*) )?' + body;     /* up to the LAST such dash */
    slots.unshift(-1);
  }
  try { return {re: new RegExp('^' + body + '$'), slots: slots, pre: pre}; } catch (e) { return null; }
}

/* The pack the page is handed is the language file cut down to what it
   needs: {code, strings: {English: text}, patterns: [[English, text]],
   rich: {English: text}} - only the texts that differ from the English. */
function i18nPattern(source, text, rich) {
  var c = i18nCompile(source, rich);
  if (!c) return null;
  c.text = String(text);
  /* The longest fixed piece of it, looked for before the expression is run:
     most texts on a page are names and numbers that match no pattern, and
     this turns them away for the cost of an indexOf. */
  var bits = source.split(/\{\d+\}/), lit = '';
  for (var i = 0; i < bits.length; i++) if (bits[i].length > lit.length) lit = bits[i];
  c.lit = lit;
  c.own = source.replace(/\{\d+\}/g, '').length;
  /* With hardly any words of its own ("from {0}", "{0} was {1}") a pattern
     would take a whole sentence for a slot; then a slot is one word or
     number at most, which is what such a pattern is ever written around. */
  c.weak = (source.replace(/\{\d+\}/g, ' ').match(/[A-Za-z]{2,}/g) || []).length < 2
    /* ...or with only a few letters of its own (1.0.103): "{0} in use" took
       "the port 1812 is" for its slot and said "the port 1812 is se používá". */
    || source.replace(/\{\d+\}/g, '').trim().length < 10;
  return c;
}
function i18nWordy(m, depth) {
  for (var i = 1; i < m.length; i++) {
    if (!/[A-Za-z]{2,}[^A-Za-z]+[A-Za-z]{2,}/.test(m[i] || '')) continue;
    /* Several words are still a slot's worth when they are a text of the
       page's own: "Started {0}." around "2 min ago". */
    if ((depth || 0) < I18N_DEEP && i18nWork(m[i], (depth || 0) + 1) !== null) continue;
    return true;
  }
  return false;
}
function i18nInit(pack) {
  if (!pack || typeof pack !== 'object' || !I18N.orig || typeof Map !== 'function') return false;
  I18N.code = String(pack.code || 'en');
  I18N.exact = new Map();
  I18N.rich = new Map();
  I18N.pats = [];
  I18N.richPats = [];
  var strings = pack.strings || {};
  Object.keys(strings).forEach(function (k) {
    var v = strings[k];
    if (typeof v === 'string' && v !== '' && v !== k) I18N.exact.set(i18nFold(k), v);
  });
  (Array.isArray(pack.patterns) ? pack.patterns : []).forEach(function (pair) {
    if (!Array.isArray(pair) || typeof pair[0] !== 'string' || typeof pair[1] !== 'string'
        || !pair[1] || pair[1] === pair[0]) return;
    var c = i18nPattern(i18nFold(pair[0]), pair[1], false);
    if (c && c.own > 0) I18N.pats.push(c);
  });
  I18N.pats.sort(function (a, b) { return b.own - a.own; });
  /* One look for any pattern's fixed words at all: most texts on a page
     are data, contain none of them, and are turned away by this alone. */
  try {
    var lits = I18N.pats.map(function (p) { return p.lit; }).filter(Boolean);
    I18N.anyLit = lits.length && lits.length === I18N.pats.length
      ? new RegExp(lits.map(i18nEsc).join('|')) : null;
  } catch (e) { I18N.anyLit = null; }
  var rich = pack.rich || {};
  Object.keys(rich).forEach(function (k) {
    var v = rich[k];
    if (typeof v !== 'string' || v === '' || v === k) return;
    var key = i18nFold(k);
    if (/\{\d+\}/.test(key)) {
      var c = i18nPattern(key, v, true);
      if (c && c.own > 0) I18N.richPats.push(c);
    } else {
      I18N.rich.set(key, v);
    }
  });
  I18N.richPats.sort(function (a, b) { return b.own - a.own; });
  if (I18N_SEEN) I18N_SEEN.clear();          /* another language: worked out again */
  I18N.on = I18N.exact.size > 0 || I18N.pats.length > 0 || I18N.rich.size > 0
    || I18N.richPats.length > 0;
  return I18N.on;
}

/** One piece of text in the chosen language, or null when it has none. */
/* What a text came to, remembered: a table of thousands of rows says the
   same few hundred things over and over, and each is worked out once. */
var I18N_SEEN = (typeof Map === 'function') ? new Map() : null;
var I18N_DEEP = 6;          /* how far a slot inside a slot is still translated */
function i18nText(s, depth) {
  if (depth) return i18nWork(s, depth);
  if (!I18N.on || !I18N.exact) return null;     /* nothing remembered for English */
  var got = I18N_SEEN.get(s);
  if (got !== undefined) return got;
  got = i18nWork(s, 0);
  if (I18N_SEEN.size > 50000) I18N_SEEN.clear();
  I18N_SEEN.set(s, got);
  return got;
}
function i18nWork(s, depth) {
  /* English, or the words not here yet: nothing to change it into - and no
     table to look in (1.0.103: the English admin page stopped at this). */
  if (!I18N.on || !I18N.exact) return null;
  depth = depth || 0;
  var key = i18nFold(s);
  if (!key || !/[A-Za-z]{2}/.test(key)) return null;
  var hit = I18N.exact.get(key);
  if (hit !== undefined) return hit;
  /* A text the page wrote with its first letter made capital - the name of a
     field as a label - is the text it was made of (1.10.207): every label
     of the firewall's popup was in English. Never a single word: that is
     as likely a name somebody gave (a packet mark called Download). */
  if (/^[A-Z][a-z]/.test(key) && key.indexOf(' ') > 0) {
    hit = I18N.exact.get(key.charAt(0).toLowerCase() + key.slice(1));
    if (hit !== undefined && hit) return hit.charAt(0).toUpperCase() + hit.slice(1);
  }
  /* A number or a name the code wrote in front of a text that begins with
     a dash or a dot: "1 — only this one". The front is kept as it is. */
  var front = /^(\S+) ([\u2014\u00b7,] .+)$/.exec(key);
  if (front) {
    hit = I18N.exact.get(front[2]);
    if (hit !== undefined) return front[1] + ' ' + hit;
  }
  var tryPats = !I18N.anyLit || I18N.anyLit.test(key);
  /* Patterns that take the whole text first; one that keeps whatever
     stands before its dash only when none of them does. */
  for (var i = 0; tryPats && i < I18N.pats.length * 2; i++) {
    var p = I18N.pats[i % I18N.pats.length];
    if (!p.pre !== (i < I18N.pats.length)) continue;
    if (p.lit && key.indexOf(p.lit) < 0) continue;
    var m = p.re.exec(key);
    if (!m || (p.weak && i18nWordy(m, depth))) continue;
    return (p.pre && m[1] ? i18nSlot(m[1], depth) + ' ' : '')
      + i18nPlural(p.text, p.slots, m).replace(/\{(\d+)\}/g, function (all, n) {
        var at = p.slots.indexOf(Number(n));
        if (at < 0) return all;
        return i18nSlot(m[at + 1], depth);
      });
  }
  /* Words with a number before or after them, where no pattern took them
     (1.10.207): "let through 17 222",
     "3 refused" - the words said, the number kept. */
  var withNum = /^(\S.*?[A-Za-z].*?)\s+([0-9][0-9\s\u00a0\u202f.,]*)$/.exec(key)
    || /^([0-9][0-9\s\u00a0\u202f.,]*?)\s+(\S.*?[A-Za-z].*)$/.exec(key);
  if (withNum) {
    var numFirst = /^[0-9]/.test(withNum[1]);
    var words = numFirst ? withNum[2] : withNum[1];
    hit = I18N.exact.get(words);
    if (hit !== undefined && hit) return numFirst ? withNum[1] + ' ' + hit : hit + ' ' + withNum[2];
  }
  /* Two or more texts the page has run together into one - "4 s ago ·
     took 9 ms", a sentence added to the end of another: each part by
     itself, the parts that have no translation left as they are. */
  if (depth < I18N_DEEP) {
    /* No lookbehind in a literal: a browser without it (Safari before
       16.4) refused this whole script, and with it every page. The end of a
       sentence is marked first and split on after. (1.10.155) */
    var parts = key.replace(/([.!?:;])\s+/g, '$1\u0001')
      .split(/(\s+[\u00b7\u2022|\u2014]\s+|\u0001)/)
      .map(function (bit) { return bit === '\u0001' ? ' ' : bit; });
    if (parts.length > 1) {
      var any = false;
      for (var k = 0; k < parts.length; k += 2) {
        if (!parts[k]) continue;
        var one = i18nText(parts[k], depth + 1);
        if (one !== null) { parts[k] = one; any = true; }
      }
      if (any) return parts.join('');
    }
  }
  return null;
}
/* What fills a pattern's slot: a number or a name stays as it is; words
   the page put there out of its own texts are translated too. */
function i18nSlot(got, depth) {
  if (!got || depth >= I18N_DEEP || !/[A-Za-z]{2}/.test(got)) return got;
  /* One word in a slot is a name - an account, a host, a list, a group -
     and a name is never translated: "Account “settings”" is somebody's
     account called settings. Words the page put there are several.
     (1.10.155) */
  if (!/\S\s+\S/.test(got.trim())) return got;
  var lead = /^\s*/.exec(got)[0], tail = /\s*$/.exec(got)[0];
  var to = i18nText(got, depth + 1);
  return to === null ? got : lead + to + tail;
}

var I18N_SKIP = {SCRIPT: 1, STYLE: 1, TEXTAREA: 1, CODE: 1, PRE: 1, INPUT: 1, NOSCRIPT: 1};
function i18nSkip(node) {
  for (var n = node; n && n.nodeType === 1; n = n.parentNode) {
    if (I18N_SKIP[n.tagName]) return true;
    if (n.isContentEditable) return true;
    if (n.classList && (n.classList.contains('mono') || n.hasAttribute('data-no-i18n'))) {
      return true;
    }
  }
  return false;
}

/* An element holding only words and inline tags, as one key. */
var I18N_INLINE = {B: 1, I: 1, EM: 1, STRONG: 1, CODE: 1, KBD: 1, BR: 1};
function i18nRichKey(el) {
  var kids = el.childNodes, inline = false, out = '';
  for (var i = 0; i < kids.length; i++) {
    var k = kids[i];
    if (k.nodeType === 3) { out += k.nodeValue; continue; }
    if (k.nodeType !== 1 || !I18N_INLINE[k.tagName]) return '';
    /* A tag the code means to find again - by an id, a class, anything -
       is never swapped away: its words are translated where they stand. */
    if (k.attributes && k.attributes.length) return '';
    inline = true;
    if (k.tagName === 'BR') { out += '<br>'; continue; }
    for (var j = 0; j < k.childNodes.length; j++) {
      if (k.childNodes[j].nodeType !== 3) return '';
    }
    var t = k.tagName.toLowerCase();
    out += '<' + t + '>' + k.textContent + '</' + t + '>';
  }
  return inline ? i18nFold(out) : '';
}
/* What a translation may hold: the same inline tags and nothing else. */
function i18nSafeHtml(s) {
  return String(s).replace(/[&<>"']/g, function (c) {
    return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
  }).replace(/&lt;(\/?)(b|i|em|strong|code|kbd)&gt;/g, '<$1$2>')
    .replace(/&lt;br\s*\/?&gt;/g, '<br>');
}
function i18nRich(el) {
  if (I18N.richOrig.has(el) || i18nSkip(el)) return false;
  var key = i18nRichKey(el);
  if (!key || !/[A-Za-z]{2}/.test(key)) return false;
  var to = I18N.rich.get(key);
  if (to === undefined) {
    for (var i = 0; i < I18N.richPats.length && to === undefined; i++) {
      var p = I18N.richPats[i];
      if (p.lit && key.indexOf(p.lit) < 0) continue;
      var m = p.re.exec(key);
      if (m && !(p.weak && i18nWordy(m))) {
        to = i18nPlural(p.text, p.slots, m).replace(/\{(\d+)\}/g, function (all, n) {
          var at = p.slots.indexOf(Number(n));
          if (at < 0) return all;
          return i18nSlot(m[at + 1], 0);
        });
      }
    }
  }
  if (to === undefined) return false;
  I18N.richOrig.set(el, key);
  /* The tags that were there stay the very same tags, in the order of
     their kind - the code that drew them may still hold one and write a
     number into it later - and only their words change. */
  var mould = document.createElement('template');
  mould.innerHTML = i18nSafeHtml(to);
  var had = {};
  Array.prototype.forEach.call(el.childNodes, function (k) {
    if (k.nodeType === 1) (had[k.tagName] = had[k.tagName] || []).push(k);
  });
  var made = mould.content;
  Array.prototype.slice.call(made.childNodes).forEach(function (k) {
    if (k.nodeType !== 1) return;
    var old = (had[k.tagName] || []).shift();
    if (!old) return;
    if (k.tagName !== 'BR') old.textContent = k.textContent;
    made.replaceChild(old, k);
  });
  while (el.firstChild) el.removeChild(el.firstChild);
  el.appendChild(made);
  return true;
}

function i18nTextNode(t, checked) {
  var p = t.parentNode;
  if (!p || p.nodeType !== 1 || (!checked && i18nSkip(p))) return;
  var now = t.nodeValue;
  if (!now || !/[A-Za-z]{2}/.test(now)) return;
  var was = I18N.orig.get(t);
  if (was && was.to === now) return;          /* our own */
  var to = i18nText(now);
  if (to === null) return;
  var lead = /^\s*/.exec(now)[0], tail = /\s*$/.exec(now)[0];
  var shown = lead + to + tail;
  I18N.orig.set(t, {from: now, to: shown});
  t.nodeValue = shown;
}

var I18N_ATTRS = ['title', 'placeholder', 'aria-label', 'alt'];
/* A box's value is never translated - it is what somebody typed - but what
   it says about itself is: its placeholder, its title, its label. They were
   skipped with the value, so every box on the page spoke English. (1.10.168) */
var I18N_BOXES = {INPUT: 1, TEXTAREA: 1};
function i18nAttrsSkip(el) {
  if (el.nodeType === 1 && I18N_BOXES[el.tagName]) {
    /* A box for a name or an address is .mono for what is typed in it, not
       for its hint: "192.0.2.1 or 192.0.2.0/24" is words (1.0.36). */
    if (el.hasAttribute('data-no-i18n')) return true;
    return !!(el.parentNode && el.parentNode.nodeType === 1 && i18nSkip(el.parentNode));
  }
  return i18nSkip(el);
}
function i18nAttrs(el, checked) {
  if (!el.getAttribute || (!checked && i18nAttrsSkip(el))) return;
  var kept = I18N.attrs.get(el) || {};
  for (var i = 0; i < I18N_ATTRS.length; i++) {
    var a = I18N_ATTRS[i];
    var v = el.getAttribute(a);
    if (!v || !/[A-Za-z]{2}/.test(v)) continue;
    if (kept[a] && kept[a].to === v) continue;
    var to = i18nText(v);
    if (to === null) continue;
    kept[a] = {from: v, to: to};
    el.setAttribute(a, to);
  }
  I18N.attrs.set(el, kept);
}

function i18nWalk(root) {
  if (!root) return;
  if (root.nodeType === 3) { i18nTextNode(root); return; }
  if (root.nodeType !== 1 && root.nodeType !== 9 && root.nodeType !== 11) return;
  if (root.nodeType === 1 && I18N_BOXES[root.tagName]) {
    if (!i18nAttrsSkip(root)) i18nAttrs(root, true);
    return;
  }
  if (root.nodeType === 1 && i18nSkip(root)) return;
  /* Whole sentences first, where an element is only words and inline tags. */
  var inl = root.querySelectorAll ? root.querySelectorAll('b, i, em, strong, code, kbd, br') : [];
  var seen = new Set();
  for (var i = 0; i < inl.length; i++) {
    var par = inl[i].parentNode;
    if (par && par.nodeType === 1) seen.add(par);
  }
  if (root.nodeType === 1) seen.add(root);
  seen.forEach(function (one) { i18nRich(one); });
  var walker = document.createTreeWalker(root, 5 /* elements and text */, null, false);
  var n = root.nodeType === 1 ? root : walker.nextNode();
  while (n) {
    /* Everything above has been looked at by now, so each node only
       needs its own kind checked, never its ancestors again. */
    if (n.nodeType === 3) i18nTextNode(n, true);
    else if (n.nodeType === 1) {
      /* A .mono box's hint is words too (1.0.103), as i18nAttrsSkip says:
         inside something drawn later it stayed English. */
      if (I18N_BOXES[n.tagName] && n.attributes.length && !n.hasAttribute('data-no-i18n')) {
        i18nAttrs(n, true);
      }
      if (I18N_SKIP[n.tagName] || n.contentEditable === 'true'
          || (n.classList && (n.classList.contains('mono')
          || n.hasAttribute('data-no-i18n')))) {
        n = i18nNextOutside(walker, n);
        continue;
      }
      if (n.attributes.length) i18nAttrs(n, true);
    }
    n = walker.nextNode();
  }
}
function i18nNextOutside(walker, n) {
  var next = walker.nextSibling();
  while (!next) {
    var up = walker.parentNode();
    if (!up) return null;
    next = walker.nextSibling();
  }
  return next;
}

/** The English an element showed before it was translated - for the code
    that reads words back off the page and decides something by them. */
function srcText(el) {
  if (!el) return '';
  if (!I18N.on) return el.textContent;
  if (el.nodeType === 3) {
    var o = I18N.orig.get(el);
    return o && o.to === el.nodeValue ? o.from : el.nodeValue;
  }
  if (I18N.richOrig.has(el)) return I18N.richOrig.get(el).replace(/<[^>]*>/g, '');
  var out = '';
  for (var i = 0; i < el.childNodes.length; i++) out += srcText(el.childNodes[i]);
  return out;
}

(function () {
  var pack = window.OTP_LANG_PACK;
  var root = document.documentElement;
  var release = function () { root.classList.remove('i18n-wait'); };
  try {
    if (!i18nInit(pack)) { release(); return; }
  } catch (e) {
    I18N.on = false;
    release();
    return;
  }
  root.setAttribute('lang', I18N.code);
  var watch = new MutationObserver(function (records) {
    try {
      for (var i = 0; i < records.length; i++) {
        var r = records[i];
        if (r.type === 'childList') {
          /* Drawn again by the page: whatever was swapped whole is the
             page's own words again, and is looked at afresh. */
          if (r.target.nodeType === 1 && I18N.richOrig.has(r.target)) {
            I18N.richOrig['delete'](r.target);
          }
          for (var j = 0; j < r.addedNodes.length; j++) i18nWalk(r.addedNodes[j]);
          if (r.target.nodeType === 1) i18nRich(r.target);
        } else if (r.type === 'characterData') {
          i18nTextNode(r.target);
        } else if (r.type === 'attributes') {
          i18nAttrs(r.target);
        }
      }
    } catch (e) { /* a word left in English is never worth a broken page */ }
    watch.takeRecords();
  });
  watch.observe(root, {childList: true, subtree: true, characterData: true, attributes: true,
                       attributeFilter: I18N_ATTRS});
  var first = function () {
    try { i18nWalk(document.body); } catch (e) { /* as above */ }
    watch.takeRecords();
    /* The title is the installation's name and its host, never translated -
       but the words around it are (1.0.36): "One-time passwords". */
    try {
      var tt = i18nText(document.title);
      if (tt) document.title = tt;
    } catch (e) { /* as above */ }
    release();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', first);
  else first();
  /* Never a page left hidden because something above went wrong. */
  setTimeout(release, 2500);
})();
