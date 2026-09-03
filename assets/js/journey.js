/* -------------------------------------------------------
   JOURNEY — development journal.

   Entries are JSON files under assets/journal/, listed in
   assets/journal/index.json (a JSON array of file names).
   Each file holds one entry object, or an array of them:

     {
       "title":    "…",
       "date":     "YYYY-MM-DD",
       "tldr":     "one-line summary",
       "contents": ["markdown block", "markdown block", …],
       "tags":     ["tag", …],
       "id":       "optional-anchor"
     }

   Filters: date, title (single entry), free-text search.
   Markdown is rendered with the vendored `marked` build; if
   it is missing, blocks fall back to escaped paragraphs.
------------------------------------------------------- */
(function () {
  'use strict';

  const JOURNAL_DIR = 'assets/journal/';
  const MANIFEST    = JOURNAL_DIR + 'index.json';
  /* Single minified bundle written by tools/build-assets.sh (one request
     instead of one per entry). Falls back to the manifest when absent. */
  const BUNDLE      = JOURNAL_DIR + 'journal.min.json';
  const TITLE_MAX   = 48;
  const PAGE_SIZE   = 3;   /* entries shown per page, newest first */

  /* ── pure helpers ─────────────────────────────────── */
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
  }

  /* Titles and summaries are prose: they may carry HTML entities
     (&reg;, &copy;, &amp;) and inline markdown, exactly like the body
     blocks. Escaping them raw would print the entity source instead. */
  const ENTITIES = {
    amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0',
    reg: '\u00ae', copy: '\u00a9', trade: '\u2122', deg: '\u00b0',
    mdash: '\u2014', ndash: '\u2013', hellip: '\u2026', middot: '\u00b7',
    times: '\u00d7', rarr: '\u2192', larr: '\u2190', laquo: '\u00ab', raquo: '\u00bb',
    lsquo: '\u2018', rsquo: '\u2019', ldquo: '\u201c', rdquo: '\u201d',
  };

  function decodeEntities(str) {
    return String(str == null ? '' : str).replace(/&(#x[0-9a-f]+|#\d+|[a-z][a-z0-9]*);/gi, (m, g) => {
      if (g[0] === '#') {
        const n = g[1].toLowerCase() === 'x' ? parseInt(g.slice(2), 16) : parseInt(g.slice(1), 10);
        return Number.isFinite(n) && n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
      }
      const v = ENTITIES[g.toLowerCase()];
      return v === undefined ? m : v;
    });
  }

  /* Inline markdown only — no wrapping <p>, safe inside a heading or button. */
  function renderInline(md) {
    const m = (typeof marked !== 'undefined') ? marked : null;
    if (m && typeof m.parseInline === 'function') {
      try { return m.parseInline(String(md == null ? '' : md)); } catch (err) { /* fall through */ }
    }
    return esc(decodeEntities(md));
  }

  /* Plain text for dropdown labels, tooltips and the search index. */
  function plainText(md) {
    return decodeEntities(String(md == null ? '' : md))
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/[*_`]+/g, '')
      .trim();
  }

  function slugify(s) {
    return String(s || '')
      .toLowerCase()
      .replace(/\.json$/, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'entry';
  }

  /* Dropdown label: the title alone, cut at a word boundary when long. */
  function shortTitle(t, max = TITLE_MAX) {
    const str = String(t || '').trim();
    if (str.length <= max) return str;
    const cut = str.slice(0, max - 1);
    const sp  = cut.lastIndexOf(' ');
    return (sp > max * 0.6 ? cut.slice(0, sp) : cut).replace(/[\s,;:.\-]+$/, '') + '…';
  }

  function asList(v) {
    if (Array.isArray(v)) return v;
    if (v == null || v === '') return [];
    return [v];
  }

  function renderMarkdown(md) {
    const m = (typeof marked !== 'undefined') ? marked : null;
    if (m && typeof m.parse === 'function') {
      try { return m.parse(md); } catch (err) { /* fall through to plain text */ }
    }
    return '<p>' + esc(md).replace(/\n{2,}/g, '</p><p>').replace(/\n/g, '<br>') + '</p>';
  }

  /* Normalise raw JSON into a predictable entry. `file` is the
     manifest name; `idx`/`count` distinguish entries that share a file. */
  function normalize(raw, file, idx, count) {
    const o = (raw && typeof raw === 'object') ? raw : {};
    const base = slugify(file);
    const id = o.id ? slugify(o.id) : (count > 1 ? `${base}-${idx + 1}` : base);
    const contents = asList(o.contents)
      .map(c => (c == null ? '' : String(c)))
      .filter(c => c.trim() !== '');
    const tags = asList(o.tags).map(t => String(t).trim()).filter(Boolean);
    const rawDate = String(o.date || '');
    const date = /^\d{4}-\d{2}-\d{2}/.test(rawDate) ? rawDate.slice(0, 10) : '';
    const e = {
      id,
      file,
      title: String(o.title || '').trim() || 'Untitled',
      date,
      tldr: String(o.tldr || o['tl;dr'] || o["tl'dr"] || o.summary || '').trim(),
      contents,
      tags,
    };
    e.plainTitle = plainText(e.title);
    e.hay = plainText([e.title, e.date, e.tldr, e.tags.join(' '), e.contents.join(' ')].join(' ')).toLowerCase();
    return e;
  }

  /* Newest first; undated entries last; manifest order breaks ties. */
  function sortEntries(list) {
    return list.slice().sort((a, b) => {
      if (a.date !== b.date) {
        if (!a.date) return 1;
        if (!b.date) return -1;
        return b.date.localeCompare(a.date);
      }
      return (a._ord || 0) - (b._ord || 0);
    });
  }

  function filterEntries(list, f) {
    const q = String(f.q || '').trim().toLowerCase();
    return list.filter(e => {
      if (f.date && e.date !== f.date) return false;
      if (f.id && e.id !== f.id) return false;
      if (q && !e.hay.includes(q)) return false;
      return true;
    });
  }

  /* Slice a filtered list into one page. `page` is 1-based and clamped, so
     a shrinking result set never strands the reader on an empty page. */
  function paginate(list, page, size = PAGE_SIZE) {
    const total = list.length;
    const pageCount = Math.max(1, Math.ceil(total / size));
    const current = Math.min(Math.max(1, Math.floor(page) || 1), pageCount);
    const start = (current - 1) * size;
    const end = Math.min(start + size, total);
    return { page: current, pageCount, total, start, end, items: list.slice(start, end) };
  }

  /* Page numbers to show: always the first and last, plus a window around the
     current page, with gaps marked by null. */
  function pageWindow(current, pageCount, span = 1) {
    const keep = new Set([1, pageCount]);
    for (let p = current - span; p <= current + span; p++) {
      if (p >= 1 && p <= pageCount) keep.add(p);
    }
    const sorted = [...keep].sort((a, b) => a - b);
    const out = [];
    sorted.forEach((p, i) => {
      if (i && p - sorted[i - 1] > 1) out.push(null);
      out.push(p);
    });
    return out;
  }

  /* ── loading ──────────────────────────────────────── */
  function resolveFile(name) {
    const n = String(name).replace(/^\.\//, '');
    return (/^(\/|[a-z]+:\/\/)/i.test(n)) ? n : JOURNAL_DIR + n;
  }

  async function fetchJson(url) {
    const res = await fetch(url, { cache: 'no-cache' });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    return res.json();
  }

  async function loadSources() {
    const bundle = await fetchJson(BUNDLE).catch(() => null);
    if (bundle && Array.isArray(bundle.files)) {
      return {
        sources: bundle.files.map(f => ({ name: String(f.file || ''), raw: f.data })),
        errors: [],
      };
    }
    const manifest = await fetchJson(MANIFEST);
    const files = Array.isArray(manifest) ? manifest : asList(manifest && manifest.entries);
    const results = await Promise.allSettled(files.map(async file => {
      const name = String(file);
      return { name, raw: await fetchJson(resolveFile(name)) };
    }));
    const sources = [], errors = [];
    results.forEach((r, i) => {
      if (r.status === 'fulfilled') sources.push(r.value);
      else errors.push(`${files[i]}: ${r.reason && r.reason.message ? r.reason.message : r.reason}`);
    });
    return { sources, errors };
  }

  async function loadEntries() {
    const { sources, errors } = await loadSources();
    const entries = [];
    sources.forEach((src, i) => {
      const items = Array.isArray(src.raw) ? src.raw : [src.raw];
      items.forEach((it, j) => {
        const e = normalize(it, src.name, j, items.length);
        e._ord = i * 1000 + j;
        e.html = e.contents.map(c => `<div class="jr-block">${renderMarkdown(c)}</div>`).join('');
        entries.push(e);
      });
    });
    return { entries: sortEntries(entries), errors };
  }

  /* ── rendering ────────────────────────────────────── */
  function tagChips(tags) {
    return tags.map(t =>
      `<button type="button" class="tag-chip jr-tag" data-tag="${esc(t)}" title="Search for ${esc(t)}">${esc(t)}</button>`
    ).join('');
  }

  function toggleLabel(open) {
    return open ? '&#x25B4; COLLAPSE' : '&#x25BE; READ';
  }

  function renderCard(e, open) {
    const bodyId = `${e.id}-body`;
    return `
<article class="jr-card${open ? ' open' : ''}" id="${esc(e.id)}" data-id="${esc(e.id)}">
  <header class="jr-head">
    <div class="jr-meta">
      <span class="jr-date">${esc(e.date || 'undated')}</span>
      ${e.tags.length ? `<span class="jr-tags">${tagChips(e.tags)}</span>` : ''}
    </div>
    <h3 class="jr-title"><button type="button" class="jr-toggle" aria-expanded="${open}" aria-controls="${esc(bodyId)}">${renderInline(e.title)}</button></h3>
    ${e.tldr ? `<p class="jr-tldr">${renderInline(e.tldr)}</p>` : ''}
    <div class="jr-actions">
      <button type="button" class="tbtn jr-toggle jr-toggle-btn" aria-expanded="${open}" aria-controls="${esc(bodyId)}">${toggleLabel(open)}</button>
      <a class="jr-link" href="#${esc(e.id)}" title="Link to this entry">#${esc(e.id)}</a>
    </div>
  </header>
  <div class="jr-body md" id="${esc(bodyId)}"${open ? '' : ' hidden'}>${e.html || '<p class="jr-empty">No contents.</p>'}</div>
</article>`;
  }

  function renderPager(info) {
    if (info.pageCount <= 1) return '';
    const btn = (label, page, opts = {}) =>
      `<button type="button" class="jr-page${opts.on ? ' on' : ''}" data-page="${page}"` +
      `${opts.disabled ? ' disabled' : ''}${opts.on ? ' aria-current="page"' : ''}` +
      `${opts.label ? ` aria-label="${esc(opts.label)}"` : ''}>${label}</button>`;
    const nums = pageWindow(info.page, info.pageCount)
      .map(p => p === null
        ? '<span class="jr-page-gap" aria-hidden="true">&hellip;</span>'
        : btn(String(p), p, { on: p === info.page, label: `Page ${p}` }))
      .join('');
    return `<nav class="jr-pager" aria-label="Journal pages">` +
      btn('&lsaquo;', info.page - 1, { disabled: info.page <= 1, label: 'Previous page' }) +
      nums +
      btn('&rsaquo;', info.page + 1, { disabled: info.page >= info.pageCount, label: 'Next page' }) +
      `</nav>`;
  }

  /* ── page wiring ──────────────────────────────────── */
  function init() {
    const list   = document.getElementById('jr-list');
    const status = document.getElementById('jr-status');
    if (!list || !status) return;

    const selDate  = document.getElementById('jf-date');
    const selTitle = document.getElementById('jf-title');
    const inpQ     = document.getElementById('jf-q');
    const btnClear = document.getElementById('jf-clear');
    const count    = document.getElementById('jf-count');
    const pager    = document.getElementById('jr-pager');

    let entries = [];
    let page = 1;
    const openIds = new Set();

    const setStatus = html => { status.innerHTML = html || ''; status.hidden = !html; };

    function setOptions(sel, options) {
      const keep = sel.value;
      const first = sel.options[0] ? sel.options[0].outerHTML : '<option value="">All</option>';
      sel.innerHTML = first + options.map(([v, l, t]) =>
        `<option value="${esc(v)}"${t && t !== l ? ` title="${esc(t)}"` : ''}>${esc(l)}</option>`).join('');
      sel.value = options.some(([v]) => v === keep) ? keep : '';
    }

    function fillDates() {
      const dates = [...new Set(entries.map(e => e.date).filter(Boolean))].sort((a, b) => b.localeCompare(a));
      setOptions(selDate, dates.map(d => [d, d]));
    }

    /* Title list is constrained by the chosen date, matrix-style. */
    function fillTitles() {
      const d = selDate.value;
      const pool = d ? entries.filter(e => e.date === d) : entries;
      setOptions(selTitle, pool.map(e => [e.id, shortTitle(e.plainTitle), e.plainTitle]));
    }

    function render() {
      const f = { date: selDate.value, id: selTitle.value, q: inpQ.value };
      const matched = filterEntries(entries, f);
      if (f.id) matched.forEach(e => openIds.add(e.id));

      const info = paginate(matched, page);
      page = info.page;
      list.innerHTML = info.items.map(e => renderCard(e, openIds.has(e.id))).join('');
      if (pager) pager.innerHTML = renderPager(info);

      const total = entries.length;
      const noun = `entr${total === 1 ? 'y' : 'ies'}`;
      if (!info.total) {
        count.textContent = `0 of ${total} ${noun}`;
      } else if (info.pageCount > 1) {
        count.textContent = `${info.start + 1}\u2013${info.end} of ${info.total} ${noun} \u00b7 page ${info.page}/${info.pageCount}`;
      } else {
        count.textContent = `${info.total} of ${total} ${noun}`;
      }

      if (!info.total) {
        setStatus(total ? 'No entries match the current filters.' : 'No journal entries yet.');
      } else if (status.dataset.sticky !== '1') {
        setStatus('');
      }
    }

    /* Filters change what is being paged through, so restart at page 1. */
    function refilter() {
      page = 1;
      render();
    }

    function goToPage(n) {
      const before = page;
      page = n;
      render();
      if (page !== before) {
        const top = document.getElementById('p-journey');
        const scroller = top ? top.querySelector('.canvas') : null;
        if (scroller && typeof scroller.scrollTo === 'function') scroller.scrollTo({ top: 0, behavior: 'smooth' });
      }
    }

    function setOpen(card, open) {
      const id = card.dataset.id;
      if (open) openIds.add(id); else openIds.delete(id);
      card.classList.toggle('open', open);
      const body = card.querySelector('.jr-body');
      if (body) body.hidden = !open;
      card.querySelectorAll('.jr-toggle').forEach(b => b.setAttribute('aria-expanded', String(open)));
      const btn = card.querySelector('.jr-toggle-btn');
      if (btn) btn.innerHTML = toggleLabel(open);
    }

    function revealHash() {
      const id = decodeURIComponent((location.hash || '').replace(/^#/, ''));
      if (!id || !entries.some(e => e.id === id)) return;
      openIds.add(id);

      /* Clear filters that hide the target, then page to where it landed. */
      const visible = () => filterEntries(entries, { date: selDate.value, id: selTitle.value, q: inpQ.value });
      if (!visible().some(e => e.id === id)) {
        selDate.value = ''; fillTitles(); selTitle.value = ''; inpQ.value = '';
      }
      const idx = visible().findIndex(e => e.id === id);
      if (idx >= 0) page = Math.floor(idx / PAGE_SIZE) + 1;
      render();

      const card = document.getElementById(id);
      if (card && card.classList.contains('jr-card')) {
        setOpen(card, true);
        card.scrollIntoView({ block: 'start', behavior: 'smooth' });
      }
    }

    list.addEventListener('click', ev => {
      const tag = ev.target.closest('.jr-tag');
      if (tag) {
        inpQ.value = tag.dataset.tag || '';
        refilter();
        return;
      }
      const toggle = ev.target.closest('.jr-toggle');
      if (toggle) {
        const card = toggle.closest('.jr-card');
        if (card) setOpen(card, !card.classList.contains('open'));
      }
    });

    if (pager) {
      pager.addEventListener('click', ev => {
        const b = ev.target.closest('.jr-page');
        if (!b || b.disabled) return;
        const n = parseInt(b.dataset.page, 10);
        if (Number.isFinite(n)) goToPage(n);
      });
    }

    selDate.addEventListener('change', () => { fillTitles(); refilter(); });
    selTitle.addEventListener('change', refilter);
    inpQ.addEventListener('input', refilter);
    btnClear.addEventListener('click', () => {
      selDate.value = ''; fillTitles(); selTitle.value = ''; inpQ.value = '';
      refilter();
    });
    window.addEventListener('hashchange', revealHash);

    setStatus('Loading journal&hellip;');
    loadEntries().then(({ entries: loaded, errors }) => {
      entries = loaded;
      fillDates();
      fillTitles();
      if (errors.length) {
        status.dataset.sticky = '1';
        setStatus(`<b>Some entries could not be loaded.</b><br>${errors.map(esc).join('<br>')}`);
      }
      refilter();
      revealHash();
    }).catch(err => {
      const hint = (location.protocol === 'file:')
        ? '<br>Entries are fetched over HTTP. Open the site through a web server (for example <code>python3 -m http.server</code>) rather than a file:// URL.'
        : '';
      status.dataset.sticky = '1';
      setStatus(`<b>Could not load the journal.</b><br>${esc(err && err.message ? err.message : err)}${hint}`);
      count.textContent = '';
    });
  }

  /* Expose the pure helpers for tests and for other scripts. */
  const root = (typeof window !== 'undefined') ? window : globalThis;
  root.JOURNEY = {
    normalize, sortEntries, filterEntries, paginate, pageWindow,
    renderMarkdown, renderInline, renderCard, renderPager,
    slugify, shortTitle, decodeEntities, plainText, PAGE_SIZE,
  };

  if (typeof document !== 'undefined') {
    window.addEventListener('DOMContentLoaded', init);
  }
})();
