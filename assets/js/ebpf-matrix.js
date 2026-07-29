/* -------------------------------------------------------
   eBPF MATRIX — sortable table over the capability matrix
   Model, filters and detail panel live in ebpf-core.js
------------------------------------------------------- */

const COLS = ['details','domain','prog','kind','object','scope','since','requires'];

let ebRows = [];
let sCol = 'prog', sAsc = true;

/* -------------------------------------------------------
   ROWS — one per program-to-object relationship, plus the
   syscall commands and unattached objects the graph also shows.
------------------------------------------------------- */
function buildRows() {
  const rows = [];

  EBPF.programs.forEach((p, pi) => {
    if (!progPasses(p)) return;
    const before = rows.length;
    KINDS.forEach(kind => {
      usesOf(p, kind).forEach(e => {
        const o = objOf(kind, e.target);
        if (!edgeInScope(e) || !leafPasses(kind, o.name)) return;
        rows.push({
          domain:p.domain, prog:p.short, progIdx:pi,
          kind, oi:e.target, object:o.name, desc:o.description,
          scope:e.scope, since:e.since || o.since || '',
          requires:[...(e.caps||[]), ...(e.kconfig||[]), ...(e.flags||[]), ...(e.attach||[])]
        });
      });
    });
    // A program type with nothing in the current scope still gets a row, so the
    // table lists the same program types the graph draws.
    if (rows.length === before) rows.push({
      domain:p.domain, prog:p.short, progIdx:pi, placeholder:true,
      kind:'', oi:null, object:'', desc:p.description,
      scope:'', since:p.since || '', requires:[]
    });
  });

  if (syscallsShown()) {
    OBJ.syscall.forEach((s, i) => {
      if (F.sys && s.name !== F.sys) return;
      rows.push({
        domain:'', prog:'', progIdx:null,
        kind:'syscall', oi:i, object:s.name, desc:s.description,
        scope:'', since:s.since || '', requires:[], family:s.family
      });
    });
  }

  if (unattachedShown()) {
    KINDS.forEach(kind => {
      UNATTACHED[kind].forEach(({o, i}) => {
        if (!leafPasses(kind, o.name)) return;
        rows.push({
          domain:'', prog:'', progIdx:null,
          kind, oi:i, object:o.name, desc:o.description,
          scope:'', since:o.since || '', requires:[], unattached:true
        });
      });
    });
  }

  return rows;
}

function rowText(r) {
  return [r.domain, r.prog, EB_KIND_LABEL[r.kind], r.object, r.desc, r.scope,
          r.since, r.requires.join(' ')].filter(Boolean).join(' ').toLowerCase();
}

/* Row totals quoted next to the filters — the unfiltered row count. */
function totalRowCount() {
  const s = EBPF.stats;
  return s.total_relationships + s.total_syscall_commands + s.unattached_helpers +
         s.unattached_map_types + s.unattached_kfuncs +
         EBPF.programs.filter(p => !KINDS.some(k => usesOf(p, k).length)).length;
}

function sortRows(rows) {
  const dir = sAsc ? 1 : -1;
  const blank = r => sCol === 'requires' ? !r.requires.length : !r[sCol];
  return rows.sort((a, b) => {
    // Rows with nothing in the sorted column stay at the bottom either way.
    if (blank(a) !== blank(b)) return blank(a) ? 1 : -1;
    let d;
    if (sCol === 'since')          d = cmpVersion(a.since, b.since);
    else if (sCol === 'requires')  d = a.requires.join(' ').localeCompare(b.requires.join(' '));
    else if (sCol === 'kind')      d = (EB_KIND_LABEL[a.kind]||'').localeCompare(EB_KIND_LABEL[b.kind]||'');
    else                           d = String(a[sCol]||'').localeCompare(String(b[sCol]||''));
    // Ties fall back to program then object so the order is always stable.
    return dir * (d || String(a.prog).localeCompare(String(b.prog)) ||
                       a.object.localeCompare(b.object));
  });
}

/* -------------------------------------------------------
   CELLS
------------------------------------------------------- */
const EMPTY = `<span style="color:var(--text-dim)">—</span>`;

function fmtCell(col, r, i) {
  switch (col) {
    case 'details':
      return `<a class="details-link" href="#" data-row="${i}" title="Open details panel" aria-label="Open details panel" onclick="event.preventDefault()">
        <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <path d="M8 1.75c3.45 0 6.25 2.8 6.25 6.25S11.45 14.25 8 14.25 1.75 11.45 1.75 8 4.55 1.75 8 1.75Z" stroke="currentColor" stroke-width="1.5"/>
          <path d="M8 7v3.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="8" cy="4.8" r="0.9" fill="currentColor"/>
        </svg>
      </a>`;
    case 'domain':
      return r.domain
        ? `<span class="tag ${EB_TAG_CLASS.domain}">${escHtml(r.domain.replace(' program types',''))}</span>`
        : EMPTY;
    case 'prog':
      return r.prog
        ? `<span class="tag ${EB_TAG_CLASS.program}" data-prog="${r.progIdx}" title="Show program type details">${escHtml(r.prog)}</span>`
        : `<span class="td-dim" style="font-size:11px">${r.unattached ? 'unattached' : 'bpf() syscall'}</span>`;
    case 'kind':
      return r.kind
        ? `<span class="tag ${EB_TAG_CLASS[r.kind]}">${escHtml(EB_KIND_LABEL[r.kind])}</span>`
        : EMPTY;
    case 'object':
      return r.placeholder
        ? `<span class="td-dim">No helper, map or kfunc relationships in this scope</span>`
        : `<span class="td-mono" style="color:var(--text)">${escHtml(r.object)}</span>` +
          (r.desc ? `<div class="td-dim" style="margin-top:2px;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(r.desc)}</div>` : '');
    case 'scope':
      return r.scope
        ? `<span class="tag ${r.scope==='core'?'t-key':'t-an'}">${escHtml(r.scope)}</span>`
        : EMPTY;
    case 'since':
      return r.since ? `<span class="td-mono">${escHtml(kver(r.since))}</span>` : EMPTY;
    case 'requires':
      return r.requires.length
        ? `<div style="display:flex;flex-wrap:wrap;gap:3px">${r.requires.map(v=>`<span class="sp-chip" style="font-size:9px;padding:1px 5px">${escHtml(v)}</span>`).join('')}</div>`
        : EMPTY;
    default:
      return EMPTY;
  }
}

/* -------------------------------------------------------
   RENDER
------------------------------------------------------- */
function renderTable() {
  const rows  = sortRows(ebRows.filter(r => !F.q || rowText(r).includes(F.q)));
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = rows.map((r, i) =>
    `<tr>${COLS.map(c => `<td${c==='details' ? ' class="td-details"' : ''}>${fmtCell(c, r, i)}</td>`).join('')}</tr>`
  ).join('');

  document.getElementById('rn').textContent = rows.length;
  document.getElementById('rt').textContent = totalRowCount();

  // Delegated — covers every row regardless of count or scroll position.
  tbody.onclick = e => {
    const btn = e.target.closest('.details-link');
    if (btn) { e.stopPropagation(); const r = rows[+btn.dataset.row]; if (r) openRowPanel(r); return; }
    const prog = e.target.closest('[data-prog]');
    if (prog) { e.stopPropagation(); openProgramPanel(+prog.dataset.prog); }
  };
  tbody.onmouseover = e => {
    const tr = e.target.closest('tr');
    if (tr && tr.parentNode === tbody) tr.classList.add('row-hl');
  };
  tbody.onmouseout = e => {
    const tr = e.target.closest('tr');
    if (tr && tr.parentNode === tbody) tr.classList.remove('row-hl');
  };
}

/* The panel shows the object plus this row's gating metadata. */
function openRowPanel(r) {
  if (r.placeholder) { openProgramPanel(r.progIdx); return; }
  const o = objOf(r.kind, r.oi);
  openPanel({ data:{
    type:r.kind, kind:r.kind, oi:r.oi, name:o.name, url:o.url,
    prog:r.prog, scope:r.scope,
    caps:r.requires.filter(v => v.startsWith('CAP_')),
    kconfig:r.requires.filter(v => v.startsWith('CONFIG_')),
    flags:r.requires.filter(v => v.startsWith('KF_')),
    attach:r.requires.filter(v => v.startsWith('BPF_'))
  }});
}

function rebuildTable() {
  ebRows = buildRows();
  renderTable();
}

/* -------------------------------------------------------
   BOOT
------------------------------------------------------- */
window.addEventListener('DOMContentLoaded', () => {
  const status = document.getElementById('eb-status');
  if (!ebInit(rebuildTable)) {
    if (status) status.innerHTML = 'Could not load <code>assets/data/ebpf.js</code>';
    return;
  }
  if (status) status.remove();

  document.querySelectorAll('#tbl th').forEach(th => {
    th.addEventListener('click', () => {
      const c = th.dataset.c;
      if (!c) return;
      document.querySelectorAll('#tbl th').forEach(h => h.classList.remove('sa','sd'));
      if (sCol === c) sAsc = !sAsc; else { sCol = c; sAsc = true; }
      th.classList.add(sAsc ? 'sa' : 'sd');
      renderTable();
    });
  });

  cascade();
});
