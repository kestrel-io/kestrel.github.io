/* -------------------------------------------------------
   SIGNALS MATRIX — sortable table over the same map inventory
   Model, filters and detail panel live in signals-core.js

   One row per map, so the visualization and the table answer
   with the same numbers: the row's producer and consumer cells
   are the graph's two halves written out.
------------------------------------------------------- */

const COLS = ['details', 'name', 'family', 'type', 'scope', 'key', 'value',
              'producers', 'consumers', 'flow', 'owners'];

let sCol = 'name', sAsc = true;

const cellText = {
  name:      m => m.name,
  family:    m => m.family,
  type:      m => m.type,
  scope:     m => SCOPE_LABEL[m.scope] || m.scope,
  key:       m => m.key || '',
  value:     m => m.value || '',
  producers: m => m.producers.length,
  consumers: m => m.consumers.length,
  flow:      m => SIGNALS.flow_label[m.flow] || m.flow,
  owners:    m => (m.owners.length ? PROGS[m.owners[0]].name : ''),
};

function sortRows(rows) {
  const dir = sAsc ? 1 : -1;
  const get = cellText[sCol] || cellText.name;
  return rows.sort((a, b) => {
    const va = get(a), vb = get(b);
    const d = typeof va === 'number'
      ? va - vb
      : String(va).localeCompare(String(vb));
    /* Ties fall back to the map name, so the order never wobbles. */
    return dir * (d || a.name.localeCompare(b.name));
  });
}

/* -------------------------------------------------------
   CELLS
------------------------------------------------------- */
const EMPTY = `<span style="color:var(--text-dim)">—</span>`;

/* A lane ring has 28 producers; spelled out, one row would be taller than the
   screen. The cell shows the first few and says how many it is holding back —
   the details panel has the whole list, with the call sites. */
const CHIP_CAP = 6;

function progChips(ids, cls, i) {
  if (!ids.length) return EMPTY;
  const shown = ids.slice(0, CHIP_CAP).map(pi =>
    `<span class="sig-chip ${cls}" data-prog="${pi}" ` +
    `title="${escHtml(DOMAIN_LABEL[PROGS[pi].domain] || PROGS[pi].domain)} program — open details">` +
    `${escHtml(PROGS[pi].name)}</span>`).join('');
  const rest = ids.length - CHIP_CAP;
  return `<div class="sig-chip-row">${shown}${rest > 0
    ? `<span class="sig-chip sig-chip-more" data-row="${i}">+${rest} more</span>` : ''}</div>`;
}

function fmtCell(col, m, i) {
  switch (col) {
    case 'details':
      return `<a class="details-link" href="#" data-row="${i}" title="Open details panel" aria-label="Open details panel" onclick="event.preventDefault()">
        <svg viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <path d="M8 1.75c3.45 0 6.25 2.8 6.25 6.25S11.45 14.25 8 14.25 1.75 11.45 1.75 8 4.55 1.75 8 1.75Z" stroke="currentColor" stroke-width="1.5"/>
          <path d="M8 7v3.4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
          <circle cx="8" cy="4.8" r="0.9" fill="currentColor"/>
        </svg>
      </a>`;
    case 'name':
      return `<span class="td-mono" style="color:var(--text);font-size:12px">${escHtml(m.name)}</span>` +
             (m.pinned ? `<span class="sp-chip" style="margin-left:6px;font-size:9px;padding:1px 5px">pinned</span>` : '');
    case 'family':
      return `<span class="tag t-tech">${escHtml(m.family)}</span>` +
             (m.blurb ? `<div class="td-dim sig-clip">${escHtml(m.blurb)}</div>` : '');
    case 'type':
      return `<span class="td-mono">${escHtml(m.type)}</span>` +
             (entriesOf(m) ? `<div class="td-dim" style="font-size:11px">max ${escHtml(entriesOf(m))}</div>` : '');
    case 'scope':
      return `<span class="tag ${m.scope === 'shared' ? 't-key' : m.scope === 'per-object' ? 't-sub' : 't-an'}">` +
             `${escHtml(SCOPE_LABEL[m.scope])}</span>` +
             (m.owners.length > 1 ? `<div class="td-dim" style="font-size:11px">${m.owners.length} objects</div>` : '');
    case 'key':
      return m.key ? `<span class="td-mono">${escHtml(m.key)}</span>` : EMPTY;
    case 'value':
      return m.value ? `<span class="td-mono">${escHtml(m.value)}</span>` : EMPTY;
    case 'producers':
      return progChips(m.producers.map(e => e.prog), 'sig-chip-p', i);
    case 'consumers':
      return progChips(m.consumers.map(e => e.prog), 'sig-chip-c', i);
    case 'flow':
      return `<span class="sig-flow-cell" style="color:${FLOW_COLOR[m.flow]}">` +
             `<i style="background:${FLOW_COLOR[m.flow]}"></i>${escHtml(FLOW_SHORT[m.flow])}</span>`;
    case 'owners':
      return progChips(m.owners, '', i);
    default:
      return EMPTY;
  }
}

/* -------------------------------------------------------
   RENDER
------------------------------------------------------- */
function renderTable() {
  const rows = sortRows(shownMaps());
  const tbody = document.getElementById('tbody');
  tbody.innerHTML = rows.map((m, i) =>
    `<tr>${COLS.map(c => `<td${c === 'details' ? ' class="td-details"' : ''}>${fmtCell(c, m, i)}</td>`).join('')}</tr>`
  ).join('');

  document.getElementById('rn').textContent = rows.length;
  document.getElementById('rt').textContent = MAPS.length;

  /* Delegated — one handler covers every row, however long the table. */
  tbody.onclick = e => {
    const btn = e.target.closest('.details-link');
    if (btn) { e.stopPropagation(); openMapPanel(MAPS.indexOf(rows[+btn.dataset.row])); return; }
    const more = e.target.closest('.sig-chip-more');
    if (more) { e.stopPropagation(); openMapPanel(MAPS.indexOf(rows[+more.dataset.row])); return; }
    const chip = e.target.closest('[data-prog]');
    if (chip) { e.stopPropagation(); openProgPanel(+chip.dataset.prog); }
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

/* -------------------------------------------------------
   BOOT
------------------------------------------------------- */
window.addEventListener('DOMContentLoaded', () => {
  const status = document.getElementById('sg-status');
  if (!sigInit(renderTable)) {
    if (status) status.innerHTML = 'Could not load <code>assets/data/signals.js</code>';
    return;
  }
  if (status) status.remove();

  document.querySelectorAll('#tbl th').forEach(th => {
    th.addEventListener('click', () => {
      const c = th.dataset.c;
      if (!c) return;
      document.querySelectorAll('#tbl th').forEach(h => h.classList.remove('sa', 'sd'));
      if (sCol === c) sAsc = !sAsc; else { sCol = c; sAsc = true; }
      th.classList.add(sAsc ? 'sa' : 'sd');
      renderTable();
    });
  });
  const first = document.querySelector('#tbl th[data-c="name"]');
  if (first) first.classList.add('sa');

  const about = document.getElementById('sg-about');
  if (about) about.addEventListener('click', openAboutPanel);

  cascade();
});
