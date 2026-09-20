/* -------------------------------------------------------
   SIGNALS VISUALIZED — producer → map → consumer flow
   Model, filters and detail panel live in signals-core.js

   Three columns, because the question has three parts: who
   writes the map, the map, who reads it. A program that does
   both appears on both sides — that is not a duplicate, it is
   the two halves of what it does, and drawing it once in the
   middle would hide the direction the page is about.
------------------------------------------------------- */

const COL_W   = 250;    /* tile width, all three columns */
const GAP     = 340;    /* clear span between columns, for the links */
const TILE_H  = 19;
const ROW_MIN = 22;
const ROW_MAX = 30;

const LGND = [
  { kind: 'link',  color: SC.produce, label: 'Writes (producer → map)' },
  { kind: 'link',  color: SC.consume, label: 'Reads (map → consumer)' },
  { kind: 'tile',  color: SC.both,    label: 'Map: read and written in kernel' },
  { kind: 'tile',  color: SC.produce, label: 'Map: written only — drained by userspace' },
  { kind: 'tile',  color: SC.consume, label: 'Map: read only — written by userspace' },
  { kind: 'tile',  color: SC.none,    label: 'Map: no reachable in-kernel access' },
];

let svg, gRoot, zoomer, labelsOn = true, focusKey = null, lastLayout = null;
let sortMode = 'family';

/* -------------------------------------------------------
   LEGEND
------------------------------------------------------- */
function buildLegend() {
  const c = document.getElementById('lg-signals');
  if (!c) return;
  /* The strip already carries the source credit; the keys go in front of it. */
  c.insertAdjacentHTML('afterbegin', LGND.map(({ kind, color, label }) =>
    `<div class="li">${kind === 'link'
      ? `<div class="ll" style="background:${color}"></div>`
      : `<div class="lt" style="border-color:${color};background:${color}22"></div>`
    }${escHtml(label)}</div>`).join(''));
}

/* -------------------------------------------------------
   TOOLTIP
------------------------------------------------------- */
const ttEl = () => document.getElementById('tt');
function showTip(e, html) {
  const t = ttEl();
  t.innerHTML = html;
  t.classList.add('on');
  moveTip(e);
}
function moveTip(e) {
  const t = ttEl();
  const x = e.clientX + 14, y = e.clientY - 8;
  const w = t.offsetWidth, h = t.offsetHeight;
  t.style.left = (x + w > window.innerWidth ? x - w - 26 : x) + 'px';
  t.style.top  = (y + h > window.innerHeight ? y - h : y) + 'px';
}
function hideTip() { ttEl().classList.remove('on'); }

function mapTip(m) {
  return `<div class="tt-type">${escHtml(m.family)}</div>` +
         `<div class="tt-name">${escHtml(m.name)}</div>` +
         `<div class="tt-id">BPF_MAP_TYPE_${escHtml(m.type)} · ${escHtml(SCOPE_LABEL[m.scope])}</div>` +
         `<div class="tt-meta">key ${escHtml(m.key || '—')}<br>value ${escHtml(m.value || '—')}</div>` +
         `<div class="tt-meta">${m.producers.length} producer${m.producers.length === 1 ? '' : 's'} · ` +
         `${m.consumers.length} consumer${m.consumers.length === 1 ? '' : 's'}</div>` +
         `<div class="tt-hint">Click for the key/value pairs and the call sites</div>`;
}
function progTip(p, side, n) {
  return `<div class="tt-type">${escHtml(DOMAIN_LABEL[p.domain] || p.domain)} program</div>` +
         `<div class="tt-name">${escHtml(p.name)}</div>` +
         `<div class="tt-meta">${side === 'L' ? 'writes' : 'reads'} ${n} of the maps shown</div>` +
         `<div class="tt-hint">Click for this program's whole map set</div>`;
}

/* -------------------------------------------------------
   LAYOUT — maps anchor the order, programs follow by barycentre
------------------------------------------------------- */
function sortMaps(list) {
  const deg = m => m.producers.length + m.consumers.length;
  if (sortMode === 'degree') return list.slice().sort((a, b) => deg(b) - deg(a) || a.name.localeCompare(b.name));
  if (sortMode === 'name')   return list.slice().sort((a, b) => a.name.localeCompare(b.name));
  if (sortMode === 'type')   return list.slice().sort((a, b) => a.type.localeCompare(b.type) || a.name.localeCompare(b.name));
  return list.slice().sort((a, b) =>
    a.family.localeCompare(b.family) || a.scope.localeCompare(b.scope) || a.name.localeCompare(b.name));
}

function buildLayout() {
  const maps = sortMaps(shownMaps());
  const pos = new Map();                       /* map index -> its row */
  maps.forEach((m, i) => pos.set(m, i));

  /* A program's row is the average row of the maps it is joined to, so the
     links run as flat as the data allows and crossings stay rare. */
  const side = (which) => {
    const byProg = new Map();
    maps.forEach(m => m[which].forEach(e => {
      if (!byProg.has(e.prog)) byProg.set(e.prog, []);
      byProg.get(e.prog).push(pos.get(m));
    }));
    return [...byProg.entries()]
      .map(([prog, rows]) => ({
        prog, rows,
        bary: rows.reduce((s, r) => s + r, 0) / rows.length,
      }))
      .sort((a, b) => a.bary - b.bary || PROGS[a.prog].name.localeCompare(PROGS[b.prog].name));
  };
  const left  = side('producers');
  const right = side('consumers');

  const rows = Math.max(maps.length, left.length, right.length, 1);
  const step = Math.max(ROW_MIN, Math.min(ROW_MAX, 900 / rows));
  const H = Math.max(rows * step, 120);

  const place = (list, colX) => list.map((d, i) => ({
    ...d, x: colX,
    y: (H - list.length * step) / 2 + i * step + step / 2,
  }));

  const midX = COL_W + GAP;
  const L = place(left, 0);
  const M = place(maps.map(m => ({ map: m })), midX);
  const R = place(right, midX + COL_W + GAP);

  const rowOfMap = new Map();
  M.forEach(n => rowOfMap.set(n.map, n));

  const links = [];
  M.forEach(n => {
    n.map.producers.forEach(e => {
      const s = L.find(d => d.prog === e.prog);
      if (s) links.push({ role: 'produce', sx: s.x + COL_W, sy: s.y, tx: n.x, ty: n.y, prog: e.prog, map: n.map });
    });
    n.map.consumers.forEach(e => {
      const t = R.find(d => d.prog === e.prog);
      if (t) links.push({ role: 'consume', sx: n.x + COL_W, sy: n.y, tx: t.x, ty: t.y, prog: e.prog, map: n.map });
    });
  });

  return { L, M, R, links, W: midX * 2 + COL_W, H };
}

/* -------------------------------------------------------
   RENDER
------------------------------------------------------- */
function initCanvas() {
  const cv = document.getElementById('cv-signals');
  cv.querySelectorAll('svg').forEach(s => s.remove());
  /* The legend is a footer strip in this canvas, so the drawing takes the
     height that is left rather than the whole box. */
  svg = d3.select(cv).insert('svg', ':first-child')
    .attr('preserveAspectRatio', 'xMidYMid meet')
    .attr('role', 'img')
    .attr('aria-label', 'Three columns: the programs that write each eBPF map on the left, ' +
          'the maps in the middle, the programs that read them on the right. An amber link is ' +
          'a write, a blue link is a read. The same figures are listed on the Signals Matrix page.')
    .style('width', '100%')
    .style('touch-action', 'none');
  zoomer = d3.zoom().scaleExtent([0.05, 6]).on('zoom', e => gRoot.attr('transform', e.transform));
  svg.call(zoomer);
  svg.on('dblclick.zoom', null);
  svg.on('dblclick', () => fitView(450));
  svg.on('click', () => { focusKey = null; applyFocus(); });
  gRoot = svg.append('g');
  gRoot.append('g').attr('class', 'sg-links');
  gRoot.append('g').attr('class', 'sg-nodes');
  return cv;
}

const curve = d3.linkHorizontal().x(d => d[0]).y(d => d[1]);
const linkPath = l => curve({ source: [l.sx, l.sy], target: [l.tx, l.ty] });

function tileKey(d) { return d.map ? 'm' + MAPS.indexOf(d.map) : (d.side || '') + 'p' + d.prog; }

function render() {
  const cv = document.getElementById('cv-signals');
  if (!cv) return;
  if (!svg) initCanvas();
  const lay = buildLayout();
  lastLayout = lay;
  lay.L.forEach(d => d.side = 'L');
  lay.R.forEach(d => d.side = 'R');

  const PAD = 28;
  svg.attr('viewBox', `${-PAD} ${-PAD} ${lay.W + PAD * 2} ${lay.H + PAD * 2}`);

  /* ── links ── */
  const gl = gRoot.select('g.sg-links');
  gl.selectAll('path').data(lay.links, l => `${l.role}:${l.prog}:${MAPS.indexOf(l.map)}`)
    .join('path')
      .attr('d', linkPath)
      .attr('fill', 'none')
      .attr('stroke', l => l.role === 'produce' ? SC.produce : SC.consume)
      .attr('stroke-width', 1.1)
      .attr('stroke-opacity', 0.42);

  /* ── nodes ── */
  const nodes = [...lay.L, ...lay.M, ...lay.R];
  const gn = gRoot.select('g.sg-nodes');
  const sel = gn.selectAll('g.sg-tile').data(nodes, tileKey).join(
    enter => {
      const g = enter.append('g').attr('class', 'sg-tile').style('cursor', 'pointer');
      /* The canvas carries the kestrel mark behind the diagram, so a tile
         needs its own ground before the flow tint goes on: without it the
         bird reads through the label. */
      g.append('rect').attr('class', 'sg-bg');
      g.append('rect').attr('class', 'sg-rect');
      g.append('text').attr('class', 'sg-label');
      g.append('text').attr('class', 'sg-sub');
      return g;
    });

  sel.attr('transform', d => `translate(${d.x},${d.y - TILE_H / 2})`)
     .on('mouseover', (e, d) => showTip(e, d.map
        ? mapTip(d.map)
        : progTip(PROGS[d.prog], d.side, d.rows.length)))
     .on('mousemove', moveTip)
     .on('mouseout', hideTip)
     .on('click', (e, d) => {
        e.stopPropagation();
        focusKey = focusKey === tileKey(d) ? null : tileKey(d);
        applyFocus();
        if (d.map) openMapPanel(MAPS.indexOf(d.map)); else openProgPanel(d.prog);
     });

  sel.select('rect.sg-bg')
     .attr('width', COL_W).attr('height', TILE_H).attr('rx', 2)
     .attr('fill', '#1c1c16').attr('fill-opacity', 0.88);

  sel.select('rect.sg-rect')
     .attr('width', COL_W).attr('height', TILE_H).attr('rx', 2)
     .attr('fill', d => d.map ? FLOW_COLOR[d.map.flow] + '26' : 'rgba(60,68,64,.55)')
     .attr('stroke', d => d.map ? FLOW_COLOR[d.map.flow]
                                : (d.side === 'L' ? SC.produce : SC.consume))
     .attr('stroke-opacity', d => d.map ? 0.95 : 0.55)
     .attr('stroke-width', 1);

  sel.select('text.sg-label')
     .attr('x', 8).attr('y', TILE_H / 2 + 4)
     .attr('fill', 'var(--text)')
     .style('font-family', 'var(--mono)')
     .style('font-size', '11px')
     .text(d => d.map ? d.map.name : PROGS[d.prog].name);

  sel.select('text.sg-sub')
     .attr('x', COL_W - 8).attr('y', TILE_H / 2 + 4)
     .attr('text-anchor', 'end')
     .attr('fill', 'var(--text-dim)')
     .style('font-family', 'var(--body)')
     .style('font-size', '9.5px')
     .text(d => d.map
        ? `${d.map.producers.length}▸${d.map.consumers.length}`
        : `${d.rows.length}`);

  sel.selectAll('text').style('display', labelsOn ? null : 'none');

  applyFocus();
  updateCounts(lay);
  fitView(0);
}

/* Focus: one node lit, everything it does not touch pushed back. */
function applyFocus() {
  if (!gRoot) return;
  const gl = gRoot.select('g.sg-links'), gn = gRoot.select('g.sg-nodes');
  if (!focusKey) {
    gl.selectAll('path').attr('stroke-opacity', 0.42);
    gn.selectAll('g.sg-tile').attr('opacity', 1);
    return;
  }
  const hot = new Set([focusKey]);
  gl.selectAll('path').each(function (l) {
    const mk = 'm' + MAPS.indexOf(l.map);
    const pk = (l.role === 'produce' ? 'L' : 'R') + 'p' + l.prog;
    const on = focusKey === mk || focusKey === pk;
    if (on) { hot.add(mk); hot.add(pk); }
    d3.select(this).attr('stroke-opacity', on ? 0.95 : 0.05)
                   .attr('stroke-width', on ? 1.8 : 1.1);
  });
  gn.selectAll('g.sg-tile').attr('opacity', d => hot.has(tileKey(d)) ? 1 : 0.16);
}

/* The viewBox is the layout's own box with a margin, so the whole diagram is
   already on screen at rest; zoom and pan ride on top of that, and fitting is
   simply going back to where the viewBox put it. */
function fitView(ms) {
  if (!svg) return;
  const go = ms ? svg.transition().duration(ms) : svg;
  go.call(zoomer.transform, d3.zoomIdentity);
}

function updateCounts(lay) {
  const el = document.getElementById('sg-count');
  if (!el) return;
  el.innerHTML = `<b>${lay.M.length}</b> maps &middot; <b>${lay.L.length}</b> producers ` +
                 `&middot; <b>${lay.R.length}</b> consumers &middot; <b>${lay.links.length}</b> edges`;
  const st = document.getElementById('sg-status');
  if (st) st.style.display = lay.M.length ? 'none' : 'block';
  if (st && !lay.M.length) st.textContent = 'No map matches these filters.';
}

/* -------------------------------------------------------
   BOOT
------------------------------------------------------- */
window.addEventListener('DOMContentLoaded', () => {
  buildLegend();
  if (!sigInit(render)) {
    const st = document.getElementById('sg-status');
    if (st) st.textContent = 'Signals dataset failed to load.';
    return;
  }
  document.getElementById('sg-reset').addEventListener('click', () => {
    focusKey = null; clearFilters(); fitView(450);
  });
  document.getElementById('sg-fit').addEventListener('click', () => fitView(450));
  document.getElementById('sg-labels').addEventListener('click', e => {
    labelsOn = !labelsOn;
    e.currentTarget.classList.toggle('lit', labelsOn);
    gRoot.selectAll('g.sg-tile').selectAll('text').style('display', labelsOn ? null : 'none');
  });
  document.getElementById('sg-sort').addEventListener('change', e => {
    sortMode = e.target.value; render();
  });
  document.getElementById('sg-about').addEventListener('click', openAboutPanel);

  initCanvas();
  cascade();
  let rt;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => fitView(0), 180); });
});
