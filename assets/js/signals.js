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
const GAP     = 300;    /* clear span between a column's nearest band and the maps */
const TILE_H  = 19;
const ROW_MIN = 22;
const ROW_MAX = 30;
/* The program columns are bands, one per program family (the name's prefix:
   l0, host, l2, l3, l4, l7). A band has a header, a gap before the next, and
   each band steps sideways from the one before it by most of a tile's width,
   so the families read as a staircase and no two share an edge. The family
   also owns a colour, carried by its tiles, its header and every link that
   leaves or enters it: direction is the side (left writes, right reads), so
   colour is free to say which family a link belongs to. */
const GROUP_GAP   = 56;  /* clear space before the next band starts */
const GROUP_HEAD  = 14;  /* the header line's own height */
const GROUP_STEP  = COL_W + 24;  /* each band's sideways step: a full tile and a
                                    margin, so no two bands share a column */
const GROUP_OVERLAP = 0.65;      /* the next band starts two thirds down the one
                                    before it: the staircase runs across the
                                    view rather than down it */
const GROUP_PAD   = 8;           /* the band's background, past its tiles */
/* A program's family is its name's prefix: the fabric (l0), each host
   producer (proc, cred, unix, syscall, guard, wait, mmap, io, module, bpf,
   file, signal — the order host.bpf.o includes them), then the network
   layers from the socket layer up. */
const GROUP_ORDER = ['l0', 'proc', 'cred', 'unix', 'syscall', 'guard', 'wait', 'mmap',
                     'io', 'module', 'bpf', 'file', 'signal',
                     'l1', 'l2', 'l3', 'l4', 'l7'];
const GROUP_LABEL = {
  l0: 'l0 — the fabric',
  proc: 'proc — processes', cred: 'cred — credentials', unix: 'unix — unix IPC',
  syscall: 'syscall — syscalls', guard: 'guard — guard bits', wait: 'wait — off-CPU waits',
  mmap: 'mmap — memory', io: 'io — block I/O', module: 'module — modules',
  bpf: 'bpf — BPF', file: 'file — files', signal: 'signal — signals',
  host: 'host — host telemetry',
  l1: 'l1 — socket layer', l2: 'l2 — link layer', l3: 'l3 — network layer',
  l4: 'l4 — transport', l7: 'l7 — application',
};
/* One colour per family, all from the page's own register (the Kestrel
   amber, tan, khaki, sage, green, slate blue, steel and the greys), laid
   down the band order so that neighbours contrast: warm against cool, and
   light against dark, in turn. Two bands that sit side by side therefore
   never share a hue or a tone, and the staircase reads band by band. */
const GROUP_COLOR = {
  l0:      '#a0a6a2',   /* ash — light, neutral */
  proc:    '#c87828',   /* --accent, the Kestrel amber — warm, mid */
  cred:    '#78a8d8',   /* slate blue — cool, light */
  unix:    '#a06018',   /* dark amber — warm, dark */
  syscall: '#c8b880',   /* pale khaki — light */
  guard:   '#5c8a68',   /* deep green — cool, dark */
  wait:    '#e0a060',   /* apricot — warm, light */
  mmap:    '#587aa2',   /* deep slate — cool, dark */
  io:      '#d8b070',   /* sand — light */
  module:  '#9c6838',   /* umber — warm, dark */
  bpf:     '#68a878',   /* --col-dc, muted green — cool, mid */
  file:    '#d89848',   /* light amber — warm, light */
  signal:  '#7888a8',   /* steel — cool, mid */
  host:    '#c87828',   /* a pre-ABI 23 dataset: one amber band */
  l1:      '#c09060',   /* --col-det, tan — warm, mid */
  l2:      '#4e6f94',   /* dark slate — cool, dark */
  l3:      '#a8a878',   /* --col-tech, khaki — light */
  l4:      '#7a9878',   /* --col-sub, sage — cool, mid */
  l7:      '#c8a040',   /* mustard — warm, light */
};
const groupColor = key => GROUP_COLOR[key] || SC.none;
function familyOf(name) { return name.split('_')[0]; }

const LGND = [
  ...GROUP_ORDER.map(g => ({ kind: 'link', color: GROUP_COLOR[g], label: g })),
  { kind: 'note', label: 'Left column writes the map; right column reads it' },
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
      : kind === 'note' ? ''
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
  const g = familyOf(p.name);
  return `<div class="tt-type" style="color:${groupColor(g)}">${escHtml(GROUP_LABEL[g] || g)} · ${escHtml(DOMAIN_LABEL[p.domain] || p.domain)}</div>` +
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

  /* A program's family is its name's prefix. Within a band the barycentre
     order stands; the bands follow a fixed order, fabric first, then the
     host, then the network from the link layer up. */
  const groupOf = d => familyOf(PROGS[d.prog].name);
  const groups = list => {
    const by = new Map();
    list.forEach(d => {
      const g = groupOf(d);
      if (!by.has(g)) by.set(g, []);
      by.get(g).push(d);
    });
    return [...by.entries()]
      .sort((a, b) => {
        const ia = GROUP_ORDER.indexOf(a[0]), ib = GROUP_ORDER.indexOf(b[0]);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a[0].localeCompare(b[0]);
      })
      .map(([key, items]) => ({ key, items }));
  };
  const lg = groups(left), rg = groups(right);

  const rows = Math.max(maps.length, left.length, right.length, 1);
  const step = Math.max(ROW_MIN, Math.min(ROW_MAX, 900 / rows));
  /* A column of bands is taller than its tiles: each band adds its header
     and the gap before the next. */
  /* A band's own height, and where each band starts: halfway down the one
     before it (plus the gap), since the bands no longer share a column. The
     column's height is the last band's bottom. */
  const bandH = g => GROUP_HEAD + g.items.length * step;
  const bandTops = gs => {
    const tops = []; let y = 0;
    gs.forEach((g, i) => {
      tops.push(y);
      y += Math.max(bandH(g) * GROUP_OVERLAP, GROUP_HEAD + step) + GROUP_GAP;
    });
    return tops;
  };
  const bandsH = gs => {
    const tops = bandTops(gs);
    return gs.reduce((h, g, i) => Math.max(h, tops[i] + bandH(g)), 0);
  };
  const H = Math.max(rows * step, bandsH(lg), bandsH(rg), 120);

  const place = (list, colX) => list.map((d, i) => ({
    ...d, x: colX,
    y: (H - list.length * step) / 2 + i * step + step / 2,
  }));

  /* Bands: stacked and centred as a whole, each stepping sideways from the
     one before. `dir` is which way the steps go: the left column steps in
     toward the maps, the right column steps out, so the links never cross
     a band they do not end in. */
  const placeBands = (gs, colX, dir) => {
    const nodes = [], heads = [];
    const top0 = (H - bandsH(gs)) / 2, tops = bandTops(gs);
    gs.forEach((g, gi) => {
      const x = colX + dir * gi * GROUP_STEP;
      let y = top0 + tops[gi];
      heads.push({ key: g.key, label: GROUP_LABEL[g.key] || g.key, n: g.items.length,
                   x, y: y + GROUP_HEAD - 3, h: bandH(g) });
      y += GROUP_HEAD;
      g.items.forEach(d => { nodes.push({ ...d, x, y: y + step / 2, group: g.key }); y += step; });
    });
    return { nodes, heads };
  };

  /* The left staircase climbs toward the maps, so the map column sits past
     its last step; the right staircase climbs away from them. */
  const lSpan = Math.max(0, lg.length - 1) * GROUP_STEP;
  const midX = COL_W + lSpan + GAP;
  const lb = placeBands(lg, 0, +1);
  const M  = place(maps.map(m => ({ map: m })), midX);
  const rb = placeBands(rg, midX + COL_W + GAP, +1);
  const L = lb.nodes, R = rb.nodes;
  const heads = [...lb.heads.map(h => ({ ...h, side: 'L' })),
                 ...rb.heads.map(h => ({ ...h, side: 'R' }))];

  const rowOfMap = new Map();
  M.forEach(n => rowOfMap.set(n.map, n));

  const links = [];
  M.forEach(n => {
    n.map.producers.forEach(e => {
      const s = L.find(d => d.prog === e.prog);
      if (s) links.push({ role: 'produce', group: s.group, sx: s.x + COL_W, sy: s.y, tx: n.x, ty: n.y, prog: e.prog, map: n.map });
    });
    n.map.consumers.forEach(e => {
      const t = R.find(d => d.prog === e.prog);
      if (t) links.push({ role: 'consume', group: t.group, sx: n.x + COL_W, sy: n.y, tx: t.x, ty: t.y, prog: e.prog, map: n.map });
    });
  });

  /* The right column's last band steps furthest out, so the box widens by it. */
  const W = midX + COL_W + GAP + COL_W + Math.max(0, rg.length - 1) * GROUP_STEP;
  return { L, M, R, links, heads, W, H };
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
          'the maps in the middle, the programs that read them on the right. Programs are ' +
          'grouped into bands by family (l0, host, l2, l3, l4, l7), each band in its own ' +
          'colour, which its links carry. The same figures are listed on the Signals Matrix page.')
    .style('width', '100%')
    .style('touch-action', 'none');
  zoomer = d3.zoom().scaleExtent([0.05, 6]).on('zoom', e => gRoot.attr('transform', e.transform));
  svg.call(zoomer);
  svg.on('dblclick.zoom', null);
  svg.on('dblclick', () => fitView(450));
  svg.on('click', () => { focusKey = null; applyFocus(); });
  gRoot = svg.append('g');
  gRoot.append('g').attr('class', 'sg-bands');     /* band backgrounds, under the links */
  gRoot.append('g').attr('class', 'sg-links');
  gRoot.append('g').attr('class', 'sg-groups');    /* band headers, over them */
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
      .attr('stroke', l => groupColor(l.group))
      .attr('stroke-width', 1.1)
      .attr('stroke-opacity', 0.42);

  /* ── band headers ── one per program family and side: the family's name,
     a count, and a rule the width of the tile under it, in the colour of the
     column's role. */
  /* The band's ground: a faint wash of its colour behind its tiles, with a
     hairline of the same colour, so a band reads as one block however the
     links cross it. It sits under the links, so it never dims them. */
  gRoot.select('g.sg-bands').selectAll('rect.sg-band')
    .data(lay.heads, h => h.side + ':' + h.key)
    .join('rect').attr('class', 'sg-band')
      .attr('x', h => h.x - GROUP_PAD)
      .attr('y', h => h.y - GROUP_HEAD + 3 - GROUP_PAD)
      .attr('width', COL_W + GROUP_PAD * 2)
      .attr('height', h => h.h + GROUP_PAD * 2)
      .attr('rx', 4)
      .attr('fill', h => groupColor(h.key)).attr('fill-opacity', 0.14)
      .attr('stroke', h => groupColor(h.key)).attr('stroke-opacity', 0.55)
      .attr('stroke-width', 1);

  const gg = gRoot.select('g.sg-groups');
  const gh = gg.selectAll('g.sg-group').data(lay.heads, h => h.side + ':' + h.key).join(
    enter => {
      const g = enter.append('g').attr('class', 'sg-group');
      g.append('line').attr('class', 'sg-group-rule');
      g.append('text').attr('class', 'sg-group-label');
      g.append('text').attr('class', 'sg-group-n');
      return g;
    });
  gh.attr('transform', h => `translate(${h.x},${h.y})`);
  gh.select('line.sg-group-rule')
    .attr('x1', 0).attr('x2', COL_W).attr('y1', 2).attr('y2', 2)
    .attr('stroke', h => groupColor(h.key))
    .attr('stroke-opacity', 0.8).attr('stroke-width', 1.5);
  gh.select('text.sg-group-label')
    .attr('x', 0).attr('y', -2)
    .attr('fill', h => groupColor(h.key))
    .style('font-family', 'var(--body)').style('font-size', '9.5px')
    .style('letter-spacing', '1px').style('text-transform', 'uppercase')
    .text(h => h.label);
  gh.select('text.sg-group-n')
    .attr('x', COL_W).attr('y', -2).attr('text-anchor', 'end')
    .attr('fill', 'var(--text-dim)')
    .style('font-family', 'var(--body)').style('font-size', '9px')
    .text(h => `${h.n} program${h.n === 1 ? '' : 's'}`);
  gh.selectAll('text').style('display', labelsOn ? null : 'none');

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
     .attr('fill', d => d.map ? FLOW_COLOR[d.map.flow] + '26' : groupColor(d.group) + '26')
     .attr('stroke', d => d.map ? FLOW_COLOR[d.map.flow] : groupColor(d.group))
     .attr('stroke-opacity', d => d.map ? 0.95 : 0.8)
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
  const gg = gRoot.select('g.sg-groups');
  if (!focusKey) {
    gl.selectAll('path').attr('stroke-opacity', 0.42);
    gn.selectAll('g.sg-tile').attr('opacity', 1);
    gg.selectAll('g.sg-group').attr('opacity', 1);
    gRoot.select('g.sg-bands').selectAll('rect.sg-band').attr('opacity', 1);
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
  /* A band stays lit while any of its programs is. */
  const hotGroups = new Set();
  gn.selectAll('g.sg-tile').each(d => {
    if (d.group && hot.has(tileKey(d))) hotGroups.add(d.side + ':' + d.group);
  });
  gg.selectAll('g.sg-group').attr('opacity', h => hotGroups.has(h.side + ':' + h.key) ? 1 : 0.3);
  gRoot.select('g.sg-bands').selectAll('rect.sg-band')
    .attr('opacity', h => hotGroups.has(h.side + ':' + h.key) ? 1 : 0.3);
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
    gRoot.selectAll('g.sg-tile, g.sg-group').selectAll('text').style('display', labelsOn ? null : 'none');
  });
  document.getElementById('sg-about').addEventListener('click', openAboutPanel);

  initCanvas();
  cascade();
  let rt;
  window.addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => fitView(0), 180); });
});
