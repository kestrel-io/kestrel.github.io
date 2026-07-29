/* -------------------------------------------------------
   eBPF VISUALIZED — force-directed view of the capability matrix
   Model, filters and detail panel live in ebpf-core.js
------------------------------------------------------- */

const ER = {
  root:14, domain:11, program:9, group:6,
  helper:4, map:4.5, kfunc:4, syscall:5
};
const EB_LGND = [
  {type:'domain',  label:'Functional Domain'},
  {type:'program', label:'Program Type'},
  {type:'group',   label:'Category'},
  {type:'helper',  label:'Helper Function'},
  {type:'map',     label:'Map Type'},
  {type:'kfunc',   label:'Kfunc'},
  {type:'syscall', label:'Syscall Command'},
];

function ebColor(d){ return EC[d.data?.type] || EC.root; }
function ebRadius(d){ return ER[d.data?.type] || 4; }

/* -------------------------------------------------------
   TOOLTIP
------------------------------------------------------- */
const ttEl = document.getElementById('tt');
function showTip(e, d) {
  const o = d.data || {};
  const t = o.type || 'root';
  let meta = '';
  if (t === 'program')  meta = `${escHtml(o.domain||'')}${o.since?` · kernel ${kver(o.since)}`:''}<br>${o.counts.helper} helpers · ${o.counts.map} maps · ${o.counts.kfunc} kfuncs`;
  if (t === 'domain')   meta = `${o.nProg||0} program types`;
  if (t === 'group')    meta = o.sub || '';
  if (KINDS.includes(t)) {
    meta = `${o.scope?`scope: ${o.scope}`:''}${o.since?` · kernel ${kver(o.since)}`:''}` +
           (o.caps    && o.caps.length    ? `<br>caps: ${escHtml(o.caps.join(', '))}` : '') +
           (o.kconfig && o.kconfig.length ? `<br>${escHtml(o.kconfig.join(', '))}` : '') +
           (o.flags   && o.flags.length   ? `<br>${escHtml(o.flags.join(' '))}` : '');
  }
  if (t === 'syscall')  meta = o.since ? `kernel ${kver(o.since)}` : '';
  ttEl.innerHTML =
    `<div class="tt-type">${escHtml(t === 'group' ? (o.kindLabel || 'Category') : t)}</div>` +
    `<div class="tt-name">${escHtml(o.name || 'eBPF Matrix')}</div>` +
    (meta ? `<div class="tt-meta">${meta}</div>` : '') +
    (o.url ? `<div class="tt-hint">Click = details · Shift+Click = docs ↗</div>` : '');
  ttEl.classList.add('on');
  moveTip(e);
}
function moveTip(e) {
  const x=e.clientX+14, y=e.clientY-8;
  const w=ttEl.offsetWidth, h=ttEl.offsetHeight;
  ttEl.style.left=(x+w>window.innerWidth  ? x-w-26 : x)+'px';
  ttEl.style.top =(y+h>window.innerHeight ? y-h    : y)+'px';
}
function hideTip(){ ttEl.classList.remove('on'); }

/* -------------------------------------------------------
   LEGEND
------------------------------------------------------- */
function buildEbLegend(id) {
  const c=document.getElementById(id); if(!c) return;
  c.innerHTML='';
  EB_LGND.forEach(({type,label})=>{
    const el=document.createElement('div'); el.className='li';
    el.innerHTML=`<div class="ld" style="background:${EC[type]}"></div>${label}`;
    c.appendChild(el);
  });
}

/* -------------------------------------------------------
   TREE — pivots from program types
------------------------------------------------------- */
function leafNode(kind, oi, edge) {
  const o = objOf(kind, oi);
  return {
    type:kind, kind, oi, ref:`${kind}:${oi}`, name:o.name,
    desc:o.description, def:o.kernel_definition,
    since:(edge && edge.since) || o.since, url:o.url,
    scope:edge ? edge.scope : '', caps:edge && edge.caps, kconfig:edge && edge.kconfig,
    flags:edge && edge.flags, attach:edge && edge.attach
  };
}

function buildTree() {
  const root = { type:'root', name:'eBPF Capability Matrix', children:[] };

  EBPF.domains.forEach((dom, di) => {
    const progs = dom.programs
      .filter(pi => progPasses(EBPF.programs[pi]))
      .map(pi => {
        const p = EBPF.programs[pi];
        const node = {
          type:'program', name:p.name, short:p.short, idx:pi,
          domain:p.domain, since:p.since, url:p.url,
          desc:p.description, usage:p.usage, context:p.context,
          subtypeOf:p.subtype_of, subtypes:p.subtypes || [], counts:p.counts, children:[]
        };
        KINDS.forEach(kind => {
          const leaves = usesOf(p, kind)
            .filter(e => edgeInScope(e) && leafPasses(kind, objOf(kind, e.target).name))
            .map(e => Object.assign(leafNode(kind, e.target, e), { prog:p.name }));
          if (!leaves.length) return;
          node.children.push({
            type:'group', kind, kindLabel:EB_KIND_LABEL[kind],
            name:`${EB_KIND_LABEL[kind]}s (${leaves.length})`,
            sub:`${p.short} · ${leaves.length} ${kind}${leaves.length>1?'s':''}`,
            prog:p.name, children:leaves
          });
        });
        return node;
      });
    if (progs.length) root.children.push({
      type:'domain', name:dom.name, di, desc:dom.description, url:dom.url,
      nProg:progs.length, children:progs
    });
  });

  // bpf() syscall commands — a program-independent management surface, so they
  // hang off the root rather than off a program type.
  if (syscallsShown()) {
    const cmds = OBJ.syscall
      .map((s, i) => ({ s, i }))
      .filter(({s}) => !F.sys || s.name === F.sys);
    if (cmds.length) {
      const fams = new Map();
      cmds.forEach(({s, i}) => {
        if (!fams.has(s.family)) fams.set(s.family, []);
        fams.get(s.family).push(leafNode('syscall', i, null));
      });
      root.children.push({
        type:'group', kind:'syscall', kindLabel:'Syscall Command',
        name:`bpf() Syscall Commands (${cmds.length})`,
        sub:'Management surface of the bpf() syscall — not scoped to a program type',
        children:[...fams.entries()].sort((a,b)=>a[0].localeCompare(b[0])).map(([label,list]) => ({
          type:'group', kind:'syscall', kindLabel:'Syscall Command',
          name:`${label} (${list.length})`, sub:label, children:list
        }))
      });
    }
  }

  // Catalog objects the bundle lists with no program-type relationship.
  const unattachedKids = [];
  ['map','kfunc','helper'].forEach(kind => {
    if (!unattachedShown()) return;
    const list = UNATTACHED[kind].filter(({o}) => leafPasses(kind, o.name));
    if (!list.length) return;
    unattachedKids.push({
      type:'group', kind, kindLabel:EB_KIND_LABEL[kind],
      name:`${EB_KIND_LABEL[kind]}s (${list.length})`,
      sub:'No program-type relationship in the bundle',
      children:list.map(({i}) => Object.assign(leafNode(kind, i, null), { unattached:true }))
    });
  });
  if (unattachedKids.length) root.children.push({
    type:'group', kind:'unattached', kindLabel:'Category',
    name:`Unattached Objects (${unattachedKids.reduce((n,g)=>n+g.children.length,0)})`,
    sub:'Catalogued by the bundle with no program-type relationship',
    children:unattachedKids
  });

  return F.q ? pruneToSearch(root) : root;
}

/* Keep a node when it or any descendant matches the search text. */
function nodeText(n) {
  return [n.name, n.desc, n.def, n.usage, n.context, n.domain, n.prog,
          (n.caps||[]).join(' '), (n.flags||[]).join(' '), (n.kconfig||[]).join(' ')]
    .filter(Boolean).join(' ').toLowerCase();
}
function pruneToSearch(node) {
  const self = node.type !== 'root' && nodeText(node).includes(F.q);
  const kids = (node.children || []).map(pruneToSearch).filter(Boolean);
  if (!self && !kids.length && node.type !== 'root') return null;
  // A direct match keeps its whole subtree; an ancestor keeps only matching kids.
  const out = { ...node };
  out.children = self && !kids.length ? (node.children || []) : kids;
  return out;
}

/* -------------------------------------------------------
   FORCE GRAPH
------------------------------------------------------- */
let eSim, eSvg, eZoom, eG, eNodeSel, eLinkSel;
let labelsOn = true;
let userZoomed = false;
let zoomK = 1;

const LINK_DIST     = { 0:230, 1:150, 2:80, 3:46 };
const LINK_STRENGTH = { 0:0.75, 1:0.6, 2:0.45, 3:0.22 };
const CHARGE        = { root:-2200, domain:-2600, program:-1600, group:-500 };

function initCanvas() {
  const cv = document.getElementById('cv-ebpf');
  cv.querySelectorAll('svg').forEach(s => s.remove());
  const W = cv.clientWidth || 1200, H = cv.clientHeight || 800;

  eSvg = d3.select(cv).append('svg')
    .attr('viewBox', `0 0 ${W} ${H}`)
    .attr('preserveAspectRatio','xMidYMid meet')
    .style('width','100%').style('height','100%')
    .style('touch-action','none');

  eZoom = d3.zoom().scaleExtent([.02,8])
    .on('zoom', e => {
      if (e.sourceEvent) userZoomed = true;
      zoomK = e.transform.k;
      eG.attr('transform', e.transform);
    })
    .on('end', scaleLabels);
  eSvg.call(eZoom);
  eSvg.on('dblclick.zoom', null);
  eSvg.on('dblclick', () => fitView(500));
  eG = eSvg.append('g');
  eG.append('g').attr('class','fl');
  eG.append('g').attr('class','fn');
  return { W, H };
}

/* Seed positions from a radial tidy tree so the first frame is already legible. */
function seedRadial(root, nodes) {
  const leaves = root.leaves().length;
  const R = Math.max(320, Math.min(2400, 240 + 15 * Math.sqrt(leaves)));
  d3.tree().size([2*Math.PI, R]).separation((a,b) => (a.parent === b.parent ? 1 : 2))(root);
  nodes.forEach(d => {
    const a = d.x - Math.PI/2, r = d.y;
    d.x = Math.cos(a) * r;
    d.y = Math.sin(a) * r;
  });
}

function rebuildGraph() {
  const cv = document.getElementById('cv-ebpf');
  if (!cv) return;
  if (eSim) { eSim.stop(); eSim = null; }
  const { W, H } = initCanvas();

  const root  = d3.hierarchy(buildTree());
  const nodes = root.descendants();
  nodes.forEach((d,i) => d._uid = i);
  const links = nodes.filter(d => d.parent).map(d => ({ source:d.parent, target:d }));

  seedRadial(root, nodes);
  root.fx = 0; root.fy = 0;

  eSim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d._uid)
      .distance(d => LINK_DIST[d.source.depth] ?? 40)
      .strength(d => LINK_STRENGTH[d.source.depth] ?? 0.2))
    .force('charge', d3.forceManyBody()
      .strength(d => CHARGE[d.data?.type] ?? -26)
      .distanceMax(1100))
    .force('collide', d3.forceCollide().radius(d => ebRadius(d) + 4).strength(0.9))
    .alpha(0.9).alphaDecay(0.028).velocityDecay(0.42);

  const gL = eG.select('g.fl'), gN = eG.select('g.fn');

  eLinkSel = gL.selectAll('line').data(links).join('line')
    .attr('stroke', '#8e9490')
    .attr('stroke-opacity', d => d.source.depth >= 3 ? 0.35 : 0.7)
    .attr('stroke-width', d => {
      const dep = d.source.depth;
      return dep===0 ? 3.5 : dep===1 ? 2.2 : dep===2 ? 1.2 : 0.6;
    })
    .attr('stroke-linecap','round');

  eNodeSel = gN.selectAll('g').data(nodes).join('g')
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start',(e,d)=>{ if(!e.active) eSim.alphaTarget(.2).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag', (e,d)=>{ d.fx=e.x; d.fy=e.y; })
      .on('end',  (e,d)=>{ if(!e.active) eSim.alphaTarget(0); if(d.depth) { d.fx=d.fy=null; } }))
    .on('click', (e,d) => {
      e.stopPropagation();
      if (e.shiftKey && d.data?.url) { window.open(d.data.url,'_blank','noopener'); return; }
      openPanel(d);
    })
    .on('mouseover',(e,d)=>showTip(e,d))
    .on('mousemove', moveTip)
    .on('mouseout',  hideTip)
    .on('touchstart.tip',(e,d)=>{
      if (e.touches && e.touches[0]) {
        const t=e.touches[0];
        showTip({clientX:t.clientX,clientY:t.clientY}, d);
        setTimeout(hideTip,1600);
      }
    });

  eNodeSel.append('circle')
    .attr('r', ebRadius)
    .attr('fill', ebColor)
    .attr('stroke', ebColor)
    .attr('stroke-width', d => (d.data?.type==='root'||d.data?.type==='domain') ? 2.5 : 1.5)
    .attr('fill-opacity', d => {
      const t = d.data?.type;
      return (t==='root'||t==='domain'||t==='program') ? 0.92 : 0.6;
    });

  addLabels();

  eSim.on('tick', () => {
    eLinkSel
      .attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    eNodeSel.attr('transform', d=>`translate(${d.x},${d.y})`);
  });
  eSim.on('end', () => { if (!userZoomed) fitView(400); });

  userZoomed = false;
  fitView(0);
  updateCounts(nodes);
}

function labelText(d) {
  const o = d.data || {};
  const nm = o.short || o.name || '';
  const t = o.type;
  const mx = t==='root'?40 : t==='domain'?30 : t==='program'?26 : t==='group'?26 : 22;
  return nm.length > mx ? nm.slice(0,mx)+'…' : nm;
}

function labelSize(d) {
  const t = d.data?.type;
  return t==='root'?14 : t==='domain'?12 : t==='program'?10.5 : t==='group'?9.5 : 8.5;
}

function addLabels() {
  const gN = eG.select('g.fn');
  gN.selectAll('text.flbl').remove();
  if (!labelsOn) return;
  const maxDepth = parseInt(document.getElementById('eb-depth').value, 10);
  const sel = gN.selectAll('g').filter(d => d.depth <= maxDepth);
  sel.append('text').attr('class','flbl flbl-bg')
    .attr('dy','0.32em')
    .attr('fill','none').attr('stroke','var(--bg)')
    .attr('stroke-linejoin','round').style('pointer-events','none')
    .attr('font-family','var(--mono)').text(labelText);
  sel.append('text').attr('class','flbl flbl-fg')
    .attr('dy','0.32em')
    .attr('fill', ebColor).style('pointer-events','none')
    .attr('font-family','var(--mono)').text(labelText);
  scaleLabels();
}

/* Labels keep a constant on-screen size, so they stay readable at any zoom. */
function scaleLabels() {
  if (!eG) return;
  const k = Math.max(0.02, zoomK);
  eG.selectAll('text.flbl')
    .attr('font-size', d => labelSize(d) / k)
    .attr('x', d => ebRadius(d) + 4 / k);
  eG.selectAll('text.flbl-bg').attr('stroke-width', d => (d.depth<=1 ? 4 : 3) / k);
}

function fitView(dur) {
  if (!eSvg || !eNodeSel) return;
  const nodes = eNodeSel.data();
  if (!nodes.length) return;
  const xs = nodes.map(d=>d.x), ys = nodes.map(d=>d.y);
  const x0=Math.min(...xs), x1=Math.max(...xs), y0=Math.min(...ys), y1=Math.max(...ys);
  const cv = document.getElementById('cv-ebpf');
  const W = cv.clientWidth || 1200, H = cv.clientHeight || 800;
  const k = Math.max(0.02, Math.min(2, 0.92 * Math.min(W/Math.max(1,x1-x0), H/Math.max(1,y1-y0))));
  const t = d3.zoomIdentity.translate(W/2 - k*(x0+x1)/2, H/2 - k*(y0+y1)/2).scale(k);
  (dur ? eSvg.transition().duration(dur) : eSvg).call(eZoom.transform, t);
  userZoomed = false;
}

function updateCounts(nodes) {
  let programs = 0;
  const uniq = { helper:new Set(), map:new Set(), kfunc:new Set(), syscall:new Set() };
  nodes.forEach(d => {
    const t = d.data?.type;
    if (t === 'program') programs++;
    else if (uniq[t]) uniq[t].add(d.data.ref);
  });
  document.getElementById('eb-count').innerHTML =
    `<b>${programs}</b> programs · <b>${uniq.helper.size}</b> helpers · ` +
    `<b>${uniq.map.size}</b> maps · <b>${uniq.kfunc.size}</b> kfuncs · ` +
    `<b>${uniq.syscall.size}</b> syscalls · <b>${nodes.length}</b> nodes`;
}

/* -------------------------------------------------------
   BOOT
------------------------------------------------------- */
window.addEventListener('DOMContentLoaded', () => {
  const status = document.getElementById('eb-status');
  if (!ebInit(rebuildGraph)) {
    if (status) status.innerHTML = 'Could not load <code>assets/data/ebpf.js</code>';
    return;
  }
  buildEbLegend('lg-ebpf');
  if (status) status.remove();

  document.getElementById('eb-labels').onclick = function() {
    labelsOn = !labelsOn;
    this.classList.toggle('lit', labelsOn);
    addLabels();
  };
  document.getElementById('eb-depth').onchange = addLabels;
  document.getElementById('eb-fit').onclick = () => fitView(400);
  document.getElementById('eb-reset').onclick = clearFilters;

  // Resize only re-frames the view — the simulation is never restarted, so
  // opening the detail panel does not scramble the layout.
  let rt;
  new ResizeObserver(() => {
    clearTimeout(rt);
    rt = setTimeout(() => {
      const cv = document.getElementById('cv-ebpf');
      if (!eSvg || !cv) return;
      eSvg.attr('viewBox', `0 0 ${cv.clientWidth} ${cv.clientHeight}`);
      if (!userZoomed) fitView(250);
    }, 160);
  }).observe(document.getElementById('cv-ebpf'));

  cascade();
});
