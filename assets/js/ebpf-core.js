/* -------------------------------------------------------
   eBPF MATRIX — shared model, filters and detail panel
   Used by ebpf.js (visualized) and ebpf-matrix.js (table).
   Data: assets/data/ebpf.js (const EBPF)
------------------------------------------------------- */

/* ── Object colours (Kestrel palette) ── */
const EC = {
  root:'#cdcfce', domain:'#c87828', program:'#a8a878', group:'#8e9490',
  helper:'#7a9878', map:'#68a878', kfunc:'#c09060', syscall:'#7888a8'
};
const EB_KIND_LABEL = { helper:'Helper', map:'Map Type', kfunc:'Kfunc', syscall:'Syscall Command' };
const EB_TAG_CLASS  = { domain:'t-tac', program:'t-tech', helper:'t-sub', map:'t-dc', kfunc:'t-det', syscall:'t-sys' };
const KINDS = ['helper','map','kfunc'];

/* Collections by kind — filled by ebInit() from the EBPF global. */
const OBJ = { helper:[], map:[], kfunc:[], syscall:[] };
/* Objects the bundle catalogues with no program-type relationship, as
   {o, i} pairs so their collection index travels with them. */
const UNATTACHED = { helper:[], map:[], kfunc:[] };

function objOf(kind, i){ return OBJ[kind][i]; }

/* -------------------------------------------------------
   HELPERS
------------------------------------------------------- */
function escHtml(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]);}
function kver(v){ return v ? `v${v}` : ''; }

/* Kernel versions sort numerically — 4.9 before 4.10. */
function cmpVersion(a, b) {
  const pa = String(a||'').split('.').map(Number), pb = String(b||'').split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i]||0) - (pb[i]||0);
    if (d) return d;
  }
  return 0;
}

/* -------------------------------------------------------
   COPY / TOAST
------------------------------------------------------- */
function copy(text) {
  navigator.clipboard.writeText(text).catch(()=>{
    const a=document.createElement('textarea');
    a.value=text;document.body.appendChild(a);a.select();
    document.execCommand('copy');document.body.removeChild(a);
  });
  const t=document.getElementById('toast');
  t.classList.add('on');
  setTimeout(()=>t.classList.remove('on'), 1700);
}

/* -------------------------------------------------------
   FILTER STATE
------------------------------------------------------- */
const F = { scope:'', domain:'', prog:'', map:'', helper:'', kfunc:'', sys:'', q:'' };
const EL = {};
let ebRender = () => {};

function edgeInScope(e){ return !F.scope || e.scope === F.scope; }
function usesOf(p, kind){ return (p.uses && p.uses[kind]) || []; }

/* Does program p use the named object of `kind`, within the active scope? */
function progUses(p, kind, name) {
  return usesOf(p, kind).some(e => edgeInScope(e) && objOf(kind, e.target).name === name);
}

/* A program survives the structural filters. `skip` omits one constraint
   (the omit-self pattern used to cascade the dropdowns). */
function progPasses(p, skip) {
  if (skip !== 'domain' && F.domain && p.domain !== F.domain) return false;
  if (skip !== 'prog'   && F.prog   && p.name   !== F.prog)   return false;
  if (skip !== 'helper' && F.helper && !progUses(p,'helper',F.helper)) return false;
  if (skip !== 'map'    && F.map    && !progUses(p,'map',F.map))       return false;
  if (skip !== 'kfunc'  && F.kfunc  && !progUses(p,'kfunc',F.kfunc))   return false;
  return true;
}

/* Object filters narrow which objects of a program are shown. */
function leafFilterActive(){ return !!(F.helper || F.map || F.kfunc); }
function leafPasses(kind, name) {
  if (kind === 'helper' && F.helper) return name === F.helper;
  if (kind === 'map'    && F.map)    return name === F.map;
  if (kind === 'kfunc'  && F.kfunc)  return name === F.kfunc;
  // With a filter on another category active, unrelated categories are hidden.
  if (leafFilterActive()) return false;
  return true;
}

/* The syscall catalogue is only shown when nothing narrows the program set. */
function syscallsShown(){ return !!(F.sys || !(F.domain || F.prog || leafFilterActive())); }
function unattachedShown(){ return !(F.domain || F.prog); }

/* -------------------------------------------------------
   DROPDOWNS — cascading, omit-self
------------------------------------------------------- */
function rebuildSelect(el, values, labelFn) {
  if (!el) return;
  const prev = el.value;
  const sentText = el.options[0] ? el.options[0].text : '';
  el.length = 0;
  el.add(new Option(sentText, ''));
  values.forEach(v => el.add(new Option(labelFn ? labelFn(v) : v, v)));
  el.selectedIndex = values.includes(prev) ? values.indexOf(prev) + 1 : 0;
}

function namesFor(kind, skip) {
  const set = new Set();
  EBPF.programs.filter(p => progPasses(p, skip)).forEach(p => {
    usesOf(p, kind).forEach(e => {
      if (edgeInScope(e)) set.add(objOf(kind, e.target).name);
    });
  });
  // Objects with no program-type mapping stay selectable while nothing narrows
  // the program set — they are catalogued on their own.
  if (!F.domain && !F.prog && !KINDS.some(k => k !== kind && F[k]))
    UNATTACHED[kind].forEach(({o}) => set.add(o.name));
  return [...set].sort((a,b)=>a.localeCompare(b));
}

function cascade() {
  F.scope  = EL.scope.value;
  F.domain = EL.domain.value;
  F.prog   = EL.prog.value;
  F.map    = EL.map.value;
  F.helper = EL.helper.value;
  F.kfunc  = EL.kfunc.value;
  F.sys    = EL.sys.value;
  F.q      = EL.q.value.trim().toLowerCase();

  rebuildSelect(EL.domain,
    EBPF.domains.filter(d => d.programs.some(i => progPasses(EBPF.programs[i],'domain'))).map(d => d.name));
  rebuildSelect(EL.prog,
    EBPF.programs.filter(p => progPasses(p,'prog')).map(p => p.name),
    v => v.replace('BPF_PROG_TYPE_',''));
  rebuildSelect(EL.map,    namesFor('map','map'),       v => v.replace('BPF_MAP_TYPE_',''));
  rebuildSelect(EL.helper, namesFor('helper','helper'));
  rebuildSelect(EL.kfunc,  namesFor('kfunc','kfunc'));
  rebuildSelect(EL.sys,    EBPF.syscall_commands.map(s => s.name), v => v.replace('BPF_',''));

  // Re-read: a selection may have been invalidated by the rebuild above.
  F.domain = EL.domain.value; F.prog = EL.prog.value;
  F.map = EL.map.value; F.helper = EL.helper.value;
  F.kfunc = EL.kfunc.value; F.sys = EL.sys.value;

  ebRender();
}

function clearFilters() {
  ['scope','domain','prog','map','helper','kfunc','sys','q'].forEach(k => {
    const el = EL[k];
    if (!el) return;
    // Back to whatever the markup marks selected (the scope default), not blank.
    // Cascaded selects are rebuilt with plain options, so they fall back to ''.
    const def = el.options && [...el.options].find(o => o.defaultSelected);
    el.value = def ? def.value : '';
  });
  cascade();
}

/* -------------------------------------------------------
   SIDE PANEL
------------------------------------------------------- */
function closePanel(){ document.getElementById('sp').classList.remove('on'); }

function docLinks(o) {
  const bits = [];
  if (o.url)     bits.push(`<a class="sp-mitre-link" href="${escHtml(o.url)}" target="_blank" rel="noopener noreferrer">↗ eBPF docs</a>`);
  if (o.kdocUrl) bits.push(`<a class="sp-mitre-link" style="background:var(--bg3);color:var(--accent)" href="${escHtml(o.kdocUrl)}" target="_blank" rel="noopener noreferrer">↗ kernel docs</a>`);
  return bits.length ? `<div style="display:flex;flex-wrap:wrap;gap:6px">${bits.join('')}</div>` : '';
}
function chips(list, cls) {
  return list.length
    ? `<div class="sp-chips">${list.map(v=>`<span class="sp-chip ${cls||''}">${escHtml(v)}</span>`).join('')}</div>`
    : '';
}
function copyRow(text) {
  const s = String(text).replace(/'/g,"\\'");
  return `<div class="sp-rule" onclick="copy('${s}')"><span class="cp">COPY</span><code>${escHtml(text)}</code></div>`;
}

/* Open the detail panel for an object identified by kind + collection index —
   used by the table rows and by the object chips inside a program panel. */
function openObjectPanel(kind, oi) {
  const o = objOf(kind, oi);
  openPanel({ data:{ type:kind, kind, oi, name:o.name, url:o.url } });
}
function openProgramPanel(pi) {
  const p = EBPF.programs[pi];
  openPanel({ data:{ type:'program', idx:pi, name:p.name, url:p.url } });
}
function openDomainPanel(di) {
  openPanel({ data:{ type:'domain', di, name:EBPF.domains[di].name } });
}

function openPanel(d) {
  const o = d.data || {};
  const t = o.type || 'root';
  const body = document.getElementById('sp-body');

  if (t === 'program') {
    const p = EBPF.programs[o.idx];
    const section = (kind, label) => {
      const seen = new Map();
      usesOf(p, kind).filter(edgeInScope).forEach(e => {
        if (!seen.has(e.target)) seen.set(e.target, e.scope);
      });
      if (!seen.size) return '';
      const core = [...seen.values()].filter(s => s === 'core').length;
      return `<div class="sp-sec">${label} (${seen.size}${core?` · ${core} core`:''})</div>` +
        `<div class="sp-chips">${[...seen.entries()].map(([ti,s]) =>
          `<span class="sp-chip sp-chip-link ${s==='core'?'audit':''}" title="${s} — click for details"
                 onclick="openObjectPanel('${kind}',${ti})">${escHtml(objOf(kind,ti).name)}</span>`).join('')}</div>`;
    };
    const anyEdges = KINDS.some(k => usesOf(p, k).length);
    body.innerHTML =
      `<div class="sp-badge">PROGRAM TYPE${p.since?` · KERNEL ${escHtml(kver(p.since))}`:''}</div>` +
      `<div class="sp-name">${escHtml(p.name)}</div>` +
      `<div class="sp-desc">${escHtml(p.description)}</div>` +
      docLinks({ url:p.url, kdocUrl:p.kernel_docs_url }) +
      `<div class="sp-sec">Domain</div><div class="sp-chips"><span class="sp-chip">${escHtml(p.domain)}</span></div>` +
      (p.subtype_of ? `<div class="sp-note">Subtype of <b>${escHtml(p.subtype_of)}</b></div>` : '') +
      (p.subtypes ? `<div class="sp-sec">Struct_ops Subtypes (${p.subtypes.length})</div>${chips(p.subtypes)}` : '') +
      (p.usage ? `<div class="sp-sec">Usage</div><div class="sp-note">${escHtml(p.usage)}</div>` : '') +
      (p.context ? `<div class="sp-sec">Context</div><div class="sp-note">${escHtml(p.context)}</div>` : '') +
      section('map','Map Types') + section('helper','Helper Functions') + section('kfunc','Kfuncs') +
      (anyEdges ? '' : `<div class="sp-note" style="margin-top:12px">No helper, map or kfunc relationships recorded for this program type in the bundle.</div>`);

  } else if (KINDS.includes(t) || t === 'syscall') {
    const obj   = objOf(t, o.oi);
    const users = (obj.used_by || []).filter(([,scope]) => !F.scope || scope === F.scope);
    const rows  = users.map(([pi, scope]) => {
      const p = EBPF.programs[pi];
      return `<div class="sp-tech-row">
         <span class="sp-link sp-link-tech" style="cursor:pointer" onclick="openProgramPanel(${pi})">${escHtml(p.short)}</span>
         <span class="sp-dc-badge">${escHtml(scope)}</span>
       </div>`;
    }).join('');
    const edgeMeta = [
      o.scope ? `<span class="sp-chip ${o.scope==='core'?'audit':''}">scope: ${escHtml(o.scope)}</span>` : '',
      ...(o.caps || []).map(c => `<span class="sp-chip audit">${escHtml(c)}</span>`),
      ...(o.kconfig || []).map(c => `<span class="sp-chip">${escHtml(c)}</span>`),
      ...(o.flags || []).map(c => `<span class="sp-chip">${escHtml(c)}</span>`),
      ...(o.attach || []).map(c => `<span class="sp-chip">${escHtml(c)}</span>`),
    ].filter(Boolean).join('');
    body.innerHTML =
      `<div class="sp-badge">${escHtml((EB_KIND_LABEL[t]||t).toUpperCase())}${obj.since?` · KERNEL ${escHtml(kver(obj.since))}`:''}</div>` +
      `<div class="sp-name">${escHtml(obj.name)}</div>` +
      `<div class="sp-desc">${escHtml(obj.description)}</div>` +
      docLinks({ url:obj.url }) +
      (o.prog ? `<div class="sp-sec">In ${escHtml(o.prog.replace('BPF_PROG_TYPE_',''))}</div><div class="sp-chips">${edgeMeta}</div>` : '') +
      (obj.kernel_definition ? `<div class="sp-sec">Kernel Definition</div><div class="sp-note">${escHtml(obj.kernel_definition)}</div>` : '') +
      `<div class="sp-sec">Name <span style="font-size:10px;color:var(--text-dim)">(click to copy)</span></div>` +
      copyRow(obj.name) +
      (t === 'syscall'
        ? `<div class="sp-note" style="margin-top:10px">bpf() syscall commands act on the BPF subsystem as a whole; the bundle records no program-type relationships for them.</div>`
        : `<div class="sp-sec">Available To Program Types (${users.length})</div>` +
          (rows || `<div class="sp-note">No program-type relationship recorded in the bundle.</div>`));

  } else if (t === 'domain') {
    const dom = EBPF.domains[o.di];
    body.innerHTML =
      `<div class="sp-badge">FUNCTIONAL DOMAIN</div>` +
      `<div class="sp-name">${escHtml(dom.name)}</div>` +
      `<div class="sp-desc">${escHtml(dom.description)}</div>` +
      docLinks({ url:dom.url }) +
      `<div class="sp-sec">Program Types (${dom.programs.length})</div>` +
      dom.programs.map(pi => {
        const p = EBPF.programs[pi];
        return `<div class="sp-tech-row">
          <span class="sp-link sp-link-tech" style="cursor:pointer" onclick="openProgramPanel(${pi})">${escHtml(p.short)}</span>
          <span class="sp-dc-badge">${p.counts.helper}h · ${p.counts.map}m · ${p.counts.kfunc}k</span>
        </div>`;
      }).join('');

  } else if (t === 'group') {
    const kids = (d.children || d._children || []);
    body.innerHTML =
      `<div class="sp-badge">CATEGORY</div>` +
      `<div class="sp-name">${escHtml(o.name)}</div>` +
      (o.sub ? `<div class="sp-desc">${escHtml(o.sub)}</div>` : '') +
      `<div class="sp-sec">Members (${kids.length})</div>` +
      chips(kids.map(k => k.data.name));

  } else {
    const s = EBPF.stats;
    const scoped = F.scope === 'core' ? s.core_relationships
                 : F.scope === 'allowed' ? s.allowed_relationships
                 : s.total_relationships;
    body.innerHTML =
      `<div class="sp-name">${escHtml(EBPF.meta.title)}</div>` +
      `<div class="sp-desc">${escHtml(EBPF.meta.description)}</div>` +
      `<div class="sp-sec">Catalog</div>` +
      `<div class="sp-note">
         ${s.total_domains} functional domains &nbsp;·&nbsp; ${s.total_program_types} program types<br>
         ${s.total_helpers} helper functions &nbsp;·&nbsp; ${s.total_map_types} map types<br>
         ${s.total_kfuncs} kfuncs &nbsp;·&nbsp; ${s.total_syscall_commands} bpf() syscall commands<br>
         ${scoped} program-to-object relationships${F.scope?` (scope: ${escHtml(F.scope)})`:''}
       </div>` +
      `<div class="sp-note" style="margin-top:6px">${escHtml(EBPF.meta.note)}</div>`;
  }
  document.getElementById('sp').classList.add('on');
}

/* -------------------------------------------------------
   INIT — shared by both eBPF pages
------------------------------------------------------- */
function ebInit(render) {
  if (typeof EBPF === 'undefined') return false;

  OBJ.helper  = EBPF.helpers;
  OBJ.map     = EBPF.map_types;
  OBJ.kfunc   = EBPF.kfuncs;
  OBJ.syscall = EBPF.syscall_commands;
  KINDS.forEach(k => {
    UNATTACHED[k] = OBJ[k].map((o,i) => ({o,i})).filter(({o}) => !o.used_by.length);
  });

  Object.assign(EL, {
    scope:  document.getElementById('eb-scope'),
    domain: document.getElementById('eb-domain'),
    prog:   document.getElementById('eb-prog'),
    map:    document.getElementById('eb-map'),
    helper: document.getElementById('eb-helper'),
    kfunc:  document.getElementById('eb-kfunc'),
    sys:    document.getElementById('eb-sys'),
    q:      document.getElementById('eb-q'),
  });
  ebRender = render;

  ['scope','domain','prog','map','helper','kfunc','sys'].forEach(k =>
    EL[k].addEventListener('change', cascade));
  let qTimer;
  EL.q.addEventListener('input', () => {
    clearTimeout(qTimer);
    qTimer = setTimeout(cascade, 260);
  });
  return true;
}
