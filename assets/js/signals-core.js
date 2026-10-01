/* -------------------------------------------------------
   SIGNALS — shared model, filters and detail panel
   Used by signals.js (visualized) and signals-matrix.js (table).
   Data: assets/data/signals.js (const SIGNALS)

   The model is one sentence long: a MAP is a rendezvous, a
   PRODUCER is a program that writes it, a CONSUMER is a program
   that reads it. Everything below either narrows that set or
   explains one member of it.
------------------------------------------------------- */

/* ── Flow colours ──────────────────────────────────────────
   Two hues carry the only meaning colour carries here — amber
   for a write, blue for a read — so a link's direction is
   readable before any label is. A map node takes the colour of
   what happens to it: amber when only the kernel writes it,
   blue when only the kernel reads it, khaki when both, and the
   neutral grey when neither (no reachable access at all).

   Validated against the page surface #1c1c16: adjacent-pair CVD
   separation ΔE 16.0 (protan) / 11.6 (tritan), normal-vision
   ΔE 16.4, every step ≥ 3:1 contrast. Every node is also
   directly labelled and the legend is always on screen, so
   identity is never colour alone. ── */
const SC = {
  produce: '#c87828',   /* write — the Kestrel amber */
  consume: '#78a8d8',   /* read  — slate blue */
  both:    '#b0b070',   /* written and read in kernel */
  none:    '#8e9490',   /* declared, no reachable access */
};
const FLOW_COLOR = {
  'kernel-state': SC.both, 'kernel-output': SC.produce,
  'control-input': SC.consume, 'declared-only': SC.none,
};
const FLOW_SHORT = {
  'kernel-state': 'read + written', 'kernel-output': 'written only',
  'control-input': 'read only', 'declared-only': 'no access',
};
const SCOPE_LABEL = {
  shared: 'Shared', 'per-object': 'Per object', object: 'Object',
};
const SCOPE_NOTE = {
  shared: 'Declared in all three objects: the loader creates it once and shares the descriptor into each before load, so there is one kernel instance.',
  'per-object': 'Declared in more than one object but not in all three; each gets its own instance.',
  object: 'Declared by one object only. Nothing outside that object reaches it without a descriptor from the loader.',
};
/* The three objects, by the key the data uses for a program's `domain`. */
const DOMAIN_LABEL = {
  host: 'host.bpf.o', net_sock: 'net_sock.bpf.o', net_pkt: 'net_pkt.bpf.o',
};

/* Filled by sigInit() from the SIGNALS global. */
let MAPS = [], PROGS = [], TYPES = {};

/* -------------------------------------------------------
   HELPERS
------------------------------------------------------- */
function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]);
}

/* A map's declared size, written the way the source writes it. */
function entriesOf(m) {
  if (m.max_entries) return m.max_entries;
  /* The storage types are sized by the kernel object they hang off, not by
     a max_entries the declaration could carry. */
  return /STORAGE/.test(m.type) ? 'per object' : '';
}

/* -------------------------------------------------------
   FILTER STATE
------------------------------------------------------- */
const F = {
  scope: '', domain: '', prog: '', role: '',
  type: '', family: '', flow: '', q: '',
};
const EL = {};
let sigRender = () => {};

function edgeProgs(m, which) { return m[which].map(e => e.prog); }
function touchProgs(m) {
  return [...new Set([...edgeProgs(m, 'producers'), ...edgeProgs(m, 'consumers'), ...m.owners])];
}

function mapText(m) {
  return [m.name, m.type, m.family, m.key, m.value, m.doc, m.blurb, m.file,
          m.macro, m.gates.join(' '), (m.objects || []).join(' '),
          touchProgs(m).map(i => PROGS[i].name).join(' ')]
    .filter(Boolean).join(' ').toLowerCase();
}

/* Does map `m` survive the filters? `skip` omits one constraint — the
   omit-self pattern that lets the dropdowns cascade without locking
   each other out. */
function mapPasses(m, skip) {
  if (skip !== 'scope'  && F.scope  && m.scope  !== F.scope)  return false;
  if (skip !== 'type'   && F.type   && m.type   !== F.type)   return false;
  if (skip !== 'family' && F.family && m.family !== F.family) return false;
  if (skip !== 'flow'   && F.flow   && m.flow   !== F.flow)   return false;
  if (skip !== 'domain' && F.domain &&
      !touchProgs(m).some(i => PROGS[i].domain === F.domain)) return false;
  if (skip !== 'prog' && F.prog !== '') {
    const pi = +F.prog;
    const asP = edgeProgs(m, 'producers').includes(pi);
    const asC = edgeProgs(m, 'consumers').includes(pi);
    const owns = m.owners.includes(pi);
    if (F.role === 'produce' ? !asP : F.role === 'consume' ? !asC : !(asP || asC || owns))
      return false;
  }
  if (skip !== 'q' && F.q && !mapText(m).includes(F.q)) return false;
  return true;
}

function shownMaps(skip) { return MAPS.filter(m => mapPasses(m, skip)); }

/* -------------------------------------------------------
   DROPDOWNS — cascading, omit-self
------------------------------------------------------- */
function rebuildSelect(el, values, labelFn) {
  if (!el) return;
  const prev = el.value;
  const sentinel = el.options[0] ? el.options[0].text : '';
  el.length = 0;
  el.add(new Option(sentinel, ''));
  values.forEach(v => el.add(new Option(labelFn ? labelFn(v) : String(v), v)));
  const at = values.map(String).indexOf(prev);
  el.selectedIndex = at < 0 ? 0 : at + 1;
}

function uniq(list) { return [...new Set(list)].sort((a, b) => String(a).localeCompare(String(b))); }

function cascade() {
  /* The graph page carries only scope, family and flow; the matrix page
     has every control. A control that is not on the page filters nothing. */
  const val = k => (EL[k] ? EL[k].value : '');
  F.scope  = val('scope');
  F.domain = val('domain');
  F.prog   = val('prog');
  F.role   = val('role');
  F.type   = val('type');
  F.family = val('family');
  F.flow   = val('flow');
  F.q      = EL.q ? EL.q.value.trim().toLowerCase() : '';

  rebuildSelect(EL.type,   uniq(shownMaps('type').map(m => m.type)));
  rebuildSelect(EL.family, uniq(shownMaps('family').map(m => m.family)));
  rebuildSelect(EL.flow,
    uniq(shownMaps('flow').map(m => m.flow)), v => SIGNALS.flow_label[v] || v);
  rebuildSelect(EL.domain,
    uniq(shownMaps('domain').flatMap(m => touchProgs(m).map(i => PROGS[i].domain))),
    v => DOMAIN_LABEL[v] || v);
  rebuildSelect(EL.prog,
    uniq(shownMaps('prog').flatMap(touchProgs)).sort((a, b) =>
      PROGS[a].name.localeCompare(PROGS[b].name)),
    v => PROGS[v].name);

  /* Re-read: a rebuild above may have dropped the previous selection. */
  F.type = val('type'); F.family = val('family'); F.flow = val('flow');
  F.domain = val('domain'); F.prog = val('prog');
  if (EL.role) EL.role.disabled = F.prog === '';

  sigRender();
}

function clearFilters() {
  ['scope', 'domain', 'prog', 'role', 'type', 'family', 'flow', 'q'].forEach(k => {
    const el = EL[k];
    if (!el) return;
    const def = el.options && [...el.options].find(o => o.defaultSelected);
    el.value = def ? def.value : '';
  });
  cascade();
}

/* -------------------------------------------------------
   SIDE PANEL
------------------------------------------------------- */
function closePanel() { document.getElementById('sp').classList.remove('on'); }

function chips(list, cls) {
  return list.length
    ? `<div class="sp-chips">${list.map(v => `<span class="sp-chip ${cls || ''}">${escHtml(v)}</span>`).join('')}</div>`
    : '';
}

/* Which objects declare this map. Every program in an object shares its
   copy, so the object, not the program, is the unit a declaration belongs
   to; the programs that actually touch it are the producers and consumers
   below. */
function ownerChips(objects) {
  if (!objects.length) return `<div class="sp-row-desc">None.</div>`;
  return `<div class="sp-chips">${objects.map(o =>
    `<span class="sp-chip">${escHtml(o)}</span>`).join('')}</div>`;
}

/* A program's section, written as the source writes it. */
function sectionOf(p) { return (p.attach && p.attach[0]) || ''; }

/* The key/value shape: the struct's members, each with the comment the
   source keeps beside it. This is the "available key/value pairs" the
   page exists to show. */
function typeBlock(label, typeName, map) {
  const bare = String(typeName || '').replace(/^const\s+/, '');
  const m = /^struct\s+(\w+)/.exec(bare);
  const t = m && TYPES[m[1]];
  let out = `<div class="sig-kv-head"><span class="sig-kv-role">${escHtml(label)}</span>` +
            `<code class="sig-kv-type">${escHtml(bare || '—')}</code></div>`;
  if (!t) {
    let why;
    if (bare) why = `A scalar ${label}: one word, no members to list.`;
    else if (map.type === 'RINGBUF') why = 'A ring buffer is a stream, not a table: it has neither.';
    else if (/STORAGE/.test(map.type)) why = 'Local storage: the kernel object it hangs off is the key.';
    else if (map.type === 'ARRAY_OF_MAPS') why = 'Each slot holds a map, not a value.';
    else why = 'Not declared with a type in the source.';
    out += `<div class="sig-kv-scalar">${escHtml(why)}</div>`;
    return `<div class="sig-kv">${out}</div>`;
  }
  if (t.doc) out += `<div class="sp-row-desc" style="margin:4px 0 7px">${escHtml(t.doc)}</div>`;
  /* One grid for the whole member list, so the type and the name line up
     down the block however long any one of them is. The comment spans both
     columns on its own line rather than fighting them for width — in a 440px
     panel a third inline column would crush all three. */
  out += '<div class="sig-members">' + t.fields.map(f => {
    /* The example is the member's encoding made concrete; `decoded` says what
       that literal means. The comment the source keeps follows, when there is
       one — it is the only part of the three that the code wrote. */
    const ex = f.example
      ? `<div class="x"><code>${escHtml(f.example)}</code>` +
        (f.decoded ? `<span class="d">${escHtml(f.decoded)}</span>` : '') + `</div>`
      : (f.decoded ? `<div class="x"><span class="d">${escHtml(f.decoded)}</span></div>` : '');
    return `<code class="t">${escHtml(f.type)}</code>` +
           `<code class="n">${escHtml(f.name)}${f.bits ? ':' + escHtml(f.bits) : ''}</code>` +
           ex +
           (f.note ? `<div class="c">${escHtml(f.note)}</div>` : '');
  }).join('') + '</div>';
  return `<div class="sig-kv">${out}</div>`;
}

/* One side of a map: the programs on it, each with the call that proves it. */
function edgeBlock(m, which) {
  const list = m[which];
  const role = which === 'producers' ? 'produce' : 'consume';
  const color = which === 'producers' ? SC.produce : SC.consume;
  if (!list.length) {
    return `<div class="sp-note">No program in <code>crates/kestrel-ebpf</code> ${
      which === 'producers'
        ? 'writes this map. Its contents come from userspace: the loader at load, or the daemon while it runs.'
        : 'reads this map. Its contents are drained by userspace.'}</div>`;
  }
  return list.map(e => {
    const p = PROGS[e.prog];
    /* The function and the helper name the access; the file it lives in is
       not something this page reports. */
    const sites = e.sites.map(s =>
      `<div class="sig-site"><code>${escHtml(s.fn)}()</code> · ${escHtml(s.helper)}</div>`)
      .join('');
    return `<div class="sig-edge" style="border-left-color:${color}">` +
           `<div class="sig-edge-head" onclick="openProgPanel(${e.prog})">` +
           `<span class="sig-edge-name">${escHtml(p.name)}</span>` +
           `<span class="sp-chip">${escHtml(DOMAIN_LABEL[p.domain] || p.domain)}</span></div>` +
           sites + `</div>`;
  }).join('');
}

function openMapPanel(i) {
  const m = MAPS[i];
  const body = document.getElementById('sp-body');
  const flowTxt = SIGNALS.flow_label[m.flow] || m.flow;
  body.innerHTML =
    `<div class="sp-badge">${escHtml(m.family.toUpperCase())}</div>` +
    `<div class="sp-name"><code>${escHtml(m.name)}</code></div>` +
    `<div class="sig-flow-pill" style="border-color:${FLOW_COLOR[m.flow]};color:${FLOW_COLOR[m.flow]}">` +
      `${escHtml(flowTxt)}</div>` +
    (m.blurb ? `<div class="sp-desc">${escHtml(m.blurb)}</div>` : '') +
    (m.doc ? `<div class="sp-note">${escHtml(m.doc)}</div>` : '') +

    `<div class="sp-sec">Declaration</div>` +
    `<table class="sig-fields sig-decl"><tbody>` +
      `<tr><td class="sig-f-type">type</td><td colspan="2" class="sig-f-name">BPF_MAP_TYPE_${escHtml(m.type)}</td></tr>` +
      `<tr><td class="sig-f-type">scope</td><td colspan="2" class="sig-f-name">${escHtml(SCOPE_LABEL[m.scope])}` +
        `<span class="sig-f-note"> — ${escHtml(SCOPE_NOTE[m.scope])}</span></td></tr>` +
      (entriesOf(m) ? `<tr><td class="sig-f-type">max_entries</td><td colspan="2" class="sig-f-name">${escHtml(entriesOf(m))}${
        m.max_entries_src && m.max_entries_src !== m.max_entries
          ? `<span class="sig-f-note"> — ${escHtml(m.max_entries_src)}</span>` : ''}</td></tr>` : '') +
      (m.map_flags ? `<tr><td class="sig-f-type">map_flags</td><td colspan="2" class="sig-f-name">${escHtml(m.map_flags)}</td></tr>` : '') +
      `<tr><td class="sig-f-type">pinned</td><td colspan="2" class="sig-f-name">${m.pinned ? escHtml(m.pinned) : 'no'}</td></tr>` +
      (m.macro ? `<tr><td class="sig-f-type">declared by</td><td colspan="2" class="sig-f-name">${escHtml(m.macro)}()</td></tr>` : '') +
      `<tr><td class="sig-f-type">instances</td><td colspan="2" class="sig-f-name">${
        m.scope === 'shared'
          ? `1, created by the loader and shared into ${m.objects.length} objects`
          : m.scope === 'object'
            ? `1, in ${escHtml(m.objects[0] || '')}`
            : `${m.objects.length}, one per declaring object`}</td></tr>` +
      `<tr><td class="sig-f-type">reached by</td><td colspan="2" class="sig-f-name">${
        m.owners.length} program${m.owners.length === 1 ? '' : 's'} share the object${
        m.objects.length > 1 ? 's' : ''}; ${
        new Set([...edgeProgs(m, 'producers'), ...edgeProgs(m, 'consumers')]).size} touch the map</td></tr>` +
    `</tbody></table>` +
    `<div class="sig-kv-role" style="margin-bottom:4px">Declared by</div>` +
    ownerChips(m.objects) +
    (m.gates.length ? `<div class="sp-row-desc" style="margin-top:6px">Declared only when the object defines ${
      m.gates.map(g => `<code>${escHtml(g)}</code>`).join(' and ')}.</div>` : '') +

    `<div class="sp-sec">Key / value pairs</div>` +
    typeBlock('key', m.key, m) +
    typeBlock('value', m.value, m) +

    `<div class="sp-sec">Producers — ${m.producers.length} program${m.producers.length === 1 ? '' : 's'} write</div>` +
    edgeBlock(m, 'producers') +

    `<div class="sp-sec">Consumers — ${m.consumers.length} program${m.consumers.length === 1 ? '' : 's'} read</div>` +
    edgeBlock(m, 'consumers');

  document.getElementById('sp').classList.add('on');
  body.scrollTop = 0;
}

function openProgPanel(i) {
  const p = PROGS[i];
  const body = document.getElementById('sp-body');
  const list = (ids, which) => ids.length
    ? `<div class="sp-chips">${ids.map(mi =>
        `<span class="sp-chip sig-chip-map" style="border-color:${FLOW_COLOR[MAPS[mi].flow]}"` +
        ` onclick="openMapPanel(${mi})">${escHtml(MAPS[mi].name)}</span>`).join('')}</div>`
    : `<div class="sp-row-desc">None.</div>`;

  body.innerHTML =
    `<div class="sp-badge">${escHtml(DOMAIN_LABEL[p.domain] || p.domain)} PROGRAM</div>` +
    `<div class="sp-name">${escHtml(p.name)}</div>` +
    (p.doc ? `<div class="sp-desc">${escHtml(p.doc)}</div>` : '') +

    `<div class="sp-sec">Composition</div>` +
    `<table class="sig-fields sig-decl"><tbody>` +
      (p.prog_type ? `<tr><td class="sig-f-type">program type</td><td class="sig-f-name">${escHtml(p.prog_type)}</td></tr>` : '') +
      `<tr><td class="sig-f-type">object</td><td class="sig-f-name">${escHtml(p.base)}</td></tr>` +
      (sectionOf(p) ? `<tr><td class="sig-f-type">section</td><td class="sig-f-name">SEC("${escHtml(sectionOf(p))}")</td></tr>` : '') +
      (p.attach_how ? `<tr><td class="sig-f-type">attached</td><td class="sig-f-name">${escHtml(p.attach_how)}</td></tr>` : '') +
      `<tr><td class="sig-f-type">catalogue bit</td><td class="sig-f-name">${
        p.catalogue >= 0 ? `${p.catalogue} of load_state.skipped` : 'not in the loader’s catalogue'}</td></tr>` +
      (p.generated ? `<tr><td class="sig-f-type">written by</td><td class="sig-f-name">${escHtml(p.generated)}()</td></tr>` : '') +
    `</tbody></table>` +
    (p.note ? `<div class="sp-note">${escHtml(p.note)}</div>` : '') +
    (p.rows && p.rows.length ? `<div class="sp-sec">Rows it writes — layer.proto</div>${chips(p.rows)}` : '') +
    (p.gates.length ? `<div class="sp-sec">Compiled under</div>${chips(p.gates)}` : '') +

    `<div class="sp-sec">Writes — ${p.produces.length} map${p.produces.length === 1 ? '' : 's'}</div>` +
    list(p.produces, 'produce') +
    `<div class="sp-sec">Reads — ${p.consumes.length} map${p.consumes.length === 1 ? '' : 's'}</div>` +
    list(p.consumes, 'consume');

  document.getElementById('sp').classList.add('on');
  body.scrollTop = 0;
}

function openAboutPanel() {
  const c = SIGNALS.counts;
  const body = document.getElementById('sp-body');
  const objects = (SIGNALS.objects || []).map(o =>
    `<div class="sig-edge"><div class="sig-edge-head"><span class="sig-edge-name">${escHtml(o.file)}</span>` +
    `<span class="sp-chip">${o.programs} programs · ${o.maps} maps</span></div>` +
    `<div class="sp-row-desc">${escHtml(o.doc)}</div></div>`).join('');
  body.innerHTML =
    `<div class="sp-name">Kestrel signals</div>` +
    `<div class="sp-desc">Every eBPF map the three objects under <code>crates/kestrel-ebpf</code> declare, ` +
    `with the programs that write it and the programs that read it.</div>` +
    `<div class="sp-note">ABI ${escHtml(SIGNALS.abi)}<br>` +
    `${c.maps} maps &nbsp;·&nbsp; ${c.shared} created once by the loader and shared by all ${c.objects} objects<br>` +
    `${c.programs} programs, the loader’s catalogue of ${c.catalogue}<br>${c.edges} producer / consumer edges</div>` +
    `<div class="sp-sec">The objects</div>` + objects +
    `<div class="sp-sec">How this was derived</div>` +
    `<div class="sp-row-desc">${escHtml(SIGNALS.method)}</div>` +
    `<div class="sp-sec">About the examples</div>` +
    `<div class="sp-row-desc">Every key and value member carries a worked example. ` +
    `The literal is <b>illustrative</b> &mdash; constructed to show the encoding, not captured ` +
    `from a run. What it decodes to is not invented: bit names, enum names and their values ` +
    `are read out of the headers. Of ${SIGNALS.counts.members} members, ` +
    `${SIGNALS.counts.basis.constants} decode against named constants, ` +
    `${SIGNALS.counts.basis.source} quote the header's own wording, ` +
    `${SIGNALS.counts.basis.unit} state a unit the member name settles, and ` +
    `${SIGNALS.counts.basis.type} say only what the C type says.</div>` +
    `<div class="sp-sec">Generated</div>` +
    `<div class="sp-row-desc">${escHtml(SIGNALS.generated)} from <code>${escHtml(SIGNALS.source)}</code> ` +
    `by <code>assets/data/source/signals_to_js.py</code>.</div>`;
  document.getElementById('sp').classList.add('on');
}

/* -------------------------------------------------------
   INIT — shared by both Signals pages
------------------------------------------------------- */
function sigInit(render) {
  if (typeof SIGNALS === 'undefined') return false;
  MAPS = SIGNALS.maps; PROGS = SIGNALS.programs; TYPES = SIGNALS.types;

  Object.assign(EL, {
    scope:  document.getElementById('sg-scope'),
    domain: document.getElementById('sg-domain'),
    prog:   document.getElementById('sg-prog'),
    role:   document.getElementById('sg-role'),
    type:   document.getElementById('sg-type'),
    family: document.getElementById('sg-family'),
    flow:   document.getElementById('sg-flow'),
    q:      document.getElementById('sg-q'),
  });
  sigRender = render;

  ['scope', 'domain', 'prog', 'role', 'type', 'family', 'flow'].forEach(k =>
    EL[k] && EL[k].addEventListener('change', cascade));
  /* The matrix page has a search box; the graph does not. */
  let qTimer;
  if (EL.q) EL.q.addEventListener('input', () => {
    clearTimeout(qTimer);
    qTimer = setTimeout(cascade, 260);
  });
  return true;
}
