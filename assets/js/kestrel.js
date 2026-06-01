/* -------------------------------------------------------
   CONSTANTS
------------------------------------------------------- */
const TC = {
  root:'#cdcfce', tactic:'#c87828', technique:'#a8a878',
  subtechnique:'#7a9878', det:'#c09060', dc:'#68a878'
};
const TR = { root:13, tactic:11, technique:9, subtechnique:7, det:5, dc:4 };
const TAC_COL = {
  TA0001:'#c87828', TA0002:'#a07838', TA0003:'#7a9878', TA0004:'#8a9870',
  TA0005:'#9890a0', TA0006:'#c06840', TA0007:'#68a878', TA0008:'#7888a8',
  TA0009:'#b08868', TA0010:'#c0a058', TA0011:'#78a898', TA0040:'#c87828',
  TA0112:'#8870a0'
};
const LGND = [
  {type:'tactic',       label:'Tactic'},
  {type:'technique',    label:'Technique'},
  {type:'subtechnique', label:'Sub-Technique'},
  {type:'det',          label:'Detection Strategy'},
  {type:'dc',           label:'Data Component'},
];

function nColor(d) {
  const t = d.data?.type;
  if (!t) return TC.root;
  return TC[t] || '#888';
}

/* -------------------------------------------------------
   TOOLTIP
------------------------------------------------------- */
const ttEl = document.getElementById('tt');
function showTip(e, d) {
  const data = d.data || {};
  const t    = data.type || 'root';
  const name = data.name || 'Root';
  const id   = data.id   || '';
  let meta   = '';
  if (t === 'dc')  meta = `${data.ebpf_program ? data.ebpf_program.replace('BPF_PROG_TYPE_','') + ' · ' : ''}${data.log_source||''}<br>Key: ${data.id||''}`;
  if (t === 'det') meta = id;
  if (t === 'tactic') meta = id;
  const hasUrl = !!data.url;
  ttEl.innerHTML =
    `<div class="tt-type">${t.toUpperCase()}</div>` +
    `<div class="tt-name">${name}</div>` +
    (id && t!=='tactic' ? `<div class="tt-id">${id}</div>` : '') +
    (meta ? `<div class="tt-meta">${meta}</div>` : '') +
    (hasUrl ? `<div class="tt-hint">Click = details  ·  Shift+Click = MITRE ↗</div>` : '');
  ttEl.classList.add('on');
  moveTip(e);
}
function moveTip(e) {
  const x=e.clientX+14, y=e.clientY-8;
  const w=ttEl.offsetWidth, h=ttEl.offsetHeight;
  ttEl.style.left=(x+w>window.innerWidth  ? x-w-26 : x)+'px';
  ttEl.style.top =(y+h>window.innerHeight ? y-h    : y)+'px';
}
function hideTip() { ttEl.classList.remove('on'); }

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
   STATS BAR
------------------------------------------------------- */
function fillStats() {
  const s = DATA.stats;
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('s0', s.total_tactics                    || 13);
  set('s1', s.total_techniques_parent          || 179);
  set('s2', s.total_sub_techniques             || 247);
  set('s3', s.total_detection_strategies       || 341);
  set('s4', s.total_analytics                  || 341);
  set('s5', s.total_data_components_referenced || 19);
  set('s6', s.unique_audit_keys                || 674);
}

/* -------------------------------------------------------
   LEGEND
------------------------------------------------------- */
function buildLegend(id) {
  const c=document.getElementById(id); if(!c) return;
  LGND.forEach(({type,label})=>{
    const el=document.createElement('div'); el.className='li';
    el.innerHTML=`<div class="ld" style="background:${TC[type]}"></div>${label}`;
    c.appendChild(el);
  });
}

/* -------------------------------------------------------
   SIDE PANEL
------------------------------------------------------- */
function openPanel(d) {
  const data = d.data || {};
  const t    = data.type || 'root';
  const sp   = document.getElementById('sp');
  const body = document.getElementById('sp-body');

  const mitreLink = data.url
    ? `<a class="sp-mitre-link" href="${data.url}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">
         ↗ View on MITRE ATT&amp;CK
       </a>`
    : '';

  // ── Shared row-query helpers ────────────────────────────────────────────
  function rowsFor(field, val) {
    return DATA.rows.filter(r => r[field] === val);
  }
  function uniqueBy(rows, keyFn, labelFn) {
    const seen = new Set();
    const out  = [];
    rows.forEach(r => {
      const k = keyFn(r);
      if (k && !seen.has(k)) { seen.add(k); out.push({ key: k, label: labelFn(r) }); }
    });
    return out.sort((a,b) => a.key.localeCompare(b.key));
  }

  // ── Link helpers ──────────────────────────────────────────────────────────
  function lnk(cls, url, text, title='') {
    if (!url) return `<span class="${cls}">${text}</span>`;
    const th = title ? ` title="${title}"` : '';
    return `<a class="sp-link ${cls}" href="${url}" target="_blank" rel="noopener noreferrer"${th}>${text}<span class="sp-ext">↗</span></a>`;
  }

  // Render detection strategy rows — each row is a linked DET ID + name
  function detRows(rows) {
    const dets = uniqueBy(rows,
      r => r.det_id,
      r => ({ id: r.det_id, name: r.det_name, url: r.det_url })
    );
    return dets.map(({ label: l }) => `
      <div class="sp-tech-row">
        ${lnk('sp-link-det', l.url, l.id)}
        <span class="sp-row-name">${lnk('sp-link-det', l.url, l.name)}</span>
      </div>`).join('');
  }

  // Render data component rows — DC badge linked + name linked + channels + auditd rules + eBPF
  function dcRows(rows) {
    const map = {};
    rows.forEach(r => {
      if (!r.dc_id) return;
      if (!map[r.dc_id]) map[r.dc_id] = { name: r.dc_name, url: r.dc_url || '', channels: new Set(), rowSet: [] };
      if (r.log_source) map[r.dc_id].channels.add(r.log_source);
      map[r.dc_id].rowSet.push(r);
    });
    const campDcRegistry = (typeof CAMPAIGNS !== 'undefined' && CAMPAIGNS.data_component_registry_linux_updated) || {};
    return Object.entries(map).sort(([a],[b]) => a.localeCompare(b)).map(([dc_id, v]) => {
      const auditChannels = [...v.channels].filter(c => c.startsWith('audit:'));
      const channelBadges = [...v.channels].slice(0,4).map(c =>
        `<span class="sp-chip ${c.startsWith('audit:')?'audit':c.startsWith('ebpf:')?'ebpf':''}" style="font-size:7.5px;padding:1px 5px">${c}</span>`
      ).join('');
      const campDcr = campDcRegistry[dc_id] || {};
      // auditd rules: full strings from campaign DCR, else audit_key list from rows
      const campRules = campDcr.auditd_rules_original || [];
      const auditKeys = [...new Set(v.rowSet.map(r=>r.audit_key).filter(Boolean))];
      const auditRulesHtml = campRules.length
        ? campRules.map(r=>{ const s=r.rule.replace(/'/g,"\\'"); return `<div class="sp-rule" onclick="copy('${s}')"><span class="cp">COPY</span><code>${r.rule}</code></div>`; }).join('')
        : auditKeys.map(k=>{ const s=k.replace(/'/g,"\\'"); return `<div class="sp-rule" onclick="copy('${s}')"><span class="cp">COPY</span><code>${k}</code></div>`; }).join('');
      // eBPF: full programs from campaign DCR, else channel+events from rows
      const campEbpf = campDcr.ebpf_programs || [];
      const ebpfRowChs = [...new Set(v.rowSet.filter(r=>r.log_source&&r.log_source.startsWith('ebpf:')).map(r=>r.log_source))];
      const ebpfHtml = campEbpf.length
        ? campEbpf.map(p=>{ const filt=p.filter?renderFilter(p.filter):''; return `<div class="cov-ebpf"><b>attach</b> ${p.attach}${filt?`<br><b>filter</b> ${filt}`:''}${p.kernel_min?` · <b>kernel ≥</b> ${p.kernel_min}`:''}${p.co_re?' · CO-RE':''}</div>`; }).join('')
        : ebpfRowChs.map(ch=>{ const evts=[...new Set(v.rowSet.filter(r=>r.log_source===ch).map(r=>r.event).filter(Boolean))]; return `<div class="cov-ebpf"><b>channel</b> ${ch}${evts.length?`<br><b>events</b> ${evts.slice(0,3).join(' · ')}`:''}</div>`; }).join('');
      return `
        <div class="sp-tech-row" style="flex-direction:column;align-items:flex-start;gap:3px;padding:5px 0">
          <div style="display:flex;align-items:center;gap:6px;width:100%">
            ${lnk('sp-link-dc sp-dc-badge', v.url, dc_id)}
            <span class="sp-row-name" style="flex:1">${lnk('sp-link-dc', v.url, v.name)}</span>
          </div>
          ${channelBadges ? `<div style="display:flex;flex-wrap:wrap;gap:3px">${channelBadges}</div>` : ''}
          ${auditRulesHtml ? `<div style="width:100%;margin-top:3px"><div style="font-size:8px;color:var(--text-dim);margin-bottom:2px;text-transform:uppercase;letter-spacing:.3px">auditd rules</div>${auditRulesHtml}</div>` : ''}
          ${ebpfHtml ? `<div style="width:100%;margin-top:3px"><div style="font-size:8px;color:var(--text-dim);margin-bottom:2px;text-transform:uppercase;letter-spacing:.3px">eBPF programs</div>${ebpfHtml}</div>` : ''}
        </div>`;
    }).join('');
  }

  // ── DC ──────────────────────────────────────────────────────────────────
  if (t === 'dc') {
    const dcId  = data.dc_id;
    const entry = DATA.dcr[dcId] || {};
    const campDcEntry = ((typeof CAMPAIGNS !== 'undefined' && CAMPAIGNS.data_component_registry_linux_updated) || {})[dcId] || {};
    const dcRows_ = DATA.rows.filter(r => r.dc_id === dcId);
    let channels = [];
    dcRows_.forEach(r=>{ if(r.log_source && !channels.includes(r.log_source)) channels.push(r.log_source); });
    const chips = channels.map(ch=>
      `<span class="sp-chip ${ch.startsWith('ebpf:')?'ebpf':ch.startsWith('audit:')?'audit':''}">${ch}</span>`
    ).join('');
    // eBPF programs: built from enriched row data (ebpf_program, ebpf_weight, ebpf_filters)
    const ebpfRows = dcRows_.filter(r => r.ebpf_program);
    const progMap = {};
    ebpfRows.forEach(r => {
      if (!progMap[r.ebpf_program]) progMap[r.ebpf_program] = { weight: r.ebpf_weight, max_count: r.ebpf_max_count, filters: r.ebpf_filters || [] };
    });
    const ebpfHtml = Object.entries(progMap).map(([prog, v]) => {
      const short = prog.replace('BPF_PROG_TYPE_', '');
      const filtersHtml = (v.filters||[]).map(f=>`<div class="sp-rule"><code>${f}</code></div>`).join('');
      return `<div class="cov-ebpf"><b>${short}</b> · weight <span style="color:var(--accent)">${v.weight}</span> · max_count ${v.max_count}${filtersHtml?`<div style="margin-top:4px">${filtersHtml}</div>`:''}`;
    }).join('');
    // Audit keys (event identifiers — secondary)
    const auditKeys = [...new Set(dcRows_.map(r=>r.audit_key).filter(Boolean))];
    const auditKeysHtml = auditKeys.map(k=>{ const s=k.replace(/'/g,"\\'"); return `<div class="sp-rule" onclick="copy('${s}')"><span class="cp">COPY</span><code>${k}</code></div>`; }).join('') || `<div class="sp-empty" style="padding:8px 0;font-size:11.5px">No event keys</div>`;
    const techs = [...new Set(DATA.rows.filter(r=>r.dc_id===dcId).map(r=>`${r.tech_id}: ${r.tech_name}`))];
    body.innerHTML = `
      <div class="sp-badge">${dcId}</div>
      <div class="sp-name">${campDcEntry.name||entry.name||data.name}</div>
      <div class="sp-desc">${campDcEntry.description||entry.description||''}</div>
      ${mitreLink}
      <div class="sp-sec">Log Source Channels</div>
      <div class="sp-chips">${chips}</div>
      ${ebpfHtml ? `<div class="sp-sec">eBPF Programs</div>${ebpfHtml}` : ''}
      <div class="sp-sec">Event Keys <span style="font-size:10px;color:var(--text-dim)">(click to copy)</span></div>
      ${auditKeysHtml}
      <div class="sp-sec">Referenced by Techniques (${techs.length})</div>
      ${(() => {
        const techRows = DATA.rows.filter(r => r.dc_id === dcId);
        const seen = new Set();
        return techRows.filter(r => {
          if (seen.has(r.tech_id)) return false;
          seen.add(r.tech_id); return true;
        }).sort((a,b) => a.tech_id.localeCompare(b.tech_id))
          .map(r => `<div class="sp-tech-row">
            ${lnk('sp-link-tech', r.tech_url, r.tech_id)}
            <span class="sp-row-name">${lnk('sp-link-tech', r.tech_url, r.tech_name)}</span>
          </div>`).join('');
      })()}
    `;

  // ── TACTIC ──────────────────────────────────────────────────────────────
  } else if (t === 'tactic') {
    const tRows    = rowsFor('tac_id', data.id);
    const children = d.children || d._children || [];
    const techs    = uniqueBy(tRows, r => r.tech_id,
                       r => ({ id: r.tech_id, name: r.tech_name, url: r.tech_url }));
    body.innerHTML = `
      <div class="sp-badge">${data.id}</div>
      <div class="sp-name">${data.name}</div>
      ${mitreLink}
      <div class="sp-sec">Techniques (${techs.length})</div>
      ${techs.map(({label:l}) => `
        <div class="sp-tech-row">
          ${lnk('sp-link-tech', l.url, l.id)}
          <span class="sp-row-name">${lnk('sp-link-tech', l.url, l.name)}</span>
        </div>`).join('')}
      <div class="sp-sec">Detection Strategies (${uniqueBy(tRows, r=>r.det_id, r=>r).length})</div>
      ${detRows(tRows)}
      <div class="sp-sec">Data Components (${Object.keys((() => { const m={}; tRows.forEach(r=>{if(r.dc_id)m[r.dc_id]=1;}); return m; })()).length})</div>
      ${dcRows(tRows)}
    `;

  // ── TECHNIQUE ────────────────────────────────────────────────────────────
  } else if (t === 'technique') {
    const tRows    = rowsFor('tech_id', data.id);
    const children = d.children || d._children || [];

    // Sub-techniques from rows (distinct)
    const subs = uniqueBy(tRows.filter(r => r.sub_id),
      r => r.sub_id,
      r => ({ id: r.sub_id, name: r.sub_name, url: r.sub_url })
    );

    // Analytics descriptions
    const analytics = uniqueBy(tRows, r => r.an_id,
      r => ({ id: r.an_id, desc: r.an_desc, url: r.an_url })
    );

    body.innerHTML = `
      <div class="sp-badge">${data.id}</div>
      <div class="sp-name">${data.name}</div>
      ${mitreLink}
      ${subs.length ? `
        <div class="sp-sec">Sub-Techniques (${subs.length})</div>
        ${subs.map(({label:l}) => `
          <div class="sp-tech-row">
            ${lnk('sp-link-sub', l.url, l.id)}
            <span class="sp-row-name">${lnk('sp-link-sub', l.url, l.name)}</span>
          </div>`).join('')}` : ''}
      <div class="sp-sec">Detection Strategies (${uniqueBy(tRows, r=>r.det_id, r=>r).length})</div>
      ${detRows(tRows)}
      <div class="sp-sec">Analytics (${analytics.length})</div>
      ${analytics.map(({label:l}) => `
        <div class="sp-tech-row" style="flex-direction:column;align-items:flex-start;gap:2px">
          ${lnk('sp-link-an', l.url, l.id)}
          <span class="sp-row-desc">${l.desc}</span>
        </div>`).join('')}
      <div class="sp-sec">Data Components (${Object.keys((() => { const m={}; tRows.forEach(r=>{if(r.dc_id)m[r.dc_id]=1;}); return m; })()).length})</div>
      ${dcRows(tRows)}
    `;

  // ── SUB-TECHNIQUE ────────────────────────────────────────────────────────
  } else if (t === 'subtechnique') {
    const tRows   = rowsFor('sub_id', data.id);
    const analytics = uniqueBy(tRows, r => r.an_id,
      r => ({ id: r.an_id, desc: r.an_desc, url: r.an_url })
    );
    body.innerHTML = `
      <div class="sp-badge">${data.id}</div>
      <div class="sp-name">${data.name}</div>
      ${mitreLink}
      <div class="sp-sec">Detection Strategies (${uniqueBy(tRows, r=>r.det_id, r=>r).length})</div>
      ${detRows(tRows)}
      <div class="sp-sec">Analytics (${analytics.length})</div>
      ${analytics.map(({label:l}) => `
        <div class="sp-tech-row" style="flex-direction:column;align-items:flex-start;gap:2px">
          ${lnk('sp-link-an', l.url, l.id)}
          <span class="sp-row-desc">${l.desc}</span>
        </div>`).join('')}
      <div class="sp-sec">Data Components (${Object.keys((() => { const m={}; tRows.forEach(r=>{if(r.dc_id)m[r.dc_id]=1;}); return m; })()).length})</div>
      ${dcRows(tRows)}
    `;

  // ── DET ──────────────────────────────────────────────────────────────────
  } else if (t === 'det') {
    const children = d.children || d._children || [];
    const tRows    = DATA.rows.filter(r => r.det_id === data.id);
    const analytics = uniqueBy(tRows, r => r.an_id,
      r => ({ id: r.an_id, desc: r.an_desc, url: r.an_url })
    );
    body.innerHTML = `
      <div class="sp-badge">${data.id}</div>
      <div class="sp-name">${data.name}</div>
      ${mitreLink}
      <div class="sp-sec">Analytics (${analytics.length})</div>
      ${analytics.map(({label:l}) => `
        <div class="sp-tech-row" style="flex-direction:column;align-items:flex-start;gap:2px">
          ${lnk('sp-link-an', l.url, l.id)}
          <span class="sp-row-desc">${l.desc}</span>
        </div>`).join('')}
      <div class="sp-sec">Data Components (${children.length})</div>
      ${dcRows(tRows)}
    `;

  // ── ROOT ─────────────────────────────────────────────────────────────────
  } else {
    const totalDets = [...new Set(DATA.rows.map(r=>r.det_id))].length;
    const totalDCs  = [...new Set(DATA.rows.map(r=>r.dc_id))].length;
    body.innerHTML = `
      <div class="sp-name">${data.name||'Root'}</div>
      <div class="sp-sec">Coverage Summary</div>
      <div class="sp-note">
        ${DATA.stats.total_tactics||12} tactics &nbsp;·&nbsp;
        ${DATA.stats.total_techniques_parent||38} techniques &nbsp;·&nbsp;
        ${DATA.stats.total_sub_techniques||29} sub-techniques<br>
        ${totalDets} detection strategies &nbsp;·&nbsp;
        ${totalDCs} data components<br>
        ${DATA.stats.unique_audit_keys||214} unique audit keys
      </div>
      <div class="sp-note" style="margin-top:6px">Click any node to view its details and associated eBPF programs.</div>
    `;
  }
  sp.classList.add('on');
}function closePanel() { document.getElementById('sp').classList.remove('on'); }

/* -------------------------------------------------------
   VIZ FILTERS — populate dropdowns & apply to graph
------------------------------------------------------- */
let vfTac='', vfTech='', vfDC='', vfQ='';
// Stored D3 selections — set by initForce(), used by applyVizFilter()
let fNodeSel = null;
let fLinkSel = null;
// Pre-computed passing set — rebuilt once per filter change, O(1) lookup per node
let _passingSet = null;

/* ── Shared name-lookup maps (built once at init) ───────────────── */
const _tacNames={}, _techNames={}, _dcNames={}, _lsLabels={};
function buildNameMaps() {
  DATA.rows.forEach(r=>{
    _tacNames[r.tac_id]   = r.tac_name;
    _techNames[r.tech_id] = r.tech_name;
    _dcNames[r.dc_id]     = r.dc_name;
    if (r.log_source) _lsLabels[r.log_source] = r.log_source;
  });
}

/* ── Generic dropdown rebuilder ─────────────────────────────────── */
// Rebuild a <select> to show only values present in `rows`.
// `labelFn` maps a raw value → display string.
// Preserves the current selection when it is still valid; resets to '' otherwise.
function rebuildSelect(el, rows, field, labelFn) {
  const prev  = el.value;
  const vals  = [...new Set(rows.map(r => r[field]).filter(Boolean))].sort();
  const first = el.options[0];       // "All …" sentinel
  el.innerHTML = '';
  el.appendChild(first);
  vals.forEach(v => {
    const o = document.createElement('option');
    o.value = v;
    o.textContent = labelFn ? labelFn(v) : v;
    el.appendChild(o);
  });
  el.value = vals.includes(prev) ? prev : '';
}

/* ── Rows that satisfy a partial constraint object ──────────────── */
// constraints: { tac_id, tech_id, dc_id, log_source } — omit or set '' to ignore
function constrainedRows(c) {
  return DATA.rows.filter(r =>
    (!c.tac_id     || r.tac_id     === c.tac_id)     &&
    (!c.tech_id    || r.tech_id    === c.tech_id)    &&
    (!c.dc_id      || r.dc_id      === c.dc_id)      &&
    (!c.log_source || r.log_source === c.log_source)
  );
}

/* -------------------------------------------------------------------
   VIZ FILTER CASCADES
------------------------------------------------------------------- */
function populateVizFilters() {
  // cascadeViz: called on every filter change.
  // Each dropdown is rebuilt from rows constrained by the OTHER two selections
  // (omit-self pattern) so any of the three can narrow the other two.
  function cascadeViz() {
    vfTac  = document.getElementById('vf-tac').value;
    vfTech = document.getElementById('vf-tech').value;
    vfDC   = document.getElementById('vf-dc').value;
    vfQ    = document.getElementById('vf-q').value.trim().toLowerCase();

    // Each dropdown's options = values reachable given the OTHER two dropdowns.
    // constrainedRows({}) with all-empty constraints returns all rows (no narrowing).
    rebuildSelect(document.getElementById('vf-tac'),
      constrainedRows({ tech_id: vfTech, dc_id: vfDC }),
      'tac_id',  v => `${v}: ${_tacNames[v]}`);

    rebuildSelect(document.getElementById('vf-tech'),
      constrainedRows({ tac_id: vfTac, dc_id: vfDC }),
      'tech_id', v => `${v}: ${_techNames[v]}`);

    rebuildSelect(document.getElementById('vf-dc'),
      constrainedRows({ tac_id: vfTac, tech_id: vfTech }),
      'dc_id',   v => `${v}: ${_dcNames[v]}`);

    // Re-read after rebuild in case a previous selection was invalidated
    // by the new constraint and rebuildSelect reset it to ''.
    vfTac  = document.getElementById('vf-tac').value;
    vfTech = document.getElementById('vf-tech').value;
    vfDC   = document.getElementById('vf-dc').value;

    applyVizFilter();
  }

  // Initial population with no active filters — all dropdowns show everything.
  cascadeViz();

  ['vf-tac', 'vf-tech', 'vf-dc'].forEach(id =>
    document.getElementById(id).addEventListener('change', cascadeViz));
  document.getElementById('vf-q').addEventListener('input', cascadeViz);
}

// ── Per-node row-matching check ────────────────────────────────────────────
// Tree-position-aware: a node's tactic/technique ancestor in the D3 hierarchy
// determines whether it matches the tac/tech filter — not just whether its
// ID appears anywhere in DATA.rows. This prevents cross-tactic contamination
// (e.g. T1078 under TA0001 staying visible when filtering by TA0003).
function nodeMatchesRows(d) {
  const t = d.data?.type;
  if (!t || t === 'root') return true;

  const nodeTacId  = (t === 'tactic')    ? d.data.id : d.data._tacId  || null;
  const nodeTechId = (t === 'technique') ? d.data.id : d.data._techId || null;

  // Tactic constraint — non-matching tactic branches are pruned
  if (vfTac) {
    if (t === 'tactic') return d.data.id === vfTac;   // direct self-check
    if (nodeTacId && nodeTacId !== vfTac) return false;
  }

  // Technique constraint
  // CRITICAL: tactic nodes must return false here so subtreeMatches is forced
  // to recurse into children rather than short-circuiting on the tactic itself.
  // Without this, every tactic passes (nodeTechId is null on tactics → null &&
  // anything = false → the rejection guard never fires → tactic returns true).
  if (vfTech) {
    if (t === 'tactic')    return false;               // force child recursion
    if (t === 'technique') return d.data.id === vfTech; // direct self-check
    if (nodeTechId && nodeTechId !== vfTech) return false;
  }

  // DC filter — non-leaf nodes never directly satisfy it
  if (vfDC) {
    if (t === 'dc') return d.data.dc_id === vfDC;
    return false;
  }

  return true;
}

function nodeMatchesText(d) {
  if (!vfQ) return true;
  const s = ((d.data?.name||'') + ' ' + (d.data?.id||'') + ' ' + (d.data?.dc_id||'')).toLowerCase();
  return s.includes(vfQ);
}

// Recursively check: does this node or any of its descendants directly match all filters?
function subtreeMatches(d) {
  if (!d.data?.type || d.data.type === 'root') return true;
  if (nodeMatchesText(d) && nodeMatchesRows(d)) return true;
  // Check all children (collapsed or not)
  const kids = d.children || d._children || [];
  return kids.some(c => subtreeMatches(c));
}

// Build a Set of all nodes that should be VISIBLE:
//   - Any node whose subtree contains a match
//   - All ancestors of any such node (automatically included since parent subtreeMatches
//     if child subtreeMatches)
function buildPassingSet(nodes) {
  const hasFilter = vfTac || vfTech || vfDC || vfQ;
  if (!hasFilter) { _passingSet = null; return; }
  const passing = new Set();
  for (const d of nodes) {
    if (subtreeMatches(d)) passing.add(d);
  }
  _passingSet = passing;
}

function nodePassesFilter(d) {
  if (!_passingSet) return true;
  return _passingSet.has(d);
}

function applyVizFilter() {
  if (!fNodeSel || !fLinkSel) return;
  const hasFilter = vfTac || vfTech || vfDC || vfQ;
  if (hasFilter) {
    buildPassingSet(fNodeSel.data());
  } else {
    _passingSet = null;
  }
  fNodeSel.style('opacity', d => (!_passingSet || _passingSet.has(d)) ? 1 : 0.08);
  fLinkSel.style('opacity', d => {
    if (!_passingSet) return 1;
    return (_passingSet.has(d.source) && _passingSet.has(d.target)) ? 1 : 0.04;
  });
}

/* -------------------------------------------------------
   FORCE GRAPH
------------------------------------------------------- */
let fSim, fSvg, fZoom, fG;
let labelsOn    = true;
// hide det nodes by default (show tech→dc directly)

function cloneTree() { return JSON.parse(JSON.stringify(DATA.tree)); }

function buildForceData() {
  const raw  = cloneTree();
  const root = d3.hierarchy(raw);

  const nodes = root.descendants();
  const links = [];
  nodes.forEach(d => { if (d.parent) links.push({source:d.parent, target:d}); });
  nodes.forEach((d,i) => {
    d._uid = i;
    // Stamp tactic ID onto every node's data so filter lookups never
    // need to walk the (potentially mutated) ancestor chain at runtime.
    if (d.data.type === 'tactic') {
      d.data._tacId  = d.data.id;
      d.data._techId = null;
    } else if (d.parent) {
      // Walk parents once at build time to find tactic and technique ancestors.
      let tacId = null, techId = null;
      let cur = d.parent;
      while (cur) {
        if (cur.data.type === 'tactic'   && !tacId)  tacId  = cur.data.id;
        if (cur.data.type === 'technique' && !techId) techId = cur.data.id;
        cur = cur.parent;
      }
      d.data._tacId  = tacId;
      d.data._techId = (d.data.type === 'technique') ? d.data.id : techId;
    }
  });
  return { nodes, links, root };
}

function initForce() {
  const cv = document.getElementById('cv-force');
  cv.querySelectorAll('svg').forEach(s=>s.remove());
  if (fSim) { fSim.stop(); fSim = null; }

  const W = cv.clientWidth  || 1200;
  const H = cv.clientHeight || 800;

  const svg = d3.select(cv).append('svg')
    .attr('viewBox', `0 0 ${W} ${H}`)
    .attr('preserveAspectRatio','xMidYMid meet')
    .style('width','100%').style('height','100%')
    .style('touch-action','none');

  fSvg = svg;

  fZoom = d3.zoom().scaleExtent([.03,8])
    .on('zoom', e => fG.attr('transform', e.transform));
  svg.call(fZoom);
  // double-click on background resets
  svg.on('dblclick.zoom', null);
  svg.on('dblclick', () =>
    svg.transition().duration(500)
       .call(fZoom.transform, d3.zoomIdentity.translate(W/2, H/2).scale(0.6))
  );

  fG = svg.append('g');
  const gL = fG.append('g').attr('class','fl'); // links
  const gN = fG.append('g').attr('class','fn'); // nodes

  const dist  = 45;
  const charg = -1500;
  const {nodes, links} = buildForceData();

  // ── Seed initial positions on concentric rings ──────────────────────────
  // This gives the simulation a structured starting state: tactics on the
  // outer ring, techniques on the next, sub-techniques / DET / DC progressively
  // closer to centre. The forces then pull the graph into its natural layout
  // while the perimeter origin keeps tactic-level links visually clear.
  const RING = { root:0, tactic:740, technique:460, subtechnique:300, det:190, dc:100 };
  const typeCount = {};
  nodes.forEach(d => {
    const t = d.data?.type || 'root';
    typeCount[t] = (typeCount[t] || 0) + 1;
  });
  const typeIdx = {};
  nodes.forEach(d => {
    const t   = d.data?.type || 'root';
    const r   = RING[t] ?? 55;
    const idx = typeIdx[t] = (typeIdx[t] || 0) + 1;
    const total = typeCount[t];
    const angle = (2 * Math.PI * (idx - 1)) / total;
    // Jitter sub-techs and DC slightly so they don't stack
    const jitter = (t==='dc'||t==='subtechnique') ? (Math.random()-0.5)*40 : 0;
    d.x  = Math.cos(angle) * (r + jitter);
    d.y  = Math.sin(angle) * (r + jitter);
  });

  fSim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links)
      .id(d=>d._uid)
      .distance(d => {
        const dep = d.source.depth;
        return dist * (dep===0?2.8 : dep===1?2.2 : dep===2?1.6 : dep===3?1.2 : 0.9);
      })
      .strength(0.7))
    .force('charge', d3.forceManyBody()
      .strength(d => charg * Math.max(0.4, TR[d.data?.type||'root']/6))
      .distanceMax(1200))
    .force('x', d3.forceX(d => {
        // Pull each node type toward a concentric ring on the x-axis
        const t = d.data?.type || 'root';
        const r = RING[t] ?? 55;
        const angle = Math.atan2(d.y || 1, d.x || 1);
        return Math.cos(angle) * r;
      }).strength(d => {
        const t = d.data?.type;
        return t==='tactic' ? 0.09 : t==='technique' ? 0.05 : 0.015;
      }))
    .force('y', d3.forceY(d => {
        const t = d.data?.type || 'root';
        const r = RING[t] ?? 55;
        const angle = Math.atan2(d.y || 1, d.x || 1);
        return Math.sin(angle) * r;
      }).strength(d => {
        const t = d.data?.type;
        return t==='tactic' ? 0.09 : t==='technique' ? 0.05 : 0.015;
      }))
    .force('collide', d3.forceCollide()
      .radius(d => (TR[d.data?.type||'root']||4) + 7).strength(0.75));

  /* ── LINKS ── */
  const link = gL.selectAll('line').data(links).join('line')
    .attr('stroke', '#8e9490')
    .attr('stroke-width', d => {
      const dep = d.source.depth;
      return dep===0 ? 4 : dep===1 ? 2.5 : dep===2 ? 1.5 : dep===3 ? 1 : 0.6;
    })
    .attr('stroke-linecap', 'round');

  /* ── NODES ── */
  const node = gN.selectAll('g').data(nodes).join('g')
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start',(e,d)=>{ if(!e.active) fSim.alphaTarget(.2).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag', (e,d)=>{ d.fx=e.x; d.fy=e.y; })
      .on('end',  (e,d)=>{ if(!e.active) fSim.alphaTarget(0); d.fx=d.fy=null; }))
    .on('click', (e,d) => {
      e.stopPropagation();
      if (e.shiftKey && d.data?.url) {
        window.open(d.data.url,'_blank','noopener');
        return;
      }
      openPanel(d);
    })
    .on('mouseover',(e,d)=>showTip(e,d))
    .on('mousemove', moveTip)
    .on('mouseout',  hideTip)
    .on('touchstart.tip',(e,d)=>{
      if(e.touches&&e.touches[0]){
        const t=e.touches[0];
        showTip({clientX:t.clientX,clientY:t.clientY},d);
        setTimeout(hideTip,1600);
      }
    });

  /* circles */
  node.append('circle')
    .attr('r', d => TR[d.data?.type||'root'] || 5)
    .attr('fill', d => {
      const t = d.data?.type;
      if (!t) return TC.root;
      return TC[t] || '#3c4440';
    })
    .attr('stroke', d => nColor(d))
    .attr('stroke-width', d => {
      const t = d.data?.type;
      return (!t||t==='root'||t==='tactic') ? 2.5 : 1.5;
    })
    .attr('fill-opacity', d => {
      const t = d.data?.type;
      return (!t||t==='dc'||t==='tactic') ? 0.92 : 0.55;
    });

  // Store live selections so applyVizFilter can access them without
  // relying on a CSS selector re-walk of the DOM.
  fNodeSel = node;
  fLinkSel = link;
  // Re-apply any active filter to the freshly built graph
  applyVizFilter();

  /* ── LABELS ── */
  function labelText(d) {
    const nm = d.data?.name || '';
    const t  = d.data?.type;
    const mx = !t?32 : t==='tactic'?24 : t==='technique'?22 : t==='subtechnique'?20 : t==='det'?18 : 16;
    return nm.length > mx ? nm.slice(0,mx)+'…' : nm;
  }

  function addLabels() {
    // remove old labels
    gN.selectAll('text.flbl').remove();

    if (!labelsOn) return;
    const maxDepth = parseInt(document.getElementById('sel-depth').value);

    // shadow/halo (readability)
    gN.selectAll('g')
      .filter(d => d.depth <= maxDepth)
      .append('text').attr('class','flbl flbl-bg')
      .attr('dy','0.32em')
      .attr('x', d => (TR[d.data?.type||'root']||5) + 4)
      .attr('fill','none')
      .attr('stroke','var(--bg)')
      .attr('stroke-width', d => d.depth<=1 ? 4 : 3)
      .attr('stroke-linejoin','round')
      .style('pointer-events','none')
      .attr('font-family','var(--mono)')
      .attr('font-size', d => {
        const t=d.data?.type;
        return !t?12 : t==='tactic'?11 : t==='technique'?10 : t==='subtechnique'?9 : 8.5;
      })
      .text(labelText);

    // coloured label
    gN.selectAll('g')
      .filter(d => d.depth <= maxDepth)
      .append('text').attr('class','flbl flbl-fg')
      .attr('dy','0.32em')
      .attr('x', d => (TR[d.data?.type||'root']||5) + 4)
      .attr('fill', d => nColor(d))
      .style('pointer-events','none')
      .attr('font-family','var(--mono)')
      .attr('font-size', d => {
        const t=d.data?.type;
        return !t?12 : t==='tactic'?11 : t==='technique'?10 : t==='subtechnique'?9 : 8.5;
      })
      .text(labelText);
  }

  addLabels();

  /* ── TICK ── */
  fSim.on('tick', () => {
    link
      .attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform', d=>`translate(${d.x},${d.y})`);
  });

  // Re-apply any active filter after simulation settles
  fSim.on('end.filter', applyVizFilter);

  /* ── CONTROLS wired up inside initForce so addLabels is in scope ── */
  document.getElementById('btn-labels').onclick = function() {
    labelsOn = !labelsOn;
    this.classList.toggle('lit', labelsOn);
    addLabels();
  };
  document.getElementById('sel-depth').onchange = addLabels;

  // initial center
  svg.call(fZoom.transform, d3.zoomIdentity.translate(W/2, H/2).scale(0.2));
}

// Reset: clears all viz filters then reinitialises the force graph
const _btnReset = document.getElementById('btn-reset');
if (_btnReset) _btnReset.onclick = function() {
  ['vf-tac','vf-tech','vf-dc'].forEach(id =>
    document.getElementById(id).value = '');
  document.getElementById('vf-q').value = '';
  vfTac = vfTech = vfDC = vfQ = '';
  if (typeof cascadeViz === 'function') cascadeViz();
  initForce();
};
/* -------------------------------------------------------
   TABLE
------------------------------------------------------- */
let tData = DATA.rows.slice();
let sCol  = 'tac_id', sAsc = true;
let tableInited = false;

function fmtCell(col, row) {
  const v = row[col];
  const empty = `<span style="color:var(--text-dim)">—</span>`;
  if (!v && col!=='sub_id') return empty;

  const extBtn = (url) => url
    ? `<a class="ext-link" href="${url}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()" title="Open on MITRE ATT&CK">↗</a>`
    : '';

  switch(col) {
    case 'tac_id':
      return `<a class="tag t-tac" href="${row.tac_url||'#'}" target="_blank" rel="noopener noreferrer">${v} ↗</a>
              <div class="td-dim" style="margin-top:2px">${row.tac_name}</div>`;
    case 'tech_id':
      return `<a class="tag t-tech" href="${row.tech_url||'#'}" target="_blank" rel="noopener noreferrer">${v} ↗</a>
              <div class="td-dim" style="margin-top:2px">${row.tech_name}</div>`;
    case 'sub_id':
      return v
        ? `<a class="tag t-sub" href="${row.sub_url||'#'}" target="_blank" rel="noopener noreferrer">${v} ↗</a>
           <div class="td-dim" style="margin-top:2px">${row.sub_name}</div>`
        : empty;
    case 'det_id':
      return `<a class="tag t-det" href="${row.det_url||'#'}" target="_blank" rel="noopener noreferrer">${v} ↗</a>
              <div class="td-dim" style="margin-top:2px;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${row.det_name}</div>`;
    case 'an_id':
      return `<a class="tag t-an" href="${row.an_url||'#'}" target="_blank" rel="noopener noreferrer">${v} ↗</a>`;
    case 'an_desc':
      return `<div class="td-dim">${v}</div>`;
    case 'dc_id':
      return `<a class="tag t-dc" href="${row.dc_url||'#'}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">${v} ↗</a>`;
    case 'dc_name':
      return row.dc_url
        ? `<a style="font-size:11px;color:var(--text);text-decoration:none;" href="${row.dc_url}" target="_blank" rel="noopener noreferrer">${v} <span style="opacity:.5;font-size:8px">↗</span></a>`
        : `<span style="font-size:11px">${v}</span>`;
    case 'audit_key':
      return v
        ? `<span class="tag t-key" onclick="copy('${v}')" title="Click to copy">${v}</span>`
        : empty;
    case 'log_source': {
      const isEbpf = v && v.startsWith('ebpf:');
      return `<span class="td-mono" style="${isEbpf?'color:var(--col-dc)':''}">${v||'—'}</span>`;
    }
    case 'event':
      return `<span class="td-mono" style="color:var(--text)">${v}</span>`;
    case 'ebpf_program':
      return v
        ? `<span class="tag t-ebpf">${v.replace('BPF_PROG_TYPE_','')}</span>`
        : `<span style="color:var(--text-dim);font-size:10px">auditd</span>`;
    case 'ebpf_weight':
      return v != null
        ? `<span class="td-mono" style="color:var(--accent)">${v}</span>`
        : empty;
    default: return v || empty;
  }
}

function openDCFromTable(dcId) {
  // Activate the force panel tab if not visible, then show side panel
  const dcEntry = DATA.dcr[dcId];
  if (!dcEntry) return;
  // Build a minimal d-like object
  const fakeD = {
    data: {
      type:'dc', dc_id:dcId,
      name: dcEntry.name,
      url: dcEntry.url || '',
      id: dcId,
    }
  };
  openPanel(fakeD);
}

function applyFilters() {
  const tac  = document.getElementById('f-tac').value;
  const tech = document.getElementById('f-tech').value;
  const dc   = document.getElementById('f-dc').value;
  const ls   = document.getElementById('f-ls').value;
  const q    = document.getElementById('f-q').value.trim().toLowerCase();

  tData = DATA.rows.filter(r => {
    if (tac  && r.tac_id     !== tac)  return false;
    if (tech && r.tech_id    !== tech) return false;
    if (dc   && r.dc_id      !== dc)   return false;
    if (ls   && r.log_source !== ls)   return false;
    if (q) {
      const hay = Object.values(r).join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  tData.sort((a,b) => {
    const av=a[sCol]||'', bv=b[sCol]||'';
    return sAsc ? av.localeCompare(bv) : bv.localeCompare(av);
  });

  renderTable();
}

function renderTable() {
  const cols=['tac_id','tech_id','sub_id','dc_id','dc_name','audit_key','ebpf_program','ebpf_weight','log_source','event'];
  const tbody = document.getElementById('tbody');
  tbody.innerHTML =
    tData.map(r=>`<tr>${cols.map(c=>`<td>${fmtCell(c,r)}</td>`).join('')}</tr>`).join('');
  document.getElementById('rn').textContent = tData.length;
  document.getElementById('rt').textContent = DATA.rows.length;
  // JS delegation — covers all rows regardless of scroll position or count
  tbody.onmouseover = e => {
    const tr = e.target.closest('tr');
    if (tr && tr.parentNode === tbody) tr.classList.add('row-hl');
  };
  tbody.onmouseout  = e => {
    const tr = e.target.closest('tr');
    if (tr && tr.parentNode === tbody) tr.classList.remove('row-hl');
  };
}

function fillDropdowns() {
  // cascadeTable: rebuilds each dropdown using the omit-self pattern —
  // each select shows only values reachable given the OTHER three selections.
  // Uses the shared constrainedRows() helper and the _*Names maps.
  function cascadeTable() {
    const tac  = document.getElementById('f-tac').value;
    const tech = document.getElementById('f-tech').value;
    const dc   = document.getElementById('f-dc').value;
    const ls   = document.getElementById('f-ls').value;

    rebuildSelect(document.getElementById('f-tac'),
      constrainedRows({ tech_id: tech, dc_id: dc, log_source: ls }),
      'tac_id',  v => `${v}: ${_tacNames[v]}`);

    rebuildSelect(document.getElementById('f-tech'),
      constrainedRows({ tac_id: tac, dc_id: dc, log_source: ls }),
      'tech_id', v => `${v}: ${_techNames[v]}`);

    rebuildSelect(document.getElementById('f-dc'),
      constrainedRows({ tac_id: tac, tech_id: tech, log_source: ls }),
      'dc_id',   v => `${v}: ${_dcNames[v]}`);

    rebuildSelect(document.getElementById('f-ls'),
      constrainedRows({ tac_id: tac, tech_id: tech, dc_id: dc }),
      'log_source', v => v);

    // Re-read after rebuild — selections invalidated by new constraints
    // are reset to '' by rebuildSelect; pick those up before filtering.
    applyFilters();
  }

  // Populate all dropdowns now (no active filter — each shows full list).
  cascadeTable();

  ['f-tac','f-tech','f-dc','f-ls'].forEach(id =>
    document.getElementById(id).addEventListener('change', cascadeTable));
  document.getElementById('f-q').addEventListener('input', applyFilters);

  // Expose cascadeTable so clearFilters can call it.
  fillDropdowns._cascade = cascadeTable;
}

function initTable() {
  if (tableInited) return;
  tableInited = true;
  fillDropdowns();
  document.querySelectorAll('#tbl th').forEach(th => {
    th.addEventListener('click', () => {
      const c = th.dataset.c;
      document.querySelectorAll('#tbl th').forEach(h => h.classList.remove('sa','sd'));
      if (sCol === c) sAsc = !sAsc; else { sCol = c; sAsc = true; }
      th.classList.add(sAsc ? 'sa' : 'sd');
      applyFilters();
    });
  });
}

function clearFilters() {
  ['f-tac','f-tech','f-dc','f-ls'].forEach(id =>
    document.getElementById(id).value = '');
  document.getElementById('f-q').value = '';
  // Trigger cascade to restore all dropdowns to full lists, then re-filter.
  if (fillDropdowns._cascade) fillDropdowns._cascade();
  else applyFilters();
}


// -------------------------------------------------------
//  DATASET PANEL
// -------------------------------------------------------
function initDatasetPanel() {
  const s = DATA.stats;
  const metrics = [
    { label: 'Tactics',              val: s.total_tactics                    || 13  },
    { label: 'Techniques',           val: s.total_techniques_parent          || 179  },
    { label: 'Sub-Techniques',       val: s.total_sub_techniques             || 247  },
    { label: 'Detection Strategies', val: s.total_detection_strategies       || 341  },
    { label: 'Analytics',            val: s.total_analytics                  || 341  },
    { label: 'Data Components',      val: s.total_data_components_referenced || 19  },
    { label: 'Unique Audit Keys',    val: s.unique_audit_keys                || 674 },
    { label: 'eBPF Enriched Keys',  val: s.ebpf_rows                        || 160 },
  ];
  const grid = document.getElementById('ds-grid');
  if (grid) {
    grid.innerHTML = metrics.map(m => `
      <div style="background:var(--bg2);border:1px solid var(--border);padding:16px 20px;border-radius:2px;border-left:3px solid var(--accent);">
        <div style="font-family:var(--mono);font-size:22px;font-weight:700;color:var(--accent);line-height:1">${m.val}</div>
        <div style="font-family:var(--body);font-size:10px;color:var(--text-dim);margin-top:5px;text-transform:uppercase;letter-spacing:.5px">${m.label}</div>
      </div>`).join('');
  }

  // DC breakdown
  const dcList = document.getElementById('ds-dc-list');
  if (dcList) {
    const dcs = {};
    DATA.rows.forEach(r => {
      if (!dcs[r.dc_id]) dcs[r.dc_id] = { name: r.dc_name, url: r.dc_url||'', keys: new Set(), channels: new Set() };
      if (r.audit_key) dcs[r.dc_id].keys.add(r.audit_key);
      if (r.log_source) dcs[r.dc_id].channels.add(r.log_source);
    });
    dcList.innerHTML = Object.entries(dcs).sort(([a],[b]) => a.localeCompare(b)).map(([id, v]) => `
      <div style="display:flex;align-items:center;gap:12px;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);">
        <span style="font-family:var(--mono);font-size:9px;color:var(--col-dc);background:#eaf4ec;border:1px solid #84b894;padding:2px 6px;white-space:nowrap">${id}</span>
        <span style="font-family:var(--body);font-size:11px;color:var(--text);flex:1">${v.name}</span>
        <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim)">${v.keys.size} keys</span>
        <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim)">${v.channels.size} channels</span>
        ${v.url ? `<a href="${v.url}" target="_blank" rel="noopener noreferrer" style="font-size:9px;color:var(--accent);text-decoration:none">↗</a>` : ''}
      </div>`).join('');
  }

  // Log source channels
  const chEl = document.getElementById('ds-channels');
  if (chEl) {
    const channels = [...new Set(DATA.rows.map(r => r.log_source).filter(Boolean))].sort();
    chEl.innerHTML = channels.map(c => {
      const isAudit = c.startsWith('audit:');
      const isEbpf  = c.startsWith('ebpf:');
      const bg = isAudit ? '#e8f0f7' : isEbpf ? '#eaf4ec' : '#f5f5f5';
      const col = isAudit ? '#1a6496' : isEbpf ? '#276221' : '#666';
      const bdr = isAudit ? '#a8c4da' : isEbpf ? '#84b894' : '#ccc';
      return `<span style="font-family:var(--mono);font-size:9px;padding:4px 10px;background:${bg};border:1px solid ${bdr};color:${col}">${c}</span>`;
    }).join('');
  }

  // Campaign Coverage grid
  const campGrid = document.getElementById('ds-camp-grid');
  if (campGrid && typeof CAMPAIGNS !== 'undefined') {
    const camps = CAMPAIGNS.campaigns || [];
    let techTotal = 0, verifiedTotal = 0, keyTotal = 0;
    camps.forEach(c => (c.linux_techniques || []).forEach(t => {
      techTotal++;
      if (t.coverage_verified) verifiedTotal++;
      keyTotal += (t.audit_keys || []).length;
    }));
    const campMetrics = [
      { label: 'Campaigns',           val: camps.length   },
      { label: 'Technique Mappings',  val: techTotal       },
      { label: 'Verified',            val: verifiedTotal   },
      { label: 'Audit Keys',          val: keyTotal        },
    ];
    campGrid.innerHTML = campMetrics.map(m => `
      <div style="background:var(--bg2);border:1px solid var(--border);padding:16px 20px;border-radius:2px;border-left:3px solid #c87828;">
        <div style="font-family:var(--mono);font-size:22px;font-weight:700;color:#c87828;line-height:1">${m.val}</div>
        <div style="font-family:var(--body);font-size:10px;color:var(--text-dim);margin-top:5px;text-transform:uppercase;letter-spacing:.5px">${m.label}</div>
      </div>`).join('');
  }

  // Campaign list rows
  const campListEl = document.getElementById('ds-camp-list');
  if (campListEl && typeof CAMPAIGNS !== 'undefined') {
    const camps = CAMPAIGNS.campaigns || [];
    campListEl.innerHTML = camps.map(c => {
      const techCount = (c.linux_techniques || []).length;
      const verCount  = (c.linux_techniques || []).filter(t => t.coverage_verified).length;
      const tacIds    = [...new Set((c.linux_techniques || []).map(t => t.tactic_id).filter(Boolean))];
      return `
        <div style="background:var(--bg2);border:1px solid var(--border);padding:12px 16px;display:flex;align-items:flex-start;gap:16px;">
          <span style="font-family:var(--mono);font-size:9px;color:#c87828;background:#fdf3e7;border:1px solid #e8c88a;padding:3px 8px;white-space:nowrap;margin-top:1px">${c.campaign_id || '—'}</span>
          <div style="flex:1;min-width:0;">
            <div style="font-family:var(--body);font-size:12px;font-weight:600;color:var(--text);margin-bottom:3px;">
              ${c.attack_url
                ? `<a href="${c.attack_url}" target="_blank" rel="noopener noreferrer" style="color:var(--text);text-decoration:none">${c.name} <span style="font-size:9px;opacity:.5">↗</span></a>`
                : c.name}
            </div>
            ${c.description ? `<div style="font-family:var(--body);font-size:10px;color:var(--text-dim);margin-bottom:5px;line-height:1.5">${c.description.length > 200 ? c.description.slice(0,200)+'…' : c.description}</div>` : ''}
            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;">
              ${tacIds.map(id => `<span style="font-family:var(--mono);font-size:8px;color:var(--col-tac);background:#f0f4ff;border:1px solid #a8b8d8;padding:2px 6px">${id}</span>`).join('')}
            </div>
          </div>
          <div style="display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0;">
            <span style="font-family:var(--mono);font-size:9px;color:var(--text-dim)">${techCount} techniques</span>
            <span style="font-family:var(--mono);font-size:9px;color:#276221">${verCount} verified</span>
          </div>
        </div>`;
    }).join('');
  }

  // eBPF programs per DC
  const ebpfListEl = document.getElementById('ds-ebpf-list');
  if (ebpfListEl && typeof CAMPAIGNS !== 'undefined') {
    const dcReg = CAMPAIGNS.data_component_registry_linux_updated || {};
    const entries = Object.entries(dcReg).filter(([, v]) => (v.ebpf_programs || []).length > 0);
    if (entries.length === 0) {
      ebpfListEl.innerHTML = `<div style="font-family:var(--body);font-size:11px;color:var(--text-dim);padding:8px 0">No eBPF programs registered.</div>`;
    } else {
      ebpfListEl.innerHTML = entries.map(([dcId, v]) => {
        const dcName = (DATA.dcr && DATA.dcr[dcId] && DATA.dcr[dcId].name) || dcId;
        const dcUrl  = (DATA.dcr && DATA.dcr[dcId] && DATA.dcr[dcId].url)  || '';
        const progs  = v.ebpf_programs.map(p => {
          const filtHtml = p.filter ? `<br><span style="color:var(--text-dim)">filter</span> <code style="font-size:9px;background:var(--bg);padding:1px 4px">${renderFilter(p.filter)}</code>` : '';
          const meta = [
            p.kernel_min ? `kernel ≥ ${p.kernel_min}` : '',
            p.co_re      ? 'CO-RE' : '',
            p.note       ? p.note  : '',
          ].filter(Boolean).join(' · ');
          return `
            <div style="background:var(--bg);border:1px solid var(--border);border-left:2px solid #276221;padding:8px 12px;margin-top:6px;">
              <div style="font-family:var(--mono);font-size:10px;font-weight:600;color:#276221;margin-bottom:2px">
                <span style="color:var(--text-dim)">attach</span> ${p.attach}${filtHtml}
              </div>
              ${meta ? `<div style="font-family:var(--body);font-size:9px;color:var(--text-dim);margin-top:3px">${meta}</div>` : ''}
            </div>`;
        }).join('');
        return `
          <div style="background:var(--bg2);border:1px solid var(--border);padding:12px 16px;">
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;">
              <span style="font-family:var(--mono);font-size:9px;color:var(--col-dc);background:#eaf4ec;border:1px solid #84b894;padding:2px 6px">${dcId}</span>
              <span style="font-family:var(--body);font-size:11px;font-weight:600;color:var(--text);flex:1">${dcName}</span>
              ${dcUrl ? `<a href="${dcUrl}" target="_blank" rel="noopener noreferrer" style="font-size:9px;color:var(--accent);text-decoration:none">↗</a>` : ''}
            </div>
            ${progs}
          </div>`;
      }).join('');
    }
  }
}

/* -------------------------------------------------------
   TAB SWITCHING
------------------------------------------------------- */
const _panelInited = {};
document.querySelectorAll('.tab[data-p]').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('on'));
    tab.classList.add('on');
    const pid = tab.dataset.p;
    const panel = document.getElementById(pid);
    if (panel) panel.classList.add('on');
    if (pid==='p-table'    && !_panelInited.table)    { initTable();           _panelInited.table    = true; }
    if (pid==='p-dataset'  && !_panelInited.dataset)  { initDatasetPanel();    _panelInited.dataset  = true; }
    if (pid==='p-campaigns'&& !_panelInited.campaigns){ initCampaignsPanel();  _panelInited.campaigns= true; }
    if (pid==='p-camp-viz' && !_panelInited.campViz)  { initCampVizForce();    _panelInited.campViz  = true; }
  });
});

/* -------------------------------------------------------
   RESIZE OBSERVER — redraw force svg on container resize
------------------------------------------------------- */
let resizeTimer;
const ro = new ResizeObserver(() => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => {
    const cv = document.getElementById('cv-force');
    const panel = document.getElementById('p-force');
    if (!cv || !panel || !panel.classList.contains('on')) return;
    const W = cv.clientWidth, H = cv.clientHeight;
    if (fSvg) fSvg.attr('viewBox',`0 0 ${W} ${H}`);
  }, 120);
});
if (document.getElementById('cv-force'))     ro.observe(document.getElementById('cv-force'));
if (document.getElementById('cv-camp-viz'))  ro.observe(document.getElementById('cv-camp-viz'));

/* -------------------------------------------------------
   INIT
------------------------------------------------------- */
window.addEventListener('DOMContentLoaded', () => {
  if (typeof DATA === 'undefined') return;
  fillStats();
  buildNameMaps();
  Object.keys(DATA.dcr).forEach(k => {
    if (!DATA.dcr[k].note) DATA.dcr[k].note = DATA.dcr[k].description;
  });
  if (document.getElementById('cv-force')) {
    buildLegend('lg-force');
    populateVizFilters();
    setTimeout(initForce, 80);
  }
});
/* -------------------------------------------------------
   CAMPAIGNS PANEL
------------------------------------------------------- */


function escHtml(s){return String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]);}

function _campTacticMap(){
  const m = new Map();
  CAMPAIGNS.campaigns.forEach(c=>c.linux_techniques.forEach(t=>{
    (t.coverage||[]).forEach(cv=>{
      if(cv && cv.tactic_id && cv.tactic_name) m.set(cv.tactic_id, cv.tactic_name);
    });
    (t.tactic_ids||[]).forEach(ti=>{ if(!m.has(ti)) m.set(ti, ti); });
  }));
  return m;
}

function initCampaignsPanel(){
  const campSel = document.getElementById('cf-camp');
  CAMPAIGNS.campaigns.forEach(c=>{
    const o = document.createElement('option');
    o.value = c.campaign_id; o.textContent = c.campaign_id + ': ' + c.name;
    campSel.appendChild(o);
  });
  const tacMap = _campTacticMap();
  const tacSel = document.getElementById('cf-tac');
  [...tacMap.entries()].sort((a,b)=>a[0].localeCompare(b[0])).forEach(([id,nm])=>{
    const o=document.createElement('option');o.value=id;
    o.textContent = id + (nm && nm!==id ? ' · ' + nm : '');
    tacSel.appendChild(o);
  });
  ['critical','high','medium','low'].forEach(p=>{
    const o=document.createElement('option');o.value=p;o.textContent=p.toUpperCase();
    document.getElementById('cf-prio').appendChild(o);
  });
  const groups = new Set();
  CAMPAIGNS.campaigns.forEach(c=>(c.attributed_groups||[]).forEach(g=>groups.add(g)));
  const grpSel = document.getElementById('cf-grp');
  [...groups].sort().forEach(g=>{
    const o=document.createElement('option');o.value=g;o.textContent=g;grpSel.appendChild(o);
  });
  ['cf-camp','cf-tac','cf-prio','cf-grp'].forEach(id=>document.getElementById(id).addEventListener('change',renderCampaigns));
  document.getElementById('cf-q').addEventListener('input',renderCampaigns);
  document.getElementById('cf-clear').addEventListener('click',()=>{
    ['cf-camp','cf-tac','cf-prio','cf-grp','cf-q'].forEach(id=>document.getElementById(id).value='');
    renderCampaigns();
  });

  // Summary pills (computed once on init from the full dataset).
  let totalTech=0, totalKeys=0, totalCovered=0, totalUnverif=0;
  CAMPAIGNS.campaigns.forEach(c=>c.linux_techniques.forEach(t=>{
    totalTech++;
    totalKeys += (t.audit_keys||[]).length;
    if (t.coverage_verified) totalCovered++; else totalUnverif++;
  }));
  const summary = document.getElementById('camp-summary');
  const stats = [
    ['Campaigns', CAMPAIGNS.campaigns.length],
    ['Technique mappings', totalTech],
    ['Verified', totalCovered],
    ['Unverified', totalUnverif],
    ['Audit keys', totalKeys],
    ['Resolved', (CAMPAIGNS.join_statistics||{}).resolved||'—'],
  ];
  summary.innerHTML = stats.map(([k,v])=>`<div class="pill-stat"><div class="v">${escHtml(v)}</div><div class="k">${escHtml(k)}</div></div>`).join('');

  renderCampaigns();
}

function renderCampaigns(){
  const fCamp = document.getElementById('cf-camp').value;
  const fTac  = document.getElementById('cf-tac').value;
  const fPrio = document.getElementById('cf-prio').value;
  const fGrp  = document.getElementById('cf-grp').value;
  const fQ    = document.getElementById('cf-q').value.toLowerCase().trim();
  const list  = document.getElementById('camp-list');
  list.innerHTML='';
  let shown=0;
  CAMPAIGNS.campaigns.forEach(c=>{
    if (fCamp && c.campaign_id !== fCamp) return;
    if (fGrp && !(c.attributed_groups||[]).includes(fGrp)) return;
    const techs = c.linux_techniques.filter(t=>{
      if (fTac && !(t.tactic_ids||[]).includes(fTac)) return false;
      if (fPrio && t.rule_priority !== fPrio) return false;
      if (fQ){
        const hay = (c.campaign_id+' '+c.name+' '+(c.aliases||[]).join(' ')+' '+
                     (c.attributed_groups||[]).join(' ')+' '+(c.description||'')+' '+
                     (t.technique_id||'')+' '+(t.sub_technique_id||'')+' '+
                     (t.technique_name||'')+' '+(t.audit_keys||[]).join(' ')).toLowerCase();
        if (!hay.includes(fQ)) return false;
      }
      return true;
    });
    if (techs.length===0 && (fTac||fPrio||fQ)) return;
    shown++;
    list.appendChild(renderCampaignCard(c, techs));
  });
  document.getElementById('cf-count').textContent = `${shown} campaign${shown===1?'':'s'} shown`;
}

function renderCampaignCard(c, techs){
  const card = document.createElement('div');
  card.className='camp-card';
  const aliases = (c.aliases||[]).length ? ' · ' + (c.aliases||[]).join(', ') : '';
  const groups = (c.attributed_groups||[]).map(g=>`<span class="tag-chip tag-grp">${escHtml(g)}</span>`).join(' ');
  const head = document.createElement('div');
  head.innerHTML = `
    <div class="camp-head">
      <span class="camp-id">${escHtml(c.campaign_id)}</span>
      <span class="camp-name">${escHtml(c.name)}</span>
      <span class="camp-aliases">${escHtml(aliases)}</span>
      <a href="${escHtml(c.attack_url)}" target="_blank" rel="noopener" style="margin-left:auto;font-size:10px;color:var(--accent);text-decoration:none;">MITRE ↗</a>
    </div>
    <div class="camp-meta">
      <span><b>First seen:</b> ${escHtml(c.first_seen||'?')}</span>
      <span><b>Last seen:</b> ${escHtml(c.last_seen||'?')}</span>
      <span><b>Groups:</b> ${groups || '<i>unattributed</i>'}</span>
      <span><b>Techniques:</b> ${techs.length} / ${c.linux_techniques.length}</span>
    </div>
    <div class="camp-desc">${escHtml(c.description||'')}</div>
  `;
  card.appendChild(head);
  const tbl = document.createElement('table');
  tbl.className='camp-tech-tbl';
  tbl.innerHTML = `<thead><tr>
    <th style="width:24px"></th>
    <th style="width:90px">Tactic(s)</th>
    <th style="width:110px">Technique</th>
    <th>Sub-Technique</th>
    <th style="width:80px">Priority</th>
    <th style="width:60px">Weight</th>
    <th style="width:160px">eBPF channels</th>
    <th style="width:50px">Keys</th>
  </tr></thead><tbody></tbody>`;
  const tb = tbl.querySelector('tbody');
  techs.forEach(t=>{
    const tactics = (t.tactic_ids||[]).join(', ');
    const ebpf = (t.ebpf_channels||[]).map(ch=>`<span class="tag-chip ebpf">${escHtml(ch.replace('ebpf:',''))}</span>`).join('');
    const verif = t.coverage_verified ? '' : ` <span class="tag-chip unverif" title="No coverage in audit registry">unverified</span>`;
    const keys = (t.audit_keys||[]).length;
    const tr = document.createElement('tr');
    tr.className='tech-row';
    tr.innerHTML = `
      <td style="color:var(--accent);text-align:center;" data-toggle="1">▸</td>
      <td>${escHtml(tactics)}</td>
      <td><a href="https://attack.mitre.org/techniques/${escHtml(t.technique_id)}/" target="_blank" rel="noopener" style="color:var(--text-hi);text-decoration:none;" onclick="event.stopPropagation()">${escHtml(t.technique_id)}</a></td>
      <td>${escHtml(t.sub_technique_id||'-')}<br><span style="color:var(--text-dim);font-size:9px;">${escHtml(t.technique_name||'')}</span>${verif}</td>
      <td class="pri-${escHtml(t.rule_priority||'low')}">${escHtml((t.rule_priority||'').toUpperCase())}</td>
      <td style="font-family:var(--mono);">${(t.weight_recommendation||0).toFixed(2)}</td>
      <td>${ebpf || '<span style="color:var(--text-dim);">—</span>'}</td>
      <td style="font-family:var(--mono);font-size:9px;color:var(--text-dim);text-align:center;">${keys}</td>
    `;
    tb.appendChild(tr);
    const dr = document.createElement('tr');
    dr.className='camp-tech-row-detail';
    dr.style.display='none';
    const dtd = document.createElement('td');
    dtd.colSpan = 8;
    dtd.innerHTML = renderCoverageBlocks(t);
    dr.appendChild(dtd);
    tb.appendChild(dr);
    tr.addEventListener('click',()=>{
      const open = dr.style.display!=='none';
      dr.style.display = open ? 'none' : 'table-row';
      tr.querySelector('[data-toggle]').textContent = open ? '▸' : '▾';
      tr.classList.toggle('expanded', !open);
    });
  });
  card.appendChild(tbl);
  return card;
}

function renderCoverageBlocks(t){
  if (!t.coverage || t.coverage.length===0){
    return `<div style="color:var(--text-dim);font-style:italic;">No coverage entries — ${escHtml(t.technique_id)} has no Linux audit-registry mapping in this dataset (coverage_verified=${escHtml(String(t.coverage_verified))}).</div>`;
  }
  const groups = new Map();
  t.coverage.forEach(c=>{
    if (c && c.resolved===false){
      groups.set('__u__'+c.audit_key, {unresolved:true, audit_key:c.audit_key});
      return;
    }
    const k = (c.det_id||'?') + '|' + ((c.analytic||{}).analytic_id||'?');
    if (!groups.has(k)) groups.set(k, {det:c, dcs:[]});
    groups.get(k).dcs.push(c);
  });
  const out=[];
  groups.forEach(v=>{
    if (v.unresolved){
      out.push(`<div class="cov-block" style="border-left-color:var(--text-dim);"><div class="cov-head">UNRESOLVED audit_key (not present in coverage v5)</div><div class="cov-dc">${escHtml(v.audit_key)}</div></div>`);
      return;
    }
    const c = v.det;
    const an = c.analytic||{};
    let dcsHtml='';
    v.dcs.forEach(d=>{
      const dc = d.data_component||{};
      const ebpf = dc.ebpf_program||{};
      const filt = ebpf.filter ? renderFilter(ebpf.filter) : '';
      const fp = (ebpf.fp_filters||[]).length;
      const cap = ebpf.capability_required ? ' · req. ' + escHtml(ebpf.capability_required) : '';
      dcsHtml += `<div style="margin-top:6px;border-top:1px dashed var(--border);padding-top:6px;">
        <div class="cov-dc"><b>${escHtml(dc.dc_id||'')}</b> ${escHtml(dc.dc_name||'')} · <span style="color:var(--text-dim);">${escHtml(dc.log_source_channel||'')}</span></div>
        <div style="color:var(--text);font-size:10px;margin:2px 0;">${escHtml(dc.event_or_syscall||'')}</div>
        ${ebpf.attach?`<div class="cov-ebpf"><b>attach</b> ${escHtml(ebpf.attach)}${filt?`<br><b>filter</b> ${filt}`:''}${fp?`<br><b>fp_filters</b> ${fp} rule${fp===1?'':'s'}`:''}${ebpf.kernel_min?` · <b>kernel ≥</b> ${escHtml(ebpf.kernel_min)}`:''}${ebpf.co_re?' · CO-RE':''}${cap}</div>`:''}
        <div style="font-family:var(--mono);font-size:8.5px;color:var(--text-dim);margin-top:2px;">${escHtml(d.audit_key)}</div>
      </div>`;
    });
    out.push(`<div class="cov-block">
      <div class="cov-head">${escHtml(c.tactic_id||'')} · ${escHtml(c.tactic_name||'')} · <a href="${escHtml(c.det_url||'')}" target="_blank" rel="noopener" style="color:var(--text-dim);text-decoration:none;">${escHtml(c.det_id||'')} ↗</a></div>
      <div class="cov-det">${escHtml(c.det_name||'')}</div>
      <div class="cov-an"><b>${escHtml(an.analytic_id||'')}</b> [${escHtml(an.platform||'Linux')}] ${escHtml(an.description||'')}</div>
      ${dcsHtml}
    </div>`);
  });
  return out.join('');
}

function renderFilter(f){
  if (!f) return '';
  if (Array.isArray(f)) return f.map(renderFilter).join(' AND ');
  if (f.logic==='or' && f.conditions) return '(' + f.conditions.map(renderFilter).join(' OR ') + ')';
  if (f.op==='none') return '<i>none</i>';
  if (f.op==='in' && f.values) return `${escHtml(f.field||'?')} ∈ {${f.values.slice(0,3).map(escHtml).join(', ')}${f.values.length>3?', …':''}}`;
  if (f.op==='in' && f.ref) return `${escHtml(f.field||'?')} ∈ BPF_MAP(${escHtml(f.ref)})`;
  if (f.op==='bitflag') return `${escHtml(f.field||'?')} & 0x${Number(f.mask||0).toString(16)}`;
  if (f.op==='raw') return `<i>${escHtml(f.raw||'')}</i>`;
  if (f.op && f.values) return `${escHtml(f.field||'?')} ${escHtml(f.op)} ${f.values.map(escHtml).join('/')}`;
  if (f.op) return `${escHtml(f.field||'?')} ${escHtml(f.op)} ${escHtml(f.value||'')}`;
  return '<i>?</i>';
}

/* -------------------------------------------------------
   CAMPAIGNS VISUALIZED — top-level tab
   Tree: Root → Campaign → Tactic → Technique → SubTech → Det → DC
------------------------------------------------------- */
const TC_CV = {
  'cviz-root':'#cdcfce', 'campaign':'#c87828',
  tactic:'#c87828', technique:'#a8a878', subtechnique:'#7a9878',
  det:'#c09060', dc:'#68a878'
};
const TR_CV = { 'cviz-root':16, 'campaign':12, tactic:10, technique:8, subtechnique:6, det:5, dc:4 };
const LGND_CV = [
  {type:'campaign',    label:'Campaign'},
  {type:'tactic',      label:'Tactic'},
  {type:'technique',   label:'Technique'},
  {type:'subtechnique',label:'Sub-Technique'},
  {type:'det',         label:'Detection'},
  {type:'dc',          label:'Data Component'},
];
let cvSim=null, cvSvg=null, cvG=null, cvZoom=null;
let cvLabelsOn=true;
let _cvFilterCamp='', _cvFilterTac='', _cvFilterQ='';

function buildCampVizTree() {
  const root = {name:'Campaign Coverage',id:'cviz-root',type:'cviz-root',children:[]};
  const fCamp = _cvFilterCamp, fTac = _cvFilterTac, fQ = _cvFilterQ.toLowerCase();

  CAMPAIGNS.campaigns.forEach(camp => {
    if (fCamp && camp.campaign_id !== fCamp) return;
    const campNode = {
      name:camp.campaign_id+': '+camp.name,
      id:camp.campaign_id, type:'campaign',
      url:camp.attack_url, _camp:camp, children:[]
    };
    // Build hierarchy maps keyed by compound dedup strings; id field = actual MITRE ID
    const tacs={}, techs={}, subs={}, dets={}, dcs={};

    camp.linux_techniques.forEach(tech => {
      (tech.coverage||[]).forEach(cov => {
        if (cov.resolved===false) return;
        const {tactic_id:taId,tactic_name:taNm,tactic_url:taUrl,
               technique_id:teId,technique_name:teNm,technique_url:teUrl,
               sub_technique_id:sId,sub_technique_name:sNm,sub_technique_url:sUrl,
               det_id:dId,det_name:dNm,det_url:dUrl} = cov;
        const dc = cov.data_component||{};

        if (fTac && taId !== fTac) return;
        if (fQ) {
          const hay = (camp.campaign_id+' '+camp.name+' '+taId+' '+(taNm||'')+' '+teId+' '+(teNm||'')).toLowerCase();
          if (!hay.includes(fQ)) return;
        }

        const cid = camp.campaign_id;
        const taKey = cid+'_'+taId;
        if (!tacs[taKey]) tacs[taKey]={name:taId+(taNm?' · '+taNm:''), id:taId, type:'tactic', url:taUrl||'', children:[], _p:campNode};

        const teKey = taKey+'_'+teId;
        if (teId && !techs[teKey]) techs[teKey]={name:teId+(teNm?' · '+teNm.slice(0,28):''), id:teId, type:'technique', url:teUrl||'', children:[], _p:tacs[taKey]};

        let detParent = techs[teKey];
        if (sId) {
          const sKey = teKey+'_'+sId;
          if (!subs[sKey]) subs[sKey]={name:sId+(sNm?' · '+sNm.slice(0,25):''), id:sId, type:'subtechnique', url:sUrl||'', children:[], _p:detParent};
          detParent = subs[sKey];
        }

        if (dId && detParent) {
          const dKey = detParent.id+'_CV_'+cid+'_'+dId;
          if (!dets[dKey]) dets[dKey]={name:dId+(dNm?' · '+dNm.slice(0,28):''), id:dId, type:'det', url:dUrl||'', children:[], _p:detParent};
          if (dc.dc_id) {
            const dcKey = dKey+'_'+dc.dc_id;
            if (!dcs[dcKey]) dcs[dcKey]={name:dc.dc_id+(dc.dc_name?': '+dc.dc_name:''), id:dc.dc_id, type:'dc', dc_id:dc.dc_id, url:dc.dc_url||'', log_source:dc.log_source_channel||'', children:[], _p:dets[dKey]};
          }
        }
      });
    });

    // Link children; delete _p to keep tree clean
    [...Object.values(tacs),...Object.values(techs),...Object.values(subs),...Object.values(dets),...Object.values(dcs)]
      .forEach(n=>{ if(n._p){n._p.children.push(n);delete n._p;} });

    if (campNode.children.length) root.children.push(campNode);
  });
  return root;
}

function initCampVizForce() {
  // Populate filter dropdowns
  const campSel = document.getElementById('cvf-camp');
  if (campSel && campSel.options.length===1) {
    CAMPAIGNS.campaigns.forEach(c=>{
      const o=document.createElement('option');o.value=c.campaign_id;
      o.textContent=c.campaign_id+': '+c.name; campSel.appendChild(o);
    });
  }
  const tacSet = new Set();
  CAMPAIGNS.campaigns.forEach(c=>c.linux_techniques.forEach(t=>(t.tactic_ids||[]).forEach(id=>tacSet.add(id))));
  const tacSel = document.getElementById('cvf-tac');
  if (tacSel && tacSel.options.length===1) {
    [...tacSet].sort().forEach(id=>{
      const o=document.createElement('option');o.value=id;
      o.textContent=id+(_tacNames[id]?' · '+_tacNames[id]:'');tacSel.appendChild(o);
    });
  }
  ['cvf-camp','cvf-tac'].forEach(id=>document.getElementById(id)?.addEventListener('change',_cvRebuild));
  document.getElementById('cvf-q')?.addEventListener('input',_cvRebuild);
  document.getElementById('btn-cv-reset')?.addEventListener('click',()=>{
    ['cvf-camp','cvf-tac','cvf-q'].forEach(id=>{const el=document.getElementById(id);if(el)el.value='';});
    _cvFilterCamp=_cvFilterTac=_cvFilterQ=''; _cvBuildSim();
  });
  document.getElementById('btn-cv-labels')?.addEventListener('click',function(){
    cvLabelsOn=!cvLabelsOn; this.classList.toggle('lit',cvLabelsOn); _cvAddLabels();
  });
  _cvBuildSim();
}

function _cvRebuild() {
  _cvFilterCamp = document.getElementById('cvf-camp')?.value||'';
  _cvFilterTac  = document.getElementById('cvf-tac')?.value||'';
  _cvFilterQ    = document.getElementById('cvf-q')?.value||'';
  _cvBuildSim();
}

function _cvBuildSim() {
  const cv = document.getElementById('cv-camp-viz');
  cv.querySelectorAll('svg').forEach(s=>s.remove());
  if (cvSim){cvSim.stop();cvSim=null;}

  const W=cv.clientWidth||1200, H=cv.clientHeight||800;
  const svg=d3.select(cv).append('svg')
    .attr('viewBox',`0 0 ${W} ${H}`).attr('preserveAspectRatio','xMidYMid meet')
    .style('width','100%').style('height','100%')
    .style('touch-action','none');
  cvSvg=svg;

  cvZoom=d3.zoom().scaleExtent([.01,8]).on('zoom',e=>cvG.attr('transform',e.transform));
  svg.call(cvZoom);
  svg.on('dblclick.zoom',null);
  svg.on('dblclick',()=>svg.transition().duration(500).call(cvZoom.transform,d3.zoomIdentity.translate(W/2,H/2).scale(0.15)));

  cvG=svg.append('g');
  const gL=cvG.append('g').attr('class','fl');
  const gN=cvG.append('g').attr('class','fn');

  const raw=buildCampVizTree();
  const hier=d3.hierarchy(raw);
  const nodes=hier.descendants();
  const links=[];
  nodes.forEach(d=>{if(d.parent)links.push({source:d.parent,target:d});});
  nodes.forEach((d,i)=>d._uid=i);

  // Seed rings
  const CVRING={'cviz-root':0,'campaign':760,'tactic':540,'technique':360,'subtechnique':240,'det':150,'dc':80};
  const tCount={},tIdx={};
  nodes.forEach(d=>{const t=d.data.type;tCount[t]=(tCount[t]||0)+1;});
  nodes.forEach(d=>{
    const t=d.data.type,r=CVRING[t]??60;
    const idx=tIdx[t]=(tIdx[t]||0)+1,total=tCount[t];
    const angle=(2*Math.PI*(idx-1))/total;
    const jitter=(t==='dc'||t==='det')?(Math.random()-.5)*40:0;
    d.x=Math.cos(angle)*(r+jitter); d.y=Math.sin(angle)*(r+jitter);
  });

  cvSim=d3.forceSimulation(nodes)
    .force('link',d3.forceLink(links).id(d=>d._uid)
      .distance(d=>{const dep=d.source.depth; return 42*(dep===0?3:dep===1?2.6:dep===2?2:dep===3?1.5:dep===4?1.1:.8);})
      .strength(0.65))
    .force('charge',d3.forceManyBody().strength(d=>-1400*Math.max(.4,(TR_CV[d.data.type]||4)/7)).distanceMax(1200))
    .force('x',d3.forceX(d=>{const r=CVRING[d.data.type]??60;return Math.cos(Math.atan2(d.y||1,d.x||1))*r;})
      .strength(d=>d.data.type==='campaign'?.1:d.data.type==='tactic'?.07:.02))
    .force('y',d3.forceY(d=>{const r=CVRING[d.data.type]??60;return Math.sin(Math.atan2(d.y||1,d.x||1))*r;})
      .strength(d=>d.data.type==='campaign'?.1:d.data.type==='tactic'?.07:.02))
    .force('collide',d3.forceCollide().radius(d=>(TR_CV[d.data.type]||4)+6).strength(.75));

  const link=gL.selectAll('line').data(links).join('line')
    .attr('stroke','#8e9490')
    .attr('stroke-width',d=>{const dep=d.source.depth;return dep===0?4:dep===1?3:dep===2?2:dep===3?1.5:dep===4?1:.6;})
    .attr('stroke-linecap','round');

  const node=gN.selectAll('g').data(nodes).join('g')
    .style('cursor','pointer')
    .call(d3.drag()
      .on('start',(e,d)=>{if(!e.active)cvSim.alphaTarget(.2).restart();d.fx=d.x;d.fy=d.y;})
      .on('drag', (e,d)=>{d.fx=e.x;d.fy=e.y;})
      .on('end',  (e,d)=>{if(!e.active)cvSim.alphaTarget(0);d.fx=d.fy=null;}))
    .on('click',(e,d)=>{
      e.stopPropagation();
      if(e.shiftKey&&d.data.url){window.open(d.data.url,'_blank','noopener');return;}
      _cvOpenPanel(d);
    })
    .on('mouseover',(e,d)=>showTip(e,d))
    .on('mousemove',moveTip).on('mouseout',hideTip)
    .on('touchstart.tip',(e,d)=>{
      if(e.touches&&e.touches[0]){
        const t=e.touches[0];
        showTip({clientX:t.clientX,clientY:t.clientY},d);
        setTimeout(hideTip,1600);
      }
    });

  node.append('circle')
    .attr('r',d=>TR_CV[d.data.type]||4)
    .attr('fill',d=>TC_CV[d.data.type]||'#888')
    .attr('stroke',d=>TC_CV[d.data.type]||'#888')
    .attr('stroke-width',d=>(d.data.type==='cviz-root'||d.data.type==='campaign')?2.5:1.5)
    .attr('fill-opacity',d=>(d.data.type==='dc'||d.data.type==='det')?.55:.92);

  _cvAddLabels=function(){
    gN.selectAll('text.flbl').remove();
    if(!cvLabelsOn)return;
    const maxDepth=parseInt(document.getElementById('sel-depth')?.value||'5');
    [['flbl-bg','none','var(--bg)',3],['flbl-fg',null,null,null]].forEach(([cls,fill,stroke,sw])=>{
      gN.selectAll('g').filter(d=>d.depth<=maxDepth)
        .append('text').attr('class','flbl '+cls)
        .attr('dy','0.32em').attr('x',d=>(TR_CV[d.data.type]||4)+4)
        .attr('fill',fill!==null?fill:d=>TC_CV[d.data.type]||'#888')
        .attr('stroke',stroke).attr('stroke-width',sw).attr('stroke-linejoin',sw?'round':null)
        .style('pointer-events','none').attr('font-family','var(--mono)')
        .attr('font-size',d=>d.data.type==='cviz-root'?12:d.data.type==='campaign'?11:d.data.type==='tactic'?10:d.data.type==='technique'?9.5:d.data.type==='subtechnique'?9:8.5)
        .text(d=>{const nm=d.data.name||'';const mx=d.data.type==='cviz-root'?32:d.data.type==='campaign'?24:d.data.type==='tactic'?22:d.data.type==='technique'?20:d.data.type==='subtechnique'?18:16;return nm.length>mx?nm.slice(0,mx)+'…':nm;});
    });
  };

  _cvAddLabels();
  cvSim.on('tick',()=>{
    link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform',d=>`translate(${d.x},${d.y})`);
  });

  // Build legend
  const lgEl=document.getElementById('lg-camp-viz');
  if(lgEl) lgEl.innerHTML=LGND_CV.map(({type,label})=>`<div class="li"><div class="ld" style="background:${TC_CV[type]||'#888'}"></div>${label}</div>`).join('');

  svg.call(cvZoom.transform,d3.zoomIdentity.translate(W/2,H/2).scale(0.15));
}
let _cvAddLabels=()=>{};

function _cvOpenPanel(d) {
  const data=d.data||{}, t=data.type;
  const sp=document.getElementById('sp'), body=document.getElementById('sp-body');
  if(t==='campaign'){
    const c=data._camp||CAMPAIGNS.campaigns.find(x=>x.campaign_id===data.id)||{};
    const groups=(c.attributed_groups||[]).map(g=>`<span class="sp-chip">${escHtml(g)}</span>`).join('');
    const totalT=(c.linux_techniques||[]).length;
    const verified=(c.linux_techniques||[]).filter(t=>t.coverage_verified).length;
    body.innerHTML=`
      <div class="sp-badge">${escHtml(c.campaign_id||data.id)}</div>
      <div class="sp-name">${escHtml(c.name||data.name)}</div>
      <div class="sp-desc">${escHtml(c.description||'')}</div>
      ${c.attack_url?`<a class="sp-mitre-link" href="${escHtml(c.attack_url)}" target="_blank" rel="noopener">↗ View on MITRE ATT&CK</a>`:''}
      <div class="sp-sec">Details</div>
      <div class="sp-note">First seen: ${escHtml(c.first_seen||'?')}<br>Last seen: ${escHtml(c.last_seen||'?')}<br>Techniques: ${totalT} &nbsp;·&nbsp; Verified: ${verified}</div>
      <div class="sp-sec">Attributed Groups</div>
      <div class="sp-chips">${groups||'<span style="color:var(--text-dim);font-size:10px">Unattributed</span>'}</div>`;
    sp.classList.add('on');
  } else if(t==='cviz-root'){
    body.innerHTML=`<div class="sp-note">Click any node to view details.<br><br>Scroll = zoom · Drag = pan/node · Click = details · Shift+Click = MITRE ↗ · Dbl-click = reset view</div>`;
    sp.classList.add('on');
  } else {
    // tactic/technique/subtechnique/det/dc — delegate to existing handler
    openPanel({data:{...data,id:data.id},children:[],_children:[]});
  }
}

/* -------------------------------------------------------
   CAMPAIGN VISUALIZATION (sub-tab within Campaigns panel — kept for compat)
------------------------------------------------------- */
const TC_CAMP = {
  'camp-root': '#cdcfce',
  'campaign':  '#c87828',
  'camp-tech': '#a8a878',
  'camp-dc':   '#68a878'
};
const TR_CAMP = { 'camp-root': 14, 'campaign': 10, 'camp-tech': 6, 'camp-dc': 4 };
const LGND_CAMP = [
  { type: 'campaign',  label: 'Campaign'       },
  { type: 'camp-tech', label: 'Technique'       },
  { type: 'camp-dc',   label: 'Data Component'  },
];

let campSim = null, campSvg = null, campG = null, campZoom = null;
let campVizInited = false;
let campLabelsOn = true;

function switchCampView(view) {
  const listEl  = document.getElementById('cv-camp-list');
  const vizEl   = document.getElementById('cv-camp-viz');
  const btnList = document.getElementById('cv-btn-list');
  const btnViz  = document.getElementById('cv-btn-viz');
  if (view === 'list') {
    listEl.style.display = '';
    vizEl.style.display  = 'none';
    btnList.classList.add('lit');
    btnViz.classList.remove('lit');
  } else {
    listEl.style.display = 'none';
    vizEl.style.display  = '';
    btnList.classList.remove('lit');
    btnViz.classList.add('lit');
    if (!campVizInited) { initCampForce(); campVizInited = true; }
  }
}

function buildCampLegend(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = LGND_CAMP.map(({ type, label }) =>
    `<div class="li"><div class="ld" style="background:${TC_CAMP[type]||'#888'}"></div>${label}</div>`
  ).join('');
}

function buildCampTree() {
  const root = { name: 'Campaign Coverage', id: 'camp-root', type: 'camp-root', children: [] };
  const campDcReg = (CAMPAIGNS.data_component_registry_linux_updated) || {};
  CAMPAIGNS.campaigns.forEach(c => {
    const campNode = {
      name: c.campaign_id + ': ' + c.name,
      id: c.campaign_id,
      type: 'campaign',
      url: c.attack_url,
      campaign: c,
      children: []
    };
    const techMap = {};
    c.linux_techniques.forEach(t => {
      const techKey = t.sub_technique_id || t.technique_id;
      if (!techMap[techKey]) {
        const techUrl = t.sub_technique_id
          ? 'https://attack.mitre.org/techniques/' + t.technique_id + '/' + t.sub_technique_id.split('.')[1] + '/'
          : 'https://attack.mitre.org/techniques/' + t.technique_id + '/';
        techMap[techKey] = {
          name: techKey + (t.technique_name ? ': ' + t.technique_name : ''),
          id: c.campaign_id + '_' + techKey,
          type: 'camp-tech',
          url: techUrl,
          technique_id: t.technique_id,
          sub_technique_id: t.sub_technique_id || null,
          priority: t.rule_priority,
          children: []
        };
        const seenDC = new Set();
        (t.dc_ids || []).forEach(dcId => {
          if (seenDC.has(dcId)) return;
          seenDC.add(dcId);
          const dcEntry = campDcReg[dcId] || {};
          techMap[techKey].children.push({
            name: dcId + (dcEntry.name ? ': ' + dcEntry.name : ''),
            id: c.campaign_id + '_' + techKey + '_' + dcId,
            type: 'camp-dc',
            dc_id: dcId,
            dc_name: dcEntry.name || dcId,
            url: 'https://attack.mitre.org/datacomponents/' + dcId + '/',
            children: []
          });
        });
      }
    });
    campNode.children = Object.values(techMap);
    root.children.push(campNode);
  });
  return root;
}

function initCampForce() {
  const cv = document.getElementById('cv-camp-viz');
  cv.querySelectorAll('svg').forEach(s => s.remove());
  if (campSim) { campSim.stop(); campSim = null; }

  const W = cv.clientWidth  || 1200;
  const H = cv.clientHeight || 800;

  const svg = d3.select(cv).append('svg')
    .attr('viewBox', `0 0 ${W} ${H}`)
    .attr('preserveAspectRatio', 'xMidYMid meet')
    .style('width', '100%').style('height', '100%')
    .style('touch-action', 'none');

  campSvg = svg;

  campZoom = d3.zoom().scaleExtent([.02, 8])
    .on('zoom', e => campG.attr('transform', e.transform));
  svg.call(campZoom);
  svg.on('dblclick.zoom', null);
  svg.on('dblclick', () =>
    svg.transition().duration(500)
       .call(campZoom.transform, d3.zoomIdentity.translate(W/2, H/2).scale(0.3))
  );

  campG = svg.append('g');
  const gL = campG.append('g').attr('class', 'fl');
  const gN = campG.append('g').attr('class', 'fn');

  const raw  = buildCampTree();
  const hier = d3.hierarchy(raw);
  const nodes = hier.descendants();
  const links = [];
  nodes.forEach(d => { if (d.parent) links.push({ source: d.parent, target: d }); });
  nodes.forEach((d, i) => { d._uid = i; });

  // Seed positions on concentric rings
  const CAMP_RING = { 'camp-root': 0, 'campaign': 600, 'camp-tech': 340, 'camp-dc': 140 };
  const typeCount = {}, typeIdx = {};
  nodes.forEach(d => { const t = d.data.type; typeCount[t] = (typeCount[t]||0) + 1; });
  nodes.forEach(d => {
    const t = d.data.type;
    const r = CAMP_RING[t] ?? 80;
    const idx = typeIdx[t] = (typeIdx[t]||0) + 1;
    const angle = (2 * Math.PI * (idx - 1)) / typeCount[t];
    const jitter = (t === 'camp-dc') ? (Math.random() - 0.5) * 50 : 0;
    d.x = Math.cos(angle) * (r + jitter);
    d.y = Math.sin(angle) * (r + jitter);
  });

  campSim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links)
      .id(d => d._uid)
      .distance(d => 40 * (d.source.depth === 0 ? 3 : d.source.depth === 1 ? 2.2 : 1.4))
      .strength(0.6))
    .force('charge', d3.forceManyBody()
      .strength(d => -1200 * Math.max(0.4, (TR_CAMP[d.data.type]||4) / 6))
      .distanceMax(1000))
    .force('x', d3.forceX(d => {
        const r = CAMP_RING[d.data.type] ?? 80;
        return Math.cos(Math.atan2(d.y||1, d.x||1)) * r;
      }).strength(d => d.data.type === 'campaign' ? 0.09 : 0.02))
    .force('y', d3.forceY(d => {
        const r = CAMP_RING[d.data.type] ?? 80;
        return Math.sin(Math.atan2(d.y||1, d.x||1)) * r;
      }).strength(d => d.data.type === 'campaign' ? 0.09 : 0.02))
    .force('collide', d3.forceCollide()
      .radius(d => (TR_CAMP[d.data.type]||4) + 6).strength(0.75));

  /* LINKS */
  const link = gL.selectAll('line').data(links).join('line')
    .attr('stroke', '#8e9490')
    .attr('stroke-width', d => d.source.depth === 0 ? 3.5 : d.source.depth === 1 ? 2 : 1)
    .attr('stroke-linecap', 'round');

  /* NODES */
  const node = gN.selectAll('g').data(nodes).join('g')
    .style('cursor', 'pointer')
    .call(d3.drag()
      .on('start', (e,d) => { if (!e.active) campSim.alphaTarget(.2).restart(); d.fx=d.x; d.fy=d.y; })
      .on('drag',  (e,d) => { d.fx=e.x; d.fy=e.y; })
      .on('end',   (e,d) => { if (!e.active) campSim.alphaTarget(0); d.fx=d.fy=null; }))
    .on('click', (e,d) => {
      e.stopPropagation();
      if (e.shiftKey && d.data.url) { window.open(d.data.url,'_blank','noopener'); return; }
      openCampPanel(d);
    })
    .on('mouseover', (e,d) => showTip(e,d))
    .on('mousemove', moveTip)
    .on('mouseout',  hideTip)
    .on('touchstart.tip', (e,d) => {
      if (e.touches && e.touches[0]) {
        const t = e.touches[0];
        showTip({ clientX: t.clientX, clientY: t.clientY }, d);
        setTimeout(hideTip, 1600);
      }
    });

  node.append('circle')
    .attr('r', d => TR_CAMP[d.data.type]||4)
    .attr('fill', d => TC_CAMP[d.data.type]||'#888')
    .attr('stroke', d => TC_CAMP[d.data.type]||'#888')
    .attr('stroke-width', d => (d.data.type==='camp-root'||d.data.type==='campaign') ? 2.5 : 1.5)
    .attr('fill-opacity', d => d.data.type==='camp-dc' ? 0.55 : 0.92);

  /* LABELS */
  function campLabelText(d) {
    const nm = d.data.name||'';
    const mx = d.data.type==='camp-root'?30 : d.data.type==='campaign'?22 : d.data.type==='camp-tech'?20 : 16;
    return nm.length > mx ? nm.slice(0,mx)+'…' : nm;
  }
  function addCampLabels() {
    gN.selectAll('text.flbl').remove();
    if (!campLabelsOn) return;
    [['flbl-bg','none','var(--bg)',3],['flbl-fg',null,null,null]].forEach(([cls,fill,stroke,sw])=>{
      gN.selectAll('g').filter(d => d.depth <= 3)
        .append('text').attr('class','flbl '+cls)
        .attr('dy','0.32em')
        .attr('x', d => (TR_CAMP[d.data.type]||4)+4)
        .attr('fill', fill !== null ? fill : d => TC_CAMP[d.data.type]||'#888')
        .attr('stroke', stroke).attr('stroke-width', sw)
        .attr('stroke-linejoin', sw?'round':null)
        .style('pointer-events','none')
        .attr('font-family','var(--mono)')
        .attr('font-size', d => d.data.type==='camp-root'?12:d.data.type==='campaign'?11:d.data.type==='camp-tech'?9.5:8.5)
        .text(campLabelText);
    });
  }

  addCampLabels();

  campSim.on('tick', () => {
    link
      .attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
    node.attr('transform', d=>`translate(${d.x},${d.y})`);
  });

  buildCampLegend('lg-camp');
  svg.call(campZoom.transform, d3.zoomIdentity.translate(W/2, H/2).scale(0.2));
}

function openCampPanel(d) {
  const data = d.data || {};
  const t    = data.type;
  const sp   = document.getElementById('sp');
  const body = document.getElementById('sp-body');

  if (t === 'campaign') {
    const c = data.campaign || CAMPAIGNS.campaigns.find(c => c.campaign_id === data.id) || {};
    const groups = (c.attributed_groups||[]).map(g =>
      `<span class="sp-chip">${escHtml(g)}</span>`
    ).join('');
    body.innerHTML = `
      <div class="sp-badge">${escHtml(c.campaign_id||data.id)}</div>
      <div class="sp-name">${escHtml(c.name||data.name)}</div>
      <div class="sp-desc">${escHtml(c.description||'')}</div>
      ${c.attack_url ? `<a class="sp-mitre-link" href="${escHtml(c.attack_url)}" target="_blank" rel="noopener noreferrer">↗ View on MITRE ATT&CK</a>` : ''}
      <div class="sp-sec">Details</div>
      <div class="sp-note">First seen: ${escHtml(c.first_seen||'?')}<br>Last seen: ${escHtml(c.last_seen||'?')}<br>Techniques: ${(c.linux_techniques||[]).length}</div>
      <div class="sp-sec">Attributed Groups</div>
      <div class="sp-chips">${groups || '<span style="color:var(--text-dim);font-size:10px">Unattributed</span>'}</div>
    `;
    sp.classList.add('on');
  } else if (t === 'camp-tech') {
    const techId = data.sub_technique_id || data.technique_id;
    const fakeD = {
      data: {
        type: data.sub_technique_id ? 'subtechnique' : 'technique',
        id: techId, name: data.name, url: data.url
      },
      children: [], _children: []
    };
    openPanel(fakeD);
  } else if (t === 'camp-dc') {
    const fakeD = {
      data: {
        type: 'dc', dc_id: data.dc_id,
        name: data.dc_name||data.name,
        url: data.url, id: data.dc_id
      }
    };
    openPanel(fakeD);
  } else {
    body.innerHTML = `<div class="sp-note">Click a campaign, technique, or data component node to view details.<br><br>Scroll = zoom · Drag = pan/node · Click = details · Shift+Click = MITRE ↗ · Dbl-click = reset view</div>`;
    sp.classList.add('on');
  }
}

