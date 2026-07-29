/* -------------------------------------------------------
   DATASET — eBPF capability matrix sections + data sources
   Reads the EBPF global from assets/data/ebpf.js; the ATT&CK
   and campaign sections are rendered by kestrel.js.
------------------------------------------------------- */
(function () {
  const esc = s => String(s == null ? '' : s)
    .replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'})[c]);

  const cmpVersion = (a, b) => {
    const pa = String(a||'').split('.').map(Number), pb = String(b||'').split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i]||0) - (pb[i]||0);
      if (d) return d;
    }
    return 0;
  };

  const CARD = 'background:var(--bg2);border:1px solid var(--border);padding:16px 20px;border-radius:2px;border-left:3px solid';
  const ROW  = 'display:flex;align-items:center;gap:12px;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);';
  const CHIP = 'font-family:var(--mono);font-size:9px;padding:2px 6px;white-space:nowrap;';
  const DIM  = 'font-family:var(--mono);font-size:9px;color:var(--text-dim)';

  function metricCards(metrics, colour) {
    return metrics.map(m => `
      <div style="${CARD} ${colour};">
        <div style="font-family:var(--mono);font-size:22px;font-weight:700;color:${colour};line-height:1">${m.val}</div>
        <div style="font-family:var(--body);font-size:10px;color:var(--text-dim);margin-top:5px;text-transform:uppercase;letter-spacing:.5px">${esc(m.label)}</div>
      </div>`).join('');
  }

  /* Headline counts for the capability matrix. */
  function renderGrid(el, s) {
    el.innerHTML = metricCards([
      { label: 'Functional Domains',  val: s.total_domains },
      { label: 'Program Types',       val: s.total_program_types },
      { label: 'Helper Functions',    val: s.total_helpers },
      { label: 'Map Types',           val: s.total_map_types },
      { label: 'Kfuncs',              val: s.total_kfuncs },
      { label: 'Syscall Commands',    val: s.total_syscall_commands },
      { label: 'Relationships',       val: s.total_relationships },
      { label: 'Core Scope',          val: s.core_relationships },
      { label: 'Allowed Scope',       val: s.allowed_relationships },
    ], '#68a878');
  }

  /* Program types grouped by the domain they belong to. */
  function renderDomains(el) {
    el.innerHTML = EBPF.domains.map(dom => {
      const rows = dom.programs.map(pi => {
        const p = EBPF.programs[pi];
        const c = p.counts;
        return `
          <div style="${ROW}">
            <span style="${CHIP}color:#a8a878;background:rgba(168,168,120,.12);border:1px solid rgba(168,168,120,.3)">${esc(p.short)}</span>
            <span style="font-family:var(--body);font-size:11px;color:var(--text);flex:1">${p.subtype_of ? `subtype of ${esc(p.subtype_of.replace('BPF_PROG_TYPE_',''))}` : ''}</span>
            <span style="${DIM}">${c.helper} helpers</span>
            <span style="${DIM}">${c.map} maps</span>
            <span style="${DIM}">${c.kfunc} kfuncs</span>
            <span style="${DIM}">${c.core} core</span>
            <span style="${DIM}">${p.since ? 'kernel v'+esc(p.since) : ''}</span>
            ${p.url ? `<a href="${esc(p.url)}" target="_blank" rel="noopener noreferrer" style="font-size:9px;color:var(--accent);text-decoration:none">↗</a>` : ''}
          </div>`;
      }).join('');
      return `
        <div style="margin-bottom:18px">
          <div style="font-family:var(--body);font-size:11px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px">
            ${esc(dom.name)} <span style="color:var(--text-dim);font-weight:400">· ${dom.programs.length} program types</span>
          </div>
          <div style="display:flex;flex-direction:column;gap:4px">${rows}</div>
        </div>`;
    }).join('');
  }

  /* One row per object catalogue, with how much of it is reachable. */
  function renderCatalog(el) {
    const cats = [
      { label:'Helper Functions',  list:EBPF.helpers,          colour:'#7a9878' },
      { label:'Map Types',         list:EBPF.map_types,        colour:'#68a878' },
      { label:'Kfuncs',            list:EBPF.kfuncs,           colour:'#c09060' },
      { label:'Syscall Commands',  list:EBPF.syscall_commands, colour:'#7888a8' },
    ];
    el.innerHTML = cats.map(({label, list, colour}) => {
      const attached = list.filter(o => (o.used_by || []).length).length;
      const vers = list.map(o => o.since).filter(Boolean).sort(cmpVersion);
      const range = vers.length ? `kernel v${vers[0]} – v${vers[vers.length-1]}` : '';
      const isSys = label === 'Syscall Commands';
      return `
        <div style="${ROW}">
          <span style="${CHIP}color:${colour};background:${colour}22;border:1px solid ${colour}66">${list.length}</span>
          <span style="font-family:var(--body);font-size:11px;color:var(--text);flex:1">${label}</span>
          <span style="${DIM}">${isSys ? 'program-independent' : `${attached} mapped to a program type`}</span>
          <span style="${DIM}">${isSys ? '' : `${list.length - attached} unattached`}</span>
          <span style="${DIM}">${range}</span>
        </div>`;
    }).join('');
  }

  /* The three corpora this site ships, and where each one comes from. */
  function renderSources(el) {
    const sources = [];

    if (typeof DATA !== 'undefined') {
      const m = DATA.meta || {}, s = DATA.stats || {};
      sources.push({
        file: 'assets/data/data.js',
        title: m.title || 'MITRE ATT&CK Linux coverage corpus',
        body: `${s.total_rows || (DATA.rows||[]).length} coverage rows · ${s.total_tactics || 0} tactics · ` +
              `${s.total_techniques_parent || 0} techniques · ${s.total_data_components_referenced || 0} data components`,
        note: m.generated_at ? `Generated ${String(m.generated_at).slice(0,10)}` : '',
        links: (m.sources || []).slice(0, 3),
      });
    }

    if (typeof CAMPAIGNS !== 'undefined') {
      const camps = CAMPAIGNS.campaigns || [];
      const techs = camps.reduce((n,c) => n + (c.linux_techniques||[]).length, 0);
      sources.push({
        file: 'assets/data/campaigns.js',
        title: 'Linux-targeting campaign corpus',
        body: `${camps.length} campaigns · ${techs} technique mappings · ` +
              `${Object.keys(CAMPAIGNS.data_component_registry_linux_updated || {}).length} data components in the registry`,
        note: '', links: [],
      });
    }

    if (typeof EBPF !== 'undefined') {
      const m = EBPF.meta || {}, s = EBPF.stats || {};
      sources.push({
        file: 'assets/data/ebpf.js',
        title: m.title || 'eBPF program capability matrix',
        body: `${s.total_program_types} program types · ${s.total_relationships} relationships · ` +
              `${s.total_helpers + s.total_map_types + s.total_kfuncs + s.total_syscall_commands} catalogued objects`,
        note: `Generated from ${esc(m.source_bundle || 'the STIX bundle')} by assets/data/source/ebpf_matrix_to_js.py` +
              (m.generated_at ? ` · ${String(m.generated_at).slice(0,10)}` : ''),
        links: (m.sources || []).slice(0, 3),
        attribution: m.attribution || '',
      });
    }

    el.innerHTML = sources.map(s => `
      <div style="background:var(--bg2);border:1px solid var(--border);border-left:3px solid var(--accent);padding:12px 16px;">
        <div style="font-family:var(--mono);font-size:11px;color:var(--accent);margin-bottom:4px">${esc(s.file)}</div>
        <div style="font-family:var(--body);font-size:12px;font-weight:600;color:var(--text);margin-bottom:4px">${esc(s.title)}</div>
        <div style="font-family:var(--body);font-size:10px;color:var(--text-dim);line-height:1.6">${esc(s.body)}</div>
        ${s.note ? `<div style="font-family:var(--body);font-size:9px;color:var(--text-dim);margin-top:5px">${s.note}</div>` : ''}
        ${s.attribution ? `<div style="font-family:var(--body);font-size:9px;color:var(--text-dim);margin-top:5px;line-height:1.6">${esc(s.attribution)}</div>` : ''}
        ${(s.links||[]).length ? `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px">${
          s.links.map(u => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer" style="font-family:var(--mono);font-size:9px;color:var(--accent);text-decoration:none">↗ ${esc(String(u).replace(/^https?:\/\//,'').slice(0,46))}</a>`).join('')
        }</div>` : ''}
      </div>`).join('');
  }

  window.renderEbpfDataset = function () {
    const sourcesEl = document.getElementById('ds-sources');
    if (typeof EBPF === 'undefined') {
      const grid = document.getElementById('ds-ebpf-grid');
      if (grid) grid.innerHTML =
        `<div style="font-family:var(--body);font-size:11px;color:var(--text-dim)">Could not load assets/data/ebpf.js</div>`;
      if (sourcesEl) renderSources(sourcesEl);
      return;
    }
    const grid    = document.getElementById('ds-ebpf-grid');
    const domains = document.getElementById('ds-ebpf-domains');
    const catalog = document.getElementById('ds-ebpf-catalog');
    if (grid)      renderGrid(grid, EBPF.stats);
    if (domains)   renderDomains(domains);
    if (catalog)   renderCatalog(catalog);
    if (sourcesEl) renderSources(sourcesEl);
  };
})();
