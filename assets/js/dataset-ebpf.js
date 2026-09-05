/* -------------------------------------------------------
   DATASET — eBPF capability matrix sections.
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
  /* Wrapping matters only on a narrow screen, where the row's seven or eight
     cells run past the edge of a panel that does not scroll sideways — the
     kernel version and the source link end up unreachable rather than
     merely off to the right. At full width the row fits and never wraps. */
  const ROW  = 'display:flex;flex-wrap:wrap;align-items:center;gap:12px;padding:8px 12px;background:var(--bg2);border:1px solid var(--border);';
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

  window.renderEbpfDataset = function () {
    if (typeof EBPF === 'undefined') {
      const grid = document.getElementById('ds-ebpf-grid');
      if (grid) grid.innerHTML =
        `<div style="font-family:var(--body);font-size:11px;color:var(--text-dim)">Could not load assets/data/ebpf.js</div>`;
      return;
    }
    const grid    = document.getElementById('ds-ebpf-grid');
    const domains = document.getElementById('ds-ebpf-domains');
    const catalog = document.getElementById('ds-ebpf-catalog');
    if (grid)      renderGrid(grid, EBPF.stats);
    if (domains)   renderDomains(domains);
    if (catalog)   renderCatalog(catalog);
  };
})();
