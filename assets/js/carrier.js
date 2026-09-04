/* ------------------------------------------------------------------ *
 * carrier.js — "Carrier Lock": 33 channels of eBPF × ATT&CK signal.
 *
 * DEMONSTRATION ONLY. Nothing here is read from live event data. The
 * display is a spectrum analyzer: 33 channels stacked on a diamond
 * floor, each with a span of its own and a noise floor that is always
 * running, and transmissions that pop up on any channel, at any bin, at
 * intervals of their own. Nothing sweeps and nothing progresses across
 * the plot. A peak is ADDED to the noise floor, never substituted for
 * it, so the grass keeps running through and over every transmission.
 *
 * Some of those channels carry a known transmission: a real event key
 * from the Kestrel corpus, at a fixed channel, bin and amplitude, which
 * comes up at long intervals with its key beside it. The key rides the
 * peak, so it lands exactly when the peak does. More keys are offered
 * than the display can label; it takes as many as it can place without
 * two labels ever touching. Those keys, and the corpus counts in the
 * page tables, are the real part.
 *
 * The same markup, stylesheet block and script serve the standalone
 * page and the Kestrel home page, so everything is namespaced cl-* and
 * every optional element is looked up defensively — there may be no
 * transport buttons and no tables at all.
 *
 * DATA IS GENERATED — do not hand-edit the blob below:
 *   python3 assets/data/source/carrier_to_js.py
 * Source corpus: models/datasets/training/ebpf_attack_training_full_v9.jsonl
 * ------------------------------------------------------------------ */
const CARRIER_DATA = {"keys":[["TA0001_T1078_000_AN1544_DC0002","Valid Accounts"],["TA0002_T1053_000_AN0259_DC0032","Scheduled Task/Job"],["TA0002_T1053_000_AN0259_DC0061","Scheduled Task/Job"],["TA0002_T1059_000_AN1429_DC0032","Command and Scripting Interpreter"],["TA0002_T1204_000_AN1315_DC0032","User Execution"],["TA0002_T1204_000_AN1315_DC0039","User Execution"],["TA0002_T1574_000_AN0610_DC0032","Hijack Execution Flow"],["TA0003_T1037_000_AN0312_DC0032","Boot or Logon Initialization Scripts"],["TA0003_T1205_000_AN1449_DC0032","Traffic Signaling"],["TA0003_T1205_000_AN1449_DC0078","Traffic Signaling"],["TA0003_T1205_000_AN1449_DC0082","Traffic Signaling"],["TA0003_T1543_000_AN1576_DC0061","Create or Modify System Process"],["TA0003_T1543_000_AN1576_DC0064","Create or Modify System Process"],["TA0003_T1546_000_AN0025_DC0059","Event Triggered Execution"],["TA0003_T1546_000_AN0025_DC0064","Event Triggered Execution"],["TA0003_T1546_004_AN0059_DC0061","Event Triggered Execution"],["TA0003_T1547_000_AN0765_DC0032","Boot or Logon Autostart Execution"],["TA0003_T1547_000_AN0765_DC0039","Boot or Logon Autostart Execution"],["TA0003_T1556_000_AN0288_DC0032","Modify Authentication Process"],["TA0003_T1556_000_AN0288_DC0061","Modify Authentication Process"],["TA0003_T1556_003_AN1250_DC0067","Modify Authentication Process"],["TA0004_T1055_000_AN1400_DC0020","Process Injection"],["TA0004_T1055_008_AN0579_DC0032","Process Injection"],["TA0005_T1027_000_AN1065_DC0032","Obfuscated Files or Information"],["TA0005_T1027_000_AN1065_DC0061","Obfuscated Files or Information"],["TA0005_T1027_001_AN1529_DC0039","Obfuscated Files or Information"],["TA0005_T1027_002_AN0067_DC0020","Obfuscated Files or Information"],["TA0005_T1036_000_AN0356_DC0032","Masquerading"],["TA0005_T1036_000_AN0356_DC0059","Masquerading"],["TA0005_T1070_000_AN0521_DC0040","Indicator Removal"],["TA0005_T1070_003_AN0467_DC0032","Indicator Removal"],["TA0005_T1480_000_AN1552_DC0032","Execution Guardrails"],["TA0005_T1497_000_AN0128_DC0032","Virtualization/Sandbox Evasion"],["TA0005_T1564_000_AN1385_DC0039","Hide Artifacts"],["TA0005_T1564_000_AN1385_DC0064","Hide Artifacts"],["TA0006_T1056_000_AN0283_DC0021","Input Capture"],["TA0006_T1056_002_AN1441_DC0032","Input Capture"],["TA0006_T1552_000_AN1154_DC0055","Unsecured Credentials"],["TA0006_T1552_000_AN1154_DC0064","Unsecured Credentials"],["TA0011_T1071_000_AN1226_DC0032","Application Layer Protocol"],["TA0011_T1071_001_AN0076_DC0085","Application Layer Protocol"],["TA0011_T1090_000_AN1230_DC0032","Proxy"],["TA0040_T1496_000_AN0742_DC0032","Resource Hijacking"],["TA0040_T1496_000_AN0742_DC0078","Resource Hijacking"]],"all":[{"id":"RAW_TRACEPOINT","total":420,"obs":2424},{"id":"LSM","total":160,"obs":24044},{"id":"TRACEPOINT","total":137,"obs":107194},{"id":"KPROBE","total":98,"obs":60991},{"id":"CGROUP_SOCK_ADDR","total":58,"obs":4325},{"id":"SOCK_OPS","total":45,"obs":4346},{"id":"SK_MSG","total":31,"obs":352},{"id":"NETFILTER","total":15,"obs":9249},{"id":"CGROUP_DEVICE","total":14,"obs":4828},{"id":"TELEMETRY_SYSCALL","total":11,"obs":30733},{"id":"TELEMETRY_CPU/MEMORY/DISK/NET","total":9,"obs":733}],"corpus":{"rows":1146,"capable":998,"techniques":159,"tactics":13}};

(() => {
  "use strict";
  const SVGNS = "http://www.w3.org/2000/svg";
  const svg = document.getElementById("cl-plot");
  if (!svg) return;

  /* ---------------- geometry: a diamond floor ----------------------
   * Ground position is (u, v): u runs the frequency axis of a channel,
   * v runs the 33 channels from the far corner to the near one. Each
   * axis gets its own screen vector and the two are mirrored in y, so
   * the unit square lands as a rhombus with its left and right corners
   * level -- the floor reads as a diamond seen from above and to one
   * side, which is how a stacked analyzer display is drawn.
   * ---------------------------------------------------------------- */
  const VB = { w: 1180, h: 780 };
  /* The visible window, which is cropped to what is actually drawn.
     Must match the viewBox on the svg in the markup. */
  const VIEW = { top: 72, bot: 724 };
  const O  = { x: 515, y: 120 };    // far corner          (u=0, v=0)
  const AU = { x: 620, y: 300 };    // to the right corner (u=1, v=0)
  const AV = { x: -470, y: 300 };   // to the left corner  (u=0, v=1)
  const ROWS = 33;                  // channels
  const N = 150;                    // frequency bins per channel
  const HMAX  = { far: 58,  near: 70 };    // a full-scale transmission
  const NOISE = { far: 3.0, near: 3.8 };   // the floor, never absent
  const DIM   = { far: 0.38, near: 0.9 };
  const SW    = { far: 0.6,  near: 1.0 };

  const keys = CARRIER_DATA.keys;
  const lerp = (a, b, t) => a + (b - a) * t;
  const clamp01 = x => (x < 0 ? 0 : x > 1 ? 1 : x);
  const smooth = t => t * t * (3 - 2 * t);
  const depth = k => k / (ROWS - 1);                  // 0 far .. 1 near
  const gx = (u, v) => O.x + u * AU.x + v * AV.x;
  const gy = (u, v) => O.y + u * AU.y + v * AV.y;
  const round2 = x => Math.round(x * 2) / 2;

  /* Fixed seed: the channel layout and the key placements are the same
     on every load and every machine. Only the traffic is live. */
  let seed = 20260904;
  const rnd = () => { seed = (seed * 1664525 + 1013904223) >>> 0; return seed / 4294967296; };
  const between = (a, b) => a + (b - a) * rnd();

  /* Per-channel geometry, and the x of every bin pre-rendered: only y
     changes from frame to frame, so the x half of each path is built
     once and concatenated rather than re-formatted thousands of times a
     frame. Each channel is also given a span of its own -- somewhere
     between half the axis and all of it -- so the traces end where they
     end instead of ruling the diamond off with two straight edges. */
  const chan = [];
  for (let k = 0; k < ROWS; k++) {
    const v = depth(k), bx = new Float64Array(N), by = new Float64Array(N), pre = new Array(N);
    const len = Math.round(N * between(0.5, 1));
    const lo = Math.floor(rnd() * (N - len)), hi = lo + len - 1;
    for (let i = 0; i < N; i++) {
      const u = i / (N - 1);
      bx[i] = gx(u, v); by[i] = gy(u, v);
      pre[i] = (i === lo ? "M" : "L") + round2(bx[i]) + " ";
    }
    chan.push({ v, bx, by, pre, lo, hi,
      hmax:  lerp(HMAX.far,  HMAX.near,  v),
      noise: lerp(NOISE.far, NOISE.near, v),
      dim:   lerp(DIM.far,   DIM.near,   v),
      sw:    lerp(SW.far,    SW.near,    v) });
  }

  /* ---------------- the noise floor --------------------------------
   * Always on, on every channel, and never smoothed away: a peak is
   * added to the floor, it does not replace it, so the grass keeps
   * running straight through and over the top of a transmission. Two
   * fields of per-bin noise are crossfaded and the far one is replaced
   * as it retires, which gives a live floor for one array of random
   * numbers every eighth of a second instead of a hash per bin per
   * frame.
   * ---------------------------------------------------------------- */
  const CELLS = ROWS * N;
  const STEP = 70;                        // ms per noise field
  const newField = () => { const f = new Float32Array(CELLS);
    for (let n = 0; n < CELLS; n++) f[n] = rnd() * 2 - 1; return f; };
  /* A static per-bin bias, so channels are not identically flat. */
  const bias = new Float32Array(CELLS);
  for (let n = 0; n < CELLS; n++) bias[n] = 0.72 + 0.56 * rnd();
  let fieldA = newField(), fieldB = newField(), fieldAge = 0;

  /* ---------------- transmissions ----------------------------------
   * Peaks do not march. Each channel runs its own timer and fires when
   * it fires, at a bin of its own choosing, and the twelve labelled
   * keys each hold a channel and a bin of their own and come up at
   * their own long intervals. A transmission is an attack, a hold and a
   * decay on top of the floor -- nothing sweeps, nothing progresses.
   * ---------------------------------------------------------------- */
  const SIG = 1.55;                       // bins; a transmission is narrow
  const peakBuf = new Float32Array(CELLS);
  const live = [];

  const envelope = (age, e) => {
    if (age < e.a) return smooth(age / e.a);
    if (age < e.a + e.h) return 1;
    const d = (age - e.a - e.h) / e.d;
    return d >= 1 ? -1 : 1 - smooth(d);   // -1 marks it spent
  };

  const fire = (k, c, amp, a, h, d, mark) => {
    live.push({ k, c, amp, a, h, d, mark, t0: clock, env: 0 });
  };

  /* Anonymous traffic: one timer per channel. */
  const timers = new Float64Array(ROWS);
  for (let k = 0; k < ROWS; k++) timers[k] = between(0, 1200);

  /* ---------------- the known transmissions ------------------------
   * One channel and one bin each, chosen so that no two labels land
   * within a label's width and height of one another, and so no channel
   * carries more than a couple. Amplitude is fixed per key, so a label
   * can be placed once and stay put every time its key comes up. More
   * keys are offered than the display can hold: the sampler takes as
   * many as it can fit and the page reports the number it used. */
  const PER_CHANNEL = 2;
  const marks0 = [];
  for (let guard = 0; guard < 40000 && marks0.length < keys.length; guard++) {
    const k = Math.floor(rnd() * ROWS);
    const ck = chan[k];
    if (ck.hi - ck.lo < 24) continue;
    const c = ck.lo + 8 + Math.floor(rnd() * (ck.hi - ck.lo - 16));
    const amp = between(0.62, 1);
    const x = chan[k].bx[c], y = chan[k].by[c] - chan[k].hmax * amp;
    if (x < 96 || x > VB.w - 96) continue;
    if (marks0.filter(o => o.k === k).length >= PER_CHANNEL) continue;
    if (marks0.some(o => Math.abs(o.x - x) < 186 && Math.abs(o.y - y) < 27)) continue;
    const [key, name] = keys[marks0.length];
    marks0.push({ k, c, amp, x, y, key, name,
                  next: between(600, 7000), idx: marks0.length,
                  drop: chan[k].hmax * amp });
  }
  marks0.sort((a, b) => a.x - b.x).forEach((m, i) => (m.idx = i));

  /* ---------------- floor and traces -------------------------------- */

  const gFloor = document.getElementById("cl-floor");
  const gRidge = document.getElementById("cl-ridges");
  const gPeaks = document.getElementById("cl-peaks");
  const el = (n, a) => { const e = document.createElementNS(SVGNS, n);
    for (const k in a) e.setAttribute(k, a[k]); return e; };

  /* ---------------- the floor grid ---------------------------------
   * Ruled both ways, but no line is drawn as a line: each is cut into
   * short segments, and every segment carries its own weight from a
   * feather that dissolves it towards its own two ends, a per-segment
   * dither that thins or drops it outright, and a dim with depth. So
   * the floor has no rim -- it thins into the dark where it stops.
   * ---------------------------------------------------------------- */
  const hash = (a, b) => {
    const s = Math.sin(a * 12.9898 + b * 78.233) * 43758.5453;
    return s - Math.floor(s);
  };
  const FEATHER_END = 0.17;
  const endFade = t => smooth(clamp01(Math.min(t, 1 - t) / FEATHER_END));
  const addSeg = (u1, v1, u2, v2, a) => {
    const d = hash(u1 * 37.1 + v1 * 11.7, v1 * 91.3 + u2 * 3.3);
    if (d < 0.1) return;                        // dither: drop a tenth outright
    const w = a * (0.52 + 0.48 * d);
    if (w < 0.05) return;
    gFloor.appendChild(el("line", { class: "cl-grid", opacity: w.toFixed(2),
      x1: round2(gx(u1, v1)), y1: round2(gy(u1, v1)),
      x2: round2(gx(u2, v2)), y2: round2(gy(u2, v2)) }));
  };
  for (let j = 0; j < 13; j++) {                 // ribs across the channels
    const u = j / 12, lead = j % 3 === 0 ? 1 : 0.5;
    for (let s = 0; s < 10; s++) {
      const v1 = s / 10, v2 = (s + 1) / 10, vm = (v1 + v2) / 2;
      addSeg(u, v1, u, v2, lead * endFade(vm) * lerp(0.62, 1, vm));
    }
  }
  for (let k = 0; k < ROWS; k += 6) {            // a rail every sixth channel
    const v = depth(k);
    for (let s = 0; s < 30; s++) {
      const u1 = s / 30, u2 = (s + 1) / 30, um = (u1 + u2) / 2;
      addSeg(u1, v, u2, v, 0.7 * endFade(um) * lerp(0.62, 1, v));
    }
  }

  /* One stroke per channel and nothing else: no fill, no shading, no
     hidden-line removal. A tall transmission crosses the channels in
     front of it, which is what a stacked analyzer display does. */
  const traces = chan.map(c => {
    const line = el("path", { class: "cl-ridge-line",
      "stroke-width": c.sw.toFixed(2), "stroke-opacity": c.dim.toFixed(2) });
    gRidge.appendChild(line);
    return line;
  });

  /* ---------------- peak labels ------------------------------------- */
  /* The only labels on the plot, and each is a whole taxonomy key. No
     leader line: the label sits beside its own peak, and rises and
     falls with it. */
  const CH = 5.75, LH = 13, GAP = 9;
  const STEPS = [];
  for (const dy of [-9, -22, 6, -35, 19]) for (const side of [1, -1]) STEPS.push({ dy, side });
  const overlap = (a, b) => !(a.x1 > b.x2 || a.x2 < b.x1 || a.y1 > b.y2 || a.y2 < b.y1);

  const marks = [];
  for (const m of marks0) {
    const w = m.key.length * CH + 2;
    for (const s of STEPS) {
      const end = s.side < 0, tx = m.x + s.side * GAP, ty = m.y + s.dy;
      const box = { x1: end ? tx - w : tx, x2: end ? tx : tx + w,
                    y1: ty - LH, y2: ty + 3 };
      if (box.x1 < 14 || box.x2 > VB.w - 14 || box.y1 < VIEW.top + 6) continue;
      if (marks.some(o => overlap(box, o.box))) continue;
      marks.push({ ...m, box, tx, ty, end });
      break;
    }
  }

  const markNodes = marks.map(m => {
    const g = el("g", { opacity: 0 });
    g.appendChild(el("circle", { class: "cl-peak-dot",
      cx: round2(m.x), cy: round2(m.y), r: 2.2 }));
    const t = el("text", { class: "cl-peak-key",
      x: round2(m.tx), y: round2(m.ty), "text-anchor": m.end ? "end" : "start" });
    t.textContent = m.key;
    g.appendChild(t);
    gPeaks.appendChild(g);
    return g;
  });

  /* ---------------- tables (standalone page only) ------------------- */

  const shortId = s => s.replace("CPU/MEMORY/DISK/NET", "CPU/MEM/DISK/NET");
  /* Only the keys that were actually placed reach the page: the table
     and the counts describe what is on the plot, never what was offered. */
  const keyBody = document.getElementById("cl-key-body");
  if (keyBody) keyBody.innerHTML = marks
    .map(m => `<tr><td class="key">${m.key}</td><td class="nm">${m.name}</td>` +
      `<td>${String(m.k + 1).padStart(2, "0")}</td></tr>`).join("");
  if (document.querySelectorAll) {
    for (const n of document.querySelectorAll(".cl-count")) n.textContent = marks.length;
  }
  const rowBody = document.getElementById("cl-row-body");
  if (rowBody) rowBody.innerHTML = (CARRIER_DATA.all || [])
    .map(r => `<tr><td>${shortId(r.id)}</td><td>${r.total}</td>` +
      `<td>${r.obs.toLocaleString("en-US")}</td></tr>`).join("");

  /* ---------------- the scan ---------------------------------------- */

  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;
  let clock = 0, last = performance.now(), playing = !reduced, raf = 0;

  function schedule(dt) {
    for (let k = 0; k < ROWS; k++) {
      timers[k] -= dt;
      if (timers[k] > 0) continue;
      timers[k] = between(70, 650);
      const c = chan[k], span = Math.max(1, c.hi - c.lo - 3);
      /* A channel rarely opens up with one transmission alone. */
      const burst = 1 + (rnd() < 0.55 ? 1 : 0) + (rnd() < 0.22 ? 1 : 0);
      for (let b = 0; b < burst; b++) {
        fire(k, c.lo + 2 + Math.floor(rnd() * span),
             between(0.16, rnd() < 0.18 ? 0.9 : 0.5),
             between(30, 80), between(30, 260), between(110, 430), -1);
      }
    }
    for (const m of marks0) {
      m.next -= dt;
      if (m.next > 0) continue;
      m.next = between(4200, 11000);
      fire(m.k, m.c, m.amp, 150, 1100, 480, m.idx);
    }
  }

  const labelEnv = new Float32Array(marks0.length);

  function draw() {
    /* Crossfade the noise fields; retire one when it is spent. */
    const alpha = fieldAge / STEP;

    peakBuf.fill(0);
    labelEnv.fill(0);
    for (let n = live.length - 1; n >= 0; n--) {
      const e = live[n], env = envelope(clock - e.t0, e);
      if (env < 0) { live.splice(n, 1); continue; }
      const amp = e.amp * env * chan[e.k].hmax, off = e.k * N;
      const lo = Math.max(0, Math.ceil(e.c - 4.5 * SIG));
      const hi = Math.min(N - 1, Math.floor(e.c + 4.5 * SIG));
      for (let i = lo; i <= hi; i++) {
        const dz = (i - e.c) / SIG;
        peakBuf[off + i] += amp * Math.exp(-0.5 * dz * dz);
      }
      if (e.mark >= 0) labelEnv[e.mark] = env;
    }

    for (let k = 0; k < ROWS; k++) {
      const c = chan[k], off = k * N;
      let d = "";
      for (let i = c.lo; i <= c.hi; i++) {
        const n = off + i;
        /* Floor first, transmission on top of it -- never instead of it. */
        const fl = Math.abs(fieldA[n] + (fieldB[n] - fieldA[n]) * alpha);
        const h = c.noise * bias[n] * (0.22 + 0.78 * fl) + peakBuf[n];
        d += c.pre[i] + round2(c.by[i] - h) + " ";
      }
      traces[k].setAttribute("d", d);
    }

    /* A label rides its own peak: it is placed for the peak at full
       height, and while the transmission is climbing or falling the
       whole group -- dot and key together -- is dropped by exactly the
       height the peak is short of. So the key lands on the floor at the
       instant the peak does, rather than hanging where the summit will
       be. Opacity is driven a little ahead of the envelope so the key is
       solid for the whole of the hold and still reaches zero with it. */
    for (let i = 0; i < marks.length; i++) {
      const m = marks[i], env = labelEnv[m.idx];
      if (env <= 0) { markNodes[i].setAttribute("opacity", "0"); continue; }
      markNodes[i].setAttribute("opacity", Math.min(1, env * 1.3).toFixed(2));
      markNodes[i].setAttribute("transform", "translate(0," + round2(m.drop * (1 - env)) + ")");
    }
  }

  function frame(now) {
    const dt = Math.min(now - last, 60); last = now;
    if (playing) {
      clock += dt;
      fieldAge += dt;
      while (fieldAge >= STEP) { fieldAge -= STEP; fieldA = fieldB; fieldB = newField(); }
      schedule(dt);
    }
    draw();
    raf = requestAnimationFrame(frame);
  }

  const play = document.getElementById("cl-play");
  const again = document.getElementById("cl-again");
  if (play) play.addEventListener("click", () => {
    playing = !playing;
    play.textContent = playing ? "Pause" : "Play";
    play.setAttribute("aria-pressed", String(playing));
    last = performance.now();
  });
  if (again) again.addEventListener("click", () => {
    /* Bring every key up at once, and stagger the channels afresh. */
    for (const m of marks0) m.next = between(120, 900);
    for (let k = 0; k < ROWS; k++) timers[k] = between(0, 1400);
    playing = true;
    if (play) { play.textContent = "Pause"; play.setAttribute("aria-pressed", "true"); }
    last = performance.now();
  });

  if (reduced) {
    /* No motion by default: one still frame with every key up. This does
       not depend on the transport being present -- the page may carry no
       buttons at all, and the still frame still has to be the good one. */
    for (const m of marks0) fire(m.k, m.c, m.amp, 1, 1e9, 1, m.idx);
    clock = 400;
    if (play) { play.textContent = "Play"; play.setAttribute("aria-pressed", "false"); }
  }
  raf = requestAnimationFrame(frame);
})();
