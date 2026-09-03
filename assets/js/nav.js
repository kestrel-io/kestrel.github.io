/* -------------------------------------------------------
   NAVIGATION — REFERENCES reveals the section tabs.
   Home and Journey show their pages on their own; every
   reference page opens with the section row already expanded.

   Only one top-row tab is lit at a time: while References is
   open it takes the highlight, and whichever top-row link was
   lit on load (Home or Journey) gets it back once References
   is closed.
------------------------------------------------------- */
window.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('nav-refs');
  const sub = document.getElementById('nav-sub');
  if (!btn || !sub) return;

  const row = btn.parentElement;
  const litOnLoad = row ? Array.from(row.querySelectorAll('a.tab.on')) : [];

  const sync = () => {
    const open = sub.classList.contains('on');
    btn.classList.toggle('on', open);
    btn.setAttribute('aria-expanded', String(open));
    litOnLoad.forEach(a => a.classList.toggle('on', !open));
  };

  btn.addEventListener('click', e => {
    e.preventDefault();
    sub.classList.toggle('on');
    sync();
  });

  sync();
});
