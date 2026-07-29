/* -------------------------------------------------------
   NAVIGATION — REFERENCES reveals the section tabs.
   Home shows index.html on its own; every other page opens
   with the section row already expanded.
------------------------------------------------------- */
window.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('nav-refs');
  const sub = document.getElementById('nav-sub');
  if (!btn || !sub) return;

  const sync = () => {
    const open = sub.classList.contains('on');
    btn.classList.toggle('on', open);
    btn.setAttribute('aria-expanded', String(open));
  };

  btn.addEventListener('click', e => {
    e.preventDefault();
    sub.classList.toggle('on');
    sync();
  });

  sync();
});
