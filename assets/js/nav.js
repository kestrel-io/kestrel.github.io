/* -------------------------------------------------------
   NAVIGATION — a top-row button reveals its own section row.
   References and Datasets each own one; opening either closes
   the other, so only one section row is ever on screen.

   Only one top-row tab is lit at a time: while a section row
   is open its button takes the highlight, and whichever
   top-row link was lit on load (Home or Journey) gets it back
   once every section row is closed.
------------------------------------------------------- */
window.addEventListener('DOMContentLoaded', () => {
  const groups = Array.from(document.querySelectorAll('button.tab[aria-controls]'))
    .map(btn => ({ btn, sub: document.getElementById(btn.getAttribute('aria-controls')) }))
    .filter(g => g.sub);
  if (!groups.length) return;

  const row = groups[0].btn.parentElement;
  const litOnLoad = row ? Array.from(row.querySelectorAll('a.tab.on')) : [];

  const sync = () => {
    let anyOpen = false;
    groups.forEach(({ btn, sub }) => {
      const open = sub.classList.contains('on');
      anyOpen = anyOpen || open;
      btn.classList.toggle('on', open);
      btn.setAttribute('aria-expanded', String(open));
    });
    litOnLoad.forEach(a => a.classList.toggle('on', !anyOpen));
  };

  groups.forEach(({ btn, sub }) => {
    btn.addEventListener('click', e => {
      e.preventDefault();
      const wasOpen = sub.classList.contains('on');
      groups.forEach(g => g.sub.classList.remove('on'));
      if (!wasOpen) sub.classList.add('on');
      sync();
    });
  });

  sync();
});
