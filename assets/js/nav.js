/* -------------------------------------------------------
   NAVIGATION — a top-row button reveals its own section row.
   References and Datasets each own one; opening either closes
   the other, so only one section row is ever on screen.

   Only one top-row tab is lit at a time: while a section row
   is open its button takes the highlight, and whichever
   top-row link was lit on load (Home or Journey) gets it back
   once every section row is closed.

   NARROW SCREENS — the same rows become a drawer. A burger
   button is added to the tagline strip and the tab rows are
   hidden until it is pressed, at which point they stack down
   the page as a full-screen menu (see the max-width: 900px
   block in kestrel.css). The section buttons keep their
   accordion behaviour inside the drawer.

   The drawer is a JS enhancement, so the stylesheet only
   hides the rows once this file has marked the document.
   Without JS the rows stay put and scroll sideways as before.
------------------------------------------------------- */
document.documentElement.classList.add('js-nav');

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

  /* ── Drawer ──────────────────────────────────────────────
     One button, added next to the tagline. It carries the
     open state on <body>, so the stylesheet decides what a
     drawer looks like at each width and this file only has to
     say whether it is open.
  ------------------------------------------------------- */
  const tagline = document.getElementById('tagline');
  if (!tagline || !row) return;

  const burger = document.createElement('button');
  burger.id = 'nav-burger';
  burger.className = 'nav-burger';
  burger.type = 'button';
  /* The drawer is both rows: the top-level entries in the tagline strip and
     the section list under them. Name both, so following the control leads
     to the whole menu rather than half of it. */
  if (!row.id) row.id = 'nav-top';
  const navEl = document.getElementById('nav');
  burger.setAttribute('aria-controls', navEl ? row.id + ' nav' : row.id);
  burger.setAttribute('aria-expanded', 'false');
  burger.setAttribute('aria-label', 'Open menu');
  burger.innerHTML = '<span class="nav-burger-bars" aria-hidden="true">' +
                     '<i></i><i></i><i></i></span>';
  tagline.insertBefore(burger, row);

  const setOpen = open => {
    document.body.classList.toggle('nav-open', open);
    burger.setAttribute('aria-expanded', String(open));
    burger.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  };

  burger.addEventListener('click', () =>
    setOpen(!document.body.classList.contains('nav-open')));

  /* A link inside the drawer navigates, so the drawer is shut
     on the way out: pages served from the cache come back with
     it closed rather than mid-open. */
  document.querySelectorAll('.nav-row a.tab').forEach(a =>
    a.addEventListener('click', () => setOpen(false)));

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && document.body.classList.contains('nav-open')) {
      setOpen(false);
      burger.focus();
    }
  });

  /* Rotating to landscape, or widening past the drawer
     breakpoint, leaves the desktop rows on screen — the open
     state would then hide the page behind an invisible menu. */
  const wide = window.matchMedia('(min-width: 901px)');
  const onWide = e => { if (e.matches) setOpen(false); };
  if (wide.addEventListener) wide.addEventListener('change', onWide);
  else if (wide.addListener) wide.addListener(onWide);
});
