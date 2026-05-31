const toggle = document.querySelector('.nav-toggle');
const links = document.querySelector('.nav-links');
const year = document.querySelector('#year');

if (toggle && links) {
  toggle.addEventListener('click', () => links.classList.toggle('open'));
}

if (year) {
  year.textContent = new Date().getFullYear();
}
