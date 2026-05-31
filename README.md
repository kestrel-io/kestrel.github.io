# GitHub Pages Scaffold

A lightweight static site scaffold for GitHub Pages.

## Structure

```text
.
├── index.html
├── assets/
│   ├── css/styles.css
│   ├── js/main.js
│   └── img/
├── docs/index.html
├── _posts/
├── .github/workflows/pages.yml
├── .gitignore
├── LICENSE
└── README.md
```

## Publish with GitHub Pages

1. Create a new GitHub repository.
2. Copy these files into the repository.
3. Commit and push to the `main` branch.
4. In GitHub, go to **Settings → Pages**.
5. Set the source to **GitHub Actions**.
6. The included workflow deploys the site automatically.

## Local Preview

Run a simple static server from this directory:

```bash
python3 -m http.server 8080
```

Open `http://localhost:8080`.

## Customize

- Edit `index.html` for content.
- Edit `assets/css/styles.css` for styling.
- Edit `assets/js/main.js` for JavaScript behavior.
- Place images in `assets/img/`.
