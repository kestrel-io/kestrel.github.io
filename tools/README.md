# Build tooling

The site is deployed as-is from the repository, so the optimized assets are
committed alongside their sources.

| Source | Generated delivery file |
|--------|-------------------------|
| `assets/js/*.js`, `assets/data/*.js` | `*.min.js` next to each source (esbuild, whitespace + syntax minification; top-level names kept) |
| `assets/journal/index.json` + entries | `assets/journal/journal.min.json`, one minified bundle fetched with a single request |
| `<script src="assets/js/X.js">` in pages | rewritten to `X.min.js` |
| the page table in `tools/seo.py` | each page's generated `<head>` block, `robots.txt`, `sitemap.xml` |

`tools/build-assets.sh` does the work (`--js`, `--journal`, `--html`, `--seo`,
or no flag for all four). It needs `python3` and `node`/`npx`; esbuild is
fetched by npx on first use and cached after that.

## Search and social metadata

`tools/seo.py` holds one table of every page: its title, its meta description
and the structured data it carries. Running it rewrites the block between the
`<!-- seo:start -->` and `<!-- seo:end -->` markers in each page's `<head>`,
plus `robots.txt` and `sitemap.xml`. Nothing outside those markers is touched,
so editing the table and re-running is how a title or a description changes —
editing the HTML directly is undone on the next build.

```sh
tools/seo.py            # rewrite the pages, robots.txt and sitemap.xml
tools/seo.py --check    # verify only; non-zero exit if anything is stale
```

It refuses to run if a page on disk is missing from the table, warns when a
title or description is long enough that search results will truncate it, and
warns when a page has no `<h1>`.

The social card at `assets/img/og-card.png` (1200x630) is rendered from
`tools/og-card.html`, which uses the site's own fonts and artwork:

```sh
qlmanage -t -s 1200 -o /tmp tools/og-card.html   # then crop to the card's bounds
```

## Pre-commit hook

`.githooks/pre-commit` runs the relevant parts of the build whenever JS,
journal JSON or pages are staged, then stages the generated files. Enable it
once per clone:

```sh
git config core.hooksPath .githooks
```

Skip it for a single commit with `git commit --no-verify`.

## Local preview

Pages reference the minified scripts. After editing a source file, run
`tools/build-assets.sh` (or just commit) so the preview picks up the change.
GitHub Pages compresses text responses on the wire (gzip/brotli) by itself,
so no pre-compressed `.gz` files are needed.
