# Build tooling

The site is deployed as-is from the repository, so the optimized assets are
committed alongside their sources.

| Source | Generated delivery file |
|--------|-------------------------|
| `assets/js/*.js`, `assets/data/*.js` | `*.min.js` next to each source (esbuild, whitespace + syntax minification; top-level names kept) |
| `assets/journal/index.json` + entries | `assets/journal/journal.min.json`, one minified bundle fetched with a single request |
| `<script src="assets/js/X.js">` in pages | rewritten to `X.min.js` |

`tools/build-assets.sh` does the work (`--js`, `--journal`, `--html`, or no
flag for all three). It needs `python3` and `node`/`npx`; esbuild is fetched
by npx on first use and cached after that.

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
