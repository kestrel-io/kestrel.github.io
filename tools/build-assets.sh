#!/usr/bin/env bash
# -------------------------------------------------------
#  build-assets.sh — minify delivery assets and point the
#  pages at the minified copies.
#
#    tools/build-assets.sh            everything below
#    tools/build-assets.sh --js       assets/js/*.js, assets/data/*.js  ->  *.min.js
#    tools/build-assets.sh --journal  assets/journal/*.json             ->  assets/journal/journal.min.json
#    tools/build-assets.sh --html     <script src="assets/{js,data}/X.js">  ->  X.min.js
#
#  .githooks/pre-commit runs this for whatever is staged and
#  stages the results (enable once: git config core.hooksPath .githooks).
#  Needs python3 and node/npx; esbuild is fetched by npx on first use.
# -------------------------------------------------------
set -euo pipefail
cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

ESBUILD_VERSION="0.28.2"

do_js=0; do_journal=0; do_html=0
if [ $# -eq 0 ]; then do_js=1; do_journal=1; do_html=1; fi
for a in "$@"; do
  case "$a" in
    --js)      do_js=1 ;;
    --journal) do_journal=1 ;;
    --html)    do_html=1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "build-assets: unknown option '$a'" >&2; exit 2 ;;
  esac
done

if [ "$do_js" = 1 ]; then
  if command -v esbuild >/dev/null 2>&1; then
    ESBUILD=(esbuild)
  elif command -v npx >/dev/null 2>&1; then
    ESBUILD=(npx --yes "esbuild@${ESBUILD_VERSION}")
  else
    echo "build-assets: need esbuild or npx (node) on PATH to minify JS" >&2; exit 1
  fi
  echo "build-assets: minifying JS"
  for src in assets/js/*.js assets/data/*.js; do
    [ -e "$src" ] || continue
    case "$src" in *.min.js) continue ;; esac
    out="${src%.js}.min.js"
    # Non-bundling transform: top-level names stay intact, so globals the
    # pages rely on (DATA, initTable, openPanel, …) keep their names.
    "${ESBUILD[@]}" "$src" --minify --charset=utf8 --legal-comments=none \
      --log-level=warning --outfile="$out"
    printf '  %-36s %9d -> %8d bytes\n' "$out" "$(wc -c < "$src")" "$(wc -c < "$out")"
  done
fi

if [ "$do_journal" = 1 ]; then
  echo "build-assets: bundling journal JSON"
  python3 - <<'PY'
import json, os
d = 'assets/journal'
with open(os.path.join(d, 'index.json'), encoding='utf-8') as fh:
    manifest = json.load(fh)
files = manifest if isinstance(manifest, list) else list(manifest.get('entries', []))
bundle = {'files': []}
for name in files:
    with open(os.path.join(d, name), encoding='utf-8') as fh:
        bundle['files'].append({'file': name, 'data': json.load(fh)})
out = os.path.join(d, 'journal.min.json')
with open(out, 'w', encoding='utf-8') as fh:
    json.dump(bundle, fh, separators=(',', ':'), ensure_ascii=False)
src_bytes = sum(os.path.getsize(os.path.join(d, n)) for n in files) + os.path.getsize(os.path.join(d, 'index.json'))
print(f"  {out:<36} {src_bytes:9d} -> {os.path.getsize(out):8d} bytes ({len(files)} file(s))")
PY
fi

if [ "$do_html" = 1 ]; then
  echo "build-assets: pointing pages at minified scripts"
  python3 - <<'PY'
import glob, os, re
pat = re.compile(r'(<script\s+src=")(assets/(?:js|data)/[^"/]+?)\.js(")')
changed = 0
for page in sorted(glob.glob('*.html')):
    with open(page, encoding='utf-8') as fh:
        html = fh.read()
    def swap(m):
        base = m.group(2)
        if base.endswith('.min') or not os.path.exists(base + '.min.js'):
            return m.group(0)
        return f'{m.group(1)}{base}.min.js{m.group(3)}'
    new = pat.sub(swap, html)
    if new != html:
        with open(page, 'w', encoding='utf-8') as fh:
            fh.write(new)
        changed += 1
        print(f'  rewrote {page}')
if not changed:
    print('  (all pages already reference minified scripts)')
PY
fi
