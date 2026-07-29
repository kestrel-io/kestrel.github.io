#!/usr/bin/env python3
"""Convert the eBPF capability matrix STIX bundle into assets/data/ebpf.js.

Emits `const EBPF = {...};` — the same load-as-a-script convention used by
data.js / campaigns.js, denormalised so the page renders without any further
joining: domains index programs, programs carry their helper/map/kfunc edges
(sorted, with the scope and gating metadata already attached), and every
object carries the program types it is available to.

    python3 assets/data/source/ebpf_matrix_to_js.py \
        assets/data/ebpf_matrix_v1.json assets/data/ebpf.js
"""

import json
import re
import sys
from collections import defaultdict

KIND_OF_TYPE = {
    'x-ebpf-helper': 'helpers',
    'x-ebpf-map-type': 'map_types',
    'x-ebpf-kfunc': 'kfuncs',
    'x-ebpf-syscall-command': 'syscall_commands',
}
KIND_OF_REL = {
    'uses-helper': 'helper',
    'uses-map': 'map',
    'uses-kfunc': 'kfunc',
}
COLLECTION_OF_KIND = {'helper': 'helpers', 'map': 'map_types', 'kfunc': 'kfuncs'}

SYS_FAMILIES = [
    ('BPF_PROG_', 'Program commands'),
    ('BPF_MAP_', 'Map commands'),
    ('BPF_BTF_', 'BTF commands'),
    ('BPF_LINK_', 'Link commands'),
    ('BPF_OBJ_', 'Object (pin/fd) commands'),
]

USAGE_SPLIT = re.compile(r'\s*Usage \(defines scope\):')


def ref_url(obj, source_name):
    for r in obj.get('external_references', []):
        if r.get('source_name') == source_name:
            return r.get('url', '')
    return ''


def short_name(name):
    for prefix in ('BPF_PROG_TYPE_', 'BPF_MAP_TYPE_', 'BPF_'):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def sys_family(name):
    for prefix, label in SYS_FAMILIES:
        if name.startswith(prefix):
            return label
    return 'Other commands'


def prune(d):
    """Drop empty values so the emitted file stays small."""
    return {k: v for k, v in d.items() if v not in ('', [], None, {})}


def convert(bundle, source_path):
    objs = bundle['objects']
    by_id = {o['id']: o for o in objs}

    matrix = next((o for o in objs if o['type'] == 'x-ebpf-matrix'), {})
    marking = next((o for o in objs if o['type'] == 'marking-definition'), {})

    # ── Domains ──────────────────────────────────────────────────────────────
    domains, domain_idx = [], {}
    for o in objs:
        if o['type'] != 'x-ebpf-domain':
            continue
        domain_idx[o['name']] = len(domains)
        domains.append({
            'name': o['name'],
            'description': o.get('description', ''),
            'url': ref_url(o, 'ebpf-docs'),
            'programs': [],
        })

    # ── Program types ────────────────────────────────────────────────────────
    programs, program_idx = [], {}
    for o in objs:
        if o['type'] != 'x-ebpf-program-type':
            continue
        di = domain_idx.get(o.get('x_ebpf_domain', ''))
        program_idx[o['name']] = len(programs)
        entry = prune({
            'name': o['name'],
            'short': short_name(o['name']),
            'domain': o.get('x_ebpf_domain', ''),
            'domain_idx': di,
            'since': o.get('x_ebpf_since_version', ''),
            # The bundle folds usage and context into the description; both are
            # kept as their own fields, so only the lead paragraph is stored.
            'description': USAGE_SPLIT.split(o.get('description', ''))[0].strip(),
            'usage': o.get('x_ebpf_usage', ''),
            'context': o.get('x_ebpf_context', ''),
            'url': ref_url(o, 'ebpf-docs'),
            'kernel_docs_url': ref_url(o, 'kernel-docs'),
        })
        entry['subtype_of'] = ''
        entry['subtypes'] = []
        entry['uses'] = {'helper': [], 'map': [], 'kfunc': []}
        if di is not None:
            domains[di]['programs'].append(len(programs))
        programs.append(entry)

    # ── Catalogued objects ───────────────────────────────────────────────────
    # Each collection is name-sorted before indexes are handed out, so the
    # emitted target indexes address the same order the page renders in.
    staged = {c: [] for c in KIND_OF_TYPE.values()}
    for o in objs:
        collection = KIND_OF_TYPE.get(o['type'])
        if not collection:
            continue
        desc = o.get('description', '')
        kdef = o.get('x_ebpf_kernel_definition', '')
        entry = prune({
            'name': o['name'],
            'short': short_name(o['name']) if short_name(o['name']) != o['name'] else '',
            'family': sys_family(o['name']) if collection == 'syscall_commands' else '',
            'description': desc,
            # Only kept when it says something the description does not.
            'kernel_definition': '' if (not kdef or kdef in desc) else kdef,
            'since': o.get('x_ebpf_since_version', ''),
            'url': ref_url(o, 'ebpf-docs'),
        })
        entry['used_by'] = []
        staged[collection].append((o['id'], entry))

    collections, obj_idx = {}, {}
    for collection, entries in staged.items():
        entries.sort(key=lambda pair: pair[1]['name'])
        collections[collection] = [entry for _, entry in entries]
        for i, (stix_id, _) in enumerate(entries):
            obj_idx[stix_id] = (collection, i)

    # ── Relationships ────────────────────────────────────────────────────────
    scope_counts = defaultdict(int)
    total_edges = 0
    for r in objs:
        if r['type'] != 'relationship':
            continue
        if r['relationship_type'] == 'subtype-of':
            src = programs[program_idx[by_id[r['source_ref']]['name']]]
            dst = programs[program_idx[by_id[r['target_ref']]['name']]]
            src['subtype_of'] = dst['name']
            dst['subtypes'].append(src['name'])
            continue
        kind = KIND_OF_REL.get(r['relationship_type'])
        if not kind:
            continue
        p = programs[program_idx[by_id[r['source_ref']]['name']]]
        collection, ti = obj_idx[r['target_ref']]
        scope = r.get('x_ebpf_scope', 'allowed')
        p['uses'][kind].append(prune({
            'target': ti,
            'scope': scope,
            'caps': r.get('x_ebpf_cap', []),
            'kconfig': r.get('x_ebpf_kconfig', []),
            'flags': r.get('x_ebpf_kfunc_flags', []),
            'since': str(r.get('x_ebpf_since_version', '') or ''),
            'attach': r.get('x_ebpf_attach_type', []),
        }))
        collections[collection][ti]['used_by'].append([program_idx[by_id[r['source_ref']]['name']], scope])
        scope_counts[scope] += 1
        total_edges += 1

    # Sorted at build time so the page never has to sort while filtering.
    for p in programs:
        for kind, edges in p['uses'].items():
            edges.sort(key=lambda e: collections[COLLECTION_OF_KIND[kind]][e['target']]['name'])
        p['counts'] = {
            'helper': len(p['uses']['helper']),
            'map': len(p['uses']['map']),
            'kfunc': len(p['uses']['kfunc']),
            'core': sum(1 for es in p['uses'].values() for e in es if e['scope'] == 'core'),
        }
        p['uses'] = {k: v for k, v in p['uses'].items() if v}
        if not p['subtype_of']:
            del p['subtype_of']
        if not p['subtypes']:
            del p['subtypes']
    for collection in collections.values():
        for entry in collection:
            entry['used_by'].sort(key=lambda u: programs[u[0]]['name'])

    return domains, programs, collections, scope_counts, total_edges, matrix, marking


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else 'assets/data/ebpf_matrix_v1.json'
    dst = sys.argv[2] if len(sys.argv) > 2 else 'assets/data/ebpf.js'
    with open(src) as fh:
        bundle = json.load(fh)

    domains, programs, collections, scope_counts, total_edges, matrix, marking = convert(bundle, src)

    unattached = {
        name: sum(1 for e in collection if not e['used_by'])
        for name, collection in collections.items()
        if name != 'syscall_commands'
    }

    data = {
        'meta': {
            'title': matrix.get('name', 'eBPF Program Capability Matrix'),
            'description': matrix.get('description', ''),
            'source_bundle': src.split('/')[-1],
            'bundle_id': bundle.get('id', ''),
            'generated_at': matrix.get('modified', ''),
            'sources': [
                'https://docs.ebpf.io/linux/program-type/',
                'https://docs.ebpf.io/linux/map-type/',
                'https://docs.ebpf.io/linux/helper-function/',
                'https://docs.ebpf.io/linux/kfuncs/',
                'https://docs.ebpf.io/linux/syscall/',
            ],
            'attribution': (marking.get('definition') or {}).get('statement', ''),
            'note': 'core = objects a program type is designed to use; '
                    'allowed = everything the verifier permits it to reach.',
        },
        'stats': {
            'total_domains': len(domains),
            'total_program_types': len(programs),
            'total_helpers': len(collections['helpers']),
            'total_map_types': len(collections['map_types']),
            'total_kfuncs': len(collections['kfuncs']),
            'total_syscall_commands': len(collections['syscall_commands']),
            'total_relationships': total_edges,
            'core_relationships': scope_counts['core'],
            'allowed_relationships': scope_counts['allowed'],
            'unattached_helpers': unattached['helpers'],
            'unattached_map_types': unattached['map_types'],
            'unattached_kfuncs': unattached['kfuncs'],
        },
        'domains': domains,
        'programs': programs,
        'helpers': collections['helpers'],
        'map_types': collections['map_types'],
        'kfuncs': collections['kfuncs'],
        'syscall_commands': collections['syscall_commands'],
    }

    with open(dst, 'w') as fh:
        fh.write('const EBPF = ')
        json.dump(data, fh, separators=(',', ':'), ensure_ascii=False)
        fh.write(';\n')
    print(f'{dst}: {len(programs)} program types, '
          f"{data['stats']['total_relationships']} relationships")


if __name__ == '__main__':
    main()
