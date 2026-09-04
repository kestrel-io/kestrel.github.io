#!/usr/bin/env python3
"""Pull the Carrier Lock demonstration set out of the v9 eBPF x ATT&CK corpus.

    python3 assets/data/source/carrier_to_js.py

The plot is a demonstration, not a measurement: carrier.js generates its own
surface from a fixed seed and gives every labelled key a peak of its own. What
comes from the corpus is the part worth being real -- the event keys themselves,
the eBPF program types that carry the ridges, and the per-program row and
observed-event counts the page tables report.

Keys are the heaviest cells of the corpus, each named by the first taxonomy_id
in that cell. More are emitted than the display can label; carrier.js takes as
many as it can place without two labels ever touching, and the page reports the
number it actually used.
"""
import collections
import json
import os
import sys

CORPUS = os.environ.get(
    "CARRIER_CORPUS",
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..",
                 "models", "datasets", "training",
                 "ebpf_attack_training_full_v9.jsonl"))

# Observed event counts, capture fedora43__aarch64__bpfel__k6.17.1-300.fc43__
# synthetic__20260904t101754z (45.0 s, 255,638 events, 29 program streams).
OBSERVED = {
    "RAW_TRACEPOINT": 2424, "LSM": 24044, "TRACEPOINT": 107194,
    "KPROBE": 60991, "CGROUP_SOCK_ADDR": 4325, "SOCK_OPS": 4346,
    "SK_MSG": 352, "NETFILTER": 9249, "CGROUP_DEVICE": 4828,
    "TELEMETRY_SYSCALL": 30733, "TELEMETRY_CPU/MEMORY/DISK/NET": 733,
}

# The four resource streams are one ridge: they are the same telemetry path.
def bucket(program_type):
    p = program_type.replace("BPF_PROG_TYPE_", "")
    if p.startswith("TELEMETRY_") and p != "TELEMETRY_SYSCALL":
        return "TELEMETRY_CPU/MEMORY/DISK/NET"
    return p

N_KEYS = 44

def main():
    rows = [json.loads(line) for line in open(CORPUS, encoding="utf-8") if line.strip()]
    corpus = [r for r in rows if r["label"] == "attack_capable"]

    tac_of, name_of = {}, {}
    for r in corpus:
        t = r["attack"]["technique"]["id"]
        tac_of.setdefault(t, r["attack"]["tactic"]["id"])
        name_of.setdefault(t, r["attack"]["technique"]["name"])

    cells = collections.defaultdict(list)          # (program, technique) -> rows
    totals = collections.Counter()
    for r in corpus:
        p = bucket(r["ebpf"]["program_type"])
        cells[(p, r["attack"]["technique"]["id"])].append(r)
        totals[p] += 1

    ranked = sorted(((len(rs), p, t) for (p, t), rs in cells.items()),
                    key=lambda c: (-c[0], c[2], c[1]))
    keys = sorted((min(r["taxonomy_id"] for r in cells[(p, t)]), name_of[t])
                  for _, p, t in ranked[:N_KEYS])

    data = {
        "keys": [[k, n] for k, n in keys],
        "all": [{"id": p, "total": totals[p], "obs": OBSERVED[p]}
                for p in sorted(totals, key=lambda k: -totals[k])],
        "corpus": {"rows": len(rows), "capable": len(corpus),
                   "techniques": len(name_of), "tactics": len(set(tac_of.values()))},
    }
    sys.stdout.write(json.dumps(data, separators=(",", ":"), ensure_ascii=False))

if __name__ == "__main__":
    main()
