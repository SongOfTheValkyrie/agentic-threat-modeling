"""Verify-phase analysis: did Verify drop correct threats?

For the newest agent_pev trace of an architecture, compare each element's
dropped_keys (candidates Explore proposed but Verify removed) against the
ground truth. A dropped key that is in the ground truth is a correct threat the
verify phase wrongly discarded — a direct recall cost of Verify.

Usage: uv run python analyze_verify.py [architecture]
"""

import glob
import json
import os
import sys

arch = sys.argv[1] if len(sys.argv) > 1 else "multi_tenant_saas"

# newest agent_pev trace for this architecture that has the new keys
best = None
for p in glob.glob("results/traces/*.json"):
    d = json.load(open(p))
    if d.get("architecture") != arch or d.get("agent") != "agent_pev":
        continue
    if any("proposed_keys" in e for e in d.get("elements", [])):
        m = os.path.getmtime(p)
        if best is None or m > best[0]:
            best = (m, p, d)

if best is None:
    print(f"No agent_pev trace with proposed_keys for {arch}.")
    raise SystemExit

_, path, d = best
print("Trace:", os.path.basename(path))

gt = json.load(open(f"benchmark/{arch}.ground_truth.json"))
gt_keys = set()
for t in gt["threats"]:
    tgt = t.get("component_id") or t.get("data_flow_id")
    gt_keys.add(f"{tgt}:{t['category']}")

total_dropped = []
dropped_correct = []
print("\n=== dropped candidates per element ===")
for e in d["elements"]:
    for k in e.get("dropped_keys", []):
        total_dropped.append(k)
        correct = k in gt_keys
        if correct:
            dropped_correct.append(k)
        mark = "CORRECT (in GT, wrongly dropped)" if correct else "(not in GT)"
        print(f"  {e['element_id']:20} dropped {k:42} {mark}")

print()
print(f"Verify dropped {len(total_dropped)} candidate(s) total.")
print(f"Of those, correct (were in ground truth): {len(dropped_correct)}")
for k in dropped_correct:
    print("  ->", k)
