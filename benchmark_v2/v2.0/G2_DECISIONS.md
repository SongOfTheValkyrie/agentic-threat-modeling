# Gate G2: decisions

Status: **G2 passed on 2026-11-03.** The owner reviewed the lists and decided all
open points (A to G below). The cause lists are frozen as GT V2.0, with checksums
in `MANIFEST.json`. No capture run has started and no model output for these
architectures has been viewed. The detail is in `REVIEW.md` (generated from the
JSON files in this directory). The decisions are recorded in `V2_SPEC.md`
(D17 to D23). Changes to a frozen list are made as a new version (V2.1).

## What was done and what limits it

- The two cause lists were derived from `benchmark/multi_tenant_saas.json` and
  `benchmark/cloud_ingest_pipeline.json` only. No V1 ground truth, no results,
  no traces, no predictions, and no baseline output were opened for this draft.
- The drafting assistant wrote those architecture files and the V1 ground truth
  earlier and had seen V1 results, so exposure cannot be excluded. The owner's
  review is the independence check. Because the same assistant designed the
  architectures to carry intended weaknesses, evidence-based reading largely
  reproduces design intent.
- Every cited value is checked by a test against the architecture file. The test
  confirms that evidence exists, not that a cause is right.
- **Limitation of the cause evaluation:** no confirmed cause is hard and every
  confirmed cause is direct. Complex attack chains across several elements are
  covered only to a limited extent. Hard-class results cannot be reported for
  these two architectures.

## What the drafts contain

17 confirmed causes: 13 easy, 4 medium, 0 hard; all `direct`.

| | multi_tenant_saas | cloud_ingest_pipeline | pooled |
|---|---|---|---|
| Threat Cause Recall denominator (STRIDE-mapped causes) | 6 | 9 | **15** |
| Security Control Gap Recall denominator (all causes) | 6 | 11 | **17** |
| Control gaps without STRIDE mapping | none | CIP-04, CIP-11 | 2 |
| (target, STRIDE) entries / distinct keys | 11 / 9 | 9 / 8 | 20 / 17 |
| Boundary cases / unsupported / chain candidates | 3 / 9 / 2 | 1 / 8 / 2 | 4 / 17 / 4 |

## Decisions (owner)

| # | Decision | Where it shows |
|---|---|---|
| 1 | Empty hard class accepted; no artificial hard causes; limitation documented. | `limitations`, `REVIEW.md`, spec D22 and section 5 |
| 2 | P1 confirmed: exposure alone is not evidence. Boundary cases stay outside the confirmed ground truth and are reviewed when predicted. | `boundary_cases`, spec D22 |
| 3 | `MTS-04` stays one cause; the two flags are not counted separately. | MTS-04 notes |
| 4 | `CIP-04`: lost recoverability, not an unauthorized write. | CIP-04 |
| 5 | `CIP-07`: missing IMDSv2 enforcement; configuration and hypothetical credential theft separated. | CIP-07 |
| A | Two cause recalls (below). CIP-04 and CIP-11 stay as documented security control gaps, outside Threat Cause Recall. The primary scoring unit stays the cause. The "STRIDE score" in earlier discussion meant the secondary (target, STRIDE) metric. | `recall_sets`, spec D17, D18, section 7.4 |
| B | `CIP-06` and `MTS-06` are handled the same way: overprivileged role models, EoP as a coarse mapping, no escalation path claimed as established. | `stride_mapping_note` on both, spec D19 |
| C | `CIP-05`, `CIP-09`, `CIP-10` stay repudiation. `CIP-11` is a detection gap outside the STRIDE score. | notes, spec D20 |
| D | No `required` flag per category. A correctly identified root cause counts once, whatever STRIDE impacts a prediction names. STRIDE classification quality is evaluated separately. | `category_semantics`, spec D21, section 7.4 |
| E | `CIP-04` stays easy. | CIP-04 difficulty |
| F | Granularity splits, exclusion of cause chains, and scope rules stay as drafted. The chains are preserved for a separate later analysis. | `chain_policy`, spec D22, section 11 |
| G | Control-gap claims: (1) with a valid mapping they are `mapped` findings in cause precision; (2) in the adjusted V2 (target, STRIDE) metric, predictions mapped to CIP-04 or CIP-11 are excluded completely (neither TP nor FP) and their number is reported; (3) unmatched and unsupported predictions are never excluded wholesale; (4) the V1 key score is reported unchanged next to it, and the adjusted score is a different metric. | spec D23, sections 7.2, 7.4, 8 |

### The two recall metrics

- **Threat Cause Recall** = found STRIDE-mapped causes / 15 (6 and 9 per
  architecture).
- **Security Control Gap Recall** = all found causes / 17 (6 and 11 per
  architecture). It contains every cause of the first metric plus CIP-04 and
  CIP-11.
- Both are read from one set of labels (one label per stored prediction, spec
  section 7.1). Each cause counts once per run. The prediction's stored STRIDE
  category does not enter either recall.
- The two (target, STRIDE) scores are separate metrics on the same predictions:
  the unchanged *V1 key score*, and the *adjusted V2 coarse score* with CIP-04 and
  CIP-11 predictions excluded and counted.
- Chain candidates are not valid labels and are in neither denominator.

## Consistency check before the freeze

`python scripts/check_cause_consistency.py` prints the report below and exits 1
on a failure. `tests/test_cause_consistency.py` (25 tests) runs the same checks
and mutation tests: a wrong declared denominator, a chain or boundary ref in a
denominator, a missing `recall_sets`, a STRIDE category on a control gap, three
categories, a duplicate, an unknown name, and a threat cause without a category
are all detected.

**1. Do the denominators match?** Yes. The `recall_sets` declared in each file
equal the sets derived from the cause fields (15 and 17 pooled; 6/6 and 9/11 per
architecture). Threat causes are a subset of all causes. The difference is
exactly the causes without STRIDE categories (CIP-04, CIP-11). No boundary,
unsupported or chain ref is in either set. Refs are unique across both files.

**2. Are the STRIDE mappings unambiguous?** The rules hold: a cause has zero
categories if and only if it is a control gap, at most two, no duplicates, only
valid names. The following overlaps remain and are by design of the coarse key.
They are reported here so they are known, not hidden:

- Three keys are shared by two causes each: `api:elevation_of_privilege` and
  `api:information_disclosure` (MTS-01 and MTS-02), and
  `raw_bucket:information_disclosure` (CIP-02 and CIP-03). The coarse metric
  cannot tell these causes apart; the cause label does.
- Three excluded entries share a key with a confirmed cause: unsupported
  `CIP-U4` (warehouse publicly reachable) with `CIP-08`, `MTS-U2` (database not
  encrypted) with `MTS-04`, `MTS-U7` (storage publicly accessible) with `MTS-05`.
  A prediction with that key may be a confirmed cause or an excluded claim. Only
  the cause label decides.
- `CIP-11` has no key of its own, but its target carries `CIP-10`'s key
  `monitoring:repudiation`. A prediction about alerting that is labelled
  repudiation hits that key by V1 rules while the cause found is CIP-11. This is
  the intended behavior of a key metric on shared targets.
- The coarse metric has 17 distinct keys (20 entries), a third denominator
  that is different from 15 and 17. It is reported as its own metric.

**3. Can both metrics be computed from the same stored predictions?** Yes, with
the existing prediction files. The reference functions in
`scripts/check_cause_consistency.py` take a stored file and one label per
prediction, check architecture and label count, and return both recalls from
that one label set. Tests build stored files through `write_predictions` and check
the numbers (for example labels CIP-01, CIP-04, CIP-11, CIP-07, CIP-10 give
Threat Cause Recall 3/9 and Security Control Gap Recall 5/11), that the first
numerator is contained in the second, that a repeated cause counts once, and
that labels outside the architecture, chain refs, a wrong architecture and a
wrong label count are rejected. Annotation labels are keyed by a stable
prediction identifier (`src/evaluation/prediction_ids.py`) and joined to the file
by it. The identifier is a one-way hash of run identity, position and content,
so it does not depend on the model's threat `id`, on the order of an export, or
on a randomization, and it does not show the approach.

**4. Control-gap claims (decision G), as tested.** The case from the review: a
prediction on `monitoring` that names repudiation and is labelled CIP-11. In the
V1 key score it hits the key `monitoring:repudiation` (CIP-10's key) as a true
positive. In the adjusted V2 coarse score it is excluded: it is neither TP nor FP,
the excluded count is 1, and CIP-10's key is **not** credited by it (it stays a
false negative unless a prediction labelled CIP-10 or another non-gap cause
carries that key). On the cause level it finds CIP-11 only. A CIP-04 prediction
naming tampering on `raw_bucket` is a false positive in the V1 key score and
excluded in the adjusted one. `none`, `unsure` and `new_cause_proposed`
predictions stay in the adjusted score and in the precision claims.

## Notes on the freeze

- Frozen files: `multi_tenant_saas.causes.json` and
  `cloud_ingest_pipeline.causes.json`, with status FROZEN and GT V2.0. The
  checksums of both lists and of both architecture files are in `MANIFEST.json`;
  `python scripts/freeze_cause_lists.py --check` and a test verify them.
- The spec change log had an entry dated 2026-09-23 by mistake. All changes were
  made on 2026-11-03 (machine date); the entry is corrected.
- Cause ids changed during the review: `MTS-05` is now
  `object_store.no_per_tenant_prefix_enforcement`, and `CIP-07` is now
  `processing_cluster.imdsv2_not_enforced`. Nothing had been matched against the
  ids.
- The annotation export (file format, randomization) is not built yet. The stable
  identifiers it needs are in place.

## Next

Preflight report for the isolated Ollama smoke test, then the smoke test after the
owner's separate approval, then the capture run on a clean, committed tree. The
reference annotation of the captured predictions is blinded and randomized.
