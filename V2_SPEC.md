# V2 Evaluation Specification

**Status: G2 passed on 2026-11-03.** The cause lists are frozen as **GT V2.0**
(section 13). The rest of this specification (annotation protocol, scorer,
validation sample) is still to be built and tested; open points are in section 12.
Frozen artifacts are never edited in place. A change is recorded as a new version
(V2.1, ...).

V1 is preserved unchanged under the git tag `v1-benchmark` (manifest and
results archive in `frozen/v1/`).

## 1. Purpose and scope

V1 matches a prediction to the ground truth by `(target, category)` only. Known
consequences (see `frozen/v1/MANIFEST.md`, "Known limitations"):

1. The stated cause is never compared, so a right key with a wrong cause counts
   as a true positive, and a right finding with a different STRIDE label counts
   as an error.
2. Some ground-truth entries are hypothetical rather than evidenced by the
   architecture, and some evidence and difficulty labels are inconsistent.
3. The `easy` class is defined as "what the deterministic baseline finds", which
   makes the baseline's per-difficulty results true by construction.
4. No stored run contains threat descriptions, so V1 runs cannot be re-scored.

**V2 changes the evaluation basis only:** ground truth, matching, difficulty
labels, review process, and logging. It does **not** change agent architectures,
prompts, model, knowledge base, retriever, or the architecture JSON files.

## 2. Decisions

| # | Decision | Source |
|---|---|---|
| D1 | The scoring unit is the **root cause**. | owner |
| D2 | `(target, category)` and STRIDE categories are kept as a secondary, coarse metric. | owner |
| D3 | Scope: evidence-based. Reasoned risk scenarios count if derivable from concrete properties or relationships of the architecture. Unsupported generic speculation is not a confirmed finding. | owner |
| D4 | Plausible predictions not in the ground truth get a separate **review status**. They are not silently dropped from precision. | owner |
| D5 | The reference mapping is made by the owner. An LLM grader is validated against it afterwards and is never used as ground truth. | owner |
| D6 | Difficulty is defined by required reasoning effort, independent of the deterministic baseline. | owner |
| D7 | Full threat descriptions are stored from now on. | owner |
| D8 | The same stored predictions are scored under both V1 and V2 rules, to isolate the effect of the evaluation method. | owner |
| D9 | Sample order: `multi_tenant_saas` first, then `cloud_ingest_pipeline`. | owner |
| D10 | Until all reviews are complete, precision is reported only as a lower and an upper bound. The final V2 score is computed after review. | owner |
| D11 | Logging changes to `structured.py` are allowed. V1 stays available through the tag. | owner |
| D12 | The repeat annotation covers at least 20 predictions per phase, at least 24 hours after the first pass. | owner |
| D13 | The main κ is computed only over items where both annotations are not `unsure`. Excluded items, their share, and the `unsure` cases are reported separately. | owner |
| D14 | If Phase A misses the criteria, Phase B is not dropped. Failures are analyzed first, and Phase B may serve as a diagnostic comparison without the method counting as validated. | owner |
| D15 | Within one run, the same cause counts once. Original predictions and their assignment to approaches are preserved. Different causes with the same target and category stay separate. | owner |
| D16 | Cause recall refers to the frozen ground-truth version and can change if later confirmed additional findings are promoted into the ground truth. | owner |
| D17 | Two cause recalls are reported. **Threat Cause Recall** is taken over the causes with a STRIDE mapping (`risk_class: stride_threat`; 15 in the current drafts). **Security Control Gap Recall** is taken over all causes (17). The scoring unit stays the cause. | owner, G2 |
| D18 | Documented security control gaps without STRIDE mapping (`recoverability`: CIP-04, `detection_gap`: CIP-11) stay in the cause list, count in Security Control Gap Recall only, and are outside Threat Cause Recall and outside the `(target, category)` metric. | owner, G2 |
| D19 | Overprivileged role models (CIP-06, MTS-06) are handled the same way: elevation of privilege is a coarse STRIDE mapping, and no escalation path is claimed as established. | owner, G2 |
| D20 | The logging causes CIP-05, CIP-09 and CIP-10 stay `repudiation`. CIP-11 (alerting) is a detection gap outside the STRIDE mapping. | owner, G2 |
| D21 | No per-category `required` flag. A correctly identified root cause counts exactly once in cause recall, whatever STRIDE impacts the prediction names. The quality of the STRIDE classification is evaluated separately (section 7.4). | owner, G2 |
| D22 | CIP-04 difficulty is `easy`. Granularity splits (MTS-01/MTS-02, CIP-02/CIP-03, CIP-10/CIP-11), the exclusion of cause chains from the confirmed list, and the scope rules stay as drafted. The chains are preserved for a separate later analysis. The empty `hard` class is accepted and documented as a limitation. Policy P1 (exposure alone is not evidence) is confirmed. MTS-04 stays one cause. | owner, G2 |
| D23 | Control-gap claims (CIP-04, CIP-11). (1) With a valid mapping they count as `mapped` findings in cause precision. (2) In the adjusted V2 `(target, category)` metric, predictions that the annotation maps to CIP-04 or CIP-11 are excluded completely, neither TP nor FP, and the number of excluded predictions is reported. (3) Unmatched and unsupported predictions are never excluded wholesale; they stay in the precision assessment. (4) The original V1 key score is reported unchanged next to it. The adjusted V2 coarse score is a different metric and is never presented as identical to V1. | owner, G2 |

Items marked *(proposed)* would be defaults that have not been explicitly
decided. This version contains none.

## 3. Ground-truth schema (V2)

One entry per **cause**. A cause lists zero to two STRIDE categories, each with a
short scenario. The categories are the plausible classifications of the cause,
none is required (D21). Causes without a STRIDE mapping carry
`risk_class: recoverability` or `detection_gap` and an empty category list
(D18). The drafts live in `benchmark_v2/draft/<architecture>.causes.json`; an
abbreviated example:

```json
{
  "ref": "MTS-03",
  "cause_id": "document_service.no_object_ownership_check",
  "target": "document_service",
  "root_cause": "The document service does not verify that a requested object belongs to the requesting caller or tenant.",
  "risk_class": "stride_threat",
  "stride_scored": true,
  "evidence": [
    {"path": "components.document_service.config.object_ownership_check",
     "observed": false, "role": "primary"}
  ],
  "evidence_type": "direct",
  "established": "The ownership check is disabled.",
  "hypothetical": "That a caller supplies another party's object identifier ...",
  "difficulty": {"level": "easy", "rationale": "..."},
  "categories": [
    {"category": "information_disclosure", "scenario": "..."},
    {"category": "tampering", "scenario": "..."}
  ]
}
```

Per cause, `established` is what the architecture states and `hypothetical` is
what is only a scenario on top of it. Each file also holds `recall_sets` (the
two denominators, which a test derives from the cause fields), `limitations`,
`boundary_cases`, `unsupported` entries, and `candidate_chain_causes`.

Rules:

- Causes are drafted **from the architecture JSON only**, blind to model
  outputs and to deterministic-baseline output.
- Cause ID convention: `<element>.<short_snake_case_weakness>`.
- Granularity: one cause is one missing or misconfigured control, or one design
  flaw, at one element or relationship. One cause can carry two STRIDE
  categories when the same gap yields different threat scenarios.
- Entries without usable evidence are not scored. They go into a separate
  `unsupported` list with a recorded reason. Exposure-only scenarios (policy P1:
  internet exposure alone is not evidence of a weakness) go into
  `boundary_cases`: not required for recall, `pending_review` if predicted.
- Cross-element chains that overlap the atomic causes are listed as
  `candidate_chain_causes`. They are preserved for a separate later analysis and
  are not part of the confirmed list or of either recall (D22).
- The cause list of an architecture is frozen by checksum before any prediction
  for that architecture is viewed (gate G2).

## 4. Evidence types

| Type | Meaning | Example |
|---|---|---|
| `direct` | The weakness is stated in an attribute or config value. | `row_level_security: false` |
| `derived` | It follows from combining stated facts or relationships. | A cache shared by two services without authentication |
| `scenario` | A reasoned risk from a concrete property, with no stated weakness. The inference must be written down. | A flow to an `external_service` crosses a trust boundary |
| none | Generic speculation. Goes to `unsupported`. | "Database may lack audit logging" when nothing is stated about logging |

The absence of a statement about a control is not evidence that the control is
missing.

## 5. Difficulty rubric

| Level | Required reasoning |
|---|---|
| easy | One stated fact leads directly to the weakness. |
| medium | Combining two or more stated facts, or applying basic, widely known security knowledge to one stated property. |
| hard | Multi-step inference across components, permissions, or trust boundaries; the weakness is not stated at any single element. |

- Assigned per cause, blind to model results and to baseline output.
- A one-sentence rationale is required and is frozen with the cause list.
- The baseline's per-class performance is reported afterwards as an empirical
  result and is never used to assign labels.
- Operationalization applied in the G2 drafts. *easy*: the stated value names a
  missing or disabled control whose relevance is general knowledge. *medium*:
  the value names a mechanism or specialist control whose weakness must be
  known, or at least two stated facts have to be combined. *hard*: facts from at
  least two different elements are combined and the weakness is stated at none
  of them. Under this reading the current drafts have **no hard cause** (13 easy,
  4 medium), because every weakness is stated as a setting on one element. The
  empty class is accepted (D22). It means the cause evaluation covers complex
  cross-element attack chains only to a limited extent; hard-class results are
  not reported for these two architectures.
- Open: the reliability of this rubric has not been validated (section 12).

## 6. Prediction logging

Per run, stored separately from `results.jsonl` and treated as immutable:

- Each predicted threat: `target`, `category`, `description`, `mitigation`.
- Run metadata: approach, model, architecture, `run_index`, code commit.
- For PEV traces: the full candidate threats before and after Verify. Today only
  counts and keys are stored.

Logging must not change behavior (gate G1). The layout is implemented in
`src/evaluation/predictions.py`.

**Prediction identifiers.** Annotation needs identifiers that do not depend on
the threat `id` assigned by the model, on the order of the review file, or on a
randomization of it, and that do not reveal the approach. `prediction_uid` in
`src/evaluation/prediction_ids.py` hashes the identity of the run (architecture,
approach, model, run index, file timestamp), the position in the stored file, and
the content (target, category, description, mitigation). It is deterministic,
opaque (`pred-` plus 16 hex characters), and recomputable from the immutable
prediction file. Labels are keyed by this identifier and joined back to the file
by it. Identifiers must be unique across the files of one export.

## 7. Matching and scoring

### 7.1 Reference annotation

Each prediction receives exactly one label: a **cause ID**, `none`,
`new_cause_proposed` (with a short text), or `unsure`. Annotation order is
randomized and the approach name is hidden. Labels are keyed by the stable
prediction identifier (section 6).

### 7.2 Outcomes per prediction

| Case | Coarse `(target, category)` metric | Cause level |
|---|---|---|
| Target, category, and cause match | TP | found |
| Cause matches, category or target differs | FP and FN (as in V1) | found, flagged "mislabeled" |
| Key matches, cause differs or is missing | TP | not found |
| `new_cause_proposed` | FP | `pending_review` (section 8) |
| `none` | FP | `unsupported` |
| `unsure` | by key | `pending_review` until resolved |

A prediction labelled with a control-gap cause (CIP-04, CIP-11) is found at the
cause level and is a `mapped` claim for precision. Its cause has no ground-truth
key, so in the adjusted V2 coarse metric it is excluded completely, neither TP
nor FP (D23). The V1 key score on the same stored predictions stays purely
key-based and is not affected. A CIP-11 prediction that names repudiation on
`monitoring` therefore hits CIP-10's key in the V1 key score, but credits
nothing and costs nothing in the adjusted V2 coarse score.

### 7.3 Claims and duplicates

Within one run (one approach on one architecture and `run_index`), predictions
that map to the same cause are collapsed into one **claim**, so repetition
earns no extra credit and removing duplicates costs nothing.

- The original predictions and their assignment to approaches and runs are
  never modified or removed. Claims are a view derived at scoring time.
- Collapsing happens only within a run, never across approaches. Each approach
  is scored on its own predictions.
- Different causes with the same target and the same STRIDE category stay
  separate claims.
- `new_cause_proposed` predictions that the annotator assigns to the same
  candidate cause collapse like mapped ones.
- Predictions labelled `none` or `unsure` are individual claims.

### 7.4 Metrics

- **Threat Cause Recall** = found causes with a STRIDE mapping / causes with a
  STRIDE mapping (15 in the current drafts: 6 for `multi_tenant_saas`, 9 for
  `cloud_ingest_pipeline`). **Security Control Gap Recall** = all found causes /
  all causes (17: 6 and 11). Both are computed from the same stored predictions
  and the same one-label-per-prediction annotation (section 7.1): the set of
  found causes is read once, and each recall is a different denominator over it,
  so Security Control Gap Recall counts every cause found in Threat Cause Recall
  plus the control gaps. Both are reported overall, per architecture, and per
  difficulty level, and each cause counts once per run (section 7.3). Pooled
  values over the two architectures are sums of counts, not averages of ratios.
  Both are defined against the **frozen ground-truth
  version** and are always reported with that version label (for example
  "GT V2.0"). Findings confirmed as `valid_additional` do not change it. If
  such findings are promoted into the ground truth (V2.1), the denominator and
  the set of found causes change. Recall values from different ground-truth
  versions are then not comparable, and all approaches are re-scored.
- **Cause precision**: bounds only until review is complete (section 8).
- **Coarse metrics**, two different ones on the same stored predictions, always
  labelled:
  - *V1 key score*: the unchanged V1 evaluator and V1 ground truth on all
    predictions.
  - *Adjusted V2 coarse score*: the same evaluator function on the V2
    `(target, category)` keys of the STRIDE-mapped causes (17 distinct keys), after
    excluding the predictions the annotation mapped to CIP-04 or CIP-11 (D23).
    Predictions labelled `none`, `unsure`, `new_cause_proposed`, or any other
    cause stay in. The number of excluded predictions is reported next to the
    score. This score is not the V1 score and is not described as such.
- **Category agreement** among cause-matched predictions, target agreement, and
  the count of "found but mislabeled". This is the separate evaluation of the
  STRIDE classification quality (D21); it has no effect on cause recall.

### 7.5 Dual scoring

A scorer reads stored prediction files and produces results under
`--scheme v1` and `--scheme v2`. The V1 evaluator code is not modified. The
report shows both schemes side by side, including rank changes of the
approaches.

## 8. Review status and precision bounds

Statuses of a claim: `mapped` (to a ground-truth cause), `pending_review`,
`valid_additional`, `unsupported`.

- `pending_review` becomes `valid_additional` or `unsupported` after the owner
  reviews it against the architecture evidence. The decision, rationale, and
  date are recorded.
- Decisions are keyed by `(architecture, candidate cause)`, so the same finding
  reported by several approaches is reviewed once.
- `valid_additional` counts as a true positive for precision. The recall
  denominator does not change. Promoting a finding into the ground truth happens
  only in a new version (V2.1) and requires re-scoring all approaches.

Let `G` = claims mapped to ground-truth causes, `V` = `valid_additional`,
`P` = `pending_review`, `U` = `unsupported`.

- **Lower bound** = (G + V) / (G + V + P + U)
- **Upper bound** = (G + V + P) / (G + V + P + U)
- F1 bounds follow from these, because F1 increases monotonically with
  precision at fixed recall.

Claims mapped to a control-gap cause belong to `G` (D23). One precision
definition is used; there is no threat-only precision. Unmatched (`none`) and
unsupported claims stay in the denominator; they are never excluded wholesale.

No single precision or F1 value is published while any `pending_review` claim
exists in the evaluated set. Cause recall does not depend on review.

## 9. Validation of the mapping (sample)

**Phases.** A: `multi_tenant_saas`. B: `cloud_ingest_pipeline`. Per phase: RAG,
PEV, and NoPlan, one run each, `temperature=0`. A prior estimate of 40 to 60
predictions was too low; expect roughly 60 per phase.

**Procedure.**

1. The owner annotates all predictions (blinded, randomized).
2. After at least 24 hours, the owner re-annotates at least 20 predictions per
   phase (a fixed minimum instead of 20 %, which would give only about 12 items
   and an unstable κ).
3. Reference labels are frozen.
4. Only then is an LLM grader run on the same inputs and compared with the
   reference.

**Reported for the repeat annotation and for the grader:**

- Cohen's κ for the main evaluation, computed **only over items where both
  annotations are not `unsure`**.
- The simple agreement rate over the same items.
- The list of disagreement cases.
- Reported separately: the items excluded from κ (count), their share of all
  items, and the list of `unsure` cases with the pass in which each occurred.
- The number of items behind every κ, because κ is unstable on small samples.

**Thresholds (provisional):**

| Criterion | Threshold |
|---|---|
| Repeat annotation, κ | ≥ 0.8 |
| Share of `unsure` | ≤ 10 % |
| LLM grader vs. reference, κ (optional) | ≥ 0.7 |

**Pass rules.** Phase A is evaluated first.

- If Phase A meets the first two criteria, Phase B follows as a generalization
  check.
- If Phase A misses a criterion, Phase B is **not** dropped. The failures are
  analyzed first: which causes or categories are confused, and whether the
  granularity of the cause list or the annotation procedure is at fault. The
  analysis is documented. Phase B may then run as a **diagnostic comparison**.
  Its results help to understand the failure, and the method is **not** treated
  as validated on the basis of such a run.
- Gate G3 passes only when both phases meet the first two criteria, evaluated
  after any cause-list revision (V2.1) and re-annotation that the analysis
  called for.
- The grader criterion does not block the evaluator. It only decides whether
  the grader may serve as a secondary check.
- If the cause granularity fails (many `unsure` or `none`), the cause list is
  revised (V2.1) and the affected predictions are re-annotated before the
  evaluator is built.

## 10. Gates

| Gate | Condition |
|---|---|
| **G1** | Offline tests with fixed model responses. A scripted LLM replaces the model for RAG, the free agent, PEV, and the ablations. Golden outputs (returned threats and trace keys) are generated from the tagged V1 code **before** the logging change and stored as test fixtures. The logging-enabled code must reproduce them exactly, and the logged predictions must equal the returned threats field by field. Independent live Ollama runs are **not** required to match each other: `temperature=0` does not guarantee bit-identical output, and the earlier ±0.00 variance is an observation, not a guarantee. Drift between repeated live runs may be recorded, without gating. |
| **G2** | The cause list, evidence, and difficulty labels of an architecture are reviewed and approved by the owner and frozen by checksum before any prediction is viewed. |
| **G3** | Sample criteria in section 9 are met. |
| **G4** | The unchanged V1 evaluator scores stored predictions reproducibly: (a) `evaluator.py` matches the checksum in the V1 manifest, (b) scoring the same prediction file twice gives identical results, (c) for archived rows that contain key fields, recomputing precision, recall, and F1 from the recorded key sets reproduces the recorded values. Checked read-only: 212 of 212 such rows reproduce; 64 older rows lack the fields. New live runs are **not** required to reproduce historical scores. |

**G2 status: passed on 2026-11-03.** The owner reviewed the cause lists and
decided the open points (D17 to D23). The lists are frozen by checksum (section 13).
The consistency check `scripts/check_cause_consistency.py` (denominators, STRIDE
mapping rules, both recalls and both coarse scores from one label set) is part of
the test suite. No model output for these architectures had been viewed at the
freeze.

## 11. Out of scope

- Agent architectures, prompts, model, knowledge base, retriever, benchmark
  architecture JSON files.
- **Knowledge base and architectures were developed together**, which may favor
  RAG. This is parked, not forgotten, and matters for the holdout evaluation.
- The holdout set (`cicd_pipeline`, `mobile_banking`) stays untouched until the
  final evaluation. Its ground truth must be rewritten under these V2 rules
  before use.
- Temperature above 0 and multiple seeds.
- Cross-element chain causes (`candidate_chain_causes`) are not evaluated in V2.0.
  They are kept for a later, separate analysis (D22).

## 12. Open items

- Reliability of the difficulty rubric is not validated.
- A prediction that describes more than one cause at once: single-label
  annotation (section 7.1) forces a choice. To be examined in the sample.
- Whether `none` predictions with near-identical text within a run should be
  merged (section 7.3 currently counts each as its own claim).
- Annotation export (file format, randomization seed handling) and the scorer.
  The stable identifiers (section 6) are implemented; the export is not.
- Because the coarse key `(target, category)` is shared by several causes in
  places (for example `api:elevation_of_privilege` by MTS-01 and MTS-02) and
  some excluded entries share a key with a confirmed cause, the coarse metric
  cannot tell these apart. The cause label does.
- Choice of grader model(s) for the optional grader test.

## 13. Frozen artifacts (GT V2.0)

| Artifact | Location |
|---|---|
| Cause lists | `benchmark_v2/v2.0/multi_tenant_saas.causes.json`, `benchmark_v2/v2.0/cloud_ingest_pipeline.causes.json` |
| Checksums (lists and architecture files) | `benchmark_v2/v2.0/MANIFEST.json` |
| Decisions of the review | `benchmark_v2/v2.0/G2_DECISIONS.md` |
| Review sheet (generated) | `benchmark_v2/v2.0/REVIEW.md` |

Verify with `python scripts/freeze_cause_lists.py --check`; a test does the same.
Recall values are reported with the label "GT V2.0". Any change to a list, to an
architecture file it is derived from, or to the manifest means a new version
(V2.1) and re-scoring of all approaches (D16).

## Change log

- 2026-11-03: Draft created from the owner's decisions.
- 2026-11-03: Incorporated owner decisions D12 to D16 (repeat annotation of at
  least 20 items at least 24 hours later; κ over non-`unsure` items with
  exclusions reported separately; Phase B kept as a diagnostic comparison if
  Phase A fails; duplicate handling within a run; cause recall tied to the
  frozen ground-truth version). Removed all `(proposed)` markers.
- 2026-11-03: G2 review decisions recorded (D17 to D22). Two cause recalls
  (Threat Cause Recall over the 15 STRIDE-mapped causes, Security Control Gap
  Recall over all 17), control gaps outside the STRIDE metric, no per-category
  required flag, chains preserved for a separate analysis, empty `hard` class
  documented. Section 3 now describes the cause-based format.
- 2026-11-03: G2 passed. D23 finalized (control-gap claims in precision and in
  the adjusted V2 coarse score, V1 key score reported unchanged). Stable
  prediction identifiers added (section 6). Cause lists frozen as GT V2.0 with
  checksums (section 13). An earlier entry of this log was dated 2026-09-23 by
  mistake; the changes were made on 2026-11-03.
