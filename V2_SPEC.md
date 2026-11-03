# V2 Evaluation Specification

**Status: DRAFT.** This becomes FROZEN on the owner's sign-off, before any V2
data (cause lists, predictions, annotations) is collected. After that, changes
are recorded as a new version (V2.1, ...), never edited in place.

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

Items marked *(proposed)* would be defaults that have not been explicitly
decided. This draft contains none.

## 3. Ground-truth schema (V2)

One entry per `(target, category)`. Entries that share `root_cause.id` describe
the same cause under different STRIDE scenarios.

```json
{
  "id": "mts_doc_ownership_info",
  "target": "document_service",
  "category": "information_disclosure",
  "root_cause": {
    "id": "document_service.no_ownership_check",
    "text": "Requested objects are not checked against the caller's tenant."
  },
  "evidence": [
    {"path": "components.document_service.config.object_ownership_check",
     "observed": false}
  ],
  "evidence_type": "direct",
  "difficulty": {"level": "medium", "rationale": "..."}
}
```

Rules:

- Causes are drafted **from the architecture JSON only**, blind to model
  outputs and to deterministic-baseline output.
- Cause ID convention: `<element>.<short_snake_case_weakness>`.
- Granularity: one cause is one missing or misconfigured control, or one design
  flaw, at one element or relationship. Two entries differ only by category when
  the same gap yields different threat scenarios.
- Entries without usable evidence are not scored. They go into a separate
  `unsupported` list with a recorded reason.
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
- Open: the reliability of this rubric has not been validated (section 12).

## 6. Prediction logging

Per run, stored separately from `results.jsonl` and treated as immutable:

- Each predicted threat: `target`, `category`, `description`, `mitigation`.
- Run metadata: approach, model, architecture, `run_index`, code commit.
- For PEV traces: the full candidate threats before and after Verify. Today only
  counts and keys are stored.

Logging must not change behavior (gate G1). The file layout is decided in the
implementation step.

## 7. Matching and scoring

### 7.1 Reference annotation

Each prediction receives exactly one label: a **cause ID**, `none`,
`new_cause_proposed` (with a short text), or `unsure`. Annotation order is
randomized and the approach name is hidden.

### 7.2 Outcomes per prediction

| Case | Coarse `(target, category)` metric | Cause level |
|---|---|---|
| Target, category, and cause match | TP | found |
| Cause matches, category or target differs | FP and FN (as in V1) | found, flagged "mislabeled" |
| Key matches, cause differs or is missing | TP | not found |
| `new_cause_proposed` | FP | `pending_review` (section 8) |
| `none` | FP | `unsupported` |
| `unsure` | by key | `pending_review` until resolved |

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

- **Cause recall** = found ground-truth causes / ground-truth causes, overall and
  per difficulty level. It is defined against the **frozen ground-truth
  version** and is always reported with that version label (for example
  "GT V2.0"). Findings confirmed as `valid_additional` do not change it. If
  such findings are promoted into the ground truth (V2.1), the denominator and
  the set of found causes change. Recall values from different ground-truth
  versions are then not comparable, and all approaches are re-scored.
- **Cause precision**: bounds only until review is complete (section 8).
- **Coarse metrics**: V1 definitions, unchanged, on the same predictions.
- **Category agreement** among cause-matched predictions, target agreement, and
  the count of "found but mislabeled".

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

## 11. Out of scope

- Agent architectures, prompts, model, knowledge base, retriever, benchmark
  architecture JSON files.
- **Knowledge base and architectures were developed together**, which may favor
  RAG. This is parked, not forgotten, and matters for the holdout evaluation.
- The holdout set (`cicd_pipeline`, `mobile_banking`) stays untouched until the
  final evaluation. Its ground truth must be rewritten under these V2 rules
  before use.
- Temperature above 0 and multiple seeds.

## 12. Open items

- Reliability of the difficulty rubric is not validated.
- A prediction that describes more than one cause at once: single-label
  annotation (section 7.1) forces a choice. To be examined in the sample.
- Whether `none` predictions with near-identical text within a run should be
  merged (section 7.3 currently counts each as its own claim).
- File layout for V2 ground truth and prediction logs.
- Choice of grader model(s) for the optional grader test.

## Change log

- 2026-11-03: Draft created from the owner's decisions.
- 2026-11-03: Incorporated owner decisions D12 to D16 (repeat annotation of at
  least 20 items at least 24 hours later; κ over non-`unsure` items with
  exclusions reported separately; Phase B kept as a diagnostic comparison if
  Phase A fails; duplicate handling within a run; cause recall tied to the
  frozen ground-truth version). Removed all `(proposed)` markers.
