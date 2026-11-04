# Claim-level annotation, two precisions, cause recall bounds, κ

Revision 3, written 2026-11-03. **Approved by the owner** (P1 to P8, Q1 to Q4, R-a to R-e) and
recorded and implemented on 2026-11-04 as `V2_SPEC.md` D27 to D32. This is the normative definition. It was written as a
proposal; where it says "proposed", read "adopted". Case 10 is the one open item.

Implemented in `src/evaluation/claims.py` (metrics), `src/evaluation/claim_sheet.py` (sheet,
validation, migration) and `scripts/claim_annotation.py` (tooling). The frozen cause lists (GT V2.0),
the stored predictions, the V1 evaluator, agents and prompts are not touched.

## 0. Decisions and what changed since revision 2

| # | Question | State |
|---|---|---|
| P1 | Claim level; claim-based precision documented as its own metric | approved |
| P2 | Precision definitions | **revised**: two metrics with two names (sections 4 to 6) |
| P3 | `unsure` is pending; precision and recall bounds | accepted |
| P4 | κ coding | **revised** (section 10) |
| P5 | Control-gap exclusion for the adjusted key score | **revised** to claim level, before keys are formed (section 8) |
| P6 | Mechanical reasoning requirement | accepted, extended by a standard reason code (section 12) |
| P7 | Unsupported claims are not deduplicated | accepted |
| P8 | Stratified, seeded repeat sample, at least 20 items, at least 24 hours, without the twelve development cases | accepted |
| Q1 | `plausible_causes` | accepted, with a justification rule (section 12) |
| Q2 | Maximum matching for the recall upper bound | accepted |
| Q3 | Absorption | **narrowed**: for recall only; unsure claims stay in both precisions (sections 5, 7) |
| Q4 | Reasoning for unsupported claims | **not accepted as proposed**: every `unsupported` claim gets a standard `reason_code` (section 12) |
| Case 8 | `unsupported` | decided; as a code it is `generic_claim` |
| Case 10 | `pending_review` until the owner decides | open; checked against the frozen architecture in section 14 |

The central correction: revision 2's "claim precision" collapsed duplicate findings, so it was
not a precision over claims. There are now **two metrics with two names**, and neither is
reported under the other's name.

## 1. The metrics, named apart

| Name | Unit | Deduplicated? | Status |
|---|---|---|---|
| **V1 key score** | unique `(target, category)` keys, V1 ground truth | by key | unchanged |
| **V2 adjusted key score** | unique keys of the threat causes | by key | exclusion made exact, section 8 |
| **Claim Precision (CP)** | individual claims | **no** | new, section 4 |
| **Unique-Finding Precision (UFP)** | deduplicated findings | **yes**, except unsupported claims | new name for the spec's section-8 precision, section 5 |
| **Threat Cause Recall**, **Security Control Gap Recall** | causes | by cause | spec D17, bounds made exact, section 7 |
| Prediction distribution | predictions | no | descriptive, section 9 |
| κ and exact set agreement | predictions, label pairs | no | section 10 |

The V1 "precision" is key-based too: it divides by the number of distinct predicted keys. Neither
CP nor UFP is a key metric.

## 2. Annotation model and notation

Fix an architecture A with the frozen causes C, threat causes T ⊆ C (`risk_class = stride_threat`)
and control gaps Γ = C \ T (CIP-04, CIP-11).

A **run** r is one approach on A with one run index. After annotation every stored prediction x
has a non-empty set of **claims** K(x). Let K_r be the multiset of all claim rows of r and
n = |K_r|. A claim κ has

| Field | Values |
|---|---|
| ℓ(κ) | a cause ref in C, or `VA` (valid_additional), `UN` (unsupported), `PR` (pending_review) |
| u(κ) | 1 if `unsure = yes`, else 0 |
| cand(κ) | optional `candidate_id` |
| Π(κ) | optional set of plausible causes ⊆ C |
| ρ(κ) | 1 if a `rationale` is present, else 0 |
| z(κ) | the `reason_code`, required when ℓ = `UN` |

A prediction in which nothing can be identified has one claim with ℓ = `UN`. The claims of one
prediction are independent statements (R9); one cause ref appears at most once per prediction.

## 3. Effective status

s(κ) ∈ {M, V, P, U}:

- s = P if u(κ) = 1 or ℓ(κ) = `PR`;
- otherwise s = M if ℓ(κ) ∈ C;
- otherwise s = V if ℓ(κ) = `VA`;
- otherwise s = U.

An unclear claim is pending whatever its label. A `UN` claim with `unsure` is pending.

## 4. Claim Precision (CP): on individual claims, no deduplication

Over the claim rows of run r:

g = |{κ : s = M}|, v = |{κ : s = V}|, p = |{κ : s = P}|, u = |{κ : s = U}|, **n = g + v + p + u = |K_r|**.

- **CP⁻ = (g + v) / n**
- **CP⁺ = (g + v + p) / n**

Every claim row is one unit. A cause named by three predictions contributes 3 to g. Repeated
`valid_additional` claims each contribute to v. Control-gap claims with s = M count in g (D23).
Every unclear claim stays in n. If n = 0 the value is undefined, not 0.

The bounds are exact: a pending claim resolves either to a correct claim (numerator + 1, denominator
unchanged) or to `unsupported` (numerator unchanged, denominator unchanged). After review p = 0 and
CP = (g + v′) / (g + v′ + u′).

CP rewards verbosity if a model restates a correct finding in several predictions.

## 5. Unique-Finding Precision (UFP): on deduplicated findings

Claims of run r are collapsed into **findings**. The identity of a claim is

- ("sure-cause", ℓ) if s = M;
- ("pending-cause", ℓ) if s = P and ℓ ∈ C;
- ("cand", cand) if s ∈ {V, P}, ℓ ∉ C and cand is given;
- unique to the claim row otherwise.

Rules:

1. A claim with s = U is its own finding and ignores `candidate_id` (P7).
2. All other claims with the same identity form one finding.
3. **There is no absorption.** A pending claim never merges into a sure finding. The namespaces
   "sure-cause" and "pending-cause" are separate, so an unsure claim for a cause that is sure
   elsewhere in the run stays a visible pending finding (Q3).

Counts: g* = number of distinct sure causes, v* = number of `valid_additional` findings, p* =
number of pending findings, u = number of `unsupported` claims (the same u as in CP),
**n\* = g\* + v\* + p\* + u**.

- **UFP⁻ = (g\* + v\*) / n\***
- **UFP⁺ = (g\* + v\* + p\*) / n\***

The bounds stay valid although a pending finding is a separate unit. A pending finding that
resolves as a duplicate of a sure cause merges away: the numerator stays, the denominator becomes
smaller by at most p\*. The result is still at least the lower bound, and at most the upper bound,
because the sure and valid findings plus the unsupported claims never exceed n\* − p\*. A pending
finding that resolves as a new valid finding moves to the numerator (the upper bound), one that
resolves as unsupported stays in the denominator only (the lower bound). No single value is
published while p\* > 0 (D10).

UFP is the spec's section-8 precision (decisions D15, D10) under its new name. It is
asymmetric by design (P7): a correct finding repeated k times counts once, an unsupported claim
repeated k times counts k times.

## 6. CP and UFP side by side

| | CP | UFP |
|---|---|---|
| Unit | claim row | deduplicated finding (unsupported claims stay individual) |
| Repeated correct claim | counts each time | counts once |
| Repeated unsupported claim | counts each time | counts each time |
| Unsure claim for a cause that is sure elsewhere | pending claim, in n | pending finding, in n\* |
| Equal when | the run has no repeated correct or pending claim | |

Both are always reported, each under its name. Proposed reading: **UFP is the headline precision**
(it matches the recall's deduplication and D15), and **CP is reported next to it** as the
repetition-sensitive view. The choice of headline is the owner's (R-a in section 17).

## 7. Cause recall

For run r and S ∈ {T, C} (Threat Cause Recall, Security Control Gap Recall):

**F** = { c ∈ C : some claim of r has ℓ = c and u = 0 } (the sure found causes).

- **Rec⁻(S) = |F ∩ S| / |S|**

**Plausible causes of pending claims.** Let 𝒫 be the claims with s = P. For κ ∈ 𝒫:
Π\*(κ) = ({ℓ(κ)} if ℓ(κ) ∈ C, else ∅) ∪ Π(κ) if ρ(κ) = 1, and Π\*(κ) = ∅ if ρ(κ) = 0. Only
documented, justified assignments count (section 12, rule V11).

**Upper bound.** Build the bipartite graph between 𝒫 and the causes S \ F, edge κ — c iff
c ∈ Π\*(κ). Let ν(S) be the size of a maximum matching.

- **Rec⁺(S) = (|F ∩ S| + ν(S)) / |S|**

A cause counts at most once (a node), a claim supports at most one cause (matching). A pending
claim for a cause that is already in F adds nothing: this absorption exists **in the recall only**.
`valid_additional`, `unsupported` and the review do not change recall (D16, R12). Pooled
over architectures: sums of numerators and denominators. Control gaps are in S = C and not in S = T.

## 8. Key scores (P5)

**V1 key score.** `evaluate(predictions, v1_ground_truth)` on all stored predictions. The V1
evaluator and the V1 ground truth are not touched.

**V2 adjusted key score.** The exclusion happens on claims, before keys are formed:

1. For every prediction x remove its **sure control-gap claims** (ℓ ∈ Γ and u = 0): K′(x) = K(x) \
   { κ : ℓ(κ) ∈ Γ, u(κ) = 0 }.
2. Form keys only from predictions with K′(x) ≠ ∅: the key of x is its stored
   `(target, category)`. A prediction has one key whatever its claims.
3. Apply the unchanged `evaluate()` function to those predictions against the V2 keys of T.
4. Report the number of predictions with K′(x) = ∅ (excluded) and the number of removed control-gap
   claims.

Consequences: a prediction with only sure control-gap claims forms no key (excluded). A prediction
with a control-gap claim and any other claim keeps its key because of the other claim. Unsure
control-gap claims are not removed (they are pending). Unmatched and unsupported predictions are
never excluded. The scorer calls the V1 function on a filtered list; the function is not changed.
This is a different metric from the V1 key score and is named so.

Target and category agreement (descriptive, never blocking a match, R1, R2): for every sure cause
claim the scorer compares the prediction's target and category with the frozen cause.

## 9. Prediction distribution (descriptive)

Per run, as counts, never as a precision. With m = number of claims with s ∈ {M, V}, p = with s =
P, u = with s = U: *clean* (p = 0, u = 0), *pending* (u = 0, p ≥ 1), *mixed* (u ≥ 1, m ≥ 1), *wrong*
(u ≥ 1, m = 0). The classes are exclusive and cover every prediction.

## 10. Reliability: κ coding and exact set agreement (P4)

**Items** are predictions. In pass t ∈ {1, 2} the label set is L_t(i) = { ℓ(κ) : κ ∈ K_t(i) }
(duplicates removed, order ignored). An item is *unsure* in a pass if any of its claims has u = 1;
unsure items are excluded as in D13, counted, and listed. Let I be the other items, n′ = |I|.

**Comparison unit of the primary κ: the pair (prediction, label).** The label universe Λ is fixed
in advance for the architecture: all its causes plus `VA`, `UN`, `PR` (9 labels for
`multi_tenant_saas`, 14 for `cloud_ingest_pipeline`). For every item i ∈ I and label λ ∈ Λ each
pass makes one binary decision y_t(i, λ) = 1 iff λ ∈ L_t(i). That gives n′ · |Λ| pairs and a 2 × 2
table with cells a (both 1), b (pass 1 only), c (pass 2 only), d (both 0), N = a + b + c + d.

- p_o = (a + d) / N
- p₁ = (a + b) / N, p₂ = (a + c) / N, p_e = p₁p₂ + (1 − p₁)(1 − p₂)
- **κ = (p_o − p_e) / (1 − p_e)**; undefined if p_e = 1

Reading: "How well do two passes agree, beyond chance, on whether a given label applies to a given
prediction?" It handles several claims directly, needs no category per label combination, and its
chance term uses the label frequencies of the sample. The threshold **κ ≥ 0.8** (unchanged) refers to
this κ. Because the pairs contain many (0, 0) cells, κ here is not on the same scale as a
single-label κ; the worked example in section 13 shows a case where 5 of 8 items are identical and
κ is about 0.70.

**Supplementary, reported next to it:**

- **Exact set agreement** = |{ i ∈ I : L₁(i) = L₂(i) }| / n′ (no chance correction, no threshold);
- the table a, b, c, d, the per-label counts, and the positive agreement 2a / (2a + b + c);
- n′, the number and share of excluded unsure items (≤ 10 % per pass), and the disagreement list
  with claim texts, evidence, reason codes and rationales of both passes.

The alternatives were: (B) κ over whole label sets as categories (strict, but sparse: many sets occur
once), and (C) κ on aligned claims (needs a matching rule between passes). Neither is proposed.

## 11. Repeat sample (P8, accepted)

At least 20 predictions per phase, at least 24 hours after the first pass, original labels hidden,
new row order. Eligible: annotated predictions of the phase **without the twelve development
cases**. Strata: *has a pending or unsure claim*, *has a sure cause claim*, *no cause claim
(unsupported or valid_additional only)*, assigned in this order; at least 4 per stratum where available, the rest in proportion; inside a stratum the order is
`sha256("<seed>:<pred_uid>")` with a fixed seed recorded in the sample file. Declared limitation: the
stratification makes the sample harder than a random one, so κ on it describes this sample.

## 12. Sheet schema and validation

One long-format sheet per architecture, `annotation_claims_<architecture>.csv`, one pre-seeded empty
claim row per prediction. Another claim: copy the row and set `claim_no` to 2, 3, ….

| Column | Filled by | Content |
|---|---|---|
| `pred_uid`, `architecture`, `target`, `target_kind`, `category`, `description`, `mitigation` | export | stored prediction, unchanged, identical on all rows of a prediction |
| `claim_no` | annotator | 1 … n |
| `claim_label` | annotator | one cause ref of the architecture, `valid_additional`, `unsupported` or `pending_review` |
| `reason_code` | annotator | required when `claim_label = unsupported` (below) |
| `claim_text` | annotator | the claimed mechanism |
| `evidence_refs` | annotator | architecture paths, separated by `;` |
| `candidate_id` | annotator | groups the same candidate across predictions |
| `plausible_causes` | annotator | cause refs separated by `;`, for `pending_review` or unsure claims |
| `rationale` | annotator | the reasoning, with rule numbers |
| `unsure` | annotator | `yes` or empty |
| `target_judgement`, `stride_judgement` | annotator, optional | `ok` or `deviates`; empty means derived |

**Reason codes for `unsupported` (Q4).** Exactly one per claim.

| Code | Meaning | Rule |
|---|---|---|
| `explicit_contradiction` | the claim contradicts an explicit architecture configuration; `evidence_refs` holds the contradicting path | R4 |
| `insufficient_evidence` | a weakness is plausible but the architecture states nothing that supports it; a missing control is inferred from silence | R5, R11 |
| `generic_claim` | too general to name a mechanism; several causes would fit | R3 |
| `wrong_mechanism` | the named mechanism is not the one the architecture states, or one it does not have; target, category or impact alone are similar | R6 |
| `out_of_scope` | concerns an external entity or something outside the system boundary | scope rules |
| `other` | none of the above; needs a `rationale` | |

The scorer reports the number of unsupported claims per code, per approach (descriptive). Case 8
would be `generic_claim`, which matches the owner's reason. The reasons of the other
development cases were not recorded and are not invented.

**Standard match** (P6): a cause claim with `unsure` empty, in a prediction with exactly one claim,
with the prediction's target equal to the cause's target and (for causes with a STRIDE mapping) its
category among the cause's categories, and no override. No reasoning is required; the scorer fills
`evidence_refs` with the evidence paths of the frozen cause.

| # | Rule |
|---|---|
| V1 | every `pred_uid` appears, `claim_no` is 1 … n without gaps |
| V2 | content columns equal the stored prediction on every row |
| V3 | `claim_label` is exactly one allowed label (no chain, boundary or foreign refs, no lists) |
| V4 | a cause ref appears at most once per prediction |
| V5 | in a prediction with two or more claims, every claim has `claim_text` and `rationale` |
| V6 | `valid_additional` needs `claim_text`, `evidence_refs`, `candidate_id`, `rationale` |
| V7 | `evidence_refs` paths exist in the frozen architecture; `plausible_causes` refs are causes of it |
| V8 | `pending_review` and every `unsure = yes` claim need `rationale` |
| V9 | a cause claim that is not a standard match needs `rationale` |
| V10 | an override of `target_judgement` or `stride_judgement` needs `rationale`; allowed values are checked |
| V11 | a non-empty `plausible_causes` needs `rationale` that **mentions every listed ref**, and non-empty `evidence_refs` (the candidates must be justified, not just listed) |
| V12 | every `unsupported` claim has a `reason_code` from the list; `explicit_contradiction` needs `evidence_refs`; `other` needs `rationale` |

A single unsupported claim without `unsure` needs the `reason_code` but no `rationale` (P6).

## 13. Worked examples

All numbers were checked with a throwaway script; the implementation will carry them as tests.

### Example A: one run, mixed claims, `valid_additional`, `pending_review`, unsure

Eleven predictions, `multi_tenant_saas` (|T| = |C| = 6):

| Prediction | Claims |
|---|---|
| x1 | MTS-04 |
| x2 | MTS-04 (other STRIDE category) |
| x3 | MTS-01; UN (`insufficient_evidence`: "passwords stored unhashed") |
| x4 | UN (`generic_claim`) |
| x5 | PR, plausible causes MTS-03; MTS-05, reasoning and evidence given |
| x6 | MTS-02, unsure, reasoning given |
| x7 | VA, candidate `tls-version` |
| x8 | VA, candidate `tls-version` |
| x9 | MTS-04, unsure, reasoning given |
| x10 | PR, no plausible cause |
| x11 | MTS-06; MTS-05 (two independent claims, each with text and reasoning) |

13 claim rows. Statuses: M: x1, x2, x3a, x11a, x11b; V: x7, x8; P: x5, x6, x9, x10; U: x3b, x4.

- **CP**: g = 5, v = 2, p = 4, u = 2, n = 13. CP⁻ = 7/13 = **0.538**, CP⁺ = 11/13 = **0.846**.
- **UFP**: sure causes {MTS-04, MTS-01, MTS-06, MTS-05} so g\* = 4; `tls-version` so v\* = 1;
  pending findings x5, x6 (pending-cause MTS-02), x9 (pending-cause MTS-04, **not absorbed**), x10 so
  p\* = 4; u = 2; n\* = 11. UFP⁻ = 5/11 = **0.455**, UFP⁺ = 9/11 = **0.818**.
- **Recall** (S = T = C): F = {MTS-04, MTS-01, MTS-06, MTS-05}, Rec⁻ = 4/6 = **0.667**. Pending
  claims with justified plausible causes: x5 → {MTS-03, MTS-05}, but MTS-05 ∈ F, so only MTS-03; x6 →
  {MTS-02}; x9 → {MTS-04} ∈ F, nothing; x10 → ∅. Maximum matching ν = 2. Rec⁺ = 6/6 = **1.00**.
  The unsure x9 is absorbed here, in the recall, and stays in both precisions.
- **Distribution**: clean x1, x2, x7, x8, x11 (5); mixed x3 (1); wrong x4 (1); pending x5, x6, x9, x10 (4).

### Example B: why CP and UFP must not share a name

Three approaches' runs on the same architecture:

| Run | Claims | CP | UFP |
|---|---|---|---|
| X | MTS-04 four times (four STRIDE variants), MTS-01, one unsupported | 5 correct of 6 = **0.833** | 2 findings correct of 2 + 1 = **0.667** |
| Y | MTS-04, MTS-01, one unsupported | 2 of 3 = **0.667** | 2 of 3 = **0.667** |
| Z | MTS-04 three times, the same unsupported claim three times | 3 of 6 = **0.500** | 1 of 1 + 3 = **0.250** |

X looks better than Y under CP only because it restated a finding. Under UFP they are equal. Z shows
the asymmetry of P7: repeated correct claims count once, repeated unsupported claims count each time,
so UFP penalises Z much harder than CP does.

### Example C: κ and exact set agreement

Nine items, two passes, `multi_tenant_saas` (Λ has 9 labels). Item 9 is unsure in pass 2 and is
excluded, so n′ = 8.

| Item | Pass 1 | Pass 2 | Identical set |
|---|---|---|---|
| 1 | {MTS-04} | {MTS-04} | yes |
| 2 | {MTS-01, UN} | {MTS-01} | no |
| 3 | {UN} | {UN} | yes |
| 4 | {MTS-03} | {PR} | no |
| 5 | {MTS-03} | {MTS-03} | yes |
| 6 | {UN} | {UN} | yes |
| 7 | {MTS-05, MTS-06} | {MTS-05, MTS-06} | yes |
| 8 | {VA} | {UN} | no |
| 9 | {UN} | unsure | excluded |

Pairs: N = 8 · 9 = 72. a = 7 (items 1, 2, 3, 5, 6, 7 twice), b = 3 (UN in item 2, MTS-03 in item 4,
VA in item 8), c = 2 (PR in item 4, UN in item 8), d = 60. p_o = 67/72 = 0.931, p₁ = 10/72, p₂ = 9/72,
p_e = 0.771, **κ = 0.697**. **Exact set agreement = 5/8 = 0.625.** Positive agreement 2 · 7 / (14 + 3 +
2) = 0.737. κ is below the 0.8 threshold in this example although most items agree, because the
disagreements are on label-relevant decisions.

### Example D: claim-level exclusion for the adjusted key score

`cloud_ingest_pipeline`, four predictions; CIP-11 and CIP-04 are control gaps:

| Prediction | Key | Claims | After removing sure control-gap claims | Forms a key? |
|---|---|---|---|---|
| p1 | monitoring:repudiation | CIP-11 | ∅ | no, excluded |
| p2 | raw_bucket:tampering | CIP-04; UN | UN | yes |
| p3 | raw_bucket:information_disclosure | CIP-02 | CIP-02 | yes |
| p4 | monitoring:repudiation | CIP-11 (unsure) | CIP-11 (unsure, kept) | yes |

Excluded predictions: 1; removed control-gap claims: 2 (p1, p2). Keys formed: `raw_bucket:tampering`
(false positive: not a V2 key), `raw_bucket:information_disclosure` (true positive), and
`monitoring:repudiation` from p4, the unsure one (true positive by key). In the V1 key score all
four predictions form keys.

## 14. Case 10 against the frozen architecture and cause list

Prediction `pred-302e7be13a9f0dae`: target `object_store`, tampering, "an attacker can modify files
stored in the Tenant File Storage due to broken object-level authorization (IDOR)", mitigation
"check ownership and tenant scope on every object access, not just authentication". **Status stays
`pending_review`.**

**Frozen facts** (architecture sha256 prefix `74f16ea7b8812904`):

- `document_service`: `object_ownership_check = false` → **MTS-03**, "does not verify that a requested
  object belongs to the requesting caller or tenant"; categories information disclosure and
  tampering. Its flow `document_service_to_store` (HTTPS, authenticated) leads to the store.
- `object_store`: `per_tenant_prefix_enforced = false` → **MTS-05**, "does not enforce a per-tenant
  prefix"; categories information disclosure and tampering. `public_access = false`,
  `encryption_at_rest = true`. The store has **no authorization or ownership setting**.

**Is it MTS-03 or a separate weakness at the store?**

- The prediction names one mechanism: missing object-level authorization (IDOR). In the architecture
  the control "a referenced object belongs to the caller" is `object_ownership_check`, and it is
  stated on `document_service`, not on the store.
- The architecture contains no statement that the store performs object-level authorization, or that
  this is missing there. R5 and R11 do not allow concluding a separate weakness at the store from
  silence. The only stated store weakness is the prefix enforcement (MTS-05), a different control that
  the prediction does not name (R6: shared target and category are not enough).
- Evidence therefore supports the **mechanism of MTS-03, localised at the affected asset** (the store is
  the target of the service's flow). That is R2. Tampering is a listed category of MTS-03.
- Remaining uncertainty: the mitigation says "tenant scope", the vocabulary of MTS-05, and the
  root cause is placed where the architecture states another control. If you read the two causes as
  indistinguishable here, `pending_review` with `plausible_causes = MTS-03; MTS-05` keeps both visible.
  Under section 7 it adds at most one cause to the recall upper bound.

**Suggested outcome, not applied:** `MTS-03` by R2, reasoning "IDOR is the missing ownership check
(`components.document_service.config.object_ownership_check = false`), affecting the store through
`document_service_to_store`; MTS-05's control (prefix enforcement) is not named", evidence_refs those
two paths. Protocol 1.1 could state the criterion used: *map under R2 only if (i) the named mechanism
corresponds to the control of exactly one cause and (ii) the named element lies on a data flow governed
by that cause's element.*

## 15. Compatibility with V1, V2 and the current sheet

| Item | Effect |
|---|---|
| V1 evaluator, V1 ground truth, V1 key score | unchanged; still computed on the same stored predictions (D8, G4) |
| Frozen cause lists, `MANIFEST.json`, stored predictions, `pred_uid`, order, seed | unchanged |
| D17 to D23 | unchanged; D23's exclusion is made exact in section 8 and is identical for single-claim predictions |
| D24 | the special case of one claim per prediction. Old annotation maps to `claim_no = 1`, `claim_label = label`, `rationale = note`, `unsure` unchanged |
| Spec section 8 "precision" | becomes **Unique-Finding Precision**; **Claim Precision** is added next to it. The word "precision" alone is not used in reports |
| Old label names | `none` → `UN`; `unsure` and `new_cause_proposed` → `PR`; still accepted by the adapter |
| Migration | an old `unsupported` has no `reason_code`; migration leaves it empty and the validator lists those rows for the owner to fill. Nothing is invented |
| What differs numerically for single-claim data | (a) an `unsure = yes` row is pending, not by its label; (b) an unsure claim for a cause that is sure elsewhere stays pending in precision, and is absorbed in recall only |
| Blind export | a new long-format sheet version with pre-seeded rows, same uids and order. The 123-row sheets remain as the record of the first export. The mapping stays valid |
| Scores computed so far | none exist for V2 |

Code that changes when approved: `annotation_export.py` (columns, validator, reader),
`check_cause_consistency.py` (`cause_claim_counts`, `coarse_scores`, `recall_from_labels`,
`labels_in_file_order`), the sheet README. Unchanged: logging, uids, V1 evaluator, freeze script.

## 16. Test design (after approval)

| Area | Test |
|---|---|
| Statuses | every combination of label and `unsure` gives the status of section 3 |
| CP | example A gives 5, 2, 4, 2, n = 13 and 0.538 / 0.846; n includes pending; n = 0 undefined; no deduplication anywhere |
| UFP | example A gives 4, 1, 4, 2, n\* = 11 and 0.455 / 0.818; an unsure duplicate of a sure cause stays pending; two identical unsupported claims count twice; two `valid_additional` with one `candidate_id` count once |
| CP versus UFP | example B gives the six values; the report layer refuses a bare "precision" label |
| Bounds | for random resolutions of pending claims the final value lies within the bounds, for CP and UFP |
| Recall bounds | example A gives 0.667 and 1.00; matching never counts a claim twice or a cause twice; an unreasoned or unjustified (V11) candidate adds nothing; absorption only in recall |
| Mixed claims | MTS-01 + unsupported: g +1, u +1, recall finds MTS-01, class `mixed`, key kept |
| Key score | example D; the V1 evaluator function is the same object; V1 key score on the same file is identical to the unchanged evaluator; with no control-gap claim the adjusted score equals the plain evaluator on the V2 keys |
| κ | example C gives a = 7, b = 3, c = 2, d = 60, κ = 0.697, exact 0.625; unsure items excluded and counted; identical passes give 1; p_e = 1 undefined; the label universe is fixed by the architecture |
| Sample | reproducible from the seed; never contains a development case; stratum minimums |
| Validation V1 to V12 | each rule has a rejecting and an accepting case; standard match needs no reasoning; every `unsupported` needs a reason code; V11 rejects a list whose rationale omits a ref |
| Join and migration | rows join to the stored file by `pred_uid`; an old sheet migrates without loss; missing reason codes are listed, not invented |
| Blindness | the claim sheet holds no approach, run, file or trace data |
| Compatibility | for single-claim sure data the new counts equal the present `cause_claim_counts` and `recall_from_labels`; the differences in section 15 are asserted |

## 17. Decisions still needed

| # | Question | Proposal |
|---|---|---|
| R-a | Which precision is the headline: UFP (matches D15 and the recall) or CP | UFP headline, CP reported next to it, always under its own name |
| R-b | Is the primary κ the (prediction, label) pair κ of section 10, with exact set agreement beside it | yes |
| R-c | The list of reason codes (section 12), including `out_of_scope` and `other` | as listed |
| R-d | V11: candidates in `plausible_causes` must be named in the rationale and backed by evidence paths | yes |
| R-e | A `UN` claim that is unsure keeps its `reason_code` | yes |
| Case 10 | decision of the owner (section 14) | `MTS-03` by R2, or stay `pending_review` |

## 18. Not part of this proposal

No automatic annotation or pre-annotation, no new capture, no comparison between RAG, PEV and NoPlan,
no change to the frozen cause lists or stored predictions. No figure is computed before the annotation
is finished, validated against the repeat sample, and the protocol version is fixed.

## 19. Open work (does not block the current commit)

- **Command-line scorer** with `--scheme v1|v2` and the **review ledger** (decisions on pending and
  `valid_additional` candidates, keyed by `(architecture, candidate)`, with rationale and date; spec
  section 8). The metrics exist as library functions in `src/evaluation/claims.py` and are tested on
  synthetic data; they have not been run on real annotation.
- **LLM-grader test** against the owner's labels (spec section 9, optional). Not started.
- **Case 10** (`pred-302e7be13a9f0dae`) is `pending_review`. The assignment to MTS-03 in section 14 is
  a suggestion and is **not released**.
- Annotation of the 123 predictions, the repeat annotation, and the review of pending claims.

