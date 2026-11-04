# Annotation protocol

**Version 1.1**, 2026-11-04. Owner decisions. Applies to the blind annotation of the V2
capture predictions (cause lists GT V2.0, `benchmark_v2/v2.0/`).

Status of this version: the rules (section 2) and the definition (section 3) are adopted and
unchanged since 1.0. Version 1.1 adds the claim-level annotation procedure (section 6): several
claims per prediction, standard reason codes for unsupported claims, and the reliability
procedure (section 7). The twelve development cases were decided under 1.0.

Versioning: a change of a rule or of the definition is a new protocol version (1.1, 2.0),
recorded in section 8. Annotations are always reported with the protocol version they
were made under. Rules are never edited in place.

## 1. Purpose

A reproducible, cause-based assessment of the model predictions. The primary question is
whether an approach identifies a root cause that the architecture actually supports, not
merely whether target and STRIDE category match. The comparison behind it is RAG, PEV
and NoPlan with a constant model (`llama3.1:8b`): does explicit planning improve
root-cause detection, and does a gain justify the extra inference cost.

## 2. Binding rules

**R1, root cause before STRIDE.** A correctly identified cause counts even if the STRIDE
label differs. The quality of the category is assessed separately.

**R2, deviating target.** A wrong target does not automatically prevent cause matching,
provided the concrete security mechanism clearly corresponds to the same cause. Different
weaknesses must not be merged because of that.

**R3, mechanistic specificity.** General statements such as "broken authorization" are not
enough when several different ground-truth causes come into question.

**R4, explicit configuration contradiction.** A claim of a weakness that contradicts an
explicit architecture configuration is `unsupported`.

**R5, missing statements.** From an undocumented security control one must not conclude
that it is missing.

**R6, no matching by superficial similarity.** Matching target, STRIDE category or impact
alone is not enough. The causal mechanism must match.

**R7, mixed statements.** If a prediction correctly identifies an evidenced root cause but
also contains unsupported claims, the correct cause recognition stays. The unsupported
claims are marked separately and count in precision.

**R8, unclear cases.** A mapping that cannot be decided clearly stays `pending_review`. It
is not silently treated as a hit or as an error.

**R9, several root causes.** A prediction may receive several cause IDs if it contains
several mutually independent, explicitly described and evidenced causes.

**R10, deduplication.** Each recognised ground-truth cause counts at most once towards
recall per approach and architecture, however often or under whatever STRIDE categories it
is named.

**R11, evidence.** Every positive mapping must be justified comprehensibly by the frozen
architecture and cause list. A plausible attack possibility alone is not sufficient
evidence.

**R12, no later change of the ground truth.** The frozen cause lists stay unchanged. New
valid causes are documented as `valid_additional`, not taken into the ground truth.

## 3. Root cause

A root cause is the concrete mechanism or configuration state, evidenced by the
architecture, from which one or more security impacts can arise.

Example: missing tenant isolation in the shared database can enable both information
disclosure and tampering. That is one root cause with several possible STRIDE impacts, not
automatically two independent causes.

Security control gaps without a STRIDE impact that the architecture evidences (CIP-04,
CIP-11) stay separately evaluable under the frozen V2 definitions (spec D17, D18, D23).

## 4. Blindness and reproducibility

- The annotation stays blind to RAG, PEV and NoPlan.
- No approach or run information in the annotation export.
- The stable `pred_uid` is kept. The assignment to original runs and approaches stays in
  the private mapping.
- Original texts are not changed.
- Randomization uses the fixed seed and stays reproducible.
- The architecture and the frozen cause lists may be used for the annotation.
- No automatic pre-annotation from ground-truth keywords.
- Neither model answers nor annotations are used to change the ground truth.

## 5. Development cases

Twelve borderline predictions of `multi_tenant_saas` were discussed to develop this
protocol. They are recorded in `dev_cases_protocol_v1.json`.

**They are development cases. They must not be used as an independent validation sample,
and they are excluded from the repeat annotation (section 7).** Their labels were reached
together with the rules and are not a test of them.

| # | Prediction | Target | Category (as predicted) | Decision | Status |
|---|---|---|---|---|---|
| 1 | `pred-1060e8d5493edefa` | shared_db | tampering | MTS-04 | decided |
| 2 | `pred-3d3f110c5b5366eb` | document_service | elevation_of_privilege | MTS-03 | decided |
| 3 | `pred-7619e9af8d0b552f` | admin_portal | elevation_of_privilege | MTS-01 | decided |
| 4 | `pred-96b4c0697c28ef80` | object_store | information_disclosure | unsupported | decided |
| 5 | `pred-6342bc38792ac760` | object_store | information_disclosure | unsupported | decided |
| 6 | `pred-38efea419daab4e0` | api_to_document_service | information_disclosure | unsupported | decided |
| 7 | `pred-3342120a3b3227a5` | api | spoofing | MTS-01 | decided |
| 8 | `pred-90614b1a365ac22b` | shared_db | elevation_of_privilege | unsupported | decided (owner, after check), see 5.1 |
| 9 | `pred-a70319600509a0a0` | api | denial_of_service | unsupported | decided |
| 10 | `pred-302e7be13a9f0dae` | object_store | tampering | pending_review | open, see 5.2 |
| 11 | `pred-3e9221b8ee512864` | admin_to_api | information_disclosure | unsupported | decided |
| 12 | `pred-71ade5264179393e` | api | elevation_of_privilege | MTS-01 | decided |

Target and category are those of the stored prediction, as shown in the blind sheet. The
owner's reasons for the other ten decisions were not recorded in the message that set
them, so none is written here.

### 5.1 Case 8, checked against the frozen architecture

Prediction: on `shared_db`, elevation of privilege, "authenticated users may access
resources beyond their rights due to missing or broken authorization checks", mitigation
"enforce least-privilege access decisions server-side on every request".

What the frozen architecture (`benchmark/multi_tenant_saas.json`, sha256 prefix
`74f16ea7b8812904`) states:

- `shared_db` has `multi_tenancy: shared_schema`, `row_level_security: false`,
  `tenant_isolation: false`. It has **no statement about authorization checks**.
- The only statement about missing authorization is on `api`:
  `authorization_checks: authentication_only` (cause MTS-02), and `document_service` has
  `object_ownership_check: false` (MTS-03).
- Nothing contradicts the claim (R4 does not apply). It is not a case of a stated
  contradiction.

Assessment against the rules: the prediction names no mechanism (the wording "missing or
broken" is a hedge) and places the weakness on an element that has no stated authorization
control. Four causes could fit it (MTS-01, MTS-02, MTS-03, MTS-04), so R3 applies. R5 and
R11 do not allow concluding a missing control on `shared_db` from silence, and R6 excludes
matching on the shared words "authenticated" and "authorization". **`unsupported` is
consistent with the rules.**

The wording is close to the root-cause text of MTS-02 ("any authenticated caller is treated as
permitted"). If R2 were applied generously, one could read the prediction as MTS-02 with a
wrong localisation. R3 stops that, because the prediction does not say where the
authorization is missing. **Owner decision: `unsupported`**, because the general
claim of missing authorization identifies no concrete root cause.

### 5.2 Case 10, analysis for the owner's decision (not decided)

Prediction: on `object_store`, tampering, "an attacker can modify files stored in the
Tenant File Storage due to broken object-level authorization (IDOR)", mitigation "check
ownership and tenant scope on every object access, not just authentication".

What the frozen architecture states:

- `document_service`: `object_ownership_check: false` (MTS-03). The service reaches the
  store through the flow `document_service_to_store`.
- `object_store`: `per_tenant_prefix_enforced: false` (MTS-05); `public_access: false`;
  `encryption_at_rest: true`. It has no authorization or ownership setting of its own.
- MTS-03 covers information disclosure and tampering. MTS-05 does too. Tampering therefore
  does not separate the two.

Readings and what each needs:

| Reading | Basis | What speaks against it |
|---|---|---|
| MTS-03 (same mechanism, localised at the asset) | "Object-level authorization (IDOR)" and "ownership" are the vocabulary of the missing ownership check. The store is the target of the service's flow, so naming the store is a localisation of impact (R2). | The architecture states the ownership check on the service, not on the store. The prediction does not name the service. |
| MTS-05 (tenant separation at the storage) | The mitigation says "tenant scope", and the prefix enforcement is a storage-level tenant control. The target matches. | The description names IDOR/ownership, not a missing prefix or partitioning. R6: a matching target and category are not enough. |
| Separate, unevidenced claim | "Object-level authorization at the store" is not stated for the store. | The prediction is plausible and close to two evidenced causes. |
| `pending_review` (R8) | The named mechanism is closest to MTS-03, the tenant-scope part touches MTS-05, and the text does not say which one it means. | None; it is the status the rules give for an undecidable case. |

The question the owner has to decide, because it recurs: *When a prediction names a
mechanism that the architecture states for another element along the same data path, is
that the same cause with a different localisation (R2) or an unevidenced claim?* A
criterion that would settle such cases, proposed as protocol 1.1 and **not applied**:
"Map under R2 only if (i) the mechanism named in the prediction corresponds to the control
of exactly one cause, and (ii) the element named in the prediction lies on a data flow
governed by that cause's element." For case 10, (ii) holds (`document_service_to_store`) and
(i) does not hold unambiguously (MTS-03 or MTS-05), which would give `pending_review`.

The record keeps `pending_review`. No automatic assignment was made. A fuller analysis, with
the suggested outcome `MTS-03` by R2 and the remaining uncertainty about the mitigation's
"tenant scope", is in `CLAIM_SCORING.md` section 14.

## 6. Sheet schema

The existing sheet carries one `label` per prediction. Rules R7 and R9 need several claims
per prediction. They are carried by the claim sheets (`benchmark_v2/annotation/blind_claims/`):
one row per claim, `claim_no` 2, 3, … for further independent causes of one prediction. Every
`unsupported` claim gets a standard `reason_code`. Columns, validation and the scoring
definitions are in `CLAIM_SCORING.md`. A filled first sheet migrates by `pred_uid`
(`scripts/claim_annotation.py migrate`); nothing is invented, so an old `unsupported` needs its
reason code filled in.

## 7. Reliability

- Intra-rater check: at least 20 predictions per phase, at least 24 hours after the first
  pass, without showing the original labels. Target κ ≥ 0.8 (unchanged).
- The twelve development cases are **not** part of the sample.
- κ is computed on (prediction, label) pairs, with the exact agreement of the label sets next to
  it (`CLAIM_SCORING.md` section 10). The repeat sample is stratified and seeded
  (`scripts/claim_annotation.py repeat-sample`).

## 8. Change log

- 1.0 (2026-11-03): rules R1 to R12, root-cause definition, the twelve development cases
  with the reservations on cases 8 and 10.
- 1.0, record update (the git history holds the date): case 8 confirmed as `unsupported` by
  the owner after the architecture check; case 10 stays `pending_review`. No rule changed.
- 1.1 (2026-11-04): claim-level annotation procedure (D27), reason codes for unsupported claims,
  reliability procedure (D31, D32). No rule R1 to R12 changed.
