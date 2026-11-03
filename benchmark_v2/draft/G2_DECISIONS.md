# Gate G2: decisions needed from the owner

Status: DRAFT. Nothing is frozen. The detail is in `REVIEW.md` (generated from
the JSON files in this directory). This page lists only what needs a decision.

## What was done and what limits it

- The two cause lists were derived from `benchmark/multi_tenant_saas.json` and
  `benchmark/cloud_ingest_pipeline.json` only. No V1 ground truth, no results,
  no traces, no predictions, and no baseline output were opened for this draft.
- The drafting assistant wrote those architecture files and the V1 ground truth
  earlier and had seen V1 results, so exposure cannot be excluded. Your review is
  the independence check. Because the same assistant designed the architectures
  to carry intended weaknesses, evidence-based reading largely reproduces design
  intent.
- Every cited value is checked by a test against the architecture file. The test
  confirms that evidence exists, not that a cause is right.

## What the drafts contain

17 confirmed causes (12 easy, 5 medium, **0 hard**), 22 (target, STRIDE) entries,
4 boundary cases, 17 unsupported items, 4 candidate chain causes.

**Consequence you should know before deciding anything else:** under the strict
difficulty rubric there is no hard cause in either architecture, because every
weakness is encoded as an explicit setting on one element. Hard-class results
cannot be reported for these two architectures. Options are in decision 2.

## Decisions

### 1. Policy P1: exposure-only scenarios

Cases such as "an internet-exposed API can be impersonated" rest only on
`internet_exposed: true`. They are listed as boundary cases (4 in total).

- **Proposed default:** not part of the confirmed list, not required for recall;
  if a model predicts one it goes to `pending_review` and you decide it once.
- Alternatives: treat them as confirmed `scenario` entries (more recall targets,
  more generic content), or treat them as `unsupported` (predictions of them
  count as false positives).

### 2. Difficulty rubric and the empty hard class

I applied an operationalization of section 5 of the spec (header of each JSON
file): easy = the value names a missing control of general relevance; medium = a
mechanism or specialist control, or two facts combined; hard = facts from two
different elements combined with the weakness stated at none of them.

- Accept the rubric as applied, or adjust the wording.
- For the hard class choose one:
  1. **Accept an empty hard class** on these architectures and report it as a
     finding about the benchmark (proposed).
  2. **Include chain candidates as hard causes** (`MTS-X1`, `MTS-X2`, `CIP-X1`).
     They overlap the atomic causes, so one prediction can map to several of
     them. That would blur exactly what the annotation sample must test.
  3. **Add new architectures** whose weaknesses only appear across elements.
     This needs new architecture files and the holdout rule applied to them.
  4. **Relax the hard definition.** This weakens the independence of the label.

### 3. Granularity (these are what the annotation sample will test)

- `MTS-04`: `row_level_security` and `tenant_isolation` merged into one cause.
- `MTS-01` and `MTS-02` kept apart (bind tenant to identity versus authorize).
- `CIP-10` (retention) and `CIP-11` (alerting) kept apart.
- `CIP-02` (public access) and `CIP-03` (encryption) kept apart.

Say where you want a merge or a split.

### 4. Entries with preconditions that are not stated

- `CIP-04` (no versioning): confirmed as `derived` through the write path shown by
  the flows. No actor that overwrites or deletes objects is stated.
- `CIP-07` (IMDSv1 allowed): the setting is stated, a foothold that uses it is not.

Keep both as confirmed, or move them to boundary cases or unsupported.

### 5. STRIDE assignment

Categories are the secondary metric. I used at most two per cause and used
`repudiation` by convention for logging and monitoring gaps (`CIP-05`, `CIP-09`,
`CIP-10`, `CIP-11`). Confirm or change.

### 6. Scope and consistency rules

- External entities (`tenant_user`, `producer`) are out of scope as targets;
  threats against the system through them are in scope.
- `CIP-02`: the attribute `internet_exposed` is false while `config.public_access`
  is true. The draft follows the explicit configuration.
- Silence is not evidence: for example `shared_db` encryption at rest is listed
  as unsupported because nothing is stated, although another store states it.

Confirm or change.

## After your approval

On approval I would freeze each cause list by checksum together with the checksum
of its architecture file, record the approved decisions in `V2_SPEC.md`, and only
then allow the capture run (step 3). Until then no model output for these
architectures should be viewed.
