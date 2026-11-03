# Blind annotation export: technical report

Date: 2026-11-03. Scope: the 123 stored predictions of the V2 capture run (commit
`627a42e`, `llama3.1:8b`, temperature 0, one run each). No label has been assigned.
No stored prediction and no cause list was changed.

## 1. What was built

| Part | Location |
|---|---|
| Library (identifiers, order, sheets, mapping, verification, label checks) | `src/evaluation/annotation_export.py` |
| Stable prediction identifiers | `src/evaluation/prediction_ids.py` |
| Command line (`export`, `verify`, `check`, `example`) | `scripts/export_annotation_sheet.py` |
| Tests (27, all synthetic data, 123-prediction layout) | `tests/test_annotation_export.py` |
| **Blind export, for the annotator** | `benchmark_v2/annotation/blind/` |
| **Private mapping, not for the annotator** | `annotation_private/mapping.json` (git-ignored) |
| Synthetic example (documentation only) | `benchmark_v2/annotation/example/` |

## 2. The export

Two sheets, one per architecture (Phase A `multi_tenant_saas`, Phase B
`cloud_ingest_pipeline`), plus `annotation_export_meta.json` and a `README.md` with
the annotation instructions.

| Sheet | Rows | SHA-256 |
|---|---|---|
| `annotation_multi_tenant_saas.csv` | 60 | `30eea18ec30c05da7bcfead396d387934ece318d59e5a6262f4ca8489331596a` |
| `annotation_cloud_ingest_pipeline.csv` | 63 | `9510928dcc8f93e42b465517aa83a3d317d82739ea0642955e27ea9e83f9a962` |

Mapping SHA-256: `109ee674d46580314a2f900c14a5d2ccc5efe3bed6261efb9a52b52e0c407a72`
(recorded in the export metadata, so a replaced mapping is detected).

**Columns.** Copied unchanged from the stored prediction: `pred_uid`, `architecture`,
`target`, `target_kind`, `category`, `description`, `mitigation`. To fill in: `label`,
`unsure`, `note`. Stored predictions carry no separate rationale field; the
description and the mitigation are the reasoning the model gave, and both are copied
verbatim.

**Identifier.** `pred-` plus 16 hex characters: a hash of the run identity
(architecture, approach, model, run index, file timestamp), the position in the stored
file and the content (target, category, description, mitigation). It does not depend on
the model's threat id, on the derived key, on the commit, on the order of an export or
on a randomization, and it does not show the approach. The owner can recompute it from
the stored file.

**Order.** Within each architecture, over all approaches together, rows are sorted
ascending by `sha256("<seed>:<pred_uid>")` with seed `20261103`. The order depends on
nothing else: not on the order of the input files, not on a random generator, not on the
Python version. The same inputs and seed always give byte-identical sheets.

**Labels.** Exactly one label per row: a cause ref of that architecture
(`MTS-01` to `MTS-06`, `CIP-01` to `CIP-11`), or `valid_additional`, `unsupported`,
`pending_review`. Chain candidates, boundary and unsupported refs are not labels. The
check `export_annotation_sheet.py check` rejects several labels in one cell, other
architectures' refs, and unknown values.

## 3. Verification (real export)

`python scripts/export_annotation_sheet.py verify` passed:

| Check | Result |
|---|---|
| Stored predictions in the 6 source files | 123 |
| Rows in the sheets | 123 (60 + 63) |
| Unique identifiers | 123 |
| Stored predictions missing from the export / rows without a stored prediction | 0 / 0 |
| Source files unchanged since the export (SHA-256), still read-only (`0444`) | 6 of 6 |
| Text of every row equals the stored prediction (target, kind, category, description, mitigation) | 123 of 123 |
| Every row joins back to file, index, run and approach through the mapping | 123 of 123 |
| Row order equals the documented rule | both sheets |
| Annotation columns empty | 123 of 123 (no label, no `unsure`, no note) |
| Blindness checks (below) | no finding |

Source files: all 6 carry commit `627a42e`, `dirty=false`, and were written by the
capture run. The deterministic baseline files are not part of the export.

The 27 tests cover completeness (123 of 123 with the same per-architecture split),
uniqueness (also for identical text from different approaches), correct join back,
deterministic and input-order-independent output, dependence on the seed, blindness,
verbatim text (commas, quotes, line breaks, CRLF, unicode, spreadsheet-like prefixes
such as `=`), untouched source files, refusal to overwrite, detection of tampering
(changed text, swapped rows, a filled label, a changed mapping, a changed source file),
and the label rules. Two mutations were tried: an order that ignores the seed and a
`strip()` on the description. Both were detected.

## 4. Blindness

**Held back from the annotator** (in the mapping only): approach, model, run index,
timestamp, source file name and path, model threat id, derived key, commit, trace.
`annotation_export_meta.json` and `README.md` hold none of these values, which a test
and the `verify` command check against the actual values. The metadata does not say how
many approaches there are or how the rows split between them.

**Mixing.** Both sheets contain all three approaches. Rows of the same approach next to
each other: 16 of 59 (multi_tenant_saas) and 19 of 62 (cloud_ingest_pipeline). About 20
and 21 would be expected from a random order. The approaches do not come in blocks.

**Free text.** A scan of descriptions and mitigations for approach and tool vocabulary
(`rag`, `pev`, `noplan`, `llm`, `llama`, `plan`, `explore`, `retrieve`, `knowledge base`,
`search_knowledge`) found no match at word level. The word `verify` or `verified` occurs
in 13 rows as ordinary English and was not removed.

**Residual risks that cannot be removed** without changing the texts:

- Style, length and wording of the text can still hint at an approach, because the
  approaches prompt differently. The texts are copied unchanged on purpose.
- The `target` and `category` mix of a sheet could show tendencies of an approach.
- The sheets stay in the same working tree as the private mapping. The mapping is in a
  separate, git-ignored directory (`annotation_private/`), and the README tells the
  annotator not to open it. Technically it is one folder away.
- Identical or near-identical predictions from different approaches remain separate rows.
  Collapsing them into claims is a scoring step (V2 spec 7.3).
- Texts that start with `=`, `+`, `-` or `@` are not escaped. A spreadsheet program may
  interpret them as formulas. They were copied unchanged on purpose, so opening the CSV
  as plain text, or importing the columns as text, is safer.
- The console output of the capture run showed the V1 scores per approach. It does not
  show which prediction belongs to which approach, but the annotator should not have
  looked at it before annotating.

## 5. Open points

- **Label vocabulary.** The owner's list (cause ref, `valid_additional`, `unsupported`,
  `pending_review`) differs from the names in section 7.1 of the spec (`none`, `unsure`,
  `new_cause_proposed`). Mapping used by the code: `none` is `unsupported`; `unsure` and
  `new_cause_proposed` are `pending_review`. To keep decision D13 workable (κ over items
  where both annotations are not `unsure`, `unsure` share at most 10 %), the sheet has a
  separate column `unsure` with the value `yes` or empty. This column is a proposal,
  not an owner decision yet. The spec is updated accordingly and marks it as proposed.
- **Annotation of the first phase.** The sheet of `cloud_ingest_pipeline` is exported now
  as well, because the export is one run. By the spec, Phase B follows only after Phase A
  has been evaluated (D14). Nothing in the export forces the order.
- **Repeat annotation.** Not built yet: a sample of at least 20 rows per phase, at least
  24 hours after the first pass (D12). It needs a second, separate sheet drawn from the
  same identifiers.
- **Mapping location.** `annotation_private/` is ignored by git, as are the prediction
  files in `results/`. They are not in the repository. Their checksums are in the
  mapping and in the export metadata.

## 6. Synthetic example

`benchmark_v2/annotation/example/` holds an export of 14 invented predictions (three
approaches, `multi_tenant_saas`). It was generated and verified with the same code.
The sheet shows what the annotator sees. The first rows:

| pred_uid | target | category | description |
|---|---|---|---|
| `pred-edbe1aff787c201d` | shared_db | tampering | SYNTHETIC: rows changed across tenants. |
| `pred-1fe6933396fb6c19` | object_store | tampering | SYNTHETIC: files can be overwritten. |
| `pred-fc383d1d44afac62` | document_service | tampering | SYNTHETIC: objects can be changed by others. |
| `pred-5375982fcd538d1d` | admin_portal | spoofing | SYNTHETIC: portal login can be impersonated. |
| `pred-57106f0bc9b1dd60` | api | elevation_of_privilege | SYNTHETIC: caller acts beyond its role. |

with empty `label`, `unsure` and `note`. The matching private mapping entry of the first
row, which is **not** part of the sheet:

```json
{
 "approach": "agent_pev_noplan",
 "architecture": "multi_tenant_saas",
 "file": "benchmark_v2/annotation/example/synthetic_sources/multi_tenant_saas_agent_pev_noplan_synthetic_run0.json",
 "index_in_file": 3,
 "key": "shared_db:tampering",
 "model": "synthetic-model",
 "row_in_sheet": 1,
 "run_index": 0,
 "sheet": "annotation_multi_tenant_saas.csv",
 "threat_id": "agent_pev_noplan-threat-3"
}
```

The example's mapping is kept next to it only because the data is invented.

## 7. Commands (from the repository root)

```
python scripts/export_annotation_sheet.py verify
python scripts/export_annotation_sheet.py check --sheet-dir <dir with filled sheets> [--complete]
```

The export itself was created with `export --predictions <the 6 files> --blind-dir
benchmark_v2/annotation/blind --mapping annotation_private/mapping.json`. The command
refuses to overwrite existing files and refuses a mapping path inside the blind directory.
