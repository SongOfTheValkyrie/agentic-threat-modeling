# Claim annotation sheets (GT V2.0, protocol 1.1)

One sheet per architecture. Every prediction has one pre-seeded row (`claim_no` 1). For each
independent, evidenced cause the prediction states, copy the row and give it the next `claim_no`
(rule R9). Do not open `annotation_private/` or any file named `*mapping*`.

Columns to fill in (all after `claim_no`):

- `claim_label`: exactly one of the causes of the architecture (listed per sheet in
  `annotation_claims_meta.json`), `valid_additional`, `unsupported` or `pending_review`.
- `reason_code`: required for `unsupported`: `explicit_contradiction`, `insufficient_evidence`,
  `generic_claim`, `wrong_mechanism`, `out_of_scope` or `other`.
- `claim_text`: the mechanism the claim states (required with several claims).
- `evidence_refs`: architecture paths separated by `;`, for example
  `components.shared_db.config.tenant_isolation`.
- `candidate_id`: a short key that groups the same candidate across predictions
  (`valid_additional`, `pending_review`).
- `plausible_causes`: causes separated by `;` that a pending or unsure claim might be; the
  rationale must name each one and evidence paths must be given.
- `rationale`: the reasoning, with rule numbers. Required except for a standard match (a single
  cause claim, same target, listed category, no doubt) and for a single `unsupported` claim.
- `unsure`: `yes` or empty.
- `target_judgement`, `stride_judgement`: optional `ok` or `deviates`; empty means derived.

All other columns are copied unchanged from the stored prediction. Row order carries no
information.
