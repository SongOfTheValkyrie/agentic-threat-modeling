# Blind annotation sheets (GT V2.0)

Annotate every row of the sheets. Do not open `annotation_private/` or any
file named `*mapping*`: it would unblind the sheets.

Columns to fill in:

- `label`: exactly one of
  - a cause ref of the architecture (listed per sheet in
    `annotation_export_meta.json` under `allowed_labels`; the causes are described in
    `benchmark_v2/v2.0/REVIEW.md`),
  - `valid_additional`: a plausible, evidenced finding that is not in the cause list,
  - `unsupported`: not supported by the architecture,
  - `pending_review`: needs a later decision.
- `unsure`: enter `yes` if you are not sure about the label, otherwise leave empty.
- `note`: optional free text, for example a short description of a proposed new cause.

All other columns are copied unchanged from the stored prediction. Rows appear in a
pseudo-random order that mixes all approaches. Row order and the identifier carry no
information.
