# Experiment Log

A running record of experimental conditions and decisions, so every figure in
`RESULTS.md` can be traced back to how it was produced. Newest entries first.

## Fixed conditions (unless noted per run)

- **Model:** Ollama `llama3.1:8b`, `temperature=0` (set in `OllamaClient`).
- **Knowledge base:** the 23-snippet corpus in `data/knowledge_base.json`,
  shared identically by `rag`, `agent`, and `agent_pev`.
- **Retriever:** `KeywordRetriever` (deterministic weighted token overlap).
- **Development set** (building / diagnosing): `simple_web_api`,
  `webapp_with_auth`, `microservices_async`, `cloud_ingest_pipeline`,
  `multi_tenant_saas`.
- **Holdout test set** (untouched until the final evaluation):
  `cicd_pipeline`, `mobile_banking`.
- **Results log:** each run appended to `results/results.jsonl`; aggregated with
  `aggregate.py`. Agent execution traces written to `results/traces/` with
  `TRACE=1` and summarized with `trace_summary.py`.

## Approaches and variants

| Label | Description |
|---|---|
| `deterministic` | Rule-based STRIDE baseline, no LLM. |
| `rag` | Fixed RAG workflow. |
| `agent` | Free tool-calling loop. |
| `agent_pev` | Plan–Explore–Verify agent (`DESIGN_agent_pev.md`, frozen). |

Ablation / experiment variants of `agent_pev` (baseline `agent_pev` stays
unchanged; each is a separate approach label, selectable via env var):

| Variant | Env var | Change | Research question |
|---|---|---|---|
| `agent_pev_noplan` | `AGENT_PEV_NOPLAN=1` | Plan phase skipped (no priorities/hypotheses, so no deepening) | Does planning improve detection? |
| `agent_pev_noverify` | `AGENT_PEV_NOVERIFY=1` | Verify phase skipped (keep all candidates) | Does Verify actually improve precision? |
| `agent_pev_richdeepen` | `AGENT_PEV_RICHDEEPEN=1` | Deepening prompt enriched with the element, plan hypothesis, retrieved knowledge, and tool purposes | Does more context make the model actually investigate, instead of stopping immediately? |

The three switches are independent (`use_plan`, `use_verify`, `rich_deepen`);
the default reproduces the frozen baseline exactly.

---

## 2026-10-19 — Freeze before ablations + trace failure-cause fix

**State frozen for the next phase.** Committed the trace tooling and a
correctness fix to the deepening trace.

**Trace fix (important for the failure analysis).** The earlier deepening trace
could not tell *"the model chose not to explore"* from *"the model could not
produce a valid action"* — both ended on one path recorded as `used=false`.
`DeepenStep` now records `raw_response`, `parsed_action`, `tool_success`, and a
`termination_reason` (`done` / `invalid_json` / `unknown_tool` / `tool_error` /
`budget_exhausted`). `PevTrace.deepened_elements()` now counts an element only
when a deepening tool call actually **succeeded**, not merely when an attempt
was recorded.

**Consequence for earlier traces.** The 10 traces from the first `TRACE=1`
sweep (archived under `results/traces_archive_*`) predate this fix and lack
`termination_reason`. The earlier observation "0/20 prioritized elements
deepened" is therefore **not yet interpretable** as a deliberate choice; it must
be re-measured with the fixed trace before any claim about *why* deepening does
not happen.

**Housekeeping.** The old `results/results.jsonl` mixed runs across several
sessions (deterministic logged 5–8× per architecture, agents 1–2×), so it was
unusable for aggregation. Archived to `results/results.archive_*.jsonl`; the log
starts clean for the multi-run sweep.

### First exploratory sweep (superseded — single run, do not cite)

`RUNS=1 AGENT=1 AGENT_PEV=1 TRACE=1`, development set. One run per
configuration, so **no variance** and not citable. Kept only as an early signal.
Headline observation on the hard domain `multi_tenant_saas`: `agent_pev` reached
hard-recall 5/6 vs. the free `agent` 1/6, i.e. the structured pipeline closed
the agent's gap on the hardest architecture. To be confirmed by the `RUNS=5`
sweep.

## 2026-10-20 — Deepening failure analysis and acceptance criteria

**Deepening is not adaptive (measured, not assumed).** After the empty-response
fix, the PEV agent issues real tool calls on 100/100 prioritized elements, but
inspecting the stored `parsed_action` of every deepening step shows the calls
are not meaningful exploration:

- **300 deepening tool calls, all `search_knowledge`; `get_connections`: 0.**
  The agent never uses the connection-exploration tool (the one that could
  surface shared-resource / tenant-isolation threats).
- **35/100 elements issued at least one word-for-word identical repeat query.**
  With a deterministic retriever such a repeat returns the same snippets, i.e.
  is information-free.
- **Every element ends on `budget_exhausted`, never `done`.** The agent spends
  its full 3-call budget regardless of the element.

Conclusion: the agent executes its actions (goal 1) but does not yet make
sensible, information-gaining decisions (goal 2). This explains mechanistically
why deepening produced no quality gain — little new information entered.

**Status of the current numbers.** The 5-run baseline ("RAG wins on 4/5") is a
**development-phase finding**, not the final result, because the agent was still
being debugged and does not yet meet the criteria below.

### Acceptance criteria for a "functioning" adaptive agent (set before tuning)

Fixed in advance so the agent is not tuned until it happens to beat RAG. The
agent need not beat RAG — that is the question — but it must:

1. Choose sensibly among `search_knowledge`, `get_connections`, and `done`
   (not call one tool exclusively).
2. Not repeat identical search queries.
3. Produce tool calls that return genuinely new, relevant information.
4. Not be required to exhaust its budget on every element (early `done` allowed
   and expected when enough is known).

Only after these hold do we freeze the implementation and run the final
comparison (including the untouched holdout set).

## 2026-10-20 — Deepening ablation and the adaptive-prompt iteration (n=1, multi_tenant_saas)

One diagnostic run each on `multi_tenant_saas` (dev architecture). n=1, so these
are qualitative signals, not statistics; threat-level keys (`matched_keys` /
`missed_keys`) were compared, not just counts.

| Variant | deepen outcome | tool calls | F1 | matched / missed |
|---|---|---|---|---|
| `agent_pev` (baseline) | `budget_exhausted` ×4 | 3 `search_knowledge` per element, 0 `get_connections` | 0.52 | 8 / 4 |
| `agent_pev_nodeepen` | — (no deepening) | 0 | 0.48 | 8 / 4 |
| `agent_pev_adaptivedeepen` | `done` ×4 | 0 | 0.48 | 8 / 4 |

Findings:

1. **The agent's deepening decision is prompt-framed, not situation-driven.**
   The baseline prompt ("you have 3 steps") makes it spend all three every
   time; the adaptive prompt ("stopping is good, only investigate an open
   question") makes it stop immediately every time. Neither produced
   element-dependent behaviour. Acceptance criterion 1 (choose sensibly among
   the tools) is **not met** by either prompt on this model.

2. **Deepening changed no threat match.** `agent_pev` and
   `agent_pev_adaptivedeepen` produced byte-identical `matched_keys` and
   `missed_keys` — the three extra tool calls per element did not add or remove
   a single detected threat.

3. **The only measurable effect of deepening was precision.** Baseline avoided
   2 false positives (F1 0.52 vs 0.48, same 8 true positives), i.e. the extra
   context slightly helped rejection, not discovery. Weak at n=1.

Interpretation (scoped): with `llama3.1:8b`, the decision *whether* to explore
was governed by prompt wording rather than by the element's actual information
need. This points to a model-capability limit for adaptive tool use, not a
prompt bug — the same model handles Plan/Explore/Verify JSON fine. A
tool-calling-tuned model is the natural next comparison, changing only
`OLLAMA_MODEL`.

## 2026-10-25 — Four-way PEV ablation (V1 scoring)

**Evaluation basis: V1.** Everything in this section is scored with the V1 rule
`(target, category)` (frozen under tag `v1-benchmark`, see `frozen/v1/MANIFEST.md`).
It says nothing about whether a matched key states the right *cause*. The V2
root-cause evaluation (`V2_SPEC.md`) is **not finished**: gate G3 has not passed
and no comparative V2 result of real runs exists. V1 and V2 figures are therefore
never mixed in this log.

**Data.** One sweep on the five development architectures, `RUNS=5`, model
`llama3.1:8b`, `temperature=0`. 125 rows in `results/results.jsonl` (timestamps
2026-10-25 20:10 to 23:58): 25 per approach, n=5 in every
(approach, architecture) cell. Rows written on 2026-11-03 in the same file belong
to the separate V2 capture and are excluded here.

| Config | Plan | Explore | Verify | env | label |
|---|---|---|---|---|---|
| PEV | yes | yes | yes | `AGENT_PEV=1` | `agent_pev` |
| NoPlan | no | yes | yes | `AGENT_PEV_NOPLAN=1` | `agent_pev_noplan` |
| NoVerify | yes | yes | no | `AGENT_PEV_NOVERIFY=1` | `agent_pev_noverify` |
| ExploreOnly | no | yes | no | `AGENT_PEV_EXPLOREONLY=1` | `agent_pev_noplan_noverify` |

### Results (V1, mean of 5 runs)

F1, and mean TP/FP in brackets:

| Architecture | PEV | NoPlan | NoVerify | ExploreOnly |
|---|---|---|---|---|
| simple_web_api | 0.571 (4/2) | 0.714 (5/1) | 0.471 (4/5) | 0.714 (5/1) |
| webapp_with_auth | 0.474 (9/10) | 0.513 (10/10) | 0.500 (11/14) | 0.476 (10/13) |
| microservices_async | 0.483 (14/19) | 0.517 (15/18) | 0.418 (14/28) | 0.448 (15/27) |
| cloud_ingest_pipeline | 0.452 (7/11) | 0.485 (8/12) | 0.513 (10/16) | 0.487 (9/15) |
| multi_tenant_saas | 0.516 (8/11) | 0.571 (8/8) | 0.526 (10/16) | 0.545 (9/12) |
| **Sum TP / FP** | **42 / 53** | **46 / 49** | **49 / 79** | **48 / 68** |

Cost per architecture run (mean over all 25 runs): PEV 35 LLM calls / 194 s,
NoPlan 22 / 143 s, NoVerify 24 / 122 s, ExploreOnly 11 / 89 s.

### What the data supports

1. **NoPlan has the higher F1 than PEV on all five development architectures**
   (differences +0.033 to +0.143; the largest, on `simple_web_api`, is one true
   positive and one false positive). The effect is small in absolute terms: +1 TP
   on four architectures and +0 on `multi_tenant_saas`, where the gain comes from
   fewer false positives (8 instead of 11). Summed, 46 vs. 42 TP.
2. **NoPlan is not a superset of PEV.** It matches 7 keys PEV does not
   (`tampering` x4, `denial_of_service`, `repudiation`, `elevation_of_privilege`)
   and misses 3 keys PEV matches (`spoofing`, `repudiation`,
   `information_disclosure`). The earlier reading "NoPlan finds the categories PEV
   overlooks" holds as a tendency toward `tampering`, not as a rule.
3. **Verify trades precision for recall, with no clear net effect on F1.** Removing
   it raises false positives sharply (53 to 79 for NoVerify, 49 to 68 for
   ExploreOnly relative to NoPlan) and also raises true positives (49 and 48). F1
   against PEV is higher on three of five architectures for NoVerify and lower on
   two. No monotone "Verify helps F1" claim is supported.
4. **Cost.** NoPlan needs 22 instead of 35 LLM calls (37 % fewer) at a higher F1.
   ExploreOnly needs 11 calls with F1 comparable to PEV (higher on four of five
   architectures, lower on `microservices_async`).
5. **Against Fixed RAG.** RAG F1 on the same architectures is 0.714 / 0.600 /
   0.582 / 0.562 / 0.625, so RAG is **at least as high as NoPlan on all five**
   (tied on `simple_web_api`, ahead by 0.054 to 0.087 elsewhere) and ahead of PEV
   on all five. RAG needs 11 calls. Evidence limit: the RAG rows exist as repeated
   single runs (`run_index=0`, two sessions, identical values); the raw rows of the
   original RUNS=5 baseline sweep are no longer in the repository (only the
   figures quoted in `RESULTS.md`). RAG code, knowledge base and benchmark files
   are unchanged since that sweep (`git log` on `src/RAG`, `data/`, `benchmark/`).

### Limits of this evidence

- **±0.00 is not a sample.** In all 25 cells TP, FP, FN and F1 have standard
  deviation 0 and the `matched_keys` are identical across the five runs. This is
  reproducibility of one deterministic path, not five independent samples. There is
  no variance estimate and no significance statement. V2_SPEC.md G1 states that
  `temperature=0` does not guarantee bit-identical output; the identity observed
  here is an observation, not a guarantee.
- **V1 only.** A matched key can state a different cause than the ground truth,
  and a correct finding with another STRIDE label counts as an error. Differences
  of one true positive are within what this scoring can distinguish from label
  noise. The V2 evaluation exists to answer exactly that and is not finished.
- **Development set, ground truth unreviewed by a second person.** The ground
  truth was AI-drafted; V2 freezes cause lists for two architectures only.
- **Verify loss is thinly evidenced.** The only threat-level check of what Verify
  dropped is the earlier single `multi_tenant_saas` run: 7 candidates dropped, 2 of
  them in the ground truth (`document_service:elevation_of_privilege`,
  `object_store:repudiation`). Traces with `dropped_keys` exist for more
  architectures, but they have not been compared with the ground truth. The
  statement "Verify drops some correct threats" is therefore a one-architecture
  observation, not a result.
- **Plan effect is not isolated.** `noplan` also removes prioritization and
  deepening. Deepening was neutral in the 2026-10-20 comparison (n=1, one
  architecture), so the plan hypotheses are the remaining candidate, but no
  experiment removes only the hypotheses.

### Status of the explanation

"The plan hypotheses narrow the STRIDE search space" is a **hypothesis consistent
with** the table, not a demonstrated mechanism. Finding 2 shows the effect is
mixed. It stays a working hypothesis until the V2 evaluation or a
hypotheses-only ablation tests it.

## 2026-11-04 — V1 results versus the unfinished V2 evaluation

| | V1 results (this log, `RESULTS.md`) | V2 root-cause evaluation |
|---|---|---|
| Scoring unit | `(target, category)` | root cause (`V2_SPEC.md` D1) |
| Ground truth | V1 ground truth, unchanged | GT V2.0, frozen for `multi_tenant_saas` and `cloud_ingest_pipeline` only |
| Status | complete, frozen under tag `v1-benchmark` | annotation protocol, claim scorer, review ledger and gate G3 are implemented and tested on synthetic data; **no real annotation has been scored, G3 has not passed, no comparative result exists** (`V2_SPEC.md`, section 12 and change log) |
| May be cited as | V1 findings, with the limits above | nothing yet |

The V2 capture (123 predictions, commit `627a42e`) and the V2 annotation files are
unchanged by this entry. Every claim in the sections above is a V1 claim. Whether
the V1 ranking (RAG above NoPlan above PEV) survives cause-level scoring is an open
question that this log does not answer.

## Next

1. **Diagnostic model comparison** (below): done, see "Result". Open from it:
   whether native tool calling (which Ollama lists for Qwen) behaves differently
   from the text-JSON format used here.
2. V2: continue with the annotation and gate G3 as specified; no agent
   architecture work and no holdout evaluation before that.

## Diagnostic: is situation-dependent tool choice limited by the model?

**Status: run on 2026-11-04 and repeated on 2026-11-11 (see "Result" below).**
Written before any Qwen output existed, so the reading of the outcome cannot be
adapted to the result. The criteria in this section are unchanged.

**Why.** On `llama3.1:8b` the adaptive-deepening decision followed the prompt
wording instead of the element (always three searches under the baseline prompt,
always `done` under the adaptive prompt; 2026-10-20, n=1). Two explanations are
open: (a) a capability limit of this model for adaptive tool use, (b) the prompt
design or the deepening step itself. A different model on identical code and
prompts can speak to (a). It cannot settle it.

**Scope.** Primary research question: does agentic exploration improve
automated threat modeling compared with simpler RAG approaches, and at what
computational cost? This diagnostic is a sub-question about the model, not a new
agent design.

**Setup (nothing changes except the model).**

| Item | Value |
|---|---|
| Architecture | `multi_tenant_saas` (development set) |
| Models | `llama3.1:8b` (existing reference rows) and `qwen2.5:7b` (new) |
| Approaches | `agent_pev` and `agent_pev_adaptivedeepen` (the two deepening prompts), `RUNS=1` |
| Prompts, agents, retriever, knowledge base | unchanged |
| Trace | `TRACE=1`, so `parsed_action` / `termination_reason` of every deepening step is stored |
| Isolation | `scripts/ollama_smoke_test.py` sandbox (temporary directory outside the repository, controlled environment, checksum guard on `results/` and `frozen/`) |
| Holdout | not touched |

**Observations that would support a model-capability limit** (set in advance):

- Qwen's deepening choice also follows the prompt rather than the element: the
  same termination under one prompt for all four prioritized elements (all
  `budget_exhausted`, or all `done`), identical to llama's pattern.
- Same degenerate tool mix: only `search_knowledge`, no `get_connections`.
- Repeated identical queries within an element.
- Invalid JSON or unknown tools at a rate clearly above llama's. Reference
  from the 2026-10-25 ablation window: all 200 deepening steps of the 50
  `agent_pev` traces ended `budget_exhausted`; none ended `invalid_json`,
  `unknown_tool`, `tool_error` or `done`.

**Observations that would speak against it** (the limit is then not simply the
model):

- Element-dependent choices under one prompt: different `termination_reason`s or
  different tools for different prioritized elements of the same run.
- `get_connections` chosen for elements where the relationship is the open
  question (for example `shared_db`, `document_service`).
- `done` early on some elements and further tool calls on others, without
  repeated identical queries.

**Inconclusive outcomes** (stated so they are not over-read):

- Qwen fails to follow the JSON format at all: a format-adherence difference, not
  evidence about adaptive decisions.
- Qwen differs from llama but is still prompt-driven in the same way: no support
  for either reading.
- Mixed pattern: report as mixed.

**How to read one run.** `RUNS=1` on one architecture with four prioritized
elements is a diagnostic hint. It can show the pattern; it cannot establish a
rate. `temperature=0` does not guarantee reproducibility (`V2_SPEC.md` G1), so a
second run could differ. Detection quality (F1, matched keys) of the Qwen run is
reported for completeness but is **not** used to rank models.

### Result (run 2026-11-04, repeated 2026-11-11)

**What ran.** `qwen2.5:7b` (digest `845dbda0ea48`, Q4_K_M, 4096-token context) on
`multi_tenant_saas`, `agent_pev` and `agent_pev_adaptivedeepen`, `RUNS=1`, with the
agents, prompts, retriever and knowledge base unchanged, through
`scripts/run_qwen_diagnostic.sh --run` (sandbox outside the repository, checksum
guard on `results/` and `frozen/`). Code commit `4e8e01b` with uncommitted V2
work in the tree. Outputs: `diagnostic_runs/qwen2.5-7b_20261104T215229/` and
`diagnostic_runs/qwen2.5-7b_20261111T215140/` (gitignored). Duration about 4
minutes per run (135 s and 107 s of model time).

**The repeat matches the first run exactly:** same plan priorities, identical
deepening steps for every element, identical `matched_keys`, identical LLM calls
(34 and 28), tokens (15 497 and 14 517) and retrieval calls (17 and 11). Only the
runtime differed by 1 to 2 seconds. That is reproducibility of this one setup on
this machine, not a rate and not a guarantee (`V2_SPEC.md` G1).

**Observations against the pre-registered lists** (both runs identical):

| Pre-registered observation | Qwen |
|---|---|
| Same termination for all prioritized elements under one prompt (supports) | Adaptive prompt: yes, 5/5 `done`, no tool call (llama: 4/4). Baseline prompt: no, 4 `tool_error` and 1 `budget_exhausted`. |
| Only `search_knowledge`, no `get_connections` (supports) | Not met: `get_connections` was attempted for all 5 elements and succeeded once. |
| Repeated identical queries (supports) | Met once: `shared_db` repeats `shared_db STRIDE threats`. |
| `invalid_json` / `unknown_tool` above llama (supports) | Not met: 0 and 0. |
| Element-dependent behaviour (against) | Met by the outcome-based indicator, but see reading below. |
| `get_connections` for relationship elements such as `shared_db` (against) | Met once (`shared_db`, correct id). It was also attempted for the other four elements. |
| Early `done` on some elements, tool calls on others (against) | Not met. |

Per the rule "mixed pattern: report as mixed", the outcome is **mixed**. It
neither supports nor speaks against a model-capability limit.

**Reading of the baseline pattern.**

- The tool *choice* is the same for every element: `search_knowledge`, then
  `get_connections`. Four times Qwen wrote the template placeholder `<id>` from the
  prompt example as the `component_id`, which is a `tool_error`. Only for
  `shared_db` the id was real, so only there the loop went on (one more search,
  then `budget_exhausted`). The difference between elements is whether the
  argument was filled in correctly, not which tool was chosen.
- The outcome-based indicator `element_dependent_behaviour: True` therefore
  mixes choice and argument filling. The indicator
  `tool_choice_same_over_common_prefix` below separates them and is `True`.
- `tool_error` and copying a placeholder were not in the pre-registered lists.
  They are not read into either direction. They show a problem with argument
  filling, which is a different question from situation-dependent choice.
- Our loop ends deepening at the first `ToolError` (`structured.py`, `_deepen`).
  The `tool_error` endings are partly a product of that code. Llama never hit it.

**Post hoc addition (not in the pre-registration).** After the first Qwen run
`scripts/diagnostic_report.py` gained `attempted_tool_sequences`,
`tool_choice_same_over_common_prefix` and `placeholder_argument_steps`, marked as
post hoc in the report's `meta`. They were added because the outcome-based
indicator could not tell choice from argument errors. Both runs were re-reported
with them into `posthoc/` of each run directory; the original reports are
unchanged. The pre-registered reading rules were not touched.

| (both runs) | `agent_pev` | `agent_pev_adaptivedeepen` |
|---|---|---|
| `attempted_tool_sequences` | `search_knowledge > get_connections` x4; `search_knowledge > get_connections > search_knowledge` x1 | `done` x5 |
| `tool_choice_same_over_common_prefix` | True | True |
| `placeholder_argument_steps` | 4 | 0 |

**Limits.**

- One architecture, one model, one prompt pair, two identical runs. The two runs
  are one observation, not two.
- Qwen planned five priorities (`tenant_user` in addition), the pre-registration
  assumed four. This does not change any criterion.
- **Format caveat.** The agents ask for a JSON action as plain text and parse it.
  They do not use native tool calling, which Ollama lists as a capability of this
  Qwen build (`capabilities: completion, tools`). A difference or similarity with
  llama under this format says little about either model's native tool-calling
  ability. Whether native tool calling changes the placeholder errors or the
  `done` pattern is untested.
- **Context length.** The client sets no `num_ctx`, so Ollama ran Qwen with its
  default of 4096 tokens (`ollama ps`), although the model supports 32 768. A
  prompt longer than that is truncated by the server. Whether this played a role
  in the placeholder errors is not known; it is a possible confound for this
  model and the same default applied to the llama runs.
- The baseline prompt contains the literal template
  `{"component_id": "<id>"}`. Copying it is a plausible prompt-design effect as
  well as a model effect. The diagnostic cannot separate the two.
- Detection quality (reported, not used to rank models): `agent_pev` F1 0.30
  (TP/FP/FN 4/11/8), `agent_pev_adaptivedeepen` F1 0.41 (6/11/6); calls 34 vs 28.

**What this does and does not say.** Qwen reproduces the llama pattern under the
adaptive prompt (always `done`) and shows a uniform tool sequence under the
baseline prompt, with failures at argument filling. Nothing in the data shows
element-dependent tool choice from either model. It does not show that a stronger
or differently prompted model could not, and it does not decide between the two
open explanations (model capability versus prompt and loop design).

## How to run the measurements

Requires a running Ollama server (`ollama serve`) and the model pulled
(`ollama pull llama3.1:8b`). All runs append to `results/results.jsonl`;
aggregate with `aggregate.py` (now also reports mean LLM calls / retrieval
calls / tokens so quality can be weighed against cost).

**Step 0 — smoke test first (not for conclusions).** One run, one architecture,
every PEV variant, with traces. Confirms each variant completes and writes a
valid trace before committing to the long sweep:

```bash
RUNS=1 ONLY=multi_tenant_saas \
  AGENT_PEV=1 AGENT_PEV_NOPLAN=1 AGENT_PEV_NOVERIFY=1 AGENT_PEV_RICHDEEPEN=1 \
  TRACE=1 uv run python main.py
uv run python trace_summary.py
```

**Step 1 — baseline sweep (quality + cost, means + std).** No traces (keeps it
faster; traces are for diagnosis, not headline numbers):

```bash
RUNS=5 RAG=1 AGENT=1 AGENT_PEV=1 uv run python main.py
uv run python aggregate.py
```

**Step 2 — ablation sweep.** Baseline alongside the two ablations, so the deltas
are directly comparable:

```bash
RUNS=5 AGENT_PEV=1 AGENT_PEV_NOPLAN=1 AGENT_PEV_NOVERIFY=1 uv run python main.py
uv run python aggregate.py
```

**Step 3 — rich-deepen variant (behaviour, so keep traces).** Compare the real
deepening rate against the baseline via the trace summary:

```bash
RUNS=5 AGENT_PEV=1 AGENT_PEV_RICHDEEPEN=1 TRACE=1 uv run python main.py
uv run python trace_summary.py
```

> Cost warning: a single PEV run makes several LLM calls per element. The full
> ablation sweep is ~100 agent runs plus RAG and the free agent, so expect well
> over an hour on local Ollama. Run Step 0 first.
