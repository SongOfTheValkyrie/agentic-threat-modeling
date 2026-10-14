# Results

Comparison of the three threat-modeling approaches across five benchmark
architectures of increasing complexity. The LLM-backed approaches used **Ollama
`llama3.1:8b`** at `temperature=0`. The agent uses a structured multi-turn
message format (see "Agent implementation" below). Figures are mean over a
5-run sweep; content variance was ±0.00 at temperature 0 (only latency varied).

> These are scoped, current measurements, not final conclusions. The ground
> truth is AI-drafted and still needs domain validation; the agent and RAG
> share one knowledge base, so this compares retrieval *orchestration*, not
> access to new information. See "Caveats and limitations" before citing.

## Overall F1 by architecture

| Architecture | difficulty focus | Deterministic | Fixed RAG | Agent |
|---|---|---|---|---|
| simple_web_api | easy/medium | 0.40 | **0.71** | 0.55 |
| webapp_with_auth | trust boundaries | 0.54 | **0.60** | 0.16 |
| microservices_async | mostly easy | **0.81** | 0.58 | 0.19 |
| cloud_ingest_pipeline | hard (AWS config) | 0.38 | **0.56** | 0.44 |
| multi_tenant_saas | hard (authorization) | 0.50 | **0.62** | 0.25 |

## Recall on the hard class (the key comparison)

Hard threats require security knowledge / configuration or authorization
reasoning that is not expressed as a single attribute.

| Architecture | Deterministic | Fixed RAG | Agent |
|---|---|---|---|
| cloud_ingest_pipeline | 0.00 | **0.71** | 0.29 |
| multi_tenant_saas | 0.00 | **0.83** | 0.17 |

## Latency (seconds per architecture)

| Architecture | Deterministic | Fixed RAG | Agent |
|---|---|---|---|
| simple_web_api | 0.0 | 18 | 13 |
| webapp_with_auth | 0.0 | 64 | 34 |
| microservices_async | 0.0 | 100 | 61 |
| cloud_ingest_pipeline | 0.0 | 65 | 32 |
| multi_tenant_saas | 0.0 | 65 | 30 |

## Agent vs. RAG gap by complexity

A central hypothesis was that the agent might *catch up* on more complex
architectures. The data does not support that (mean F1 over 5 runs):

| Architecture (increasing complexity) | RAG | Agent | gap (RAG−Agent) |
|---|---|---|---|
| simple_web_api | 0.71 | 0.55 | 0.17 |
| webapp_with_auth | 0.60 | 0.16 | 0.44 |
| microservices_async | 0.58 | 0.19 | 0.39 |
| cloud_ingest_pipeline | 0.56 | 0.44 | 0.12 |
| multi_tenant_saas | 0.62 | 0.25 | 0.38 |

The gap does not shrink with complexity, and on the two hard architectures RAG
stays clearly ahead (hard recall 0.71 vs 0.29 and 0.83 vs 0.17). With n=5 this
is an exploratory observation, not a general claim, but it shows **no sign of a
complexity advantage for the agent** in this setup.

## Key findings

1. **The deterministic baseline is precise but blind to hard threats.**
   Precision is 1.00 everywhere (no false positives) and it covers all easy
   threats, but hard-class recall is 0.00 in both hard domains. It only wins
   outright on `microservices_async`, which is ~68% easy threats that fixed
   rules cover perfectly.

2. **Fixed RAG scored best in this benchmark**, leading on F1 on four of five
   architectures and reaching the hard threats in both domains (recall 0.71 and
   0.83). This is a *relative* result: at F1 ≈ 0.56–0.71 RAG is the best of the
   three, not necessarily a strong threat-modeling solution in absolute terms.
   Its main weakness is precision (0.47–0.83) — but see the ground-truth caveat:
   some apparent false positives may be legitimate threats missing from the
   curated ground truth.

3. **The tested agent variants showed no measurable improvement.** We tried
   several designs on the same model (naive loop; enforced full-element
   coverage; plain-text vs. structured message format; an explicit reporting
   pass; a standing reminder). All landed at a similarly weak level: the agent
   either under-reports (good precision, low recall) or, when pushed to report
   more, invents false threats (precision collapses). We state this as an
   observation — the changes we tried did not help — and do **not** conclude the
   cause is the model rather than the implementation; tool design, prompting,
   context handling, or agent architecture could all still contribute.

4. **Answer to the research question (scoped).** *In our benchmark, with small
   local language models, Fixed RAG achieved better threat-modeling quality
   than the tested agentic approach at substantially lower latency. An
   additional benefit from agentic orchestration could not be demonstrated
   under these conditions.* This does not generalize to agentic AI as such, nor
   to stronger models or more sophisticated agents (see caveats).

## Agent implementation

The agent uses prompt-based tool calling (tools: list/inspect components and
flows, get_connections, search_knowledge, report_threat) in a structured
multi-turn message history (system / assistant / user roles). It shares the
same model and knowledge base as RAG, so the only difference under test is the
agentic control flow. The loop detects repeated actions and blocks `finish`
until every element has been inspected.

A plain-text transcript variant scored higher on these benchmarks (e.g.
multi_tenant F1 0.62 vs 0.25 with messages). We kept the structured message
format because it is the standard-conforming implementation and report its
(lower) scores honestly rather than selecting the format that happened to score
best. We do not have enough evidence to say why the formats differ on the 8B
model.

## Caveats and limitations

- **Ground truth is the biggest risk (validate first).** The five architectures
  are synthetic and their ground truth was AI-drafted. If it is incomplete or
  wrong, precision/recall are distorted directly — e.g. an apparent RAG false
  positive may be a legitimate threat simply absent from the ground truth, which
  is plausible since threat modeling admits several valid models per
  architecture. This should be reviewed before further model comparisons.
- **The agent and RAG share the same 23-snippet knowledge base.** The agent has
  no tool that fetches information RAG cannot obtain; its only extra capability
  is exploring component *connections* and choosing its own queries. So this
  experiment primarily tests **fixed vs. dynamic retrieval orchestration over
  the same knowledge**, not the fuller promise of agentic AI (reaching new
  information sources, e.g. live CVE lookups or code analysis). Claims should be
  scoped accordingly.
- **The tested agent is deliberately simple** (a tool loop without planning,
  reflection, or verification). A more sophisticated agent might do better; and
  "simple" is not symmetric — a simple RAG workflow is closer to RAG's ceiling
  than a simple agent is to an agent's. This asymmetry favors RAG.
- **Small models only** (`llama3.1:8b`, cross-checked with `gemma2:9b`). The
  mediocre absolute F1 (~0.6) is likely in part a model limit; a stronger model
  might lift all approaches and could change the picture. Whether the agent's
  disadvantage is model-bound, task-bound, or implementation-bound is not
  established.
- **RAG retrieval vocabulary** was aligned with architecture config keys
  (conservatively, not per ground-truth); disclosed here for transparency.
- Figures come from a 5-run sweep on one machine/session; temperature 0 kept
  content variance at ±0.00 across repeats (only latency varied).
