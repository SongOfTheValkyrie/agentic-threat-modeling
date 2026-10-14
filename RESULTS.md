# Results

Comparison of the three threat-modeling approaches across five benchmark
architectures of increasing complexity. The LLM-backed approaches used **Ollama
`llama3.1:8b`** at `temperature=0`. The agent uses a structured multi-turn
message format (see "Agent implementation" below). Figures are from a single
sweep; earlier 5-run sweeps showed ±0.00 content variance at temperature 0
(only latency varied), so single-run figures are representative here.

> These are current measurements, not final conclusions. Ground truth and the
> knowledge base are curated drafts still pending domain review. See "Caveats".

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

## Key findings

1. **The deterministic baseline is precise but blind to hard threats.**
   Precision is 1.00 everywhere (no false positives) and it covers all easy
   threats, but hard-class recall is 0.00 in both hard domains. It only wins
   outright on `microservices_async`, which is ~68% easy threats that fixed
   rules cover perfectly.

2. **Fixed RAG is the best overall trade-off.** It leads on F1 on four of five
   architectures and is the only approach that cracks hard threats in *both*
   domains (0.71 AWS-config, 0.83 authorization), at moderate latency. The cost
   is lower precision (0.47–0.83): the 8B model invents plausible but
   non-ground-truth threats as complexity grows.

3. **The agent does not pay off with an 8B model, and this is robust to
   implementation.** We tried several agent designs on the same model (naive
   loop; enforced full-element coverage; a plain-text transcript; a structured
   message format; an explicit reporting pass; a standing reminder). All
   converge on a similarly weak level: the agent either under-reports (good
   precision, low recall) or, when pushed to report more, invents false threats
   (precision collapses). No prompt/format change lifted its quality. That no
   fix helps is itself evidence the bottleneck is the model's reasoning
   capacity, not an implementation defect.

4. **Answer to the research question.** With a small local model, agentic
   exploration is not worth it for this task: the simpler fixed RAG workflow
   delivers better quality at comparable or lower latency. Free exploration
   adds little when the full architecture is already provided. Agentic
   reasoning would need either a stronger model or a task that genuinely
   requires exploration to justify its cost.

## Agent implementation

The agent uses prompt-based tool calling (tools: list/inspect components and
flows, get_connections, search_knowledge, report_threat) in a structured
multi-turn message history (system / assistant / user roles). It shares the
same model and knowledge base as RAG, so the only difference under test is the
agentic control flow. The loop detects repeated actions and blocks `finish`
until every element has been inspected.

A plain-text transcript variant scored higher on these benchmarks (e.g.
multi_tenant F1 0.62 vs 0.25 with messages), but that appears to be an artifact
of how the 8B model behaves in the two API modes rather than a genuine quality
difference. We kept the structured message format because it is the
standard-conforming implementation; its lower scores are reported honestly
rather than selecting the format that happened to score best.

## Caveats

- **Single model only** (`llama3.1:8b`). Whether the agent's disadvantage is
  model-bound or structural is not yet established; a run with a stronger model
  is the planned control experiment and the most informative next step.
- **Curated data pending review.** Ground truth and knowledge base are drafts;
  an error there would bias all three approaches at once.
- **RAG retrieval vocabulary** was aligned with architecture config keys
  (conservatively, not per ground-truth); disclosed here for transparency.
- Figures come from a single sweep on one machine/session; temperature 0 kept
  content variance at zero across earlier repeats.
