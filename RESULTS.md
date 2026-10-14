# Results

Comparison of the three threat-modeling approaches across five benchmark
architectures of increasing complexity. Figures are the mean over 5 runs per
configuration; the LLM-backed approaches used **Ollama `llama3.1:8b`** at
`temperature=0`. Precision/recall/F1 showed ±0.00 standard deviation across
runs (only latency varied), so at temperature 0 the pipeline is effectively
deterministic in content.

> These are current measurements, not final conclusions. Ground truth and the
> knowledge base are curated drafts still pending domain review, and the agent
> implementation is being hardened. See "Caveats" below.

## Overall F1 by architecture

| Architecture | difficulty focus | Deterministic | Fixed RAG | Agent |
|---|---|---|---|---|
| simple_web_api | easy/medium | 0.40 | **0.71** | 0.57 |
| webapp_with_auth | trust boundaries | 0.54 | **0.60** | 0.32 |
| microservices_async | mostly easy | **0.81** | 0.58 | 0.30 |
| cloud_ingest_pipeline | hard (AWS config) | 0.38 | **0.56** | 0.58 |
| multi_tenant_saas | hard (authorization) | 0.50 | **0.62** | 0.62 |

## Recall on the hard class (the key comparison)

Hard threats require security knowledge / configuration or authorization
reasoning that is not expressed as a single attribute.

| Architecture | Deterministic | Fixed RAG | Agent |
|---|---|---|---|
| cloud_ingest_pipeline | 0.00 | **0.71** | 0.29 |
| multi_tenant_saas | 0.00 | **0.83** | 0.67 |

## Latency (mean seconds per architecture)

| Architecture | Deterministic | Fixed RAG | Agent |
|---|---|---|---|
| simple_web_api | 0.0 | 17 | 23 |
| webapp_with_auth | 0.0 | 59 | 269 |
| microservices_async | 0.0 | 93 | 292 |
| cloud_ingest_pipeline | 0.0 | 60 | 51 |
| multi_tenant_saas | 0.0 | 61 | 340 |

## Key findings

1. **The deterministic baseline is precise but blind to hard threats.**
   Precision is 1.00 everywhere (no false positives) and it covers all easy
   threats, but hard-class recall is 0.00 in both hard domains. It only wins
   outright on `microservices_async`, which is ~68% easy threats that fixed
   rules cover perfectly.

2. **Fixed RAG is the best overall trade-off.** It leads or ties on F1 on four
   of five architectures and is the only approach that cracks hard threats in
   *both* domains (0.71 AWS-config, 0.83 authorization), at moderate latency.
   The cost is lower precision (0.47–0.83): the 8B model invents plausible but
   non-ground-truth threats as complexity grows.

3. **The agent does not pay off with an 8B model.** After design improvements
   (enforced full-element coverage, all-STRIDE prompting) it improved markedly
   versus a naive version (e.g. simple_web_api F1 0.33 → 0.57, cloud hard
   recall 0.14 → 0.29), but it is still generally weaker than RAG and **3–5×
   slower** (up to ~340 s per architecture). Free exploration adds little when
   the full architecture is already given.

4. **Answer to the research question.** With a small local model, agentic
   exploration is not worth it for this task: the simpler fixed RAG workflow
   delivers better quality at a fraction of the latency. Agentic reasoning
   would need either a stronger model or a task that genuinely requires
   exploration to justify its cost.

## Caveats

- **Single model only** (`llama3.1:8b`). Whether the agent's disadvantage is
  model-bound or structural is not yet established; a run with a stronger model
  is the planned control experiment.
- **Agent implementation is still being hardened** (e.g. moving from a
  plain-text transcript to a structured message format), to rule out that its
  results are due to implementation rather than to the agentic approach itself.
- **Curated data pending review.** Ground truth and knowledge base are drafts;
  an error there would bias all three approaches at once.
- **RAG retrieval vocabulary** was aligned with architecture config keys
  (conservatively, not per ground-truth); disclosed here for transparency.
- Measurements come from a single 5-run sweep; `temperature=0` kept content
  variance at zero across runs, but this is one machine / one session.
