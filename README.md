# Agentic Threat Modeling

> Comparing deterministic, RAG-based, and agentic approaches to automated threat modeling.

## Overview

Threat modeling is a structured process for identifying potential security threats in software systems and determining appropriate mitigations.

Traditional threat modeling approaches often rely on predefined frameworks and deterministic rules. Large Language Models (LLMs) make it possible to incorporate broader security knowledge through Retrieval-Augmented Generation (RAG), while agentic systems can go one step further by actively exploring a system architecture, retrieving information, and deciding which components or data flows require additional investigation.

This project investigates a simple question:

> **When is an AI agent actually worth it for threat modeling?**

To answer this, the project implements and evaluates three approaches on the same set of system architectures:

1. **Deterministic threat modeling**
2. **Fixed RAG + LLM workflow**
3. **Agentic RAG + tool use**

The goal is not to demonstrate that the most complex architecture performs best, but to measure the trade-offs between **threat detection quality, reliability, cost, latency, and system complexity**.

---

## Research Question

The main research question is:

> **Does agentic exploration improve automated threat modeling compared with deterministic and fixed RAG workflows, and at what cost?**

More specifically, the project investigates:

- How well can deterministic security rules identify threats?
- Does retrieval of external security knowledge improve threat coverage?
- Does iterative, agent-driven exploration provide additional value?
- Does the benefit of agentic reasoning increase with architecture complexity?
- How much additional latency and token usage does agentic execution introduce?
- Which failure modes occur in deterministic, RAG-based, and agentic systems?

---

## System Architecture

All approaches receive the same structured description of a software architecture and produce the same structured threat model.

```text
                     System Architecture
                            |
            +---------------+---------------+
            |               |               |
            v               v               v
     Deterministic      Fixed RAG       Agentic RAG
       Baseline          Workflow           Agent
            |               |               |
      STRIDE Rules       Retrieval       Tool Calls
            |               |               |
            |              LLM        Iterative Analysis
            |               |               |
            +---------------+---------------+
                            |
                            v
                       Threat Model
                            |
                            v
                        Evaluation
                            |
              +-------------+-------------+
              |             |             |
           Quality        Latency        Cost
```

A fourth approach, an agent variant (`agent_pev`), is evaluated alongside the
agentic RAG agent; see [Approaches](#approaches) below.

---

## Approaches

Four approaches are compared. All implement the same `ThreatModeler` interface
(`analyze(architecture) -> list[Threat]`), so the benchmark runner and evaluator
treat them identically. The three LLM-backed approaches share the **same** model,
retriever, and knowledge base, so what differs between them is the
*orchestration*, not access to new information.

| Label | Approach | Summary |
|---|---|---|
| `deterministic` | Rule-based baseline | Fixed STRIDE rules over element attributes. No LLM. Precise but blind to threats that need security knowledge. |
| `rag` | Fixed RAG workflow | Per element: build a fixed query, retrieve top-k knowledge, prompt the LLM, parse threats. Retrieval is fixed, not chosen by the model. |
| `agent` | Agentic RAG (free loop) | The model decides each step via tool calls (list / inspect / get_connections / search_knowledge / report_threat). Includes loop detection and a block on finishing before every element is inspected. |
| `agent_pev` | Plan–Explore–Verify agent | A hybrid pipeline: plan once, then deterministic iteration over all elements with mandatory retrieval and bounded plan-driven deepening, then a per-element verify phase. Design frozen in advance (`DESIGN_agent_pev.md`). |

### Agent execution traces

Both agent variants can record a step-by-step execution trace, which is how the
agents' behaviour (e.g. premature finishing, unused retrieval, candidates
dropped at verification) is diagnosed. Traces are written as JSON to
`results/traces/` when the `TRACE=1` environment variable is set (see
[Usage](#usage)). Capturing a trace does not change an agent's behaviour.

---

## Getting Started

### Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (used for dependency management)
- [Ollama](https://ollama.com/) — only needed for the RAG and agent approaches

### Setup

```bash
# install dependencies into a local virtual environment
uv sync
```

The deterministic baseline runs with no further setup. The RAG and agent
approaches additionally require a running Ollama server and a pulled model:

```bash
# start the Ollama server (leave running in its own terminal)
ollama serve

# pull the default model (~4.9 GB)
ollama pull llama3.1:8b
```

## Usage

The benchmark runner lives in `main.py`. It evaluates each enabled approach
against every benchmark architecture and reports precision, recall, F1, and
recall broken down by threat difficulty (easy / medium / hard), plus latency.
Every run is also appended as a JSON line to `results/results.jsonl` for later
aggregation.

The approaches are toggled with environment variables so the default run stays
dependency-free:

```bash
# deterministic baseline only (no Ollama required)
uv run python main.py

# baseline + fixed RAG workflow
RAG=1 uv run python main.py

# baseline + agentic approach (free tool-calling loop)
AGENT=1 uv run python main.py

# baseline + Plan-Explore-Verify agent
AGENT_PEV=1 uv run python main.py

# every approach side by side
RAG=1 AGENT=1 AGENT_PEV=1 uv run python main.py
```

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `RAG` | off | Enable the fixed RAG workflow (needs Ollama). |
| `AGENT` | off | Enable the agentic (free-loop) approach (needs Ollama). |
| `AGENT_PEV` | off | Enable the Plan–Explore–Verify agent (needs Ollama). |
| `OLLAMA_MODEL` | `llama3.1:8b` | Model used by all LLM-backed approaches. |
| `RUNS` | `1` | Repeat the full sweep N times, each with a distinct run index, so LLM variance can be captured. |
| `HOLDOUT` | off | Run the held-out test architectures (`benchmark/holdout/`) instead of the development set. |
| `ONLY` | off | Comma-separated architecture ids to narrow the run to (e.g. `ONLY=multi_tenant_saas`). Handy for a quick, targeted trace. |
| `TRACE` | off | Write a per-run agent execution trace to `results/traces/` (agents only). |

```bash
# five repeats of the agent to measure variance (no traces)
RUNS=5 AGENT=1 uv run python main.py

# one targeted trace of both agents on a single architecture (fast)
ONLY=multi_tenant_saas AGENT=1 AGENT_PEV=1 TRACE=1 uv run python main.py

# a different model
OLLAMA_MODEL=qwen2.5:7b RAG=1 uv run python main.py
```

### Aggregating results

`aggregate.py` reads `results/results.jsonl` and reports the mean and standard
deviation of precision, recall, F1, and latency across repeats, grouped by
approach, model, and architecture, plus mean per-difficulty recall:

```bash
uv run python aggregate.py
```

> **Note:** LLM-backed approaches are not fully deterministic even at
> temperature 0. For reliable figures, use `RUNS` to repeat each configuration
> and aggregate with `aggregate.py`.

## Project Layout

```text
benchmark/   System architectures (*.json) + STRIDE ground truth
  holdout/     Held-out test architectures for the final evaluation
data/        Curated security knowledge corpus for retrieval
results/     Appended run log (results.jsonl) and agent traces (traces/)
tests/       Pytest suite (deterministic, no Ollama required)
src/
  models/        Architecture and threat data models + loaders
  deterministic/ Rule-based baseline
  RAG/           Knowledge base, retriever, query builder, LLM client, pipeline
  agent/         Tools, the two agent variants, and execution tracing
  evaluation/    Precision / recall / F1, per-difficulty metrics, run records
  core.py        The ThreatModeler interface shared by all approaches
main.py            Benchmark runner comparing the approaches
aggregate.py       Aggregates results.jsonl into mean +/- std figures
DESIGN_agent_pev.md  Frozen design of the Plan-Explore-Verify agent
RESULTS.md           Current measured results and caveats
```

## Tests

The test suite is deterministic and offline (LLM-backed code paths use a fake
client), so it needs no Ollama server:

```bash
uv run pytest
```
