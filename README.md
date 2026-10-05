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

The three approaches are toggled with environment variables so the default run
stays dependency-free:

```bash
# deterministic baseline only (no Ollama required)
uv run python main.py

# baseline + fixed RAG workflow
RAG=1 uv run python main.py

# baseline + agentic approach
AGENT=1 uv run python main.py

# all three approaches side by side
RAG=1 AGENT=1 uv run python main.py
```

Select a different Ollama model with `OLLAMA_MODEL`:

```bash
OLLAMA_MODEL=qwen2.5:7b RAG=1 uv run python main.py
```

> **Note:** LLM-backed approaches are not fully deterministic even at
> temperature 0. For reliable figures, run each configuration several times and
> average the results.

## Project Layout

```text
benchmark/   System architectures (*.json) and their STRIDE ground truth
data/        Curated security knowledge corpus for retrieval
src/
  models/        Architecture and threat data models + loaders
  deterministic/ Rule-based baseline
  RAG/           Knowledge base, retriever, query builder, LLM client, pipeline
  agent/         Tools and the agentic (tool-calling) threat modeler
  evaluation/    Precision / recall / F1 and per-difficulty metrics
  core.py        The ThreatModeler interface shared by all approaches
main.py      Benchmark runner comparing the approaches
```
