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