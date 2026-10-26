"""Evaluation engines (Stages 2–4).

- deterministic: Stage 2 — rule engine, zero-LLM
- semantic:      Stage 3 — LLM intent alignment (llm | mock)
- scoring:       TIS computation (per-constraint, severity-weighted)
- evidence:      Stage 4 — AAA-style packet + hash chain
"""
