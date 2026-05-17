# tawasolpay-risk-assistant

Threat-risk assistant prototype — ingest, enrich, score, and explain risks.

Structure (top-level):

- `data/` — raw, reference, processed datasets
- `scripts/` — helper scripts to fetch/parse/embed
- `src/` — library code (ingest, enrichment, scoring, retrieval, LLM)
- `api/` — FastAPI application
- `frontend/` — Next.js app (placeholder)
- `tests/` — unit test skeletons

See `pyproject.toml` for dependencies.
