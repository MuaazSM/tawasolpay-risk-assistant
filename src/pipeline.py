"""End-to-end pipeline orchestrator.

Entry point: run_pipeline(top_k: int = 5) -> List[TopRiskOutput]

Steps: load -> enrich -> score -> take top-k -> for each: retrieve NIST
controls + generate explanation + validate faithfulness -> return.

Includes timing logs per step and a --cache flag to pickle intermediates
to data/processed/ for faster iteration during development.
"""
