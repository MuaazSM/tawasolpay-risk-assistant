"""Retrieve relevant NIST 800-53 controls via semantic search over Chroma.

Entry point: retrieve_controls_for_risk(risk: EnrichedRisk, k: int = 3) -> List[NistControl]

Builds a deterministic query string from risk fields (vulnerability name,
affected component, asset type, campaign keywords) — no LLM in query
construction. Queries the persisted Chroma collection and returns top-k
NistControl objects. Optional family-boost for known mappings (e.g.,
auth issues -> AC, IA families).
"""
