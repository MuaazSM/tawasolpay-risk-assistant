"""Generate structured risk explanations via LLM.

Entry point: generate_explanation(risk, controls, campaigns) -> RiskExplanation

Constructs a prompt containing the full risk evidence packet, retrieved NIST
control texts, and relevant campaign data. Output schema: headline,
why_it_ranks_here, business_impact, cited_cves, cited_campaigns,
cited_controls, recommended_actions. Strict citation rules enforced in
prompt with few-shot examples of good vs hallucinated output.
"""
