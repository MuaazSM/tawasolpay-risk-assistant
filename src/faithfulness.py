"""Validate LLM explanations against the evidence packet.

Entry point: validate_faithfulness(explanation, risk, retrieved_controls) -> Tuple[bool, List[str]]

Checks:
1. Every cited CVE exists in the risk's evidence or threat_intel_matches.
2. Every cited campaign appears in campaign_matches.
3. Every cited NIST control ID appears in retrieved_controls.
4. cited_cves, cited_campaigns, cited_controls are all non-empty.
5. recommended_actions has 3-5 items.

On failure, returns (False, list_of_violations) for retry logic.
"""
