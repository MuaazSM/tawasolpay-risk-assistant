"""Validate LLM explanation citations against the evidence packet."""

import logging

from .schemas import EnrichedRisk, NistControl, RiskExplanation

logger = logging.getLogger(__name__)


def validate_faithfulness(
    explanation: RiskExplanation,
    risk: EnrichedRisk,
    retrieved_controls: list[NistControl],
) -> tuple[bool, list[str]]:
    """Check that every citation in the explanation traces to evidence."""
    violations: list[str] = []

    # the risk's own CVE plus chain partners are valid citations.
    # threat_intel_matches contains TI row IDs (e.g. TI-3001), not CVEs.
    allowed_cves = {risk.cve_id} | set(risk.chain_partners)
    bad_cves = set(explanation.cited_cves) - allowed_cves
    if bad_cves:
        violations.append(
            f"cited_cves contains CVEs not in evidence: {sorted(bad_cves)}. "
            f"Allowed: {sorted(allowed_cves)}"
        )

    allowed_campaigns = set(risk.campaign_matches)
    bad_campaigns = set(explanation.cited_campaigns) - allowed_campaigns
    if bad_campaigns:
        violations.append(
            f"cited_campaigns contains campaigns not in evidence: {sorted(bad_campaigns)}. "
            f"Allowed: {sorted(allowed_campaigns)}"
        )

    allowed_controls = {c.control_id for c in retrieved_controls}
    bad_controls = set(explanation.cited_controls) - allowed_controls
    if bad_controls:
        violations.append(
            f"cited_controls contains controls not retrieved: {sorted(bad_controls)}. "
            f"Allowed: {sorted(allowed_controls)}"
        )

    if not explanation.cited_cves:
        violations.append("cited_cves must not be empty.")
    if not explanation.cited_campaigns and risk.campaign_matches:
        # only a violation if there *are* campaigns to cite
        violations.append(
            "cited_campaigns is empty but risk has campaign matches: "
            f"{risk.campaign_matches}"
        )
    if not explanation.cited_controls:
        violations.append("cited_controls must not be empty.")

    n_actions = len(explanation.recommended_actions)
    if n_actions < 3 or n_actions > 5:
        violations.append(
            f"recommended_actions has {n_actions} items; must be 3-5."
        )
    if not explanation.recommended_actions:
        violations.append("recommended_actions must not be empty.")

    passed = len(violations) == 0

    if not passed:
        logger.warning(
            "Faithfulness check failed for %s on %s: %s",
            risk.cve_id,
            risk.asset_name,
            violations,
        )
    else:
        logger.debug(
            "Faithfulness check passed for %s on %s",
            risk.cve_id,
            risk.asset_name,
        )

    return passed, violations
