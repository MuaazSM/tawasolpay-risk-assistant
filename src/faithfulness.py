"""Validate LLM explanations against the evidence packet.

Entry point: validate_faithfulness(explanation, risk, retrieved_controls)

Checks every citation in the LLM output against allowlists derived from
the risk's evidence packet and retrieved NIST controls. Returns (passed,
violations) so callers can retry with violations injected into the prompt.
"""

import logging

from .schemas import EnrichedRisk, NistControl, RiskExplanation

logger = logging.getLogger(__name__)


def validate_faithfulness(
    explanation: RiskExplanation,
    risk: EnrichedRisk,
    retrieved_controls: list[NistControl],
) -> tuple[bool, list[str]]:
    """Check that every citation in the explanation traces to evidence.

    Args:
        explanation: The LLM-generated explanation to validate.
        risk: The enriched risk row that was explained.
        retrieved_controls: NIST controls retrieved for this risk.

    Returns:
        A tuple of (passed, violations). If passed is True, violations
        is an empty list.
    """
    violations: list[str] = []

    # --- CVE check ---
    # The risk's own CVE plus any CVEs surfaced via threat intel are valid
    allowed_cves = {risk.cve_id} | set(risk.threat_intel_matches)
    bad_cves = set(explanation.cited_cves) - allowed_cves
    if bad_cves:
        violations.append(
            f"cited_cves contains CVEs not in evidence: {sorted(bad_cves)}. "
            f"Allowed: {sorted(allowed_cves)}"
        )

    # --- Campaign check ---
    allowed_campaigns = set(risk.campaign_matches)
    bad_campaigns = set(explanation.cited_campaigns) - allowed_campaigns
    if bad_campaigns:
        violations.append(
            f"cited_campaigns contains campaigns not in evidence: {sorted(bad_campaigns)}. "
            f"Allowed: {sorted(allowed_campaigns)}"
        )

    # --- Control check ---
    allowed_controls = {c.control_id for c in retrieved_controls}
    bad_controls = set(explanation.cited_controls) - allowed_controls
    if bad_controls:
        violations.append(
            f"cited_controls contains controls not retrieved: {sorted(bad_controls)}. "
            f"Allowed: {sorted(allowed_controls)}"
        )

    # --- Non-empty checks ---
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

    # --- Recommended actions count (3-5) ---
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
