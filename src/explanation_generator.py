"""Generate structured risk explanations via LLM.

Entry point: generate_explanation(risk, controls, campaigns) -> (RiskExplanation, list[str])

Constructs a prompt containing the full risk evidence packet, retrieved NIST
control texts, and relevant campaign data. Output schema: headline,
why_it_ranks_here, business_impact, cited_cves, cited_campaigns,
cited_controls, recommended_actions. Strict citation rules enforced in
prompt with few-shot examples of good vs hallucinated output.

After generation, the faithfulness checker validates all citations against the
evidence packet. On failure, one retry is attempted with violations injected
into the prompt. If the retry also fails, the explanation is returned with a
faithfulness_failed flag.
"""

import logging

from .faithfulness import validate_faithfulness
from .llm_client import generate_structured
from .schemas import Campaign, EnrichedRisk, NistControl, RiskExplanation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt construction helpers
# ---------------------------------------------------------------------------


def _build_evidence_block(risk: EnrichedRisk) -> str:
    """Format the risk's evidence into a readable text block for the prompt."""
    signals = []
    if risk.kev_match:
        signals.append("CISA KEV listed (known exploited)")
    if risk.kev_ransomware_use:
        signals.append("KEV ransomware association")
    if risk.threat_intel_weaponized:
        signals.append("weaponized exploit observed in threat intel")
    if risk.threat_intel_ransomware:
        signals.append("ransomware linkage via threat intel")
    if risk.campaign_ransomware:
        signals.append("ransomware linkage via campaign data")
    if risk.active_exploitation_signal:
        signals.append("active exploitation signal")

    lines = [
        "=== RISK EVIDENCE PACKET ===",
        f"Asset: {risk.asset_name} (ID: {risk.asset_id}, type: {risk.asset_type})",
        f"Internet-exposed: {risk.internet_exposed}",
        f"Last seen: {risk.last_seen_days} days ago",
        f"Owner: {risk.owner or 'unassigned'}",
        "",
        f"Business service: {risk.service_name} (criticality: {risk.business_criticality})",
        f"Business impact: {risk.business_impact_description}",
        f"Compliance scope: {risk.compliance_scope}",
        f"RTO: {risk.rto_hours} hours",
        "",
        f"Vulnerability: {risk.vuln_id}",
        f"CVE: {risk.cve_id}",
        f"CVSS: {risk.cvss}  Severity: {risk.severity}",
        f"Exploit maturity: {risk.exploit_maturity}",
        f"Description: {risk.description}",
        f"Days open: {risk.days_open}",
        "",
        f"Threat signals: {', '.join(signals) if signals else 'none'}",
        f"Threat intel matches: {risk.threat_intel_matches or 'none'}",
        f"Campaign matches: {risk.campaign_matches or 'none'}",
        f"Chain partners (same-campaign CVEs on this asset): {risk.chain_partners or 'none'}",
        f"Missing controls: {risk.missing_controls or 'none'}",
    ]
    return "\n".join(lines)


def _build_controls_block(controls: list[NistControl]) -> str:
    """Format retrieved NIST controls for the prompt."""
    if not controls:
        return "=== RETRIEVED NIST 800-53 CONTROLS ===\nNone retrieved."

    sections = ["=== RETRIEVED NIST 800-53 CONTROLS ==="]
    for ctrl in controls:
        sections.append(
            f"\n[{ctrl.control_id}] {ctrl.title} (family: {ctrl.family})\n"
            f"Statement: {ctrl.statement}\n"
            f"Discussion: {ctrl.discussion}\n"
            f"Related controls: {', '.join(ctrl.related_controls) if ctrl.related_controls else 'none'}"
        )
    return "\n".join(sections)


def _build_campaigns_block(
    risk: EnrichedRisk, campaigns: list[Campaign],
) -> str:
    """Format only the campaigns that matched this risk."""
    matched_names = set(risk.campaign_matches)
    relevant = [c for c in campaigns if c.name in matched_names]

    if not relevant:
        return "=== MATCHED CAMPAIGN DATA ===\nNo campaign matches for this risk."

    sections = ["=== MATCHED CAMPAIGN DATA ==="]
    for camp in relevant:
        sections.append(
            f"\nCampaign: {camp.name}\n"
            f"Associated CVEs: {', '.join(camp.associated_cves)}\n"
            f"Targeted asset types: {', '.join(camp.targeted_asset_types)}\n"
            f"TTPs: {'; '.join(camp.ttps)}\n"
            f"IOCs: {'; '.join(camp.iocs)}"
        )
    return "\n".join(sections)


def _build_allowlists(
    risk: EnrichedRisk,
    controls: list[NistControl],
) -> str:
    """Explicit allowlists so the LLM knows exactly what it may cite."""
    # threat_intel_matches are CVEs surfaced by threat intel — valid citations
    allowed_cves = sorted({risk.cve_id} | set(risk.threat_intel_matches))
    allowed_campaigns = sorted(set(risk.campaign_matches))
    allowed_controls = sorted({c.control_id for c in controls})

    return (
        "=== CITATION ALLOWLISTS (you MUST only cite from these) ===\n"
        f"Allowed CVEs: {allowed_cves}\n"
        f"Allowed campaigns: {allowed_campaigns}\n"
        f"Allowed control IDs: {allowed_controls}"
    )


# ---------------------------------------------------------------------------
# Few-shot examples — baked into prompt to steer citation behavior
# ---------------------------------------------------------------------------

_FEW_SHOT = """
=== EXAMPLE: GOOD OUTPUT (follow this pattern) ===
Given evidence for CVE-2024-21762 on asset "FortiGate-01" with campaign "CrimsonJackal — Gateway Breaker" and retrieved controls [SI-2, RA-5, SC-7]:

{
  "headline": "Critical Fortinet SSL-VPN RCE on internet-exposed gateway actively exploited by CrimsonJackal campaign.",
  "why_it_ranks_here": "CVE-2024-21762 carries a CVSS of 9.8 with weaponized exploit maturity and is listed in the CISA KEV catalog, confirming active exploitation in the wild. The CrimsonJackal — Gateway Breaker campaign specifically targets Fortinet appliances in financial services, and this asset is internet-exposed with Critical business criticality. Chain amplification applies because a second CrimsonJackal CVE is present on the same asset.",
  "business_impact": "Compromise of FortiGate-01 gives attackers a network entry point into the payment processing service. The CrimsonJackal campaign deploys LockBit 3.0 ransomware post-exploitation, which could halt transaction processing and trigger regulatory notification requirements.",
  "cited_cves": ["CVE-2024-21762"],
  "cited_campaigns": ["CrimsonJackal — Gateway Breaker"],
  "cited_controls": ["SI-2", "RA-5", "SC-7"],
  "recommended_actions": [
    "Apply the vendor patch for CVE-2024-21762 immediately per SI-2 flaw remediation requirements.",
    "Run an authenticated vulnerability scan against all Fortinet appliances per RA-5 to identify additional unpatched instances.",
    "Restrict SSL-VPN access to known IP ranges and enforce MFA per SC-7 boundary protection guidance."
  ]
}

=== EXAMPLE: BAD OUTPUT (DO NOT do this) ===
{
  "headline": "Critical vulnerability on firewall.",
  "why_it_ranks_here": "This is a serious vulnerability that could be exploited by attackers. CVE-2023-44228 is a well-known Log4Shell vulnerability. The APT29 threat group has been targeting similar infrastructure.",
  "cited_cves": ["CVE-2024-21762", "CVE-2023-44228"],
  "cited_campaigns": ["CrimsonJackal — Gateway Breaker", "APT29"],
  "cited_controls": ["SI-2", "RA-5", "AC-2"],
  "recommended_actions": ["Patch the vulnerability.", "Monitor the network."]
}
PROBLEMS: CVE-2023-44228 was NOT in the evidence. "APT29" was NOT a matched campaign. AC-2 was NOT a retrieved control. Recommendations are vague and not grounded in specific controls. Only 2 actions instead of 3-5.
""".strip()


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a cybersecurity risk analyst writing a structured explanation for why a specific risk ranks in the top 5 for a fintech company. You will be given:

1. A RISK EVIDENCE PACKET with asset details, vulnerability info, threat signals, and missing controls.
2. RETRIEVED NIST 800-53 CONTROLS with full statement and discussion text.
3. MATCHED CAMPAIGN DATA with TTPs and IOCs.
4. CITATION ALLOWLISTS — the exact CVEs, campaigns, and control IDs you may reference.

STRICT RULES:
- cited_cves: ONLY include CVEs from the allowlist. Never invent or add CVEs not in the evidence.
- cited_campaigns: ONLY include campaigns from the allowlist. Never reference threat groups or campaigns not matched to this risk.
- cited_controls: ONLY include control IDs from the allowlist. Never reference controls that were not retrieved.
- recommended_actions: Each action MUST reference a specific cited control by ID and describe a concrete step grounded in that control's statement. Provide 3 to 5 actions.
- headline: One sentence summarizing the risk. Be specific — name the CVE, asset, and threat.
- why_it_ranks_here: 3-4 sentences explaining the scoring factors (exposure, exploitation evidence, business criticality, chain amplification) that placed this risk in its tier.
- business_impact: 2-3 sentences describing what happens to the business if this risk is realized. Reference the business service and compliance scope.

If the evidence packet has no campaign matches, cited_campaigns should contain only the campaigns listed in the allowlist (which may be empty — use an empty list if so).

Write precisely. Every claim must trace back to the evidence provided. Hallucinating entities not in the evidence is a failure."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _build_retry_prompt(base_prompt: str, violations: list[str]) -> str:
    """Append faithfulness violations to the prompt for a correction retry."""
    violation_block = "\n".join(f"  - {v}" for v in violations)
    return (
        f"{base_prompt}\n\n"
        "=== FAITHFULNESS VIOLATIONS FROM YOUR PREVIOUS ATTEMPT ===\n"
        "Your previous response failed the citation check. Fix ALL of the\n"
        "following violations. Do NOT cite any entity not in the allowlists.\n\n"
        f"{violation_block}\n\n"
        "Respond with a corrected JSON object matching the RiskExplanation schema."
    )


def generate_explanation(
    risk: EnrichedRisk,
    controls: list[NistControl],
    campaigns: list[Campaign],
) -> tuple[RiskExplanation, list[str]]:
    """Generate an LLM-written explanation for a single scored risk.

    Constructs a prompt from the risk evidence, retrieved NIST controls,
    and matched campaign data, then calls the LLM with strict citation
    rules. The response is validated against the RiskExplanation schema
    and checked for faithfulness to the evidence packet.

    If the faithfulness check fails, one retry is attempted with violations
    injected into the prompt. If the retry also fails, the explanation is
    returned anyway with the violation list so the caller can surface them.

    Args:
        risk: A single enriched risk row (output of enrichment + scoring).
        controls: NIST 800-53 controls retrieved for this risk.
        campaigns: All parsed campaigns; only those matching the risk are
            included in the prompt.

    Returns:
        A tuple of (explanation, faithfulness_violations). An empty list
        means all citations checked out. A non-empty list contains human-
        readable descriptions of each violation.

    Raises:
        pydantic.ValidationError: If the LLM output fails schema validation
            (e.g., fewer than 3 recommended_actions).
        RuntimeError: If both LLM providers fail.
    """
    evidence = _build_evidence_block(risk)
    controls_text = _build_controls_block(controls)
    campaigns_text = _build_campaigns_block(risk, campaigns)
    allowlists = _build_allowlists(risk, controls)

    base_prompt = (
        f"{_SYSTEM_PROMPT}\n\n"
        f"{_FEW_SHOT}\n\n"
        f"Now produce the explanation for this risk:\n\n"
        f"{evidence}\n\n"
        f"{controls_text}\n\n"
        f"{campaigns_text}\n\n"
        f"{allowlists}\n\n"
        "Respond with a single JSON object matching the RiskExplanation schema."
    )

    logger.info(
        "Generating explanation for %s on %s (campaigns: %s, controls: %d)",
        risk.cve_id,
        risk.asset_name,
        risk.campaign_matches,
        len(controls),
    )

    # --- First attempt ---
    explanation = generate_structured(base_prompt, RiskExplanation)
    passed, violations = validate_faithfulness(explanation, risk, controls)

    if passed:
        return explanation, []

    # --- Retry once with violations injected ---
    logger.info(
        "Retrying explanation for %s on %s (%d violations)",
        risk.cve_id,
        risk.asset_name,
        len(violations),
    )
    retry_prompt = _build_retry_prompt(base_prompt, violations)
    explanation = generate_structured(retry_prompt, RiskExplanation)
    passed, violations = validate_faithfulness(explanation, risk, controls)

    if passed:
        logger.info(
            "Retry succeeded for %s on %s", risk.cve_id, risk.asset_name,
        )
        return explanation, []

    # --- Both attempts failed — return with violations ---
    logger.error(
        "Faithfulness check failed after retry for %s on %s: %s",
        risk.cve_id,
        risk.asset_name,
        violations,
    )
    return explanation, violations


