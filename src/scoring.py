"""Deterministic tier assignment and weighted scoring.

Entry point: score_risks(enriched: pd.DataFrame) -> pd.DataFrame

Two-stage ranking:
1. Tier gates (act_now / act_soon / track / monitor) based on exposure,
   exploitation signals, ransomware association, and business impact.
2. Within-tier weighted score (0-100) from: exposure, exploitation evidence,
   ransomware, business criticality, missing controls, CVSS, days_open.
   Chain bonus (+15) for assets with exploit-chain partners.

Output is sorted by tier rank then score descending, with a score_breakdown
column for full auditability.
"""
