"""Deterministic tier assignment and weighted scoring.

Entry point: score_risks(enriched: pd.DataFrame) -> pd.DataFrame

Two-stage ranking:
1. Tier gates (act_now / act_soon / track / monitor) based on exposure,
   exploitation signals, ransomware association, and business criticality.
2. Within-tier weighted score (0-100) from: exposure, exploitation evidence,
   ransomware, business criticality, missing controls, CVSS, days_open.
   Chain bonus (+15) for assets with exploit-chain partners.

Output is sorted by tier rank then score descending, with a score_breakdown
column for full auditability.
"""

from __future__ import annotations

import logging

import pandas as pd

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# tier rank for sorting — lower rank = more urgent
_TIER_RANK: dict[str, int] = {
    "act_now": 0,
    "act_soon": 1,
    "track": 2,
    "monitor": 3,
}

# within-tier score weights (sum to 85 before chain bonus, so max with
# chain bonus = 100).
# CVSS is intentionally low (5) — it captures technical severity but not
# operational context. missing_controls is higher (10) because control gaps
# (no EDR, stale asset, no owner) represent real defensive failures the
# organization can act on, not just a vendor-assigned number.
_WEIGHTS = {
    "exposure": 15,
    "exploitation_evidence": 20,
    "ransomware": 15,
    "business_criticality": 15,
    "missing_controls": 10,
    "cvss": 5,
    "days_open": 5,
}

_CHAIN_BONUS = 15

# business criticality → fractional contribution (1.0 = max)
_CRITICALITY_SCORE: dict[str, float] = {
    "Critical": 1.0,
    "High": 0.7,
    "Medium": 0.4,
    "Low": 0.1,
}

# days_open normalization cap — anything above this scores 1.0
_DAYS_OPEN_CAP = 180


# ---------------------------------------------------------------------------
# Tier assignment
# ---------------------------------------------------------------------------


def _assign_tier(row: pd.Series) -> str:
    """Assign a priority tier to one enriched risk row.

    Rules applied in order (first match wins):

    act_now:
        (internet_exposed AND active_exploitation_signal
         AND (ransomware_match OR business_criticality == Critical))
        OR (chain_partners >= 1 AND campaign_matches >= 1
            AND business_criticality == Critical)

    act_soon:
        (internet_exposed AND active_exploitation_signal)
        OR (active_exploitation_signal AND business_criticality == Critical)

    track:
        active_exploitation_signal
        OR (internet_exposed AND cvss >= 7)

    monitor:
        everything else
    """
    exposed = row["internet_exposed"] == "Yes"
    active = row["active_exploitation_signal"]
    ransomware = row["ransomware_match"]
    critical = row["business_criticality"] == "Critical"
    has_chain = len(row["chain_partners"]) >= 1
    has_campaign = len(row["campaign_matches"]) >= 1

    # act_now
    if (exposed and active and (ransomware or critical)):
        return "act_now"
    if (has_chain and has_campaign and critical):
        return "act_now"

    # act_soon
    if exposed and active:
        return "act_soon"
    if active and critical:
        return "act_soon"

    # track
    if active:
        return "track"
    if exposed and row["cvss"] >= 7:
        return "track"

    return "monitor"


# ---------------------------------------------------------------------------
# Within-tier weighted score
# ---------------------------------------------------------------------------


def _compute_score(row: pd.Series) -> dict:
    """Compute the 0-100 weighted score and return a breakdown dict.

    Each component contributes weight * (0 or 1 or fractional value).
    Chain bonus is additive on top.
    """
    breakdown: dict[str, float] = {}

    # exposure: binary — internet-exposed or not
    exposed = 1.0 if row["internet_exposed"] == "Yes" else 0.0
    breakdown["exposure"] = round(exposed * _WEIGHTS["exposure"], 2)

    # exploitation evidence: fractional based on how many sources fire
    # kev_match, threat_intel_weaponized, campaign_match — each worth 1/3
    evidence_signals = sum([
        bool(row["kev_match"]),
        bool(row["threat_intel_weaponized"]),
        len(row["campaign_matches"]) >= 1,
    ])
    breakdown["exploitation_evidence"] = round(
        (evidence_signals / 3) * _WEIGHTS["exploitation_evidence"], 2
    )

    # ransomware: binary
    ransomware = 1.0 if row["ransomware_match"] else 0.0
    breakdown["ransomware"] = round(ransomware * _WEIGHTS["ransomware"], 2)

    # business criticality: graded
    crit_fraction = _CRITICALITY_SCORE.get(row["business_criticality"], 0.1)
    breakdown["business_criticality"] = round(
        crit_fraction * _WEIGHTS["business_criticality"], 2
    )

    # missing controls: fractional — each gap adds 1/3 up to 1.0
    # possible gaps: no_edr, stale_asset, no_owner
    n_gaps = min(len(row["missing_controls"]), 3)
    breakdown["missing_controls"] = round(
        (n_gaps / 3) * _WEIGHTS["missing_controls"], 2
    )

    # CVSS: normalized 0-10 → 0-1
    breakdown["cvss"] = round((row["cvss"] / 10.0) * _WEIGHTS["cvss"], 2)

    # days_open: capped linear normalization
    days_fraction = min(row["days_open"] / _DAYS_OPEN_CAP, 1.0)
    breakdown["days_open"] = round(days_fraction * _WEIGHTS["days_open"], 2)

    # chain bonus: +15 if asset has exploit-chain partners
    if len(row["chain_partners"]) >= 1:
        breakdown["chain_bonus"] = float(_CHAIN_BONUS)
    else:
        breakdown["chain_bonus"] = 0.0

    breakdown["total"] = round(sum(breakdown.values()), 2)

    return breakdown


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def score_risks(enriched: pd.DataFrame) -> pd.DataFrame:
    """Apply tier gates and weighted scoring to enriched risks.

    Tier assignment uses the rules described in docs/DESIGN.md §2-3.
    Within each tier, a 0-100 weighted score breaks ties. A chain bonus
    of +15 is applied when an asset has 2+ vulnerabilities matching the
    same campaign.

    Args:
        enriched: Output of enrichment.build_enriched_risks. Must contain
            the active_exploitation_signal, ransomware_match, and
            chain_partners columns.

    Returns:
        The input dataframe with added columns: tier, tier_rank, score,
        score_breakdown. Sorted by tier_rank ascending, then score descending.
    """
    required = {
        "internet_exposed", "active_exploitation_signal", "ransomware_match",
        "business_criticality", "kev_match", "threat_intel_weaponized",
        "campaign_matches", "chain_partners", "missing_controls", "cvss",
        "days_open",
    }
    missing = required - set(enriched.columns)
    if missing:
        raise ValueError(f"Enriched DataFrame missing required columns: {sorted(missing)}")

    df = enriched.copy()

    # stage 1: tier gates
    df["tier"] = df.apply(_assign_tier, axis=1)
    df["tier_rank"] = df["tier"].map(_TIER_RANK)

    # stage 2: within-tier weighted score
    df["score_breakdown"] = df.apply(_compute_score, axis=1)
    df["score"] = df["score_breakdown"].apply(lambda bd: bd["total"])

    # sort: tier rank ascending (act_now first), then score descending
    df = df.sort_values(
        ["tier_rank", "score"], ascending=[True, False],
    ).reset_index(drop=True)

    # log tier distribution
    tier_counts = df["tier"].value_counts()
    for tier in ["act_now", "act_soon", "track", "monitor"]:
        logger.info("scoring: %s = %d", tier, tier_counts.get(tier, 0))

    return df
