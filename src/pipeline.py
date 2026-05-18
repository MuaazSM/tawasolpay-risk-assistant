"""End-to-end pipeline orchestrator.

Entry point: run_pipeline(top_k: int = 5) -> list[TopRiskOutput]

Steps: load -> enrich -> score -> take top-k -> for each: retrieve NIST
controls + generate explanation + validate faithfulness -> return.

Includes timing logs per step and a --cache flag to pickle intermediates
to data/processed/ for faster iteration during development.
"""

from __future__ import annotations

import json
import logging
import pickle
import time
from pathlib import Path

import pandas as pd

from src.enrichment import build_enriched_risks
from src.explanation_generator import generate_explanation
from src.nist_retrieval import retrieve_controls_for_risk
from src.schemas import (
    Campaign,
    EnrichedRisk,
    NistControl,
    ScoreBreakdown,
    TopRiskOutput,
)
from src.scoring import score_risks

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CACHE_DIR = _PROJECT_ROOT / "data" / "processed"
_ENRICHED_CACHE = _CACHE_DIR / "enriched_cache.pkl"
_SCORED_CACHE = _CACHE_DIR / "scored_cache.pkl"


# ---------------------------------------------------------------------------
# DataFrame row -> Pydantic model conversion
# ---------------------------------------------------------------------------


def _row_to_enriched_risk(row: pd.Series) -> EnrichedRisk:
    """Convert a scored DataFrame row to an EnrichedRisk model.

    The DataFrame has slightly different column names than EnrichedRisk
    expects (e.g. business_service vs service_id, owner_team vs owner).
    This function handles the mapping.
    """
    return EnrichedRisk(
        asset_id=row["asset_id"],
        vuln_id=row["vuln_id"],
        cve_id=row["cve_id"],
        asset_name=row["asset_name"],
        asset_type=row.get("asset_type", ""),
        internet_exposed=row["internet_exposed"],
        last_seen_days=int(row["last_seen_days"]),
        owner=row.get("owner_team") or None,
        service_id=row.get("business_service", ""),
        service_name=row.get("business_service", ""),
        business_criticality=row["business_criticality"],
        business_impact_description=row.get("business_impact_description", ""),
        compliance_scope=row.get("compliance_scope", ""),
        rto_hours=int(row.get("rto_hours", 0)),
        cvss=float(row["cvss"]),
        severity=row["severity"],
        exploit_maturity=row.get("threat_intel_max_maturity", "Not Available"),
        description=row.get("vulnerability_name", ""),
        days_open=int(row["days_open"]),
        kev_match=bool(row.get("kev_match", False)),
        kev_ransomware_use=bool(row.get("kev_ransomware_use", False)),
        threat_intel_matches=row.get("threat_intel_matches", []),
        threat_intel_weaponized=bool(row.get("threat_intel_weaponized", False)),
        threat_intel_max_maturity=row.get("threat_intel_max_maturity", "Not Available"),
        threat_intel_ransomware=bool(row.get("threat_intel_ransomware", False)),
        campaign_matches=row.get("campaign_matches", []),
        campaign_ransomware=bool(row.get("campaign_ransomware", False)),
        chain_partners=row.get("chain_partners", []),
        missing_controls=row.get("missing_controls", []),
        ransomware_match=bool(row.get("ransomware_match", False)),
        active_exploitation_signal=bool(row.get("active_exploitation_signal", False)),
    )


def _row_to_score_breakdown(row: pd.Series) -> ScoreBreakdown:
    """Extract ScoreBreakdown from the score_breakdown dict in a scored row."""
    bd = row["score_breakdown"]
    return ScoreBreakdown(**bd)


def _load_campaigns() -> list[Campaign]:
    """Load parsed campaigns from campaigns.json."""
    path = _PROJECT_ROOT / "data" / "processed" / "campaigns.json"
    with open(path) as f:
        raw = json.load(f)
    return [Campaign(**c) for c in raw]


# ---------------------------------------------------------------------------
# Timing helper
# ---------------------------------------------------------------------------


def _timed(label: str):
    """Context manager that logs elapsed time for a pipeline step."""
    class Timer:
        def __enter__(self):
            self.start = time.monotonic()
            logger.info("pipeline: starting %s", label)
            return self

        def __exit__(self, *_):
            elapsed = time.monotonic() - self.start
            logger.info("pipeline: %s completed in %.2fs", label, elapsed)

    return Timer()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_pipeline(
    top_k: int = 5,
    use_cache: bool = False,
    light_refresh: bool = False,
) -> list[TopRiskOutput]:
    """Run the full risk analysis pipeline.

    Args:
        top_k: Number of top risks to return.
        use_cache: If True, load/save enriched and scored DataFrames from
            pickle cache in data/processed/ to skip recomputation.
        light_refresh: If True, re-use cached enriched data but re-run
            scoring and explanation generation. Does not re-fetch external
            data (CISA KEV, threat intel CSVs, threat report). Requires
            an existing enriched cache — raises ValueError if missing.
            Implies use_cache=True for enrichment loading.

    Returns:
        A list of TopRiskOutput objects, one per top-k risk, with
        explanations, retrieved controls, and faithfulness status.
    """
    if light_refresh:
        if not _ENRICHED_CACHE.exists():
            raise ValueError(
                "light_refresh requires enriched cache at "
                f"{_ENRICHED_CACHE} — run a full pipeline first"
            )
        use_cache = True

    # --- Step 1: Enrich ---
    if use_cache and _ENRICHED_CACHE.exists():
        logger.info("pipeline: loading enriched cache from %s", _ENRICHED_CACHE)
        with open(_ENRICHED_CACHE, "rb") as f:
            enriched = pickle.load(f)
    else:
        with _timed("enrichment"):
            enriched = build_enriched_risks()
        if use_cache:
            with open(_ENRICHED_CACHE, "wb") as f:
                pickle.dump(enriched, f)
            logger.info("pipeline: cached enriched to %s", _ENRICHED_CACHE)

    # --- Step 2: Score ---
    # light_refresh always re-scores to pick up scoring formula changes
    if use_cache and not light_refresh and _SCORED_CACHE.exists():
        logger.info("pipeline: loading scored cache from %s", _SCORED_CACHE)
        with open(_SCORED_CACHE, "rb") as f:
            scored = pickle.load(f)
    else:
        with _timed("scoring"):
            scored = score_risks(enriched)
        if use_cache:
            with open(_SCORED_CACHE, "wb") as f:
                pickle.dump(scored, f)
            logger.info("pipeline: cached scored to %s", _SCORED_CACHE)

    # --- Step 3: Take top-k ---
    top_rows = scored.head(top_k)
    logger.info(
        "pipeline: selected top %d risks (tiers: %s)",
        len(top_rows),
        top_rows["tier"].tolist(),
    )

    # --- Step 4: Load campaigns for explanation context ---
    campaigns = _load_campaigns()

    # --- Step 5: For each top risk, retrieve + explain + validate ---
    results: list[TopRiskOutput] = []

    for rank_idx, (_, row) in enumerate(top_rows.iterrows(), start=1):
        risk = _row_to_enriched_risk(row)
        breakdown = _row_to_score_breakdown(row)

        with _timed(f"risk #{rank_idx} ({risk.cve_id} on {risk.asset_name})"):
            # retrieve NIST controls
            controls = retrieve_controls_for_risk(risk)

            # generate explanation with faithfulness validation + retry
            explanation, violations = generate_explanation(
                risk, controls, campaigns,
            )

        output = TopRiskOutput(
            rank=rank_idx,
            tier=row["tier"],
            asset_id=risk.asset_id,
            vuln_id=risk.vuln_id,
            cve_id=risk.cve_id,
            asset_name=risk.asset_name,
            score=float(row["score"]),
            score_breakdown=breakdown,
            explanation=explanation,
            retrieved_controls=controls,
            faithfulness_violations=violations,
        )
        results.append(output)

        logger.info(
            "pipeline: risk #%d — %s on %s — tier=%s score=%.1f faithfulness=%s",
            rank_idx,
            risk.cve_id,
            risk.asset_name,
            row["tier"],
            row["score"],
            "PASSED" if output.faithfulness_passed else f"FAILED ({len(violations)} violations)",
        )

    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import argparse
    import sys

    from dotenv import load_dotenv
    load_dotenv()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    parser = argparse.ArgumentParser(description="Run the risk analysis pipeline")
    parser.add_argument("--top-k", type=int, default=5, help="Number of top risks")
    parser.add_argument("--cache", action="store_true", help="Use pickle cache")
    parser.add_argument("--json", action="store_true", help="Print JSON output to stdout")
    args = parser.parse_args()

    results = run_pipeline(top_k=args.top_k, use_cache=args.cache)

    if args.json:
        import json as json_mod
        output = [r.model_dump() for r in results]
        print(json_mod.dumps(output, indent=2, default=str))
    else:
        for r in results:
            status = "PASSED" if r.faithfulness_passed else f"FAILED: {r.faithfulness_violations}"
            print(f"\n{'='*70}")
            print(f"Rank #{r.rank}: {r.cve_id} on {r.asset_name}")
            print(f"Tier: {r.tier}  Score: {r.score:.1f}")
            print(f"Headline: {r.explanation.headline}")
            print(f"Faithfulness: {status}")
            print(f"Cited CVEs: {r.explanation.cited_cves}")
            print(f"Cited campaigns: {r.explanation.cited_campaigns}")
            print(f"Cited controls: {r.explanation.cited_controls}")
            print(f"Actions: {len(r.explanation.recommended_actions)}")
