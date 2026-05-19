"""Join all data sources into a single enriched risk DataFrame.

Each row is an (asset_id, vuln_id) pair with KEV flags, threat intel
matches, campaign matches, chain partners, and missing controls.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pandas as pd

from src.ingest import (
    load_assets,
    load_business_services,
    load_threat_intel,
    load_vulnerabilities,
)

logger = logging.getLogger(__name__)

_DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
_DEFAULT_REF_DIR = Path(__file__).resolve().parent.parent / "data" / "reference"
_DEFAULT_PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"

_STALE_THRESHOLD_DAYS = 30

# criticality ordering for max() computation (higher index = more critical)
_CRITICALITY_RANK: dict[str, int] = {
    "Low": 0,
    "Medium": 1,
    "High": 2,
    "Critical": 3,
}
_RANK_TO_CRITICALITY: dict[int, str] = {v: k for k, v in _CRITICALITY_RANK.items()}


def _load_kev(ref_dir: Path = _DEFAULT_REF_DIR) -> pd.DataFrame:
    """Load CISA KEV catalog CSV.

    Returns a DataFrame with cve_id as the key and a boolean
    ransomware_known column (True when known_ransomware_use == "Known").
    """
    path = ref_dir / "cisa_kev.csv"
    df = pd.read_csv(path, dtype=str, usecols=["cve_id", "known_ransomware_use"])
    df["kev_ransomware_use"] = df["known_ransomware_use"].str.strip().str.lower() == "known"
    # deduplicate (KEV should have unique CVEs, but be defensive)
    df = df.drop_duplicates(subset="cve_id", keep="first")
    return df[["cve_id", "kev_ransomware_use"]]


def _load_campaigns(processed_dir: Path = _DEFAULT_PROCESSED_DIR) -> list[dict]:
    """Load parsed campaign intelligence from campaigns.json."""
    path = processed_dir / "campaigns.json"
    with open(path) as f:
        return json.load(f)


def _merge_assets_vulns(
    assets: pd.DataFrame, vulns: pd.DataFrame,
) -> pd.DataFrame:
    """Inner join vulnerabilities onto assets.

    Join key: asset_id (assets.asset_id == vulns.asset_id).
    Every vulnerability must have a matching asset; orphan vulns are logged
    and dropped via inner join.
    """
    n_vulns_before = len(vulns)
    merged = vulns.merge(assets, on="asset_id", how="inner", suffixes=("", "_asset"))
    n_dropped = n_vulns_before - len(merged)
    if n_dropped:
        logger.warning(
            "enrichment: %d vulnerability row(s) dropped: no matching asset_id",
            n_dropped,
        )
    return merged


def _merge_business_services(
    df: pd.DataFrame, services: pd.DataFrame,
) -> pd.DataFrame:
    """Left join business service context onto the asset-vuln DataFrame.

    Join key: business_service (df.business_service == services.business_service).
    Assets without a matching service get defaults (business_criticality="Low",
    empty compliance_scope, rto_hours=0).
    """
    # select only the columns we need from services to avoid clutter
    svc_cols = [
        "business_service", "business_impact", "compliance_scope",
        "revenue_impact", "rto_hours",
    ]
    svc = services[svc_cols].copy()

    # rename to preserve provenance:
    # - revenue_impact → service_revenue_impact (service-level criticality)
    # - business_impact → business_impact_description (prose description)
    svc = svc.rename(columns={
        "revenue_impact": "service_revenue_impact",
        "business_impact": "business_impact_description",
    })

    merged = df.merge(svc, on="business_service", how="left")

    n_missing = merged["service_revenue_impact"].isna().sum()
    if n_missing:
        logger.warning(
            "enrichment: %d row(s) have no matching business_service, "
            "defaulting service_revenue_impact to 'Low'",
            n_missing,
        )
        merged["service_revenue_impact"] = merged["service_revenue_impact"].fillna("Low")
        merged["business_impact_description"] = merged["business_impact_description"].fillna("")
        merged["compliance_scope"] = merged["compliance_scope"].fillna("")
        merged["rto_hours"] = merged["rto_hours"].fillna(0).astype(int)

    # preserve asset-level criticality under a distinct name
    merged["asset_criticality"] = merged["criticality"]

    # business_criticality = max(asset.criticality, service.revenue_impact)
    # where Critical > High > Medium > Low. This captures the worst-case
    # interpretation: a High-criticality asset underlying a Critical revenue
    # service (e.g., CitrixBleed on Payment Processing) scores Critical, and
    # a Critical asset on a High revenue service (e.g., VPN edges on Remote
    # Access) also scores Critical. Neither signal alone tells the whole story.
    merged["business_criticality"] = merged.apply(
        lambda row: _RANK_TO_CRITICALITY[
            max(
                _CRITICALITY_RANK.get(row["asset_criticality"], 0),
                _CRITICALITY_RANK.get(row["service_revenue_impact"], 0),
            )
        ],
        axis=1,
    )

    return merged


def _merge_kev(df: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    """Left join CISA KEV data to flag actively exploited CVEs.

    Join key: cve_id (df.cve_id == kev.cve_id).
    Adds kev_match (bool) and kev_ransomware_use (bool) columns.
    Synthetic CVEs (CVE-SYN-*, CICD-SYN-*) will never match KEV.
    That's expected; the threat intel and campaign data catch those.
    """
    merged = df.merge(kev, on="cve_id", how="left", suffixes=("", "_kev"))

    # kev_ransomware_use comes from the KEV join; NaN means no KEV match
    merged["kev_match"] = merged["kev_ransomware_use"].notna()
    merged["kev_ransomware_use"] = merged["kev_ransomware_use"].fillna(False)

    n_kev = merged["kev_match"].sum()
    logger.info("enrichment: %d / %d rows matched CISA KEV", n_kev, len(merged))

    return merged


def _add_threat_intel_matches(
    df: pd.DataFrame, intel: pd.DataFrame,
) -> pd.DataFrame:
    """Aggregate threat intel matches per (asset_id, vuln_id) pair.

    Join key: cve_id (df.cve_id == intel.matched_cve_or_control).
    Adds columns:
        threat_intel_matches: list of intel_ids matching this CVE
        threat_intel_weaponized: True if any match has exploit_maturity == "Weaponized"
        threat_intel_max_maturity: highest exploit_maturity among matches
        threat_intel_ransomware: True if any match has ransomware_association == True
    """
    # higher index = more mature / dangerous
    maturity_rank = {
        "Not Applicable": 0,
        "Social Engineering": 1,
        "Proof of Concept": 2,
        "Commodity Exploit": 3,
        "Active Exploitation": 4,
        "Weaponized": 5,
    }

    # build per-CVE aggregates in one pass
    intel_by_cve: dict[str, list[str]] = {}
    weaponized_by_cve: dict[str, bool] = {}
    max_maturity_by_cve: dict[str, str] = {}
    ransomware_by_cve: dict[str, bool] = {}

    for cve, group in intel.groupby("matched_cve_or_control"):
        intel_by_cve[cve] = group["intel_id"].tolist()

        maturities = group["exploit_maturity"].dropna().tolist()
        weaponized_by_cve[cve] = "Weaponized" in maturities
        if maturities:
            max_maturity_by_cve[cve] = max(maturities, key=lambda m: maturity_rank.get(m, -1))
        else:
            max_maturity_by_cve[cve] = "Not Available"

        # ransomware_association is already a bool from ingest
        ransomware_by_cve[cve] = group["ransomware_association"].any()

    df["threat_intel_matches"] = df["cve_id"].map(lambda cve: intel_by_cve.get(cve, []))
    df["threat_intel_weaponized"] = df["cve_id"].map(lambda cve: weaponized_by_cve.get(cve, False))
    df["threat_intel_max_maturity"] = df["cve_id"].map(lambda cve: max_maturity_by_cve.get(cve, "Not Available"))
    df["threat_intel_ransomware"] = df["cve_id"].map(lambda cve: ransomware_by_cve.get(cve, False))

    return df


def _add_campaign_matches(
    df: pd.DataFrame, campaigns: list[dict],
) -> pd.DataFrame:
    """Tag each row with campaigns whose exploit chain includes its CVE.

    Uses the parsed campaigns.json. A campaign matches when the row's cve_id
    appears in the campaign's associated_cves list.

    Adds campaign_matches column: list of campaign names.
    """
    # build lookup: cve → list of campaign names
    cve_to_campaigns: dict[str, list[str]] = {}
    for campaign in campaigns:
        for cve in campaign["associated_cves"]:
            cve_to_campaigns.setdefault(cve, []).append(campaign["name"])

    df["campaign_matches"] = df["cve_id"].map(
        lambda cve: cve_to_campaigns.get(cve, [])
    )

    n_matched = (df["campaign_matches"].str.len() > 0).sum()
    logger.info(
        "enrichment: %d / %d rows matched at least one campaign", n_matched, len(df),
    )
    return df


def _add_chain_partners(df: pd.DataFrame) -> pd.DataFrame:
    """Identify exploit-chain partners: other vuln_ids on the same asset
    sharing the same campaign.

    For each row, chain_partners lists the cve_ids of other vulnerabilities
    on the same asset that appear in at least one of the same campaigns.
    This detects multi-link attack paths like CrimsonJackal's
    CVE-2024-21762 + CVE-2024-55591 on asset A-1005.

    Adds chain_partners column: list of partner cve_ids (not including self).
    """
    # only consider rows that have campaign matches
    has_campaigns = df["campaign_matches"].str.len() > 0
    campaign_rows = df.loc[has_campaigns, ["asset_id", "vuln_id", "cve_id", "campaign_matches"]].copy()

    # explode campaigns so we can group by (asset_id, campaign)
    exploded = campaign_rows.explode("campaign_matches")
    exploded = exploded.rename(columns={"campaign_matches": "campaign"})

    # for each (asset_id, campaign), collect all cve_ids
    chain_groups = (
        exploded
        .groupby(["asset_id", "campaign"])["cve_id"]
        .apply(set)
        .reset_index()
        .rename(columns={"cve_id": "chain_cves"})
    )

    # only keep groups with 2+ CVEs (single CVE = no chain)
    chain_groups = chain_groups[chain_groups["chain_cves"].apply(len) >= 2]

    # build a lookup: (asset_id, cve_id) → set of partner cve_ids
    partner_lookup: dict[tuple[str, str], set[str]] = {}
    for _, row in chain_groups.iterrows():
        for cve in row["chain_cves"]:
            key = (row["asset_id"], cve)
            partners = row["chain_cves"] - {cve}
            if key in partner_lookup:
                partner_lookup[key] |= partners
            else:
                partner_lookup[key] = partners.copy()

    df["chain_partners"] = df.apply(
        lambda row: sorted(partner_lookup.get((row["asset_id"], row["cve_id"]), set())),
        axis=1,
    )

    n_chained = (df["chain_partners"].str.len() > 0).sum()
    if n_chained:
        logger.info("enrichment: %d row(s) have chain partners", n_chained)

    return df


def _add_missing_controls(df: pd.DataFrame) -> pd.DataFrame:
    """Flag missing security controls based on asset metadata.

    Checks:
    - no_edr: edr_installed != "Yes"
    - stale_asset: last_seen_days > 30
    - no_owner: owner_team is missing or blank

    Adds missing_controls column: list of control gap labels.
    """
    def _check_controls(row: pd.Series) -> list[str]:
        gaps: list[str] = []
        if str(row.get("edr_installed", "")).strip().lower() != "yes":
            gaps.append("no_edr")
        if row.get("last_seen_days", 0) > _STALE_THRESHOLD_DAYS:
            gaps.append("stale_asset")
        owner = row.get("owner_team", "")
        if pd.isna(owner) or str(owner).strip() == "":
            gaps.append("no_owner")
        return gaps

    df["missing_controls"] = df.apply(_check_controls, axis=1)

    n_with_gaps = (df["missing_controls"].str.len() > 0).sum()
    logger.info("enrichment: %d / %d rows have missing controls", n_with_gaps, len(df))

    return df


def _add_campaign_ransomware(
    df: pd.DataFrame, campaigns: list[dict],
) -> pd.DataFrame:
    """Flag rows where a matched campaign mentions ransomware in its TTPs.

    Adds campaign_ransomware column: True if any campaign in campaign_matches
    has "ransomware" (case-insensitive) in its TTPs list.
    """
    # build lookup: campaign name → has ransomware in TTPs
    campaign_has_ransomware: dict[str, bool] = {}
    for campaign in campaigns:
        has_ransom = any("ransomware" in ttp.lower() for ttp in campaign.get("ttps", []))
        campaign_has_ransomware[campaign["name"]] = has_ransom

    df["campaign_ransomware"] = df["campaign_matches"].apply(
        lambda matches: any(campaign_has_ransomware.get(name, False) for name in matches)
    )

    return df


def _compute_derived_signals(df: pd.DataFrame) -> pd.DataFrame:
    """Compute union signals from individual source booleans.

    Adds:
        ransomware_match: kev_ransomware_use OR threat_intel_ransomware OR campaign_ransomware
        active_exploitation_signal: kev_match OR threat_intel_weaponized OR has campaign matches
    """
    df["ransomware_match"] = (
        df["kev_ransomware_use"] | df["threat_intel_ransomware"] | df["campaign_ransomware"]
    )

    df["active_exploitation_signal"] = (
        df["kev_match"] | df["threat_intel_weaponized"] | (df["campaign_matches"].str.len() > 0)
    )

    n_ransom = df["ransomware_match"].sum()
    n_active = df["active_exploitation_signal"].sum()
    logger.info(
        "enrichment: %d ransomware_match, %d active_exploitation_signal out of %d rows",
        n_ransom, n_active, len(df),
    )

    return df


def build_enriched_risks(
    data_dir: Path = _DEFAULT_DATA_DIR,
    ref_dir: Path = _DEFAULT_REF_DIR,
    processed_dir: Path = _DEFAULT_PROCESSED_DIR,
) -> pd.DataFrame:
    """Build the fully enriched risk DataFrame.

    Returns a DataFrame with one row per (asset_id, vuln_id), columns
    matching the EnrichedRisk schema. Join sequence is documented by
    the inline step comments below.
    """
    # load all sources
    assets = load_assets(data_dir)
    vulns = load_vulnerabilities(data_dir)
    services = load_business_services(data_dir)
    intel = load_threat_intel(data_dir)
    kev = _load_kev(ref_dir)
    campaigns = _load_campaigns(processed_dir)

    logger.info(
        "enrichment: loaded %d assets, %d vulns, %d services, %d intel, %d KEV, %d campaigns",
        len(assets), len(vulns), len(services), len(intel), len(kev), len(campaigns),
    )

    # step 1: inner join vulns ↔ assets on asset_id
    df = _merge_assets_vulns(assets, vulns)

    # step 2: left join business services on business_service
    df = _merge_business_services(df, services)

    # step 3: left join KEV on cve_id
    df = _merge_kev(df, kev)

    # step 4: aggregate threat intel matches by cve_id
    df = _add_threat_intel_matches(df, intel)

    # step 5: tag campaign matches from campaigns.json
    df = _add_campaign_matches(df, campaigns)

    # step 6: compute chain partners (same asset + same campaign)
    df = _add_chain_partners(df)

    # step 7: flag missing controls from asset metadata
    df = _add_missing_controls(df)

    # step 8: flag campaign ransomware from campaign TTPs
    df = _add_campaign_ransomware(df, campaigns)

    # step 9: compute derived union signals
    df = _compute_derived_signals(df)

    logger.info("enrichment: built %d enriched risk rows", len(df))

    return df
