"""Load and clean raw CSVs into typed DataFrames.

One loader per CSV: assets, vulnerabilities, business_services, threat_intel,
remediation_guidance. Handles missing owners (warn, don't drop), flags stale
assets (last_seen_days > 30), coerces types to match schema expectations.
Returns clean pandas DataFrames ready for the enrichment join step.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

# single constant for all loaders — override in tests via the data_dir parameter
_DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

# confidence strings → floats matching the 0-1 range the ThreatIntel schema expects
_CONFIDENCE_MAP: dict[str, float] = {
    "High": 0.9,
    "Medium": 0.6,
    "Low": 0.3,
}

# required columns per CSV — catch broken files fast
_REQUIRED_ASSETS_COLS = frozenset({
    "asset_id", "asset_name", "asset_type", "owner_team",
    "business_service", "internet_exposed", "last_seen_days",
})
_REQUIRED_VULN_COLS = frozenset({
    "vuln_id", "asset_id", "cve", "severity", "cvss", "days_open",
})
_REQUIRED_INTEL_COLS = frozenset({
    "intel_id", "campaign_name", "matched_cve_or_control", "confidence",
})
_REQUIRED_SERVICE_COLS = frozenset({
    "business_service", "revenue_impact", "rto_hours",
})
_REQUIRED_REMED_COLS = frozenset({
    "finding_type", "recommended_action", "priority_hint",
})

_STALE_THRESHOLD_DAYS = 30


def _check_required_columns(
    df: pd.DataFrame, required: frozenset[str], source: str,
) -> None:
    """Raise ValueError if any required columns are missing from *df*."""
    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"{source} is missing required columns: {sorted(missing)}"
        )


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------


def load_assets(data_dir: Path = _DEFAULT_DATA_DIR) -> pd.DataFrame:
    """Load assets.csv, coerce types, flag stale assets, warn on missing owners.

    Adds an ``is_stale`` boolean column (True when last_seen_days > 30).
    Rows with missing ``owner_team`` are kept but logged at WARNING level.

    Returns:
        DataFrame with all original columns plus ``is_stale``.
    """
    path = data_dir / "assets.csv"
    df = pd.read_csv(path, dtype={"asset_id": str, "internet_exposed": str})

    _check_required_columns(df, _REQUIRED_ASSETS_COLS, path.name)

    df["last_seen_days"] = pd.to_numeric(df["last_seen_days"], errors="coerce").fillna(0).astype(int)

    # flag stale assets — don't drop, the scoring engine decides what to do
    df["is_stale"] = df["last_seen_days"] > _STALE_THRESHOLD_DAYS

    # warn on missing owners so operators notice, but keep the rows
    missing_owner_mask = df["owner_team"].isna() | (df["owner_team"].str.strip() == "")
    n_missing = missing_owner_mask.sum()
    if n_missing:
        ids = df.loc[missing_owner_mask, "asset_id"].tolist()
        logger.warning(
            "assets.csv: %d row(s) with missing owner_team — %s",
            n_missing, ids,
        )

    return df


def load_vulnerabilities(data_dir: Path = _DEFAULT_DATA_DIR) -> pd.DataFrame:
    """Load vulnerabilities.csv, coerce types, rename ``cve`` → ``cve_id``.

    Returns:
        DataFrame with ``cve_id`` column and numeric ``cvss`` / ``days_open``.
    """
    path = data_dir / "vulnerabilities.csv"
    df = pd.read_csv(path, dtype={"vuln_id": str, "asset_id": str, "cve": str})

    _check_required_columns(df, _REQUIRED_VULN_COLS, path.name)

    # rename to match schema convention used everywhere downstream
    df = df.rename(columns={"cve": "cve_id"})

    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce")
    df["days_open"] = pd.to_numeric(df["days_open"], errors="coerce").fillna(0).astype(int)

    bad_cvss = df["cvss"].isna()
    if bad_cvss.any():
        logger.warning(
            "vulnerabilities.csv: %d row(s) with unparseable CVSS — set to 0.0",
            bad_cvss.sum(),
        )
        df.loc[bad_cvss, "cvss"] = 0.0

    return df


def load_threat_intel(data_dir: Path = _DEFAULT_DATA_DIR) -> pd.DataFrame:
    """Load threat_intelligence.csv, map confidence to float, ransomware to bool.

    Confidence mapping: High → 0.9, Medium → 0.6, Low → 0.3.
    Unknown confidence values are logged and default to 0.3.

    Returns:
        DataFrame with numeric ``confidence`` and boolean ``ransomware_association``.
    """
    path = data_dir / "threat_intelligence.csv"
    df = pd.read_csv(path, dtype=str)

    _check_required_columns(df, _REQUIRED_INTEL_COLS, path.name)

    # map confidence labels → floats
    unmapped = set(df["confidence"].dropna().unique()) - set(_CONFIDENCE_MAP)
    if unmapped:
        logger.warning(
            "threat_intelligence.csv: unknown confidence values %s — defaulting to 0.3",
            sorted(unmapped),
        )
    df["confidence"] = (
        df["confidence"]
        .map(_CONFIDENCE_MAP)
        .fillna(_CONFIDENCE_MAP["Low"])
    )

    # ransomware flag → boolean
    df["ransomware_association"] = df["ransomware_association"].str.strip().str.lower() == "yes"

    return df


def load_business_services(data_dir: Path = _DEFAULT_DATA_DIR) -> pd.DataFrame:
    """Load business_services.csv, coerce ``rto_hours`` to numeric.

    Returns:
        DataFrame with numeric ``rto_hours`` and all original columns.
    """
    path = data_dir / "business_services.csv"
    df = pd.read_csv(path, dtype={"business_service": str})

    _check_required_columns(df, _REQUIRED_SERVICE_COLS, path.name)

    df["rto_hours"] = pd.to_numeric(df["rto_hours"], errors="coerce").fillna(0).astype(int)

    return df


def load_remediation_guidance(data_dir: Path = _DEFAULT_DATA_DIR) -> pd.DataFrame:
    """Load remediation_guidance.csv with minimal cleaning.

    Returns:
        DataFrame with ``finding_type``, ``recommended_action``,
        ``priority_hint``, and ``validation_evidence`` columns.
    """
    path = data_dir / "remediation_guidance.csv"
    df = pd.read_csv(path, dtype=str)

    _check_required_columns(df, _REQUIRED_REMED_COLS, path.name)

    # strip whitespace from the priority hint to normalise "P0 " → "P0"
    df["priority_hint"] = df["priority_hint"].str.strip()

    return df
