"""Pydantic models for all domain objects.

Defines: Asset, Vulnerability, BusinessService, ThreatIntel, Campaign,
KevEntry, EnrichedRisk, NistControl, RiskExplanation, TopRiskOutput.

Each model maps directly to a data source (CSV column or derived join).
Validators enforce constraints: CVSS 0-10, exposure enums, non-empty IDs.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums as Literal types (lightweight, no separate Enum class needed)
# ---------------------------------------------------------------------------

ExposureLevel = Literal["Yes", "No"]
Criticality = Literal["Critical", "High", "Medium", "Low"]
ExploitMaturity = Literal["Weaponized", "PoC", "Unproven", "Not Available"]
Tier = Literal["act_now", "act_soon", "track", "monitor"]


# ---------------------------------------------------------------------------
# Source data models — one per CSV
# ---------------------------------------------------------------------------


class Asset(BaseModel):
    """One row from assets.csv."""

    asset_id: str = Field(min_length=1)
    asset_name: str
    owner: str | None = None
    service_id: str
    asset_type: str = ""
    internet_exposed: ExposureLevel = "No"
    last_seen_days: int = Field(default=0, ge=0)

    @field_validator("asset_id")
    @classmethod
    def asset_id_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("asset_id must not be blank")
        return v.strip()


class Vulnerability(BaseModel):
    """One row from vulnerabilities.csv."""

    vuln_id: str = Field(min_length=1)
    asset_id: str = Field(min_length=1)
    cve_id: str = Field(min_length=1)
    severity: Criticality
    description: str = ""
    cvss: float = Field(ge=0.0, le=10.0)
    exploit_maturity: ExploitMaturity = "Not Available"
    days_open: int = Field(default=0, ge=0)


class BusinessService(BaseModel):
    """One row from business_services.csv."""

    service_id: str = Field(min_length=1)
    service_name: str
    criticality: Criticality


class ThreatIntel(BaseModel):
    """One row from threat_intelligence.csv."""

    ti_id: str = Field(min_length=1)
    campaign: str
    indicator: str
    confidence: float = Field(ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Derived / parsed data models
# ---------------------------------------------------------------------------


class Campaign(BaseModel):
    """Parsed from the synthetic threat report markdown."""

    name: str = Field(min_length=1)
    associated_cves: list[str] = Field(default_factory=list)
    targeted_asset_types: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)


class KevEntry(BaseModel):
    """One row from the CISA KEV catalog (normalized)."""

    cve_id: str = Field(min_length=1)
    vendor: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""
    ransomware_use: Literal["Known", "Unknown"] = "Unknown"


# ---------------------------------------------------------------------------
# Enriched risk — the join of all sources for a single (asset, vuln) pair
# ---------------------------------------------------------------------------


class EnrichedRisk(BaseModel):
    """Fully enriched risk row after all joins. Input to the scoring engine."""

    asset_id: str
    vuln_id: str
    cve_id: str
    asset_name: str
    asset_type: str = ""
    internet_exposed: ExposureLevel
    last_seen_days: int = Field(ge=0)
    owner: str | None = None

    service_id: str
    service_name: str = ""
    business_impact: Criticality

    cvss: float = Field(ge=0.0, le=10.0)
    severity: Criticality
    exploit_maturity: ExploitMaturity = "Not Available"
    description: str = ""
    days_open: int = Field(default=0, ge=0)

    kev_match: bool = False
    kev_ransomware_use: bool = False
    threat_intel_matches: list[str] = Field(default_factory=list)
    campaign_matches: list[str] = Field(default_factory=list)
    chain_partners: list[str] = Field(default_factory=list)
    missing_controls: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# NIST 800-53 control (from Chroma retrieval)
# ---------------------------------------------------------------------------


class NistControl(BaseModel):
    """A single NIST 800-53 Rev 5 control retrieved from the vector store."""

    control_id: str = Field(min_length=1)
    title: str
    family: str = ""
    statement: str = ""
    discussion: str = ""
    related_controls: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# LLM output models
# ---------------------------------------------------------------------------


class RiskExplanation(BaseModel):
    """Structured output from the LLM explanation generator."""

    headline: str = Field(min_length=1)
    why_it_ranks_here: str = Field(min_length=1)
    business_impact: str = Field(min_length=1)
    cited_cves: list[str] = Field(min_length=1)
    cited_campaigns: list[str] = Field(min_length=1)
    cited_controls: list[str] = Field(min_length=1)
    recommended_actions: list[str] = Field(min_length=3, max_length=5)


# ---------------------------------------------------------------------------
# Final output
# ---------------------------------------------------------------------------


class ScoreBreakdown(BaseModel):
    """Component-level breakdown of the within-tier score."""

    exposure: float = 0.0
    exploitation_evidence: float = 0.0
    ransomware: float = 0.0
    business_criticality: float = 0.0
    missing_controls: float = 0.0
    cvss: float = 0.0
    days_open: float = 0.0
    chain_bonus: float = 0.0
    total: float = 0.0


class TopRiskOutput(BaseModel):
    """A single entry in the top-k risk response."""

    rank: int = Field(ge=1)
    tier: Tier
    asset_id: str
    vuln_id: str
    cve_id: str
    asset_name: str
    score: float
    score_breakdown: ScoreBreakdown
    explanation: RiskExplanation
    retrieved_controls: list[NistControl]
    faithfulness_passed: bool = True
