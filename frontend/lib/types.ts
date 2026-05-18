// Types mirror the backend's Pydantic schemas in src/schemas.py.
// Keep these in sync; if a backend field changes, update here.

export type Tier = "act_now" | "act_soon" | "track" | "monitor";

export type Criticality = "Critical" | "High" | "Medium" | "Low";

export interface ScoreBreakdown {
  exposure: number;
  exploitation_evidence: number;
  ransomware: number;
  business_criticality: number;
  missing_controls: number;
  cvss: number;
  days_open: number;
  chain_bonus: number;
  total: number;
}

export interface RiskExplanation {
  headline: string;
  why_it_ranks_here: string;
  business_impact: string;
  cited_cves: string[];
  cited_campaigns: string[];
  cited_controls: string[];
  recommended_actions: string[];
}

export interface NistControlRef {
  control_id: string;
  title: string;
  family: string;
}

// Matches backend src/schemas.py TopRiskOutput exactly.
// Fields marked optional (?) are planned for the enriched API response
// but not yet serialized by the backend.
export interface TopRiskOutput {
  rank: number;
  tier: Tier;
  asset_id: string;
  vuln_id: string;
  cve_id: string;
  asset_name: string;
  score: number;
  score_breakdown: ScoreBreakdown;
  explanation: RiskExplanation;
  retrieved_controls: NistControlRef[];
  faithfulness_violations: string[];
  faithfulness_passed: boolean;
  // Enriched fields — present when the backend exposes them.
  vulnerability_name?: string;
  asset_type?: string;
  owner_team?: string | null;
  business_service?: string;
  business_criticality?: Criticality;
  internet_exposed?: boolean;
  kev_match?: boolean;
  threat_intel_max_maturity?: string | null;
  campaign_matches?: string[];
  chain_partners?: string[];
  missing_controls?: string[];
  ransomware_match?: boolean;
  active_exploitation_signal?: boolean;
}

export interface HealthResponse {
  status: string;
  pipeline_ready: boolean;
  risk_count: number;
  last_refresh: string | null;
}
