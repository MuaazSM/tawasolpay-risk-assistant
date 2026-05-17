"""Join all data sources into a single enriched risk DataFrame.

Entry point: build_enriched_risks() -> pd.DataFrame

Merges assets, vulnerabilities, business services, KEV data, threat intel,
and parsed campaign intelligence. Each row is an (asset_id, vuln_id) pair
enriched with: kev_match, kev_ransomware_use, threat_intel_matches,
campaign_matches, chain_partners, missing_controls.
"""
