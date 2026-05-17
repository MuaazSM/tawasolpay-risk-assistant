"""Load and clean raw CSVs into typed DataFrames.

One loader per CSV: assets, vulnerabilities, business_services, threat_intel.
Handles missing owners (warn, don't drop), flags stale assets (last_seen_days > 30),
coerces types to match schema expectations. Returns clean pandas DataFrames
ready for the enrichment join step.
"""
