"""Download CISA KEV catalog and normalize to data/reference/cisa_kev.csv."""

import csv
import logging
import urllib.request
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Resolve paths relative to the project root (parent of scripts/)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = PROJECT_ROOT / "data" / "reference" / "cisa_kev.csv"

CSV_COLUMNS = [
    "cve_id",
    "vendor",
    "product",
    "vulnerability_name",
    "date_added",
    "known_ransomware_use",
    "required_action",
]


def fetch_kev_json() -> list[dict]:
    """Download the KEV JSON feed and return the vulnerabilities list."""
    import json

    logger.info("Fetching CISA KEV catalog from %s", KEV_URL)
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "TawasolPay-RiskAssistant/1.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        data = json.loads(response.read().decode("utf-8"))

    vulnerabilities = data.get("vulnerabilities", [])
    logger.info("Fetched %d KEV entries", len(vulnerabilities))
    return vulnerabilities


def normalize_entry(raw: dict) -> dict:
    """Extract and rename fields from a raw KEV JSON entry."""
    return {
        "cve_id": raw.get("cveID", ""),
        "vendor": raw.get("vendorProject", ""),
        "product": raw.get("product", ""),
        "vulnerability_name": raw.get("vulnerabilityName", ""),
        "date_added": raw.get("dateAdded", ""),
        "known_ransomware_use": raw.get("knownRansomwareCampaignUse", "Unknown"),
        "required_action": raw.get("requiredAction", ""),
    }


def write_csv(entries: list[dict]) -> None:
    """Write normalized entries to CSV."""
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(entries)
    logger.info("Wrote %d rows to %s", len(entries), OUTPUT_PATH)


def main() -> None:
    raw_entries = fetch_kev_json()
    normalized = [normalize_entry(entry) for entry in raw_entries]
    write_csv(normalized)


if __name__ == "__main__":
    main()
