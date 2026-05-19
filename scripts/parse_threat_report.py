"""Parse the synthetic MDR threat report into data/processed/campaigns.json."""

import json
import logging
import re
from pathlib import Path

from pydantic import TypeAdapter

# Add src/ to path so we can import schemas
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from schemas import Campaign

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = PROJECT_ROOT / "data" / "raw" / "synthetic_threat_report.md"
OUTPUT_PATH = PROJECT_ROOT / "data" / "processed" / "campaigns.json"

# matches campaign section headers: ### N. ActorName - "CampaignName"
# handles em-dash, en-dash, or hyphen as separator, curly or straight quotes
SECTION_HEADER = re.compile(
    r'^###\s+\d+\.\s+(.+?)\s*[\u2014\u2013\-]\s*[\u201c""](.+?)[\u201d""]',
    re.MULTILINE,
)


def extract_sections(text: str) -> list[tuple[str, str, str]]:
    """Split the report into (actor_name, campaign_name, section_body) tuples."""
    headers = list(SECTION_HEADER.finditer(text))
    sections = []
    for i, match in enumerate(headers):
        actor_name = match.group(1).strip()
        campaign_name = match.group(2).strip()
        start = match.end()
        # Section body extends to the next header or end of text
        end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
        body = text[start:end]
        sections.append((actor_name, campaign_name, body))
    return sections


def parse_cves(body: str) -> list[str]:
    """Extract all CVE IDs from a section body.

    Matches three forms:
      - Standard: CVE-YYYY-NNNNN (4-digit year, 4-7 digit sequence)
      - Synthetic: CVE-SYN-YYYY-NNNN
      - CI/CD synthetic: CICD-SYN-NNN
    """
    cve_pattern = re.compile(
        r"(?:CVE-(?:SYN-)?\d{4}-\d{4,7}|CICD-SYN-\d{3,})"
    )
    matches = cve_pattern.findall(body)
    # Deduplicate while preserving order
    seen: set[str] = set()
    result: list[str] = []
    for cve in matches:
        if cve not in seen:
            seen.add(cve)
            result.append(cve)
    return result


def parse_target_profile(body: str) -> list[str]:
    """Extract targeted asset types from the Target profile line."""
    match = re.search(r"\*\*Target profile:\*\*\s*(.+)", body)
    if not match:
        return []
    raw = match.group(1).strip()
    # Split on commas and clean up
    return [segment.strip() for segment in raw.split(",") if segment.strip()]


def parse_ransomware(body: str) -> bool:
    """Determine if the campaign uses ransomware."""
    match = re.search(r"\*\*Ransomware:\*\*\s*(Yes|No)", body)
    if not match:
        return False
    return match.group(1) == "Yes"


def parse_iocs(body: str) -> list[str]:
    """Extract IOCs from the **IOCs:** line.

    IOCs are semicolon-separated. The section ends at a blank line,
    a horizontal rule (---), or end of text.
    """
    match = re.search(
        r"\*\*IOCs:\*\*\s*(.+?)(?:\r?\n\r?\n|\r?\n---|\Z)", body, re.DOTALL
    )
    if not match:
        return []
    raw = match.group(1).strip()
    # IOCs are semicolon-separated
    return [ioc.strip() for ioc in raw.split(";") if ioc.strip()]


def parse_ttps(body: str, actor_name: str, has_ransomware: bool) -> list[str]:
    """Extract TTPs from the descriptive paragraph.

    Captures: initial access method, lateral movement technique,
    post-exploitation objective, and ransomware variant if applicable.
    """
    ttps: list[str] = []

    # Exploit chain as a TTP
    chain_match = re.search(r"\*\*Exploit chain:\*\*\s*(.+)", body)
    if chain_match:
        ttps.append(f"Exploit chain: {chain_match.group(1).strip()}")

    # Ransomware variant
    ransom_match = re.search(r"\*\*Ransomware:\*\*\s*Yes\s*[—–-]\s*(.+)", body)
    if ransom_match:
        ttps.append(f"Ransomware: {ransom_match.group(1).strip()}")

    # Confidence level as context
    conf_match = re.search(r"\*\*Confidence:\*\*\s*(.+)", body)
    if conf_match:
        ttps.append(f"Confidence: {conf_match.group(1).strip()}")

    return ttps


def parse_campaign(actor_name: str, campaign_name: str, body: str) -> Campaign:
    """Parse a single campaign section into a Campaign model."""
    has_ransomware = parse_ransomware(body)
    # Full campaign name includes actor for disambiguation
    full_name = f"{actor_name} — {campaign_name}"

    return Campaign(
        name=full_name,
        associated_cves=parse_cves(body),
        targeted_asset_types=parse_target_profile(body),
        ttps=parse_ttps(body, actor_name, has_ransomware),
        iocs=parse_iocs(body),
    )


def main() -> None:
    if not REPORT_PATH.exists():
        raise FileNotFoundError(f"Threat report not found at {REPORT_PATH}")

    text = REPORT_PATH.read_text(encoding="utf-8")
    sections = extract_sections(text)

    if not sections:
        raise ValueError("No campaign sections found in threat report")

    campaigns = [parse_campaign(actor, campaign, body) for actor, campaign, body in sections]
    logger.info("Parsed %d campaigns from threat report", len(campaigns))

    # Serialize using Pydantic for consistency
    adapter = TypeAdapter(list[Campaign])
    output_json = adapter.dump_json(campaigns, indent=2).decode("utf-8")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(output_json, encoding="utf-8")
    logger.info("Wrote campaigns to %s", OUTPUT_PATH)


if __name__ == "__main__":
    main()
