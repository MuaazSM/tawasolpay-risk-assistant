"""Parse the synthetic MDR threat report markdown into structured JSON.

Regex-parses campaign names, associated CVEs, targeted asset types, TTPs,
and IOCs from the markdown report. Writes data/processed/campaigns.json.
Idempotent — safe to re-run.
"""


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
