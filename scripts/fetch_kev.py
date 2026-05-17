"""Download CISA Known Exploited Vulnerabilities catalog and normalize to CSV.

Fetches the JSON feed from CISA, extracts relevant fields (CVE ID, vendor,
product, vulnerability name, date added, ransomware use), and writes a
normalized CSV to data/reference/cisa_kev.csv. Idempotent — safe to re-run.
"""


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
