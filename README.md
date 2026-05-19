# TawasolPay Cyber Risk Assistant

> AI Engineering Intern Assessment for Hive Pro

Ranks the top 5 cyber risks for a fictional fintech (TawasolPay) by combining structured vulnerability data, asset context, threat intelligence, and semantic retrieval over NIST 800-53 controls. The ranking is fully deterministic. LLMs write explanations, not rankings.

**Live demo:** [Frontend](https://tawasolpay-risk-assistant.vercel.app/) | [API docs](https://tawasolpay-risk-assistant.onrender.com/docs) | [GitHub](https://github.com/MuaazSM/tawasolpay-risk-assistant)

---

## How it works

Five CSVs (assets, vulnerabilities, threat intelligence, business services, remediation guidance) and one MDR threat report feed into an enrichment layer that joins them against the CISA KEV catalog and parsed campaign intelligence. A deterministic scoring engine assigns priority tiers (`act_now` / `act_soon` / `track` / `monitor`) via categorical gates, then applies a weighted 0-100 score with chain amplification within each tier. For each top-5 risk, a retrieval step pulls relevant NIST 800-53 controls from a Chroma vector index. Gemini 2.5 Flash (with Groq Llama 3.3 70B as fallback) writes structured JSON explanations that are constrained to cite only verified evidence. A faithfulness check enforces that every cited CVE, campaign, and NIST control is present in the risk's evidence packet, with a single retry if the LLM strays.

![Architecture diagram](architecture.png)

### Pipeline stages

```
CSV + MDR report
    -> ingest (type coercion, stale-asset flagging)
    -> enrichment (join assets <> vulns <> services <> KEV <> threat intel <> campaigns <> chains)
    -> scoring (tier gates -> weighted score -> sort)
    -> top-k selection
    -> NIST 800-53 retrieval (two-query RAG from Chroma)
    -> LLM explanation (Gemini -> Groq fallback, Pydantic-validated)
    -> faithfulness validation (reject hallucinated citations, retry once)
    -> API / frontend
```

---

## Sample output

Actual JSON returned by `GET /risks/top?k=5` (first risk, `retrieved_controls` truncated for brevity):

```json
{
  "rank": 1,
  "tier": "act_now",
  "asset_id": "A-1005",
  "vuln_id": "V-2015",
  "cve_id": "CVE-2024-21762",
  "asset_name": "vpn-edge-01",
  "score": 88.98,
  "score_breakdown": {
    "exposure": 15.0,
    "exploitation_evidence": 20.0,
    "ransomware": 15.0,
    "business_criticality": 15.0,
    "missing_controls": 3.33,
    "cvss": 4.9,
    "days_open": 0.75,
    "chain_bonus": 15.0,
    "total": 88.98
  },
  "explanation": {
    "headline": "Critical Fortinet SSL-VPN RCE on internet-exposed vpn-edge-01 gateway actively exploited by CrimsonJackal campaign.",
    "why_it_ranks_here": "CVE-2024-21762 carries a CVSS of 9.8 with weaponized exploit maturity and is listed in the CISA KEV catalog, confirming active exploitation in the wild. The CrimsonJackal — Gateway Breaker campaign specifically targets financial services and fintech firms, and this asset is internet-exposed with Critical business criticality. Chain amplification applies because a second CrimsonJackal CVE is present on the same asset.",
    "business_impact": "Compromise of vpn-edge-01 gives attackers a network entry point into the Remote Access service. The CrimsonJackal campaign deploys LockBit 3.0 ransomware post-exploitation, which could halt transaction processing and increase incident-response and compliance obligations for an ISO 27001-scoped service.",
    "cited_cves": ["CVE-2024-21762", "CVE-2024-55591"],
    "cited_campaigns": ["CrimsonJackal — Gateway Breaker"],
    "cited_controls": ["SC-12.5", "SC-7.7", "SI-2"],
    "recommended_actions": [
      "Apply the vendor patch for CVE-2024-21762 immediately per SI-2 flaw remediation requirements.",
      "Implement split tunneling restrictions per SC-7.7 to prevent unauthorized external connections.",
      "Utilize PKI certificates or hardware tokens per SC-12.5 to harden VPN authentication."
    ]
  },
  "retrieved_controls": ["... 3 full NIST 800-53 controls with statement + discussion ..."],
  "ransomware_match": true,
  "faithfulness_violations": [],
  "faithfulness_passed": true
}
```

The assignment requires each risk to surface: asset, vulnerability, matched threat intel, business service at risk, and plain-English explanation. In the response above: `asset_name` is the asset, `cve_id` + `explanation.headline` identify the vulnerability, `explanation.cited_campaigns` carries matched threat intel, `explanation.business_impact` names the business service ("Remote Access service"), and the `explanation` object as a whole is the plain-English output.

Full top-5 ranking:

| Rank | Tier | Asset | CVE | Score | Headline |
|------|------|-------|-----|-------|----------|
| 1 | `act_now` | vpn-edge-01 | CVE-2024-21762 | 88.98 | Fortinet SSL-VPN RCE, CrimsonJackal chain |
| 2 | `act_now` | vpn-edge-02 | CVE-2024-21762 | 88.98 | Fortinet SSL-VPN RCE on second VPN edge in HA pair |
| 3 | `act_now` | vpn-edge-01 | CVE-2024-55591 | 88.62 | FortiOS auth bypass, second link in CrimsonJackal chain |
| 4 | `act_now` | vpn-edge-02 | CVE-2024-55591 | 88.62 | FortiOS auth bypass on second VPN edge in HA pair |
| 5 | `act_now` | teamcity-prod | CVE-2024-27198 | 88.04 | TeamCity auth bypass, SilentForge Build Chain Theft |

VPN edges dominate because they are internet-exposed, carry two chained CVEs from an active ransomware campaign (CrimsonJackal), and underlie a Critical business service. This is the correct outcome. The scoring formula directly encodes the assignment's central rule: "a 10/10 CVSS on an internal dev server must rank below an 8/10 on an internet-exposed payment gateway with active ransomware."

### Rendered output

![Dashboard](dashboard_hero.png)

The frontend renders the same JSON as an operations-style risk register. Each card expands to show the full explanation, cited evidence, NIST controls, and per-component score breakdown. The deterministic scoring is auditable at a glance.

---

## The data split

**What I embedded (vector store):** NIST 800-53 Rev 5 controls (~1,100 controls from the OSCAL JSON). These are the only data that benefit from semantic retrieval. A risk description like "authentication bypass on VPN gateway" needs to find controls like IA-2 (Identification and Authentication) and AC-17 (Remote Access) by meaning, not by keyword match. One chunk per control (natural semantic boundary), embedded with `BAAI/bge-small-en-v1.5`.

**What I kept as structured records:** Everything else. The five CSVs are joined and filtered with pandas. They have clean foreign keys (`asset_id`, `cve_id`, `business_service`) and categorical fields that are best handled by exact-match joins, not approximate similarity. The MDR threat report is regex-parsed into `campaigns.json` with discrete fields (actor name, CVE list, target profile, TTPs, IOCs). Its value is structural and precise. Embedding it would sacrifice specificity for approximation.

---

## Design decisions

**Deterministic scoring, not LLM ranking.** The ranking is the most consequential output of the system. A CISO who asks "why is #1 above #2?" deserves a score decomposition (`exposure +15, active ransomware +15, chain bonus +15, ...`), not "the LLM concluded it was riskier." LLMs have no information beyond the structured fields the scorer already reads. They would add non-determinism, latency, and an explainability gap.

**Tier gates + weighted score.** Pure additive scoring lets many small factors bury large ones (five medium issues on a dev server outscore three severe ones on a payment gateway). Pure multiplicative scoring zeroes out non-exposed assets that still matter (CI/CD, domain controllers). Tier gates encode structural rules categorically, and the weighted score breaks ties within each tier. The tiering approach is inspired by CISA SSVC's action-oriented philosophy: prioritize vulnerabilities by exploitation context and mission impact, not by technical severity alone.

**Chain amplification (+15, tier-promoting).** When the same asset carries multiple CVEs matching the same active campaign, the system is looking at a validated multi-step attack path, not two independent findings. The +15 bonus promotes risks across tier boundaries when the asset is critical, and also contributes to within-tier ranking. A confirmed chain is genuinely worse than a single exploit, and both effects are intentional.

**Three parallel sources of "actively exploited."** CISA KEV (external validation), threat intel `exploit_maturity=Weaponized` (assessment-specific), and campaign match (parsed MDR report). Synthetic CVEs (`CVE-SYN-*`) never appear in KEV. Treating "not in KEV" as "not exploited" would systematically miss half the assessment's scenarios. Each source is surfaced as a distinct boolean for auditability; the union drives scoring.

**Two-query NIST retrieval.** A single context-rich query pulls toward network/VPN controls and misses base controls like IA-2 (authentication) and SI-2 (patching). A second query using only NIST vocabulary catches them. Results are interleaved via round-robin so both queries contribute.

---

## What I considered and rejected

1. **LangChain / LangGraph for pipeline orchestration.** The pipeline is linear: ingest, enrich, score, retrieve, explain, validate. No conditional branches, no tool-use loops, no agent decisions. LangChain would add dependency weight and abstraction layers without enabling anything the plain Python pipeline can't do in fewer lines. Every stage is a pure function that takes a DataFrame or dict and returns one. No framework needed.

2. **LLM council reranking (multi-model ensemble for risk ordering).** Every signal the council would weigh is already present as a structured field. The council adds non-determinism (run twice, get different rankings), 3-5x latency, token cost, and an explainability gap. The deterministic scorer is auditable, reproducible, and fast. The LLM's job is constrained to explanation writing, where its strengths (fluency, synthesis) are actually useful.

3. **Embedding the threat report into the vector store.** The MDR report's value is structural: actor names, exact CVE lists, target sectors, TTP sequences, IOC lists. These are discrete, enumerable fields that should be joined precisely, not retrieved approximately. Regex-parsing into `campaigns.json` preserves every field at full fidelity. Embedding would lose the structure and return fuzzy matches when exact matches are available.

---

## Where it goes wrong

**1. Hand-tuned weights without empirical validation.** The scoring weights (exploitation evidence: 20, exposure: 15, ransomware: 15, ...) and tier gate thresholds were tuned by working backward from desired rankings on this dataset. They produce correct orderings for TawasolPay's 60 assets and 114 vulnerabilities, but there is no backtest against historical incident data to validate that they generalize. A different asset distribution (mostly internal, few internet-exposed) could produce counterintuitive rankings. *Mitigation:* The perturbation tests in `test_scoring_invariants.py` verify structural properties (toggling exposure drops tier, chain bonus increases score, CVSS alone doesn't override context) rather than exact scores, so they survive weight changes. Production use would require calibration against incident data.

**2. Threat report parsing is brittle.** The regex parser in `scripts/parse_threat_report.py` assumes the MDR report follows a specific markdown structure (H2 headers per campaign, bullet-pointed CVEs, "Target Profile" / "Indicators of Compromise" sections). A report with different heading levels, inline CVE references, or restructured sections would silently produce incomplete `campaigns.json`, with missing campaigns, missing CVEs, or empty TTP lists. The system would still run but score risks as if those campaigns don't exist. *Mitigation:* The parser logs extracted campaign counts and CVE lists. A structural validator comparing expected vs. extracted campaign count would catch silent failures. In production, this would be replaced by structured STIX/TAXII feeds.

When the faithfulness check does fire, the retry loop looks like this (from a deliberately stress-tested run with a higher-temperature setting):

```
faithfulness FAIL -- risk A-1014/V-2043: cited control IA-7 not in
    retrieved set [IA-2, IA-5.11, SC-12.5]. Retrying with violations injected.
faithfulness PASS -- risk A-1014/V-2043: retry successful, violations=[]
```

In normal operation (temperature 0.1), all 5 risks pass on first attempt. The retry path exists for when they don't.

**3. Faithfulness checks miss subtle misattributions.** The validator catches hallucinated entities (a CVE not in the evidence, a campaign the risk doesn't match). It does not catch *incorrect pairings*. The LLM could attribute CVE-2024-21762 to the SilentForge campaign instead of CrimsonJackal, and the validator would pass it because both the CVE and the campaign name are individually in the allowlist. *Mitigation:* The prompt constrains the LLM with explicit allowlists and few-shot examples, which reduces but does not eliminate cross-attribution. A production system would need relation-level validation (CVE X belongs to campaign Y), not just entity-level.

---

## What I would improve with one more day

**Backtested scoring weights from historical incident data.** The +15 chain bonus, the 20-point exploitation evidence weight, the tier gate thresholds: these are hand-tuned to produce correct rankings on this assessment's dataset. They work, and the perturbation tests verify structural invariants survive weight changes. But the weights are not empirically validated against real-world outcomes. Given another day, I would build a calibration harness: take a set of historical incidents (which vulnerabilities were actually exploited, which assets were actually compromised), run the scorer against the pre-incident state, and measure how well the ranking predicted incident priority. That turns "the weights feel right" into "the weights correlate with observed outcomes at r=0.X", which is the difference between a prototype and a defensible operational tool.

---

## Run it locally

### Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend)
- API keys: [Gemini](https://aistudio.google.com/apikey) (primary) and/or [Groq](https://console.groq.com/keys) (fallback)

### Backend

```bash
git clone https://github.com/MuaazSM/tawasolpay-risk-assistant.git
cd tawasolpay-risk-assistant

python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Configure API keys
cp .env.example .env
# Edit .env with your GEMINI_API_KEY and/or GROQ_API_KEY

# Build reference data (one-time)
python scripts/fetch_kev.py            # Download CISA KEV catalog
python scripts/parse_threat_report.py  # Parse MDR report -> campaigns.json
python scripts/build_nist_index.py     # Build Chroma index (~1,100 NIST controls)
python scripts/export_onnx_model.py    # Export embedding model to ONNX

# Run the pipeline (CLI)
python -m src.pipeline --cache --json

# Start the API server
uvicorn api.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install

# Point at local backend
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local  # Next.js uses .env.local for local dev

npm run dev   # -> http://localhost:3000
```

### Tests

```bash
pytest                        # All tests
pytest tests/test_scoring_invariants.py  # Scoring perturbation tests
pytest tests/test_nist_retrieval.py      # RAG golden tests (needs Chroma index)
pytest --cov=src              # With coverage
```

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Pipeline readiness, risk count, last refresh timestamp |
| `GET` | `/risks/top?k=5` | Top-k ranked risks with explanations and NIST controls |
| `GET` | `/risk/{asset_id}/{vuln_id}` | Single risk detail |
| `POST` | `/refresh` | Re-run scoring + retrieval + explanation on cached enriched data |
| `GET` | `/docs` | Auto-generated OpenAPI (Swagger UI) |

---

## Project structure

```
src/
  schemas.py              Pydantic models, source of truth for all domain objects
  ingest.py               5 CSV loaders with type coercion and validation
  enrichment.py           Join all sources into one row per (asset, vulnerability)
  scoring.py              Tier gates + weighted score + chain bonus
  nist_retrieval.py       Two-query RAG retrieval from Chroma
  llm_client.py           Gemini primary, Groq fallback, structured output
  explanation_generator.py Prompt construction, LLM call, retry on failure
  faithfulness.py         Validate LLM citations against evidence packet
  pipeline.py             Full pipeline orchestrator with caching

api/
  main.py                 FastAPI app, lifespan startup, CORS config
  routes.py               4 endpoints + OpenAPI

frontend/
  app/page.tsx            Server component, fetches and renders risk dashboard
  components/             RiskCard, TierBadge, ScoreBars, EvidencePill, Header
  lib/                    TypeScript types, API client, format constants

scripts/
  fetch_kev.py            Download CISA KEV catalog -> data/reference/cisa_kev.csv
  parse_threat_report.py  Regex-parse MDR report -> data/processed/campaigns.json
  build_nist_index.py     Build Chroma vector index from NIST OSCAL JSON
  export_onnx_model.py    Export BGE-small to ONNX (removes PyTorch dependency)

tests/
  test_schemas.py         Pydantic model construction and validation
  test_ingest.py          CSV loading, type coercion, edge cases (27 tests)
  test_enrichment.py      business_criticality max() rule verification
  test_scoring_invariants.py  Perturbation tests, structural properties (5 classes)
  test_nist_retrieval.py  Golden tests against real Chroma index (4 risk profiles)
  test_faithfulness.py    Validation logic + retry loop (16+ tests)

data/
  raw/                    5 CSVs + MDR threat report (input data pack)
  reference/              CISA KEV catalog, NIST 800-53 OSCAL JSON
  processed/              campaigns.json, Chroma index, ONNX model, caches
```

---

## Tech stack

| Component | Choice | Why |
|-----------|--------|-----|
| Language | Python 3.11 | Standard for data + ML pipelines |
| Schemas | Pydantic v2 | Every cross-module boundary and LLM output is schema-validated |
| Data joins | pandas | 60 assets, 114 vulns, readability beats Spark |
| Vector store | Chroma | Lightweight, persisted to disk, no infra |
| Embeddings | `BAAI/bge-small-en-v1.5` (ONNX) | Better than MiniLM on technical prose, no API cost, ~50MB |
| LLM (primary) | Gemini 2.5 Flash | Native structured output, large context, generous free tier |
| LLM (fallback) | Groq (Llama 3.3 70B) | Fast inference, separate rate limits |
| API | FastAPI | Auto-generated OpenAPI as demo backup |
| Frontend | Next.js (App Router) | Server components, Tailwind, deployed on Vercel |
| Deploy | Render (backend) + Vercel (frontend) | Free tier, Dockerfile support |

---

## Production evolution

This is a take-home prototype. To make it operational:

- CISA KEV refresh as a scheduled job (currently fetched once at build time and cached)
- SIEM/EDR signal ingestion for real-time exploitation evidence instead of static CSVs
- Backtested scoring weights, calibrated against historical incident data
- Structured threat feeds (STIX/TAXII) to replace brittle markdown parsing
- Relation-level faithfulness validation to catch CVE-campaign misattributions, not just entity hallucinations
- Human-in-the-loop review of top risks before generating tickets
- Audit logging with full scoring evidence per risk for compliance
- Multi-tenancy and RBAC for per-organization asset sets
