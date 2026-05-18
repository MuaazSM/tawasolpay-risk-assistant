"use client";

import { useState } from "react";
import type { TopRiskOutput } from "@/lib/types";
import { TIER_CONFIG } from "@/lib/format";
import { TierBadge } from "./TierBadge";
import { EvidencePill } from "./EvidencePill";
import { ScoreBars } from "./ScoreBars";

interface RiskCardProps {
  risk: TopRiskOutput;
}

export function RiskCard({ risk }: RiskCardProps) {
  const [expanded, setExpanded] = useState(false);
  const tier = TIER_CONFIG[risk.tier];

  return (
    <article
      className={`
        card-glow group relative border bg-bg-raised
        transition-all duration-300 ease-out
        ${expanded ? "border-bg-border-strong" : "border-bg-border hover:border-bg-border-strong"}
      `}
      style={{ "--tier-accent": tier.accent } as React.CSSProperties}
    >
      {/* Left accent stripe — the tier color as a hard visual signal. */}
      <div
        className="absolute left-0 top-0 bottom-0 w-[3px]"
        style={{ backgroundColor: tier.accent }}
        aria-hidden
      />

      {/* Collapsed header row — always visible. */}
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="
          w-full text-left pl-7 pr-6 py-5
          focus:outline-none focus-visible:bg-bg-sunken
          transition-colors cursor-pointer
        "
        aria-expanded={expanded}
      >
        <div className="flex items-start gap-5">
          {/* Rank — large, monospace, monumental. */}
          <div className="flex-shrink-0 w-12 pt-0.5">
            <div
              className="font-mono text-[32px] font-semibold tabular-nums leading-none"
              style={{ color: `color-mix(in srgb, ${tier.accent} 50%, #6b6862)` }}
            >
              {String(risk.rank).padStart(2, "0")}
            </div>
          </div>

          {/* Center: identity + headline */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <TierBadge tier={risk.tier} />
              {risk.faithfulness_passed ? (
                <span className="font-mono text-[10px] tracking-wider text-verified/70 uppercase flex items-center gap-1.5">
                  <span className="inline-block h-1 w-1 rounded-full bg-verified" />
                  verified
                </span>
              ) : (
                <span className="font-mono text-[10px] tracking-wider text-warning uppercase flex items-center gap-1.5">
                  <span className="inline-block h-1 w-1 rounded-full bg-warning animate-pulse-soft" />
                  unverified
                </span>
              )}
              <span className="font-mono text-[11px] text-ink-faint">
                {risk.cve_id}
              </span>
            </div>

            <h2 className="font-sans text-[17px] font-semibold text-ink leading-snug mb-2">
              {risk.explanation.headline}
            </h2>

            <div className="flex items-center gap-3 flex-wrap font-mono text-[11px] text-ink-muted tracking-terminal">
              <span className="text-ink">{risk.asset_name}</span>
              {risk.vulnerability_name && (
                <>
                  <span className="text-ink-faint">·</span>
                  <span>{risk.vulnerability_name}</span>
                </>
              )}
              {risk.business_service && (
                <>
                  <span className="text-ink-faint">·</span>
                  <span>{risk.business_service}</span>
                </>
              )}
            </div>
          </div>

          {/* Right: score + expand chevron */}
          <div className="flex-shrink-0 flex items-center gap-4">
            <div className="text-right">
              <div className="font-mono text-2xl font-semibold text-ink tabular-nums leading-none">
                {risk.score.toFixed(1)}
              </div>
              <div className="eyebrow mt-1">score</div>
            </div>
            <div
              className={`
                text-ink-dim transition-transform duration-300
                ${expanded ? "rotate-180" : ""}
              `}
              aria-hidden
            >
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path
                  d="M3 5l4 4 4-4"
                  stroke="currentColor"
                  strokeWidth="1.5"
                  strokeLinecap="square"
                  strokeLinejoin="miter"
                />
              </svg>
            </div>
          </div>
        </div>
      </button>

      {/* Expanded content — only rendered when expanded for perf. */}
      {expanded && (
        <div className="border-t border-bg-border pl-7 pr-6 py-6 animate-fade-in">
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-8">
            {/* Left column: prose explanation + evidence */}
            <div className="space-y-0">
              <Section title="Why this ranks here">
                <p className="text-ink leading-relaxed text-[14px]">
                  {risk.explanation.why_it_ranks_here}
                </p>
              </Section>

              <div className="section-divider">
                <Section title="Business impact">
                  <p className="text-ink leading-relaxed text-[14px]">
                    {risk.explanation.business_impact}
                  </p>
                </Section>
              </div>

              <div className="section-divider">
                <Section title="Cited evidence">
                  <div className="space-y-3">
                    {risk.explanation.cited_cves.length > 0 && (
                      <EvidenceRow
                        label="CVEs"
                        items={risk.explanation.cited_cves}
                        kind="cve"
                      />
                    )}
                    {risk.explanation.cited_campaigns.length > 0 && (
                      <EvidenceRow
                        label="Campaigns"
                        items={risk.explanation.cited_campaigns}
                        kind="campaign"
                      />
                    )}
                    {risk.explanation.cited_controls.length > 0 && (
                      <EvidenceRow
                        label="NIST controls"
                        items={risk.explanation.cited_controls}
                        kind="control"
                      />
                    )}
                  </div>
                </Section>
              </div>

              <div className="section-divider">
                <Section title="Recommended actions">
                  <ol className="space-y-2.5 list-none">
                    {risk.explanation.recommended_actions.map((action, i) => (
                      <li
                        key={i}
                        className="flex gap-3 text-[14px] text-ink leading-relaxed"
                      >
                        <span className="font-mono text-ink-faint tabular-nums flex-shrink-0 mt-px">
                          {String(i + 1).padStart(2, "0")}
                        </span>
                        <span>{action}</span>
                      </li>
                    ))}
                  </ol>
                </Section>
              </div>

              {!risk.faithfulness_passed &&
                risk.faithfulness_violations.length > 0 && (
                  <div className="section-divider">
                    <Section title="Faithfulness violations">
                      <div className="border border-warning/20 bg-warning/5 p-3">
                        <ul className="space-y-1 text-[12px] text-warning font-mono">
                          {risk.faithfulness_violations.map((v, i) => (
                            <li key={i}>— {v}</li>
                          ))}
                        </ul>
                      </div>
                    </Section>
                  </div>
                )}
            </div>

            {/* Right column: score breakdown + metadata panels */}
            <div className="space-y-4">
              <div className="border border-bg-border bg-bg-sunken/50 p-5">
                <ScoreBars breakdown={risk.score_breakdown} tier={risk.tier} />
              </div>

              <div className="border border-bg-border bg-bg-sunken/50 p-5 space-y-3">
                <div className="eyebrow mb-2">Asset context</div>
                <MetaRow label="asset_id" value={risk.asset_id} />
                <MetaRow label="vuln_id" value={risk.vuln_id} />
                <MetaRow label="cve_id" value={risk.cve_id} />
                {risk.asset_type && (
                  <MetaRow label="asset_type" value={risk.asset_type} />
                )}
                {risk.owner_team !== undefined && (
                  <MetaRow
                    label="owner"
                    value={risk.owner_team ?? "— unassigned —"}
                  />
                )}
                {risk.internet_exposed !== undefined && (
                  <MetaRow
                    label="exposure"
                    value={risk.internet_exposed ? "internet-facing" : "internal"}
                    highlight={risk.internet_exposed}
                  />
                )}
                {risk.business_criticality && (
                  <MetaRow
                    label="criticality"
                    value={risk.business_criticality}
                  />
                )}
              </div>

              {/* Exploitation signals — only render if enriched fields are present */}
              {(risk.kev_match !== undefined ||
                risk.campaign_matches ||
                risk.ransomware_match !== undefined) && (
                <div className="border border-bg-border bg-bg-sunken/50 p-5 space-y-3">
                  <div className="eyebrow mb-2">Exploitation signals</div>
                  {risk.kev_match !== undefined && (
                    <SignalRow label="CISA KEV" active={risk.kev_match} />
                  )}
                  {risk.threat_intel_max_maturity !== undefined && (
                    <SignalRow
                      label="Threat intel"
                      active={!!risk.threat_intel_max_maturity}
                      detail={risk.threat_intel_max_maturity}
                    />
                  )}
                  {risk.campaign_matches && risk.campaign_matches.length > 0 && (
                    <SignalRow
                      label="Campaign match"
                      active
                      detail={risk.campaign_matches.join(", ")}
                    />
                  )}
                  {risk.ransomware_match !== undefined && (
                    <SignalRow label="Ransomware" active={risk.ransomware_match} />
                  )}
                  {risk.chain_partners && risk.chain_partners.length > 0 && (
                    <SignalRow
                      label="Chain partners"
                      active
                      detail={`+${risk.chain_partners.length} on same asset`}
                    />
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </article>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h3 className="eyebrow mb-2">{title}</h3>
      {children}
    </section>
  );
}

function EvidenceRow({
  label,
  items,
  kind,
}: {
  label: string;
  items: string[];
  kind: "cve" | "campaign" | "control";
}) {
  return (
    <div className="flex items-start gap-3 flex-wrap">
      <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim pt-1.5 w-20 flex-shrink-0">
        {label}
      </span>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item) => (
          <EvidencePill key={item} label={item} kind={kind} />
        ))}
      </div>
    </div>
  );
}

function MetaRow({
  label,
  value,
  highlight,
}: {
  label: string;
  value: string;
  highlight?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="font-mono text-[10px] uppercase tracking-wider text-ink-dim">
        {label}
      </span>
      <span
        className={`font-mono text-[11px] truncate ${
          highlight ? "text-tier-act-now" : "text-ink"
        }`}
      >
        {value}
      </span>
    </div>
  );
}

function SignalRow({
  label,
  active,
  detail,
}: {
  label: string;
  active: boolean;
  detail?: string | null;
}) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <div className="flex items-center gap-2">
        <span
          className={`inline-block h-1.5 w-1.5 rounded-full transition-colors ${
            active ? "bg-tier-act-now" : "bg-bg-border-strong"
          }`}
        />
        <span
          className={`font-mono text-[11px] ${
            active ? "text-ink" : "text-ink-dim"
          }`}
        >
          {label}
        </span>
      </div>
      {detail && (
        <span className="font-mono text-[10px] text-ink-muted text-right">
          {detail}
        </span>
      )}
    </div>
  );
}
