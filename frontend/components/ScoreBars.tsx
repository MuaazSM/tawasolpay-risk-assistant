import type { ScoreBreakdown } from "@/lib/types";
import type { Tier } from "@/lib/types";
import { TIER_CONFIG } from "@/lib/format";

// Component-to-max-weight mapping. Keep in sync with src/scoring.py.
// If you change weights in the backend, mirror them here.
const COMPONENT_MAX: Record<keyof Omit<ScoreBreakdown, "total">, number> = {
  exposure: 15,
  exploitation_evidence: 20,
  ransomware: 15,
  business_criticality: 15,
  missing_controls: 10,
  cvss: 5,
  days_open: 5,
  chain_bonus: 15,
};

// Display labels — terse, monospace-friendly.
const COMPONENT_LABEL: Record<keyof Omit<ScoreBreakdown, "total">, string> = {
  exposure: "exposure",
  exploitation_evidence: "exploit evidence",
  ransomware: "ransomware",
  business_criticality: "criticality",
  missing_controls: "missing controls",
  cvss: "cvss",
  days_open: "days open",
  chain_bonus: "chain bonus",
};

interface ScoreBarsProps {
  breakdown: ScoreBreakdown;
  tier: Tier;
}

export function ScoreBars({ breakdown, tier }: ScoreBarsProps) {
  const components = Object.keys(COMPONENT_MAX) as Array<keyof typeof COMPONENT_MAX>;
  const tierAccent = TIER_CONFIG[tier].accent;

  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between mb-3">
        <span className="eyebrow">Score decomposition</span>
        <span className="font-mono text-xs text-ink-muted tabular-nums">
          total{" "}
          <span className="text-ink font-medium">{breakdown.total.toFixed(1)}</span>
          <span className="text-ink-faint"> / 100</span>
        </span>
      </div>
      {components.map((key) => {
        const value = breakdown[key];
        const max = COMPONENT_MAX[key];
        const pct = Math.min(100, (value / max) * 100);
        const isZero = value === 0;
        // High-contribution components (>70% of max) get the tier accent color;
        // mid-range gets a muted version; zero stays dark.
        const barColor = isZero
          ? "bg-bg-border"
          : pct >= 70
            ? ""
            : "bg-ink/30";
        return (
          <div key={key} className="grid grid-cols-[130px_1fr_56px] items-center gap-3">
            <span className="font-mono text-[11px] text-ink-muted tracking-terminal truncate">
              {COMPONENT_LABEL[key]}
            </span>
            <div className="h-1.5 bg-bg-sunken overflow-hidden">
              <div
                className={`h-full transition-all duration-700 ease-out ${barColor}`}
                style={{
                  width: `${pct}%`,
                  // High-fill bars use the tier accent for visual punch.
                  ...(pct >= 70 && !isZero
                    ? { backgroundColor: `color-mix(in srgb, ${tierAccent} 70%, #e8e6e3)` }
                    : {}),
                }}
              />
            </div>
            <span
              className={`font-mono text-[11px] tabular-nums text-right ${
                isZero ? "text-ink-faint" : "text-ink"
              }`}
            >
              {value.toFixed(1)}
              <span className="text-ink-faint">/{max}</span>
            </span>
          </div>
        );
      })}
    </div>
  );
}
