import type { TopRiskOutput, HealthResponse } from "@/lib/types";
import { formatTimestamp, pluralize } from "@/lib/format";

interface HeaderProps {
  risks: TopRiskOutput[];
  health: HealthResponse | null;
}

export function Header({ risks, health }: HeaderProps) {
  const actNowCount = risks.filter((r) => r.tier === "act_now").length;
  const actSoonCount = risks.filter((r) => r.tier === "act_soon").length;
  const ransomwareCount = risks.filter((r) => r.ransomware_match ?? false).length;

  return (
    <header className="border-b border-bg-border bg-bg-base/80 backdrop-blur-md sticky top-0 z-20">
      {/* Top utility strip */}
      <div className="border-b border-bg-border/40 px-6 py-2.5">
        <div className="max-w-[1180px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2.5 font-mono text-xs uppercase tracking-wider text-ink-dim">
            <span
              className={`inline-block h-2 w-2 rounded-full ${
                health?.pipeline_ready
                  ? "bg-verified animate-pulse-soft"
                  : "bg-warning animate-pulse-soft"
              }`}
            />
            <span className="text-ink-muted">tawasolpay</span>
            <span className="text-ink-faint">/</span>
            <span>risk console</span>
            <span className="text-ink-faint">·</span>
            <span className="text-ink-faint">v0.1.0</span>
          </div>
          <div className="flex items-center gap-4 font-mono text-xs uppercase tracking-wider text-ink-dim">
            <span>
              refreshed{" "}
              <span className="text-ink-muted">
                {formatTimestamp(health?.last_refresh ?? null)}
              </span>
            </span>
            <span className="text-ink-faint">·</span>
            <span>
              pipeline{" "}
              <span
                className={
                  health?.pipeline_ready ? "text-verified" : "text-warning"
                }
              >
                {health?.pipeline_ready ? "ready" : "starting"}
              </span>
            </span>
          </div>
        </div>
      </div>

      {/* Main header — title, description, and stat counters. */}
      <div className="px-6 py-8">
        <div className="max-w-[1180px] mx-auto">
          <div className="flex items-end justify-between gap-8 flex-wrap">
            <div>
              <div className="eyebrow mb-3">
                Risk register · top {risks.length}
              </div>
              <h1 className="font-sans text-4xl font-bold text-ink leading-tight max-w-2xl tracking-tight">
                Top risks by{" "}
                <span className="text-tier-act-now">deterministic</span>{" "}
                priority
              </h1>
              <p className="mt-3 text-ink-muted text-base max-w-xl leading-relaxed">
                Ranked by tier gates and weighted scoring across exposure,
                exploitation evidence, business impact, and chain matches.
                Explanations are NIST 800-53 grounded and citation-verified.
              </p>
            </div>

            {/* Stats cluster */}
            <div className="flex items-end gap-6">
              <Stat
                value={actNowCount}
                label={pluralize(actNowCount, "act-now risk")}
                accent="text-tier-act-now"
                glow={actNowCount > 0}
              />
              <div className="h-12 w-px bg-bg-border" />
              <Stat
                value={actSoonCount}
                label={pluralize(actSoonCount, "act-soon risk")}
                accent="text-tier-act-soon"
              />
              <div className="h-12 w-px bg-bg-border" />
              <Stat
                value={ransomwareCount}
                label="ransomware"
                accent="text-ink"
              />
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}

function Stat({
  value,
  label,
  accent,
  glow,
}: {
  value: number;
  label: string;
  accent: string;
  glow?: boolean;
}) {
  return (
    <div className="text-right">
      <div
        className={`
          font-mono text-6xl font-semibold tabular-nums leading-none
          ${accent}
          ${glow ? "drop-shadow-[0_0_12px_rgba(239,68,68,0.3)]" : ""}
        `}
      >
        {String(value).padStart(2, "0")}
      </div>
      <div className="eyebrow mt-2">{label}</div>
    </div>
  );
}
