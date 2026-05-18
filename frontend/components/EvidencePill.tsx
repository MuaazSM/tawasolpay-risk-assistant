interface EvidencePillProps {
  label: string;
  kind?: "cve" | "campaign" | "control" | "neutral";
  prefix?: string; // small icon/label before the value
}

// A pill for a single piece of cited evidence. The kind prop changes
// the accent color to make scanning faster (campaigns look different
// from CVEs at a glance).
export function EvidencePill({ label, kind = "neutral", prefix }: EvidencePillProps) {
  const accentClass = {
    cve: "border-l-2 border-l-tier-act-now/60",
    campaign: "border-l-2 border-l-tier-act-soon/60",
    control: "border-l-2 border-l-tier-track/60",
    neutral: "",
  }[kind];

  return (
    <span className={`pill ${accentClass}`}>
      {prefix && (
        <span className="text-ink-dim text-[9px] tracking-wider uppercase">
          {prefix}
        </span>
      )}
      {label}
    </span>
  );
}
