import type { Tier } from "@/lib/types";
import { TIER_CONFIG } from "@/lib/format";

interface TierBadgeProps {
  tier: Tier;
  size?: "sm" | "md";
}

export function TierBadge({ tier, size = "md" }: TierBadgeProps) {
  const config = TIER_CONFIG[tier];
  const sizeClasses =
    size === "sm"
      ? "text-[10px] px-1.5 py-0.5"
      : "text-[11px] px-2 py-1";

  // Only act_now pulses — visual urgency should be reserved for true urgency.
  const dotAnimation = tier === "act_now" ? "animate-pulse-soft" : "";

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 border font-mono uppercase tracking-wider
        ${config.bgClass} ${config.textClass} ${config.borderClass} ${sizeClasses}
      `}
    >
      <span
        className={`inline-block h-1 w-1 rounded-full ${dotAnimation}`}
        style={{ backgroundColor: config.accent }}
        aria-hidden
      />
      {config.label}
    </span>
  );
}
