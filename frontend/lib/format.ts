import type { Tier } from "./types";

// Centralized tier display config. Keep code paths consistent — every
// place that renders a tier should pull from here.
export const TIER_CONFIG: Record<
  Tier,
  {
    label: string;
    description: string;
    accent: string; // hex
    bgClass: string;
    textClass: string;
    borderClass: string;
  }
> = {
  act_now: {
    label: "ACT NOW",
    description: "Board-level urgency. Patch within 24 hours.",
    accent: "#ef4444",
    bgClass: "bg-tier-act-now/10",
    textClass: "text-tier-act-now",
    borderClass: "border-tier-act-now/40",
  },
  act_soon: {
    label: "ACT SOON",
    description: "High priority. Patch within 7 days.",
    accent: "#f59e0b",
    bgClass: "bg-tier-act-soon/10",
    textClass: "text-tier-act-soon",
    borderClass: "border-tier-act-soon/40",
  },
  track: {
    label: "TRACK",
    description: "Monitor and patch within next sprint.",
    accent: "#3b82f6",
    bgClass: "bg-tier-track/10",
    textClass: "text-tier-track",
    borderClass: "border-tier-track/40",
  },
  monitor: {
    label: "MONITOR",
    description: "Low risk. Schedule for next cycle.",
    accent: "#64748b",
    bgClass: "bg-tier-monitor/10",
    textClass: "text-tier-monitor",
    borderClass: "border-tier-monitor/40",
  },
};

export function formatTimestamp(iso: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

export function pluralize(n: number, singular: string, plural?: string): string {
  return n === 1 ? singular : plural ?? `${singular}s`;
}
