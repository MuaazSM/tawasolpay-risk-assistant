import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        // Wired up via next/font CSS variables in layout.tsx
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
        sans: ["var(--font-sans)", "system-ui", "sans-serif"],
      },
      colors: {
        // Background system — near-black with subtle warmth
        bg: {
          base: "#0a0a0b",
          raised: "#121214",
          sunken: "#070708",
          border: "#1f1f23",
          "border-strong": "#2a2a30",
        },
        // Text — warm off-white, never pure
        ink: {
          DEFAULT: "#e8e6e3",
          muted: "#a3a098",
          dim: "#6b6862",
          faint: "#3f3d39",
        },
        // Tier accents — sharp, saturated, used sparingly
        tier: {
          "act-now": "#ef4444",   // red-500
          "act-soon": "#f59e0b",  // amber-500
          "track": "#3b82f6",     // blue-500
          "monitor": "#64748b",   // slate-500
        },
        // Faithfulness signals
        verified: "#22c55e",      // green-500
        warning: "#fbbf24",       // amber-400
      },
      letterSpacing: {
        terminal: "0.02em",
        wide: "0.08em",
        wider: "0.14em",
      },
      animation: {
        "fade-in": "fadeIn 0.5s ease-out forwards",
        "fade-in-up": "fadeInUp 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards",
        "pulse-soft": "pulseSoft 2.5s ease-in-out infinite",
      },
      keyframes: {
        fadeIn: {
          "0%": { opacity: "0" },
          "100%": { opacity: "1" },
        },
        fadeInUp: {
          "0%": { opacity: "0", transform: "translateY(8px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
        pulseSoft: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.55" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
