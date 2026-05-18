// Shown by Next.js while the page is being server-rendered.
// Kept minimal and on-aesthetic so it doesn't flash an inconsistent UI.
export default function Loading() {
  return (
    <main className="relative z-10 min-h-screen flex items-center justify-center px-6">
      <div className="text-center">
        <div className="font-mono text-xs uppercase tracking-wider text-ink-dim mb-3 flex items-center gap-2 justify-center">
          <span className="inline-block h-2 w-2 rounded-full bg-tier-act-now animate-pulse-soft" />
          loading risk register
        </div>
        <div className="font-mono text-sm text-ink-faint">
          fetching top 5 from pipeline · this can take a moment on cold start
        </div>
      </div>
    </main>
  );
}
