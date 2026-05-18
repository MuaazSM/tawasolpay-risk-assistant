import type { HealthResponse, TopRiskOutput } from "./types";

// Read API base from env. Falls back to localhost for dev so the page
// at least renders an error rather than crashing the build.
function getApiBase(): string {
  const base = process.env.NEXT_PUBLIC_API_URL;
  if (!base) {
    if (process.env.NODE_ENV === "development") {
      return "http://localhost:8000";
    }
    throw new Error(
      "NEXT_PUBLIC_API_URL is not set. Configure it in Vercel project settings.",
    );
  }
  return base.replace(/\/$/, ""); // strip trailing slash
}

export interface FetchResult<T> {
  data: T | null;
  error: string | null;
}

// Server-side fetch with no caching — risk data is operational, not static.
export async function fetchTopRisks(k = 5): Promise<FetchResult<TopRiskOutput[]>> {
  try {
    const res = await fetch(`${getApiBase()}/risks/top?k=${k}`, {
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      return {
        data: null,
        error: `API returned ${res.status}: ${res.statusText}`,
      };
    }
    const data = (await res.json()) as TopRiskOutput[];
    return { data, error: null };
  } catch (err) {
    return {
      data: null,
      error: err instanceof Error ? err.message : "Unknown fetch error",
    };
  }
}

export async function fetchHealth(): Promise<FetchResult<HealthResponse>> {
  try {
    const res = await fetch(`${getApiBase()}/health`, {
      cache: "no-store",
      headers: { Accept: "application/json" },
    });
    if (!res.ok) {
      return { data: null, error: `Health check returned ${res.status}` };
    }
    const data = (await res.json()) as HealthResponse;
    return { data, error: null };
  } catch (err) {
    return {
      data: null,
      error: err instanceof Error ? err.message : "Unknown fetch error",
    };
  }
}
