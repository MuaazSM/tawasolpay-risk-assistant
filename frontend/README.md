# TawasolPay Risk Console — Frontend

Next.js 14 App Router dashboard for the top 5 risks. Server-rendered,
dark mode, Tailwind, no UI library.

## Local development

```bash
npm install
cp .env.example .env.local
# Edit .env.local to point at your local backend
npm run dev
```

Open http://localhost:3000.

## Deploying to Vercel

1. Push the repo to GitHub.
2. Import the project on Vercel. Set the root directory to `frontend/`.
3. Add `NEXT_PUBLIC_API_URL` in project settings → Environment Variables.
   Set it to the production Render URL of the backend.
4. Deploy.

## Architecture

- `app/page.tsx` — server component, fetches from the API and renders
  the page. Forces dynamic rendering (`cache: 'no-store'`) because risk
  data is operational.
- `components/RiskCard.tsx` — client component for expand/collapse state.
  Everything else is server-rendered.
- `lib/api.ts` — typed fetch helpers with error handling.
- `lib/format.ts` — tier display config; the single source of truth for
  colors and labels.
- `lib/types.ts` — mirrors the backend Pydantic schemas.

If the backend `TopRiskOutput` schema changes, update `lib/types.ts` to
match.

## Aesthetic

Operations-center serious — dense, terminal-influenced, dark.
JetBrains Mono for data, Inter for body. Four sharp tier colors.
No purple gradients.
