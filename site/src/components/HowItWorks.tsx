const DIAGRAM = `              ┌─────────────────────────┐
              │   Internet / Users      │
              └──────────┬──────────────┘
                         │ HTTP request
                         ▼
            ┌─────────────────────────────────┐
            │   Your FastAPI / ASGI app       │
            │   ┌───────────────────────────┐ │
            │   │   AntsilkMiddleware       │ │
            │   │   ─ threat-intel (IP)     │ │
            │   │   ─ rate limiter          │ │
            │   │   ─ pattern scanner       │ │
            │   │   ─ header sanity check   │ │
            │   │   ─ event logger          │ │
            │   └─────────┬─────────────────┘ │
            │             │ pass / block      │
            │             ▼                   │
            │      Route handlers             │
            └─────────────┬───────────────────┘
                          │ event sink
                          ▼
                   ┌──────────────┐
                   │  events.db   │
                   │  (SQLite)    │
                   └──────────────┘`

const STEPS = [
  {
    title: 'Inspect every request',
    body: 'IP threat-intel runs first (cheapest). Then rate limit, then regex pattern scan over URL / query / non-UA headers, then header sanity. The route never sees a blocked request.',
  },
  {
    title: 'Record what got stopped',
    body: 'Every block writes a row to a local SQLite ledger — timestamp, IP, path, rule, severity, response code, raw User-Agent, rule-specific JSON. PII never leaves your host.',
  },
  {
    title: 'Carve out the routes that need it',
    body: 'Webhooks bypass rate limit. Chatbot / comment endpoints bypass pattern scan. Payment endpoints bypass threat-intel. All via a single RouteRule dataclass.',
  },
]

export default function HowItWorks() {
  return (
    <section className="mt-20 sm:mt-28">
      <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">
        How it works
      </h2>
      <p className="mt-2 max-w-2xl text-sm text-[color:var(--color-fg-mute)]">
        One middleware, four rules, one ledger. No external services. No
        runtime dependencies.
      </p>

      <div className="mt-8 grid gap-6 lg:grid-cols-5">
        <div className="rounded-lg border border-white/10 bg-[color:var(--color-bg-soft)] p-4 lg:col-span-3">
          <pre className="overflow-x-auto text-xs leading-snug text-[color:var(--color-fg-mute)] sm:text-sm">
            <code>{DIAGRAM}</code>
          </pre>
        </div>

        <ol className="space-y-4 lg:col-span-2">
          {STEPS.map((step, i) => (
            <li
              key={step.title}
              className="rounded-lg border border-white/10 bg-[color:var(--color-bg-soft)] p-4"
            >
              <p className="text-xs uppercase tracking-wider text-[color:var(--color-accent)]">
                step {i + 1}
              </p>
              <p className="mt-1 text-base font-medium">{step.title}</p>
              <p className="mt-2 text-sm text-[color:var(--color-fg-mute)]">
                {step.body}
              </p>
            </li>
          ))}
        </ol>
      </div>
    </section>
  )
}
