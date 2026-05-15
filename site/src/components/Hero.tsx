export default function Hero() {
  return (
    <section className="text-center sm:text-left">
      <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-[color:var(--color-fg-mute)]">
        <span className="size-1.5 rounded-full bg-[color:var(--color-accent)]" />
        v0.1.0 &middot; zero runtime dependencies
      </div>

      <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-6xl">
        Drop-in security middleware
        <br />
        for Python ASGI apps.
      </h1>

      <p className="mt-6 max-w-2xl text-base text-[color:var(--color-fg-mute)] sm:text-lg">
        Two lines of glue. Every request gets rate-limited, scanned for SQLi /
        XSS / path traversal, checked against threat-intel feeds, and inspected
        for suspicious headers. Blocks land as structured events in a local
        SQLite ledger.
      </p>

      <p className="mt-3 max-w-2xl text-sm text-[color:var(--color-fg-mute)]">
        <span className="text-[color:var(--color-accent)]">&lt; 1ms p99</span>{' '}
        overhead. FastAPI, Starlette, Litestar — anything ASGI.
      </p>

      <div className="mt-8 flex flex-wrap justify-center gap-3 sm:justify-start">
        <a
          href="https://pypi.org/project/antsilk/"
          className="inline-flex items-center gap-2 rounded-md bg-[color:var(--color-accent)] px-4 py-2 text-sm font-medium text-[color:var(--color-bg)] hover:brightness-110"
        >
          pip install antsilk
        </a>
        <a
          href="https://github.com/brianchenhao/antsilk"
          className="inline-flex items-center gap-2 rounded-md border border-white/15 px-4 py-2 text-sm font-medium hover:bg-white/5"
        >
          GitHub
        </a>
        <a
          href="https://docs.antsilk.com"
          className="inline-flex items-center gap-2 rounded-md border border-white/15 px-4 py-2 text-sm font-medium hover:bg-white/5"
        >
          Docs
        </a>
      </div>
    </section>
  )
}
