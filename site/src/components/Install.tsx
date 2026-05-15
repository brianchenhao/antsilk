const PIP_COMMAND = 'pip install antsilk'

const SNIPPET = `from fastapi import FastAPI
from antsilk import AntsilkMiddleware

app = FastAPI()
app.add_middleware(AntsilkMiddleware)`

export default function Install() {
  return (
    <section className="mt-16 sm:mt-24">
      <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">
        Two lines. That&apos;s it.
      </h2>
      <p className="mt-2 max-w-2xl text-sm text-[color:var(--color-fg-mute)]">
        Install the package, add the middleware. Defaults are tuned to be
        safe in production from the first request.
      </p>

      <div className="mt-6 grid gap-4 sm:grid-cols-5">
        <div className="rounded-lg border border-white/10 bg-[color:var(--color-bg-soft)] p-4 sm:col-span-2">
          <p className="text-xs uppercase tracking-wider text-[color:var(--color-fg-mute)]">
            1. install
          </p>
          <pre className="mt-3 overflow-x-auto text-sm">
            <code>
              <span className="text-[color:var(--color-fg-mute)]">$ </span>
              <span className="text-[color:var(--color-accent)]">
                {PIP_COMMAND}
              </span>
            </code>
          </pre>
        </div>

        <div className="rounded-lg border border-white/10 bg-[color:var(--color-bg-soft)] p-4 sm:col-span-3">
          <p className="text-xs uppercase tracking-wider text-[color:var(--color-fg-mute)]">
            2. wire it up
          </p>
          <pre className="mt-3 overflow-x-auto text-sm leading-6">
            <code>{SNIPPET}</code>
          </pre>
        </div>
      </div>
    </section>
  )
}
