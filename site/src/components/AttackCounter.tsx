import stats from '../data/attack_stats.json'

type Rule =
  | 'threat_intel'
  | 'rate_limit'
  | 'sqli'
  | 'xss'
  | 'path_traversal'
  | 'bad_header'
  | 'bad_token'

const RULE_LABEL: Record<Rule, string> = {
  threat_intel: 'threat-intel',
  rate_limit: 'rate limit',
  sqli: 'SQL injection',
  xss: 'XSS',
  path_traversal: 'path traversal',
  bad_header: 'bad header',
  bad_token: 'bad token',
}

const RULE_ORDER: Rule[] = [
  'threat_intel',
  'rate_limit',
  'sqli',
  'xss',
  'path_traversal',
  'bad_header',
  'bad_token',
]

function formatDate(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  })
}

export default function AttackCounter() {
  const byRule = stats.by_rule as Record<Rule, number>
  const total = stats.total_blocked
  const generated = formatDate(stats.generated_at)
  const window = `${formatDate(stats.first_seen)} – ${formatDate(stats.last_seen)}`

  return (
    <section className="mt-20 sm:mt-28">
      <div className="rounded-2xl border border-white/10 bg-[color:var(--color-bg-soft)] p-6 sm:p-10">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-xs uppercase tracking-wider text-[color:var(--color-fg-mute)]">
              blocked on geyam.com
            </p>
            <p className="mt-2 text-5xl font-semibold tracking-tight sm:text-7xl">
              {total.toLocaleString()}
              <span className="ml-3 text-base font-normal text-[color:var(--color-fg-mute)]">
                requests
              </span>
            </p>
          </div>
          <p className="text-xs text-[color:var(--color-fg-mute)]">
            window: {window} &middot; refreshed {generated}
          </p>
        </div>

        <div className="mt-8 grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
          {RULE_ORDER.map((rule) => (
            <div
              key={rule}
              className="rounded-lg border border-white/10 bg-black/30 p-3"
            >
              <p className="text-xs text-[color:var(--color-fg-mute)]">
                {RULE_LABEL[rule]}
              </p>
              <p className="mt-1 text-2xl font-semibold text-[color:var(--color-accent)]">
                {(byRule[rule] ?? 0).toLocaleString()}
              </p>
            </div>
          ))}
        </div>

        <p className="mt-6 text-xs text-[color:var(--color-fg-mute)]">
          Counts are aggregate hits recorded in antsilk's local SQLite ledger
          on the geyam.com production deployment. Per-IP details stay on the
          host; only totals are published here.
        </p>
      </div>
    </section>
  )
}
