export default function Footer() {
  const year = new Date().getFullYear()
  return (
    <footer className="border-t border-white/10">
      <div className="mx-auto flex max-w-5xl flex-col items-center justify-between gap-4 px-6 py-8 text-xs text-[color:var(--color-fg-mute)] sm:flex-row">
        <p>
          &copy; {year} antsilk &middot; MIT licensed &middot; built by{' '}
          <a
            href="https://brianchenhao.com"
            className="text-[color:var(--color-fg)] hover:text-[color:var(--color-accent)]"
          >
            Brian Chen
          </a>
        </p>
        <nav className="flex flex-wrap items-center gap-4">
          <a
            href="https://pypi.org/project/antsilk/"
            className="hover:text-[color:var(--color-fg)]"
          >
            PyPI
          </a>
          <a
            href="https://github.com/brianchenhao/antsilk"
            className="hover:text-[color:var(--color-fg)]"
          >
            GitHub
          </a>
          <a
            href="https://docs.antsilk.com"
            className="hover:text-[color:var(--color-fg)]"
          >
            Docs
          </a>
          <a
            href="https://github.com/brianchenhao/antsilk/blob/main/CHANGELOG.md"
            className="hover:text-[color:var(--color-fg)]"
          >
            Changelog
          </a>
        </nav>
      </div>
    </footer>
  )
}
