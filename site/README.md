# antsilk.com landing page

Static Vite + React + TypeScript site for [antsilk.com](https://antsilk.com).
Built with Tailwind 4 via `@tailwindcss/vite`. Same stack as
[brianchenhao.com](https://brianchenhao.com) so the portfolio shares one
toolchain.

## Local dev

```bash
cd site
npm install
npm run dev          # http://localhost:5173
```

## Build

```bash
npm run build        # outputs to site/dist
npm run preview      # serve the built output locally
```

## Attack counter data

`src/data/attack_stats.json` is generated from a local `antsilk_events.db`
by `scripts/build_stats.py`. The site bundles whatever JSON is present at
build time; no runtime DB queries (the page is fully static on Hostinger).

```bash
# refresh from the repo-root events.db (default)
python scripts/build_stats.py

# point at the geyam production DB
python scripts/build_stats.py --db /path/to/geyam/backend/antsilk_events.db
```

Re-run before pushing to refresh the counter shown on antsilk.com. The
script writes zeroed stats if the DB is missing, so the build never
breaks.

## Deploy

`.github/workflows/site-deploy.yml` builds and SFTPs `dist/` to Hostinger
on every push to `main` that touches `site/**`.

Required GitHub secrets:

- `HOSTINGER_HOST` — SFTP hostname
- `HOSTINGER_USER` — SFTP username (Hostinger File Manager → SFTP)
- `HOSTINGER_PASSWORD` — SFTP password
- `HOSTINGER_PORT` — optional, defaults to 22
- `HOSTINGER_REMOTE_PATH` — e.g. `/home/uXXXXXX/domains/antsilk.com/public_html`
