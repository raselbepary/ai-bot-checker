# Clay Visibility Studio

By The Clay Media.

A self-hosted tool for agencies to check how AI crawlers and AI assistants see client websites: what bots receive, what they miss, whether the site is cited in AI answers, and what to fix. Includes client projects, branded reports and scheduled monitoring with email alerts.

The app is a single Python file using only the standard library, plus a small web front end. A headless Chromium (installed in the Docker image) powers the JavaScript gap view and PDF reports.

## Features

The sidebar is organized the way the work is usually done: pick a client, check the whole site, then individual pages, then AI answers.

### Clients

| Page | What it does |
|---|---|
| **Projects** | Save each client once: website, brand names, competitors, location and customer questions. Choosing a client in the sidebar fills in every page and shows only that client's results. |
| **Reports** | Branded client report with a scorecard, key findings and detailed sections. Shared as a private link (no sign-in needed, hidden from search engines) or downloaded as a PDF. |
| **Monitoring** | Re-checks clients daily or weekly and emails you when something gets worse: a crawler becomes blocked, pages start failing, or the readiness or visibility score drops. |
| **Client portal** | On the Reports page: give a client their own sign-in at `/portal` to view their scores, visibility trend, reports and monitoring history. View only; clients can't run checks or see other clients. |

### Site checks (whole site)

| Page | What it does |
|---|---|
| **Site scan** | Checks any number of pages from the sitemap, up to 2,000 per scan by default, as a chosen bot (4 pages at a time, so client servers aren't overloaded): blocked pages, errors, animated counters showing 0, noindex, thin pages, missing titles, descriptions and structured data. History and CSV export. |
| **AI access** | Tests 17 AI crawlers against robots.txt and live server responses (allowed, blocked by robots.txt, blocked by server), plus a robots.txt builder for AI crawler rules. |
| **Crawler visits** | Upload a server or Cloudflare log to see which AI crawlers really visited, which pages they read and what they got back. Fake bots are filtered out using the IP lists that OpenAI, Perplexity, Google, Bing, Apple and Mistral publish. The log is analyzed in memory and not stored. |
| **llms.txt** | Checks `/llms.txt` and `/llms-full.txt` (format and links) and drafts one from the sitemap. |
| **Competitors** | Runs the same checks on your site and up to five competitors side by side, and lists where competitors are ahead. |

### Page checks (one page at a time)

| Page | What it does |
|---|---|
| **Bot view** | What each crawler (GPTBot, ClaudeBot, PerplexityBot, Googlebot and others) receives from a page: status, robots.txt verdict, readable text, animated counters, structured data. |
| **JavaScript gap** | Loads the page in a real browser and compares it with the raw HTML crawlers get: text, numbers, headings and links that only appear after JavaScript runs. |
| **AI readiness** | Scores how easy a page is for AI tools to understand and quote: a direct opening answer, clear structure, concrete facts, freshness and trust signals, basics. Optional AI suggestions for a better opening, changes and an FAQ. |
| **Structured data** | Reviews JSON-LD for errors, warnings and missing information, with a suggested Organization snippet. |

### AI answers

| Page | What it does |
|---|---|
| **AI citations** | Asks AI models with live web search the questions customers ask. Shows whether the site is named or cited, a visibility score (0 to 100) and its trend, sentiment, share of voice against competitors, the sources AI cites, citation opportunities with outreach drafts, and AI-suggested questions. |
| **AI test** | Lets models read a page (as text, or by fetching it live) and answer questions about it, to check what they understand. |

### Settings

OpenRouter API key and model list, email (SMTP) for monitoring alerts, and agency branding (name, contact line, and logos for light and dark backgrounds) shown in the sidebar, sign-in pages, reports, the client portal and alert emails.

## Suggested routine for a new client

1. **Projects:** create the client. On AI citations, **Suggest questions with AI** can draft customer questions.
2. **AI access** and **Site scan:** fix crawler blocks and broken pages first.
3. **JavaScript gap** and **AI readiness** on the key pages (homepage, main services).
4. **AI citations** and **Competitors:** set the baseline.
5. **Reports:** create the first client report.
6. **Monitoring:** turn on weekly checks with email alerts.

## Run locally

```bash
python3 app.py
```

Opens http://localhost:8765. No password is needed on localhost. The JavaScript gap view and PDF reports need Chromium's headless shell; without it, those two features show a clear message and everything else works.

## Deploy on Coolify

1. Point a Coolify application at this repository.
2. **Build pack:** Dockerfile. **Port:** `8765`.
3. **Persistent storage:** mount a volume at `/data` so clients, results, reports and settings survive updates.
4. **Environment variables:** at least `APP_PASSWORD` (see below).
5. Set the domain and deploy. A deploy takes a few minutes because the image includes the headless browser.

The Dockerfile uses `python:3.12-slim-bookworm` (Debian 12) because the browser installer does not support Debian 13 yet.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APP_PASSWORD` | none | Sign-in password. The app refuses to start on a public interface without it. Changing it signs everyone out. |
| `APP_USERNAME` | `admin` | Sign-in user name |
| `HOST` / `PORT` | `0.0.0.0` in Docker / `8765` | Where the app listens |
| `DATA_DIR` | `/data` in Docker, `./data` locally | Where everything is saved |
| `SESSION_DAYS` | `30` | How long a sign-in lasts |
| `OPENROUTER_API_KEY` | none | Optional server-side OpenRouter key (it can also be saved in Settings) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM` | none | Optional email settings; override what is saved in Settings. `SMTP_SECURITY` is `starttls`, `ssl` or `none`. |
| `SCAN_MAX_PAGES` | `2000` | Most pages one site scan may check (up to 10000). Larger scans take longer and use more storage. |
| `CHROME_PATH` | auto-detected | Path to a Chromium headless shell, if it is not in the default location |
| `ALLOW_PRIVATE_URLS` | off | `1` allows checking private or internal addresses (local testing only) |
| `ALLOW_NO_AUTH` | off | `1` allows running publicly without a password (not recommended) |

## What is saved in `DATA_DIR`

| Path | Contents |
|---|---|
| `settings.json` | OpenRouter key, model list, email settings, branding (owner-only permissions) |
| `projects.json` | Client projects and their monitoring settings |
| `scans/` | Site scans (last 30) |
| `cites/` | AI citation tests (last 50) |
| `compares/` | Competitor comparisons (last 50) |
| `reports/` | Client reports and their PDFs |
| `monitor/` | Monitoring history per client |
| `brand/` | Uploaded logos (served publicly at `/brand/logo-light` and `/brand/logo-dark` for sign-in pages and emails) |
| `portal_users.json` | Client portal logins (passwords stored only as salted PBKDF2 hashes; owner-only permissions) |

Uploaded server logs are never saved.

## What costs money

Only features that call AI models use OpenRouter credits: AI test, AI citations (including the optional sentiment rating), question ideas, outreach drafts, AI readiness suggestions, and monitoring when its citation test is switched on. Everything else is free to run.

## Safety

- Every page and API call requires sign-in (signed, HttpOnly session cookie), except `/health`, `/login`, report share links and the client portal. Ten failed sign-ins from one address block sign-in for 15 minutes.
- Client portal sessions are separate from the agency sign-in and only open that client's portal page. Creating a new password or disabling a login signs that client out everywhere.
- Report share links use long random addresses, send `noindex`, and stop working when the report is deleted.
- The OpenRouter key and email password are stored on the server only and never sent back to the browser.
- Addresses that resolve to private, loopback, link-local or reserved networks are refused, including after redirects. The headless browser is routed through a built-in filter that applies the same rule to every image, script and file it loads.
- Checks come from the server's own IP address with each crawler's user agent. Firewalls such as Cloudflare verify real crawlers by IP, so results show what the server sends today, not what AI tools have stored from earlier visits.

## Development

- `app.py`: server, checks, background jobs (site scans, citation tests, monitoring) and the report renderer.
- `web/index.html`, `web/app.css`, `web/app.js`: the interface (no build step).
- `web/login.html`: the sign-in page.
