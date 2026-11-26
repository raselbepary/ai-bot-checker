# AI Bot View Checker

See a page the way AI crawlers fetch it (raw HTML, no JavaScript) and ask several AI models through OpenRouter what they understand from that view.

Single Python file, standard library only.

## Run locally

```bash
python3 app.py
```

Opens http://localhost:8765. No password is needed on localhost.

## Deploy on Coolify

1. **+ New Resource → Application → Public Repository**, use this repo.
2. **Build Pack:** Dockerfile. **Ports Exposes:** `8765`.
3. **Environment variables:** `APP_PASSWORD` (required), optionally `APP_USERNAME` and `OPENROUTER_API_KEY`.
4. **Persistent storage:** add a volume mounted at `/data` so a saved OpenRouter key and model list survive redeploys.
5. Set your domain and deploy.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `0.0.0.0` in Docker, `127.0.0.1` locally | Interface to listen on |
| `PORT` | `8765` | Port |
| `APP_USERNAME` | `admin` | Login user name |
| `APP_PASSWORD` | none | Login password; the app refuses to start on a public interface without it |
| `OPENROUTER_API_KEY` | none | Server-side OpenRouter key |
| `ALLOW_PRIVATE_URLS` | off | Set `1` to allow checking private or internal addresses |
| `ALLOW_NO_AUTH` | off | Set `1` to run publicly without a password (not recommended) |
| `DATA_DIR` | `/data` in Docker, `./data` locally | Where the saved key and model list are stored |
| `SESSION_DAYS` | `30` | How long a sign-in lasts |

## Safety

- Sign-in page with a signed, HttpOnly session cookie on every page and API call except `/health` and `/login`. Ten failed attempts from one IP block sign-in for 15 minutes.
- The OpenRouter key can be saved on the server (Save key on server) and is then used from any browser after sign-in. It is stored in `DATA_DIR/settings.json` with owner-only file permissions and is never sent back to the browser; the page only shows a masked hint.
- Changing `APP_PASSWORD` signs everyone out.
- URLs that resolve to private, loopback, link-local or reserved addresses are refused, including after redirects.
- Requests come from the server's IP. Cloudflare and other firewalls may treat this differently from real crawlers, which they verify by IP.
