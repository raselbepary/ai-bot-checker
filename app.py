#!/usr/bin/env python3
"""
AI Bot View Checker
-------------------
See any page the way AI crawlers fetch it (raw HTML, no JavaScript), then ask
several AI models through OpenRouter what they understand from that view.

Local:   python3 app.py            -> http://localhost:8765 (opens automatically)
Server:  see README.md / Dockerfile (HOST=0.0.0.0, APP_PASSWORD required)

Environment variables
  HOST                 Interface to listen on (default 127.0.0.1)
  PORT                 Port (default 8765)
  APP_USERNAME         Login user name (default admin)
  APP_PASSWORD         Login password. Required when HOST is not localhost.
  OPENROUTER_API_KEY   Optional server-side OpenRouter key
  ALLOW_PRIVATE_URLS   Set to 1 to allow checking private/internal addresses (off by default)
  ALLOW_NO_AUTH        Set to 1 to run on a public interface without a password (not recommended)
  DATA_DIR             Folder for saved settings (default ./data, /data in Docker)
  SESSION_DAYS         How long a login lasts (default 30)

No extra packages needed: uses only Python's standard library.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT") or (sys.argv[1] if len(sys.argv) > 1 else 8765))
APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_URLS", "") == "1"
ALLOW_NO_AUTH = os.environ.get("ALLOW_NO_AUTH", "") == "1"
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")
MAX_BODY = 5 * 1024 * 1024
DATA_DIR = os.environ.get("DATA_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
SESSION_COOKIE = "abvc_session"
SESSION_DAYS = int(os.environ.get("SESSION_DAYS", "30"))
_SETTINGS_LOCK = threading.Lock()
_LOGIN_FAILS = {}
TIMEOUT = 25
MAX_BYTES = 6 * 1024 * 1024
MAX_TEXT_FOR_AI = 40000

CHROME_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# id, label, robots.txt token, user agent, who uses it, checked by default
BOTS = [
    ("browser", "Browser (reference)", None, CHROME_UA, "Normal Chrome request, no JavaScript run", True),
    ("gptbot", "GPTBot", "GPTBot",
     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot",
     "OpenAI training crawler", True),
    ("oai-search", "OAI-SearchBot", "OAI-SearchBot",
     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
     "ChatGPT search index", True),
    ("chatgpt-user", "ChatGPT-User", "ChatGPT-User",
     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
     "ChatGPT fetching a page for a user", True),
    ("claudebot", "ClaudeBot", "ClaudeBot",
     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
     "Anthropic training crawler", True),
    ("claude-search", "Claude-SearchBot", "Claude-SearchBot",
     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +Claude-SearchBot@anthropic.com)",
     "Claude search index", True),
    ("claude-user", "Claude-User", "Claude-User",
     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
     "Claude fetching a page for a user", True),
    ("perplexitybot", "PerplexityBot", "PerplexityBot",
     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
     "Perplexity search index", True),
    ("perplexity-user", "Perplexity-User", "Perplexity-User",
     "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)",
     "Perplexity fetching a page for a user", False),
    ("googlebot", "Googlebot (raw HTML)", "Googlebot",
     "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
     "Google's first fetch; Google renders JS later", True),
    ("bingbot", "Bingbot", "bingbot",
     "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
     "Bing, also feeds Copilot and ChatGPT search", True),
    ("applebot", "Applebot", "Applebot",
     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
     "Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
     "Siri and Apple Intelligence", False),
    ("ccbot", "CCBot", "CCBot", "CCBot/2.0 (https://commoncrawl.org/faq/)",
     "Common Crawl, used by many AI labs", False),
    ("meta", "Meta-ExternalAgent", "meta-externalagent",
     "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
     "Meta AI crawler", False),
    ("bytespider", "Bytespider", "Bytespider",
     "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 "
     "(compatible; Bytespider; spider-feedback@bytedance.com)",
     "ByteDance crawler", False),
]
BOT_BY_ID = {b[0]: b for b in BOTS}

_UNVERIFIED_SSL = ssl._create_unverified_context()


# ---------------------------------------------------------------- safety
class BlockedURL(Exception):
    pass


def check_public_url(url):
    """Refuse URLs that resolve to private, loopback, link-local or reserved addresses."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("http", "https"):
        raise BlockedURL("Only http and https URLs can be checked.")
    if ALLOW_PRIVATE:
        return
    host = p.hostname
    if not host:
        raise BlockedURL("The URL has no host name.")
    try:
        infos = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise BlockedURL(f"Could not resolve {host}. Check the domain name.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped:
            ip = mapped
        if not ip.is_global:
            raise BlockedURL(f"{host} points to a private or reserved address ({ip}), which this tool blocks.")


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(SafeRedirect())
_OPENER_INSECURE = urllib.request.build_opener(SafeRedirect(), urllib.request.HTTPSHandler(context=_UNVERIFIED_SSL))


# ---------------------------------------------------------------- fetching
def http_get(url, ua, timeout=TIMEOUT, accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"):
    req = urllib.request.Request(url, headers={
        "User-Agent": ua,
        "Accept": accept,
        "Accept-Language": "en-US,en;q=0.9",
    })
    out = {"status": None, "final_url": url, "ms": None, "bytes": 0, "html": "",
           "error": None, "insecure_ssl": False, "headers": {}}
    t0 = time.time()
    resp = None
    try:
        check_public_url(url)
        try:
            resp = _OPENER.open(req, timeout=timeout)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLError) or "CERTIFICATE" in str(e.reason).upper():
                out["insecure_ssl"] = True
                resp = _OPENER_INSECURE.open(req, timeout=timeout)
            else:
                raise
    except urllib.error.HTTPError as e:
        resp = e
    except BlockedURL as e:
        out["error"] = str(e)
        out["ms"] = int((time.time() - t0) * 1000)
        return out
    except Exception as e:  # network error, timeout, DNS...
        out["error"] = f"{type(e).__name__}: {e}"
        out["ms"] = int((time.time() - t0) * 1000)
        return out

    try:
        out["status"] = resp.getcode() if hasattr(resp, "getcode") else resp.code
        out["final_url"] = resp.geturl() if hasattr(resp, "geturl") else url
        out["headers"] = {k.lower(): v for k, v in resp.headers.items()} if resp.headers else {}
        raw = resp.read(MAX_BYTES)
        out["bytes"] = len(raw)
        charset = None
        try:
            charset = resp.headers.get_content_charset()
        except Exception:
            pass
        out["html"] = raw.decode(charset or "utf-8", errors="replace")
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    out["ms"] = int((time.time() - t0) * 1000)
    return out


# ---------------------------------------------------------------- parsing
class PageExtractor(HTMLParser):
    SKIP = {"script", "style", "noscript", "template", "svg", "iframe", "head", "object", "canvas"}
    BLOCK = {"p", "div", "section", "article", "header", "footer", "nav", "main", "aside", "li", "ul", "ol",
             "h1", "h2", "h3", "h4", "h5", "h6", "tr", "table", "br", "hr", "blockquote", "pre", "figure",
             "figcaption", "form", "dt", "dd", "td", "th", "label", "button"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.parts = []
        self.title = ""
        self.in_title = False
        self.meta = {}
        self.canonical = ""
        self.headings = []
        self.cur_heading = None
        self.links = 0
        self.images = 0
        self.images_no_alt = 0

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self.in_title = True
        elif tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name in ("description", "robots", "og:title", "og:description"):
                self.meta[name] = a.get("content", "")
        elif tag == "link" and "canonical" in a.get("rel", "").lower():
            self.canonical = a.get("href", "")
        if tag in self.SKIP:
            self.skip_depth += 1
            return
        if self.skip_depth:
            return
        if tag == "a" and a.get("href"):
            self.links += 1
        if tag == "img":
            self.images += 1
            alt = a.get("alt", "").strip()
            if not alt:
                self.images_no_alt += 1
            else:
                self.parts.append(f" [image: {alt}] ")
        if tag in ("h1", "h2", "h3"):
            self.cur_heading = [tag, ""]
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        if tag in self.SKIP:
            self.skip_depth = max(0, self.skip_depth - 1)
            return
        if self.skip_depth:
            return
        if self.cur_heading and tag == self.cur_heading[0]:
            txt = re.sub(r"\s+", " ", self.cur_heading[1]).strip()
            if txt:
                self.headings.append({"level": tag, "text": txt})
            self.cur_heading = None
        if tag in self.BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if self.in_title:
            self.title += data
        if self.skip_depth:
            return
        self.parts.append(data)
        if self.cur_heading is not None:
            self.cur_heading[1] += data

    def text(self):
        raw = "".join(self.parts)
        lines = [re.sub(r"[ \t\r\f\v\u00a0]+", " ", ln).strip() for ln in raw.split("\n")]
        out, blank = [], False
        for ln in lines:
            if ln:
                out.append(ln)
                blank = False
            elif not blank and out:
                out.append("")
                blank = True
        return "\n".join(out).strip()


COUNTER_RE = re.compile(r'(<span\b[^>]*class="[^"]*\bcounter-number\b(?!-)[^"]*"[^>]*>)([^<]*)<', re.I)
TO_RE = re.compile(r'data-to-value="([^"]*)"', re.I)
FROM_RE = re.compile(r'data-from-value="([^"]*)"', re.I)

CHALLENGE_MARKERS = ("just a moment...", "cf-chl", "attention required! | cloudflare",
                     "checking your browser", "captcha", "access denied", "request unsuccessful")


def find_counters(html):
    found = []
    for m in COUNTER_RE.finditer(html):
        tag, shown = m.group(1), m.group(2).strip()
        to = TO_RE.search(tag)
        frm = FROM_RE.search(tag)
        found.append({"shown": shown, "to": to.group(1) if to else None,
                      "from": frm.group(1) if frm else None})
    return found


def analyze(url, bot, rp):
    bid, label, token, ua, note, _ = bot
    r = http_get(url, ua)
    res = {"id": bid, "label": label, "note": note, "ua": ua, "status": r["status"],
           "final_url": r["final_url"], "ms": r["ms"], "bytes": r["bytes"], "error": r["error"],
           "insecure_ssl": r["insecure_ssl"], "x_robots_tag": r["headers"].get("x-robots-tag", ""),
           "server": r["headers"].get("server", ""), "cf_cache": r["headers"].get("cf-cache-status", ""),
           "title": "", "meta": {}, "canonical": "", "headings": [], "words": 0, "text": "",
           "links": 0, "images": 0, "images_no_alt": 0, "counters": [], "challenge": False}
    html = r["html"]
    if html:
        p = PageExtractor()
        try:
            p.feed(html)
            p.close()
        except Exception:
            pass
        text = p.text()
        res.update({"title": re.sub(r"\s+", " ", p.title).strip(), "meta": p.meta, "canonical": p.canonical,
                    "headings": p.headings[:60], "text": text[:300000],
                    "words": len(re.findall(r"\w+", text)), "links": p.links,
                    "images": p.images, "images_no_alt": p.images_no_alt,
                    "counters": find_counters(html)})
        low = html[:20000].lower()
        res["challenge"] = any(mk in low for mk in CHALLENGE_MARKERS) and res["words"] < 400
    if token is None:
        res["robots_allowed"] = None
    elif rp is None:
        res["robots_allowed"] = True
    else:
        try:
            res["robots_allowed"] = rp.can_fetch(token, url)
        except Exception:
            res["robots_allowed"] = None
    return res


def load_robots(url):
    parts = urllib.parse.urlsplit(url)
    robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
    r = http_get(robots_url, CHROME_UA, accept="text/plain,*/*")
    info = {"url": robots_url, "status": r["status"], "error": r["error"], "text": ""}
    rp = urllib.robotparser.RobotFileParser()
    rp.set_url(robots_url)
    if r["status"] == 200 and r["html"]:
        rp.parse(r["html"].splitlines())
        info["text"] = r["html"][:20000]
    elif r["status"] in (401, 403):
        rp.disallow_all = True
        rp.modified()
    else:
        rp.allow_all = True
        rp.modified()
    return rp, info


def run_check(url, bot_ids):
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    try:
        check_public_url(url)
    except BlockedURL as e:
        return {"error": str(e)}
    selected = [b for b in BOTS if b[0] == "browser" or b[0] in bot_ids]
    rp, robots_info = load_robots(url)
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda b: analyze(url, b, rp), selected))
    return {"url": url, "robots": robots_info, "results": results, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}


# ---------------------------------------------------------------- settings
def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def storage_writable():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        return os.access(DATA_DIR, os.W_OK)
    except Exception:
        return False


def save_settings(updates):
    with _SETTINGS_LOCK:
        data = load_settings()
        data.update(updates)
        data = {k: v for k, v in data.items() if v is not None and v != ""}
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = SETTINGS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        os.replace(tmp, SETTINGS_FILE)
        return data


def key_hint(key):
    return f"{key[:8]}…{key[-4:]}" if len(key) > 16 else "set"


def settings_public():
    s = load_settings()
    saved = s.get("openrouter_key", "")
    env = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if saved:
        source, hint = "saved", key_hint(saved)
    elif env:
        source, hint = "env", key_hint(env)
    else:
        source, hint = "none", ""
    return {"key_source": source, "key_hint": hint, "models": s.get("models", []),
            "storage_ok": storage_writable(), "auth": bool(APP_PASSWORD)}


# ---------------------------------------------------------------- sessions
def _session_secret():
    base = os.environ.get("SESSION_SECRET") or APP_PASSWORD or "local"
    return hashlib.sha256(("abvc-session|" + APP_USERNAME + "|" + base).encode()).digest()


def make_session():
    exp = str(int(time.time()) + SESSION_DAYS * 86400)
    sig = hmac.new(_session_secret(), exp.encode(), hashlib.sha256).hexdigest()
    return f"{exp}.{sig}"


def valid_session(token):
    try:
        exp, sig = token.split(".", 1)
        if int(exp) < time.time():
            return False
        good = hmac.new(_session_secret(), exp.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, good)
    except Exception:
        return False


def login_allowed(ip):
    now = time.time()
    recent = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < 900]
    _LOGIN_FAILS[ip] = recent
    return len(recent) < 10


def record_login_fail(ip):
    _LOGIN_FAILS.setdefault(ip, []).append(time.time())


# ---------------------------------------------------------------- OpenRouter
def openrouter_key(given):
    return ((given or "").strip() or load_settings().get("openrouter_key", "")
            or os.environ.get("OPENROUTER_API_KEY", "").strip())


def ask_model(key, model, bot_label, url, text, question):
    key = openrouter_key(key)
    if not key:
        return {"model": model, "error": "No OpenRouter API key. Save one in the page or set OPENROUTER_API_KEY."}
    truncated = len(text) > MAX_TEXT_FOR_AI
    content = text[:MAX_TEXT_FOR_AI]
    system = (
        f"You are an AI assistant. Below is the content of one web page exactly as the crawler "
        f"'{bot_label}' received it: the raw HTML converted to text, with no JavaScript executed. "
        "Answer the user's question using ONLY this content. Do not use outside knowledge about the "
        "site or company. If information is missing, unclear, or looks like a placeholder (such as 0), "
        "say so explicitly. Quote numbers exactly as they appear in the content."
    )
    user = (f"URL: {url}\n\nPAGE CONTENT{' (truncated)' if truncated else ''}:\n<<<\n{content}\n>>>\n\n"
            f"QUESTION: {question}")
    body = json.dumps({"model": model, "temperature": 0.2,
                       "messages": [{"role": "system", "content": system},
                                    {"role": "user", "content": user}]}).encode()
    req = urllib.request.Request("https://openrouter.ai/api/v1/chat/completions", data=body, headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost",
        "X-Title": "AI Bot View Checker",
    })
    t0 = time.time()
    try:
        try:
            resp = urllib.request.urlopen(req, timeout=180)
        except urllib.error.URLError as e:
            if not isinstance(e, urllib.error.HTTPError) and "CERTIFICATE" in str(e.reason).upper():
                resp = urllib.request.urlopen(req, timeout=180, context=_UNVERIFIED_SSL)
            else:
                raise
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        try:
            msg = json.loads(msg).get("error", {}).get("message", msg)
        except Exception:
            pass
        return {"model": model, "error": f"HTTP {e.code}: {msg}", "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"model": model, "error": f"{type(e).__name__}: {e}", "ms": int((time.time() - t0) * 1000)}
    if "error" in data:
        err = data["error"]
        return {"model": model, "error": err.get("message", str(err)) if isinstance(err, dict) else str(err)}
    try:
        answer = data["choices"][0]["message"]["content"] or ""
    except Exception:
        answer = json.dumps(data)[:2000]
    return {"model": model, "answer": answer, "ms": int((time.time() - t0) * 1000),
            "usage": data.get("usage", {}), "truncated": truncated}


def list_models():
    r = http_get("https://openrouter.ai/api/v1/models", CHROME_UA, accept="application/json")
    if r["error"] or r["status"] != 200:
        return {"error": r["error"] or f"HTTP {r['status']}"}
    try:
        data = json.loads(r["html"]).get("data", [])
        return {"models": sorted(m.get("id", "") for m in data if m.get("id"))}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------- web server
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype, headers=None):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _json(self, obj, code=200, headers=None):
        self._send(code, json.dumps(obj), "application/json; charset=utf-8", headers)

    def _redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _client_ip(self):
        fwd = self.headers.get("X-Forwarded-For", "")
        return fwd.split(",")[0].strip() if fwd else self.client_address[0]

    def _cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _secure(self):
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def _authorized(self):
        if not APP_PASSWORD:
            return True
        return valid_session(self._cookie(SESSION_COOKIE))

    def _deny(self):
        self._json({"error": "Login required", "login": True}, 401)

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/health":
            return self._json({"ok": True})
        if path == "/login":
            if self._authorized():
                return self._redirect("/")
            return self._send(200, LOGIN_PAGE, "text/html; charset=utf-8")
        if path == "/logout":
            return self._redirect("/login", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
        if not self._authorized():
            return self._deny() if path.startswith("/api/") else self._redirect("/login")
        if path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        elif path == "/api/bots":
            self._json([{"id": b[0], "label": b[1], "note": b[4], "default": b[5]} for b in BOTS])
        elif path == "/api/models":
            self._json(list_models())
        elif path == "/api/settings":
            self._json(settings_public())
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if "application/json" not in self.headers.get("Content-Type", ""):
            return self._json({"error": "Expected a JSON request"}, 415)
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                return self._json({"error": "Request too large"}, 413)
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError
        except Exception:
            return self._json({"error": "Invalid request body"}, 400)

        if path == "/api/login":
            if not APP_PASSWORD:
                return self._json({"ok": True})
            ip = self._client_ip()
            if not login_allowed(ip):
                return self._json({"error": "Too many failed attempts. Try again in 15 minutes."}, 429)
            user = str(payload.get("username", ""))
            pw = str(payload.get("password", ""))
            if (hmac.compare_digest(user.encode(), APP_USERNAME.encode())
                    and hmac.compare_digest(pw.encode(), APP_PASSWORD.encode())):
                cookie = (f"{SESSION_COOKIE}={make_session()}; Path=/; Max-Age={SESSION_DAYS * 86400}; "
                          f"HttpOnly; SameSite=Lax" + ("; Secure" if self._secure() else ""))
                return self._json({"ok": True}, headers={"Set-Cookie": cookie})
            record_login_fail(ip)
            time.sleep(0.6)
            return self._json({"error": "Wrong username or password."}, 401)

        if not self._authorized():
            return self._deny()
        try:
            if path == "/api/check":
                if not payload.get("url"):
                    return self._json({"error": "Enter a URL to check."}, 400)
                return self._json(run_check(payload["url"], payload.get("bots", [])))
            if path == "/api/ask":
                return self._json(ask_model(payload.get("key"), payload.get("model", ""),
                                            payload.get("bot", ""), payload.get("url", ""),
                                            payload.get("text", ""), payload.get("question", "")))
            if path == "/api/settings":
                if not storage_writable():
                    return self._json({"error": f"The server cannot write to {DATA_DIR}. Add a persistent volume there."}, 500)
                updates = {}
                if payload.get("clear_key"):
                    updates["openrouter_key"] = None
                elif payload.get("openrouter_key"):
                    updates["openrouter_key"] = str(payload["openrouter_key"]).strip()[:500]
                if isinstance(payload.get("models"), list):
                    updates["models"] = [str(m).strip()[:200] for m in payload["models"] if str(m).strip()][:50]
                save_settings(updates)
                return self._json(settings_public())
        except Exception as e:
            return self._json({"error": f"{type(e).__name__}: {e}"}, 500)
        self._send(404, "Not found", "text/plain")

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Bot View Checker</title>
<style>
:root{
  --paper:#eef1f4; --surface:#ffffff; --ink:#18232f; --muted:#5b6876; --line:#d3d9e0;
  --accent:#1f4e8c; --accent-ink:#ffffff; --ok:#1d7a4c; --ok-bg:#e3f3ea; --bad:#b3261e; --bad-bg:#fbe7e5;
  --warn:#8a5a00; --warn-bg:#fdf1d6; --code:#f6f8fa;
  color-scheme: light;
}
@media (prefers-color-scheme: dark){
  :root{
    --paper:#11161c; --surface:#19212a; --ink:#e4e9ef; --muted:#97a3b0; --line:#2c3743;
    --accent:#6fa3e8; --accent-ink:#0d1620; --ok:#6fd1a0; --ok-bg:#163527; --bad:#ff8a80; --bad-bg:#3b1a18;
    --warn:#f2c46b; --warn-bg:#3a2d12; --code:#141b22;
    color-scheme: dark;
  }
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--paper);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 80px}
h1{font-size:28px;line-height:1.2;margin:0 0 6px;letter-spacing:-.01em}
h2{font-size:19px;margin:0 0 4px}
.lede{color:var(--muted);margin:0 0 24px;max-width:70ch}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:20px;margin-bottom:22px}
.panel > p.hint{color:var(--muted);margin:0 0 14px;font-size:14px;max-width:75ch}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
input[type=text],input[type=password],textarea,select{
  font:inherit;color:var(--ink);background:var(--paper);border:1px solid var(--line);border-radius:7px;padding:9px 11px;width:100%}
textarea{resize:vertical;min-height:70px}
input:focus,textarea:focus,select:focus,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
button{font:inherit;font-weight:600;border:1px solid var(--accent);background:var(--accent);color:var(--accent-ink);
  border-radius:7px;padding:9px 16px;cursor:pointer;white-space:nowrap}
button.ghost{background:transparent;color:var(--accent)}
button:disabled{opacity:.55;cursor:progress}
.url-row input{flex:1;min-width:240px;font-size:16px}
.bots{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:6px 16px;margin:16px 0 4px}
.bots label{display:flex;gap:8px;align-items:flex-start;font-size:14px;cursor:pointer}
.bots small{display:block;color:var(--muted);font-size:12.5px}
.links{font-size:13px;margin-top:6px}
.links a{color:var(--accent);cursor:pointer;text-decoration:underline;margin-right:12px}
.status{color:var(--muted);font-size:14px;min-height:1.4em;margin-top:10px}
.tablewrap{overflow-x:auto;margin-top:6px}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12.5px;color:var(--muted);font-weight:600}
td.num{font-variant-numeric:tabular-nums;white-space:nowrap}
.chip{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12.5px;font-weight:600;white-space:nowrap}
.chip.ok{background:var(--ok-bg);color:var(--ok)} .chip.bad{background:var(--bad-bg);color:var(--bad)}
.chip.warn{background:var(--warn-bg);color:var(--warn)} .chip.na{background:var(--code);color:var(--muted)}
.counters{font-variant-numeric:tabular-nums}
.counters .start{color:var(--bad);font-weight:700}
details.bot{border:1px solid var(--line);border-radius:8px;margin-top:10px;background:var(--surface)}
details.bot > summary{padding:11px 14px;cursor:pointer;font-weight:600;list-style:none;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details.bot > summary::-webkit-details-marker{display:none}
details.bot > summary::before{content:"";width:7px;height:7px;border-right:2px solid var(--muted);border-bottom:2px solid var(--muted);
  transform:rotate(-45deg);transition:transform .15s}
details.bot[open] > summary::before{transform:rotate(45deg)}
.dbody{padding:0 14px 14px}
.kv{display:grid;grid-template-columns:150px 1fr;gap:4px 14px;font-size:14px;margin:4px 0 12px}
.kv dt{color:var(--muted)} .kv dd{margin:0;word-break:break-word}
pre.text{background:var(--code);border:1px solid var(--line);border-radius:7px;padding:12px;max-height:420px;overflow:auto;
  white-space:pre-wrap;word-break:break-word;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:6px 0 0}
.subhead{font-weight:600;font-size:14px;margin:14px 0 4px}
ul.heads{margin:0;padding-left:18px;font-size:14px} ul.heads li span{color:var(--muted);font-size:12px;margin-right:6px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media (max-width:760px){.grid2{grid-template-columns:1fr}.kv{grid-template-columns:1fr}}
label.fld{display:block;font-size:13.5px;font-weight:600;margin:0 0 5px}
.answers{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px;margin-top:16px}
.answer{border:1px solid var(--line);border-radius:8px;padding:14px;background:var(--paper)}
.answer h3{font-size:14.5px;margin:0 0 2px;word-break:break-all}
.answer .meta{color:var(--muted);font-size:12.5px;margin-bottom:8px}
.answer .body{white-space:pre-wrap;font-size:14px;word-break:break-word}
.answer.err .body{color:var(--bad)}
.note{font-size:13px;color:var(--muted);margin-top:10px;max-width:80ch}
.inline-check{display:flex;gap:6px;align-items:center;font-size:13px;color:var(--muted);margin-top:6px}
.topbar{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap}
.signout{color:var(--accent);font-size:14px}
#keyStatus{font-size:13.5px;margin:0 0 8px;color:var(--muted)}
.hidden{display:none}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar"><h1>AI Bot View Checker</h1><a href="/logout" class="signout hidden" id="signout">Sign out</a></div>
  <p class="lede">Fetch a page as each AI crawler would, with no JavaScript, and compare what they receive. Then ask real models what they understand from that view.</p>

  <section class="panel">
    <h2>1. Check a page</h2>
    <div class="row url-row" style="margin-top:12px">
      <input id="url" type="text" placeholder="https://www.example.com/page/" autocomplete="url">
      <button id="checkBtn">Check page</button>
    </div>
    <div class="bots" id="bots"></div>
    <div class="links"><a id="selAll">Select all</a><a id="selNone">Clear</a></div>
    <div class="status" id="checkStatus"></div>
  </section>

  <section class="panel hidden" id="resultsPanel">
    <h2>2. What each bot received</h2>
    <p class="hint">Requests come from the machine running this tool, with each bot's user agent. Cloudflare and some firewalls verify real bots by IP address, so a real crawler can be treated differently from this test.</p>
    <div id="robotsLine" class="note" style="margin:0 0 10px"></div>
    <div class="tablewrap"><table id="summary"></table></div>
    <div id="details"></div>
  </section>

  <section class="panel hidden" id="askPanel">
    <h2>3. Ask AI models about this view</h2>
    <p class="hint">Sends the text one bot received to each model through OpenRouter, with instructions to answer only from that text. This shows how a model interprets what the crawler saw; it is not the model's own crawler visiting your site.</p>
    <div class="grid2">
      <div>
        <label class="fld" for="key">OpenRouter API key</label>
        <div id="keyStatus"></div>
        <input id="key" type="password" placeholder="sk-or-..." autocomplete="off">
        <div class="row" style="margin-top:8px"><button class="ghost" id="saveKey">Save key on server</button><button class="ghost hidden" id="clearKey">Remove saved key</button></div>
        <div class="note" id="keyNote"></div>
      </div>
      <div>
        <label class="fld" for="viewBot">Send the view of</label>
        <select id="viewBot"></select>
      </div>
    </div>
    <div class="grid2" style="margin-top:14px">
      <div>
        <label class="fld" for="models">Models (one OpenRouter model ID per line)</label>
        <textarea id="models" rows="6"></textarea>
        <div class="row" style="margin-top:8px">
          <input id="modelPick" type="text" list="modelList" placeholder="Search model IDs…" style="flex:1">
          <datalist id="modelList"></datalist>
          <button class="ghost" id="addModel">Add</button>
          <button class="ghost" id="loadModels">Load model list</button>
        </div>
      </div>
      <div>
        <label class="fld" for="question">Question</label>
        <textarea id="question" rows="6">List every statistic or number shown on this page and what each one refers to.</textarea>
        <div class="links"><a data-q="numbers">Numbers</a><a data-q="summary">Summary</a><a data-q="company">Company facts</a><a data-q="missing">What's unclear</a></div>
      </div>
    </div>
    <div class="row" style="margin-top:16px"><button id="askBtn">Ask models</button><span class="status" id="askStatus" style="margin:0"></span></div>
    <div class="answers" id="answers"></div>
  </section>
</div>

<script>
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const DEFAULT_MODELS = ["openai/gpt-4o-mini","anthropic/claude-3.5-haiku","google/gemini-2.0-flash-001","deepseek/deepseek-chat","x-ai/grok-3-mini"];
const QUESTIONS = {
  numbers: "List every statistic or number shown on this page and what each one refers to.",
  summary: "Summarize what this page is about in 4-5 sentences, including any key figures.",
  company: "What does this company do, and what concrete facts (sizes, counts, values, locations) does the page state?",
  missing: "Is any information on this page missing, contradictory, or shown as a placeholder (for example 0 values)? List it."
};
let LAST = null;
let SETTINGS = null;

function store(k, v){ try{ localStorage.setItem(k, v); }catch(e){} }
function load(k){ try{ return localStorage.getItem(k); }catch(e){ return null; } }

async function api(path, opts){
  const res = await fetch(path, opts);
  if (res.status === 401){ location.href = '/login'; throw new Error('Login required'); }
  return res.json();
}
const post = (path, body) => api(path, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});

function renderKey(s){
  SETTINGS = s;
  const st = $('#keyStatus');
  if (s.key_source === 'saved') st.innerHTML = `<span class="chip ok">Saved key in use</span> ${esc(s.key_hint)}`;
  else if (s.key_source === 'env') st.innerHTML = `<span class="chip ok">Server key in use</span> ${esc(s.key_hint)} (from OPENROUTER_API_KEY)`;
  else st.innerHTML = '<span class="chip warn">No key saved</span>';
  $('#clearKey').classList.toggle('hidden', s.key_source !== 'saved');
  $('#saveKey').disabled = !s.storage_ok;
  $('#keyNote').textContent = s.storage_ok
    ? 'A saved key works from any browser after you sign in. A key typed here without saving is used for this test only.'
    : 'Saving is unavailable because the server has no writable storage. A key typed here is used for this test only.';
}

async function init(){
  const [bots, s] = await Promise.all([api('/api/bots'), api('/api/settings')]);
  $('#bots').innerHTML = bots.filter(b => b.id !== 'browser').map(b =>
    `<label><input type="checkbox" class="bot-cb" value="${b.id}" ${b.default ? 'checked' : ''}>
     <span>${esc(b.label)}<small>${esc(b.note)}</small></span></label>`).join('');
  $('#url').value = load('abvc_url') || '';
  const savedModels = s.models && s.models.length ? s.models.join('\n') : '';
  $('#models').value = savedModels || load('abvc_models') || DEFAULT_MODELS.join('\n');
  $('#signout').classList.toggle('hidden', !s.auth);
  renderKey(s);
}

$('#selAll').onclick = () => document.querySelectorAll('.bot-cb').forEach(c => c.checked = true);
$('#selNone').onclick = () => document.querySelectorAll('.bot-cb').forEach(c => c.checked = false);
$('#url').addEventListener('keydown', e => { if (e.key === 'Enter') runCheck(); });
$('#checkBtn').onclick = runCheck;
document.querySelectorAll('[data-q]').forEach(a => a.onclick = () => $('#question').value = QUESTIONS[a.dataset.q]);

$('#saveKey').onclick = async () => {
  const k = $('#key').value.trim();
  if (!k){ $('#keyNote').textContent = 'Paste a key first, then save it.'; return; }
  $('#saveKey').disabled = true;
  try{
    const s = await post('/api/settings', {openrouter_key: k});
    if (s.error) throw new Error(s.error);
    $('#key').value = ''; renderKey(s); $('#askStatus').textContent = 'Key saved on the server.';
  }catch(e){ $('#keyNote').textContent = 'Could not save the key: ' + e.message; $('#saveKey').disabled = false; }
};
$('#clearKey').onclick = async () => {
  if (!confirm('Remove the saved OpenRouter key from the server?')) return;
  try{
    const s = await post('/api/settings', {clear_key: true});
    if (s.error) throw new Error(s.error);
    renderKey(s); $('#askStatus').textContent = 'Saved key removed.';
  }catch(e){ $('#keyNote').textContent = 'Could not remove the key: ' + e.message; }
};

function norm(v){ return String(v ?? '').replace(/[,\s]/g, ''); }
function counterInfo(r){
  if (!r.counters || !r.counters.length) return {html: '<span class="chip na">none</span>', bad: 0};
  let bad = 0;
  const html = r.counters.map(c => {
    const wrong = c.to !== null && c.to !== undefined && norm(c.shown) !== norm(c.to);
    if (wrong) bad++;
    return wrong ? `<span class="start" title="Shows ${esc(c.shown)}, final value is ${esc(c.to)}">${esc(c.shown || '∅')}</span>` : esc(c.shown);
  }).join(', ');
  return {html, bad};
}
function statusChip(r){
  if (r.error) return `<span class="chip bad">Error</span>`;
  if (r.challenge) return `<span class="chip bad">${r.status} challenge</span>`;
  if (r.status >= 200 && r.status < 300) return `<span class="chip ok">${r.status}</span>`;
  if (r.status >= 300 && r.status < 400) return `<span class="chip warn">${r.status}</span>`;
  return `<span class="chip bad">${r.status ?? '?'}</span>`;
}
function robotsChip(r){
  if (r.robots_allowed === null || r.robots_allowed === undefined) return '<span class="chip na">n/a</span>';
  return r.robots_allowed ? '<span class="chip ok">Allowed</span>' : '<span class="chip bad">Blocked</span>';
}

async function runCheck(){
  const url = $('#url').value.trim();
  if (!url){ $('#checkStatus').textContent = 'Enter a URL to check.'; return; }
  store('abvc_url', url);
  const bots = [...document.querySelectorAll('.bot-cb:checked')].map(c => c.value);
  $('#checkBtn').disabled = true;
  $('#checkStatus').textContent = `Fetching as ${bots.length + 1} user agents…`;
  try{
    const data = await post('/api/check', {url, bots});
    if (data.error){ $('#checkStatus').textContent = data.error; return; }
    LAST = data; render(data);
    $('#checkStatus').textContent = `Checked ${data.url} at ${data.checked_at}.`;
  }catch(e){
    $('#checkStatus').textContent = 'Check failed: ' + e.message;
  }finally{ $('#checkBtn').disabled = false; }
}

function render(data){
  $('#resultsPanel').classList.remove('hidden');
  $('#askPanel').classList.remove('hidden');
  const rb = data.robots;
  $('#robotsLine').innerHTML = rb.status === 200
    ? `robots.txt found at <a href="${esc(rb.url)}" target="_blank" rel="noopener">${esc(rb.url)}</a>.`
    : `robots.txt returned ${esc(rb.status ?? rb.error)}; treated as ${rb.status === 401 || rb.status === 403 ? 'blocking all bots' : 'allowing all bots'}.`;
  const base = data.results.find(r => r.id === 'browser');
  const rows = data.results.map(r => {
    const ci = counterInfo(r);
    let diff = '';
    if (base && base.words && r.id !== 'browser'){
      const pct = Math.round((r.words - base.words) / base.words * 100);
      diff = pct === 0 ? '<span class="chip ok">same</span>' : `<span class="chip ${Math.abs(pct) > 10 ? 'bad' : 'warn'}">${pct > 0 ? '+' : ''}${pct}%</span>`;
    }
    return `<tr>
      <td><strong>${esc(r.label)}</strong></td>
      <td>${statusChip(r)}</td>
      <td>${robotsChip(r)}</td>
      <td class="num">${r.ms ?? '–'} ms</td>
      <td class="num">${(r.bytes/1024).toFixed(0)} KB</td>
      <td class="num">${r.words.toLocaleString()}</td>
      <td>${diff}</td>
      <td class="counters">${ci.html}${ci.bad ? ` <span class="chip bad">${ci.bad} not final</span>` : ''}</td>
    </tr>`;
  }).join('');
  $('#summary').innerHTML = `<thead><tr><th>Bot</th><th>HTTP</th><th>robots.txt</th><th>Time</th><th>Size</th><th>Words</th><th>vs browser</th><th>Animated counters</th></tr></thead><tbody>${rows}</tbody>`;

  $('#details').innerHTML = data.results.map(r => {
    const heads = r.headings.length
      ? `<ul class="heads">${r.headings.map(h => `<li><span>${h.level}</span>${esc(h.text)}</li>`).join('')}</ul>`
      : '<div class="note">No H1–H3 headings found.</div>';
    const counters = r.counters.length
      ? `<div class="tablewrap"><table><thead><tr><th>Shown in HTML</th><th>Final (data-to-value)</th><th>Start (data-from-value)</th></tr></thead><tbody>${
          r.counters.map(c => `<tr><td>${esc(c.shown)}</td><td>${esc(c.to)}</td><td>${esc(c.from)}</td></tr>`).join('')}</tbody></table></div>`
      : '<div class="note">No animated counters detected.</div>';
    return `<details class="bot">
      <summary>${esc(r.label)} ${statusChip(r)} <span class="note" style="margin:0;font-weight:400">${r.words.toLocaleString()} words</span></summary>
      <div class="dbody">
        ${r.error ? `<p class="chip bad">${esc(r.error)}</p>` : ''}
        <dl class="kv">
          <dt>User agent</dt><dd>${esc(r.ua)}</dd>
          <dt>Final URL</dt><dd>${esc(r.final_url)}</dd>
          <dt>Title</dt><dd>${esc(r.title) || '<span class="chip bad">missing</span>'}</dd>
          <dt>Meta description</dt><dd>${esc(r.meta.description) || '<span class="chip warn">missing</span>'}</dd>
          <dt>Meta robots</dt><dd>${esc(r.meta.robots) || '–'}</dd>
          <dt>X-Robots-Tag</dt><dd>${esc(r.x_robots_tag) || '–'}</dd>
          <dt>Canonical</dt><dd>${esc(r.canonical) || '–'}</dd>
          <dt>Links / images</dt><dd>${r.links} links, ${r.images} images (${r.images_no_alt} without alt)</dd>
          <dt>Server / cache</dt><dd>${esc(r.server) || '–'}${r.cf_cache ? ' / Cloudflare ' + esc(r.cf_cache) : ''}</dd>
          ${r.insecure_ssl ? '<dt>SSL</dt><dd><span class="chip warn">Certificate could not be verified</span></dd>' : ''}
        </dl>
        <div class="subhead">Headings</div>${heads}
        <div class="subhead">Animated counters</div>${counters}
        <div class="subhead">Text this bot can read <a class="links" style="font-weight:400" data-copy="${esc(r.id)}">Copy text</a></div>
        <pre class="text">${esc(r.text) || '(no readable text)'}</pre>
      </div></details>`;
  }).join('');
  document.querySelectorAll('[data-copy]').forEach(a => a.onclick = (e) => {
    e.preventDefault();
    const r = LAST.results.find(x => x.id === a.dataset.copy);
    navigator.clipboard.writeText(r.text).then(() => { a.textContent = 'Copied'; setTimeout(() => a.textContent = 'Copy text', 1500); });
  });

  const sel = $('#viewBot'); const prev = sel.value;
  sel.innerHTML = data.results.filter(r => r.text).map(r => `<option value="${r.id}">${esc(r.label)} (${r.words.toLocaleString()} words)</option>`).join('');
  sel.value = data.results.some(r => r.id === prev) ? prev : (data.results.find(r => r.id === 'gptbot' && r.text) ? 'gptbot' : sel.options[0]?.value);
}

$('#loadModels').onclick = async () => {
  $('#loadModels').disabled = true; $('#askStatus').textContent = 'Loading model list…';
  try{
    const d = await api('/api/models');
    if (d.error) throw new Error(d.error);
    $('#modelList').innerHTML = d.models.map(m => `<option value="${esc(m)}">`).join('');
    $('#askStatus').textContent = `${d.models.length} models loaded. Type in the search box to add one.`;
  }catch(e){ $('#askStatus').textContent = 'Could not load models: ' + e.message; }
  finally{ $('#loadModels').disabled = false; }
};
$('#addModel').onclick = () => {
  const m = $('#modelPick').value.trim(); if (!m) return;
  const list = $('#models').value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!list.includes(m)) list.push(m);
  $('#models').value = list.join('\n'); $('#modelPick').value = '';
};

$('#askBtn').onclick = async () => {
  if (!LAST){ $('#askStatus').textContent = 'Check a page first.'; return; }
  const key = $('#key').value.trim();
  if (!key && SETTINGS && SETTINGS.key_source === 'none'){ $('#askStatus').textContent = 'Add an OpenRouter key first: paste it, and save it to reuse it.'; return; }
  const models = $('#models').value.split('\n').map(s => s.trim()).filter(Boolean);
  if (!models.length){ $('#askStatus').textContent = 'Add at least one model ID.'; return; }
  store('abvc_models', models.join('\n'));
  if (SETTINGS && SETTINGS.storage_ok) post('/api/settings', {models}).catch(() => {});
  const view = LAST.results.find(r => r.id === $('#viewBot').value);
  if (!view){ $('#askStatus').textContent = 'Pick a bot view that has readable text.'; return; }
  const question = $('#question').value.trim() || QUESTIONS.numbers;
  $('#askBtn').disabled = true;
  let done = 0;
  $('#askStatus').textContent = `Asking ${models.length} models using the ${view.label} view…`;
  $('#answers').innerHTML = models.map((m, i) =>
    `<div class="answer" id="ans${i}"><h3>${esc(m)}</h3><div class="meta">Waiting for answer…</div><div class="body"></div></div>`).join('');
  await Promise.all(models.map(async (model, i) => {
    const card = $('#ans' + i);
    try{
      const r = await post('/api/ask', {key, model, bot: view.label, url: LAST.url, text: view.text, question});
      if (r.error){ card.classList.add('err'); card.querySelector('.meta').textContent = 'Failed'; card.querySelector('.body').textContent = r.error; }
      else{
        const tok = r.usage && r.usage.total_tokens ? `, ${r.usage.total_tokens.toLocaleString()} tokens` : '';
        card.querySelector('.meta').textContent = `${(r.ms/1000).toFixed(1)} s${tok}${r.truncated ? ', page text truncated' : ''}`;
        card.querySelector('.body').textContent = r.answer;
      }
    }catch(e){ card.classList.add('err'); card.querySelector('.meta').textContent = 'Failed'; card.querySelector('.body').textContent = e.message; }
    done++; $('#askStatus').textContent = `${done} of ${models.length} answered.`;
  }));
  $('#askBtn').disabled = false;
};

init();
</script>
</body>
</html>
"""


LOGIN_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in – AI Bot View Checker</title>
<style>
:root{--paper:#eef1f4;--surface:#ffffff;--ink:#18232f;--muted:#5b6876;--line:#d3d9e0;--accent:#1f4e8c;--accent-ink:#ffffff;--bad:#b3261e;color-scheme:light}
@media (prefers-color-scheme: dark){:root{--paper:#11161c;--surface:#19212a;--ink:#e4e9ef;--muted:#97a3b0;--line:#2c3743;--accent:#6fa3e8;--accent-ink:#0d1620;--bad:#ff8a80;color-scheme:dark}}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--paper);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{min-height:100vh;display:grid;place-items:center;padding:24px}
form{width:100%;max-width:360px;background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:28px}
h1{font-size:22px;line-height:1.25;margin:0 0 4px}
p{color:var(--muted);margin:0 0 18px;font-size:14px}
label{display:block;font-size:13.5px;font-weight:600;margin:14px 0 5px}
input{font:inherit;color:var(--ink);background:var(--paper);border:1px solid var(--line);border-radius:7px;padding:10px 11px;width:100%}
input:focus,button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
button{margin-top:22px;width:100%;font:inherit;font-weight:600;border:1px solid var(--accent);background:var(--accent);
  color:var(--accent-ink);border-radius:7px;padding:10px 16px;cursor:pointer}
button:disabled{opacity:.6;cursor:progress}
.err{color:var(--bad);font-size:14px;min-height:1.4em;margin-top:12px}
</style>
</head>
<body>
<main>
<form id="f">
  <h1>AI Bot View Checker</h1>
  <p>Sign in to check pages and run model tests.</p>
  <label for="u">Username</label>
  <input id="u" name="username" autocomplete="username" required>
  <label for="p">Password</label>
  <input id="p" name="password" type="password" autocomplete="current-password" required>
  <button id="b" type="submit">Sign in</button>
  <div class="err" id="e" role="alert"></div>
</form>
</main>
<script>
document.getElementById('f').addEventListener('submit', async ev => {
  ev.preventDefault();
  const b = document.getElementById('b'), err = document.getElementById('e');
  b.disabled = true; err.textContent = '';
  try{
    const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({username: document.getElementById('u').value, password: document.getElementById('p').value})});
    const d = await r.json();
    if (r.ok && d.ok){ location.href = '/'; return; }
    err.textContent = d.error || 'Sign in failed.';
  }catch(x){ err.textContent = 'Could not reach the server. Try again.'; }
  b.disabled = false;
});
document.getElementById('u').focus();
</script>
</body>
</html>
"""


def main():
    is_local = HOST in LOCAL_HOSTS
    if not is_local and not APP_PASSWORD and not ALLOW_NO_AUTH:
        print("Refusing to start: HOST is public but APP_PASSWORD is not set.\n"
              "Set APP_PASSWORD (recommended) or ALLOW_NO_AUTH=1.", flush=True)
        sys.exit(1)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://localhost:{PORT}"
    print(f"\n  AI Bot View Checker listening on {HOST}:{PORT}", flush=True)
    print(f"  Login: {'on (user ' + APP_USERNAME + ')' if APP_PASSWORD else 'off'}", flush=True)
    print(f"  Settings folder: {DATA_DIR} ({'writable' if storage_writable() else 'NOT writable'})", flush=True)
    print(f"  Private URLs: {'allowed' if ALLOW_PRIVATE else 'blocked'}", flush=True)
    print("  Press Ctrl+C to stop.\n", flush=True)
    if is_local and not os.environ.get("NO_BROWSER"):
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
        server.server_close()


if __name__ == "__main__":
    main()
