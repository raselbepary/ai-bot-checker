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
import gzip
import io
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape as html_unescape
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
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except Exception:
                pass
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
            if name in ("description", "robots", "og:title", "og:description", "og:site_name", "og:image"):
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


# ---------------------------------------------------------------- structured data
JSONLD_RE = re.compile(r'<script\b[^>]*type\s*=\s*["\']?application/ld\+json["\']?[^>]*>(.*?)</script\s*>', re.I | re.S)
MICRODATA_RE = re.compile(r'itemtype\s*=\s*["\']https?://schema\.org/([A-Za-z]+)', re.I)

LOCAL_BUSINESS_TYPES = {
    "LocalBusiness", "HVACBusiness", "Plumber", "Electrician", "RoofingContractor", "GeneralContractor",
    "HomeAndConstructionBusiness", "Locksmith", "MovingCompany", "HousePainter", "AutoRepair", "AutomotiveBusiness",
    "Dentist", "MedicalBusiness", "MedicalClinic", "Physician", "Pharmacy", "Optician", "LegalService", "Attorney",
    "Notary", "RealEstateAgent", "Restaurant", "FoodEstablishment", "CafeOrCoffeeShop", "Bakery", "BarOrPub",
    "Store", "ProfessionalService", "FinancialService", "AccountingService", "InsuranceAgency", "BankOrCreditUnion",
    "HealthAndBeautyBusiness", "BeautySalon", "HairSalon", "DaySpa", "LodgingBusiness", "Hotel",
    "SportsActivityLocation", "ExerciseGym", "EntertainmentBusiness", "EmergencyService", "ChildCare",
    "DryCleaningOrLaundry", "EmploymentAgency", "SelfStorage", "TravelAgency", "AnimalShelter", "VeterinaryCare",
}
ORG_TYPES = {
    "Organization", "Corporation", "NGO", "EducationalOrganization", "GovernmentOrganization", "MedicalOrganization",
    "NewsMediaOrganization", "OnlineBusiness", "OnlineStore", "SportsOrganization", "PerformingGroup", "Airline",
    "Consortium", "ResearchOrganization", "Cooperative", "Project",
}
ARTICLE_TYPES = {"Article", "BlogPosting", "NewsArticle", "TechArticle", "Report", "ScholarlyArticle",
                 "SocialMediaPosting", "AnalysisNewsArticle", "OpinionNewsArticle", "LiveBlogPosting"}
WEBPAGE_TYPES = {"WebPage", "AboutPage", "ContactPage", "CollectionPage", "ItemPage", "ProfilePage",
                 "SearchResultsPage", "CheckoutPage", "MedicalWebPage", "RealEstateListing", "QAPage"}

SCHEMA_RULES = {
    "Organization": {"required": ["name", "url"], "recommended": ["logo", "sameAs", "description", "contactPoint"]},
    "LocalBusiness": {"required": ["name", "address"],
                      "recommended": ["url", "telephone", "image", "openingHoursSpecification", "geo", "areaServed", "sameAs"]},
    "WebSite": {"required": ["name", "url"], "recommended": ["publisher", "inLanguage"]},
    "WebPage": {"required": ["name", "url"], "recommended": ["description", "isPartOf", "dateModified", "inLanguage"]},
    "Article": {"required": ["headline", "author", "datePublished"],
                "recommended": ["image", "dateModified", "publisher", "description"]},
    "Product": {"required": ["name", "offers"], "recommended": ["image", "description", "brand", "sku", "aggregateRating"]},
    "Service": {"required": ["name"], "recommended": ["description", "provider", "areaServed", "serviceType"]},
    "FAQPage": {"required": ["mainEntity"], "recommended": []},
    "BreadcrumbList": {"required": ["itemListElement"], "recommended": []},
    "Person": {"required": ["name"], "recommended": ["url", "jobTitle", "sameAs", "image", "worksFor"]},
    "Event": {"required": ["name", "startDate", "location"], "recommended": ["endDate", "image", "description", "offers", "organizer"]},
    "VideoObject": {"required": ["name", "thumbnailUrl", "uploadDate"], "recommended": ["description", "contentUrl", "duration"]},
    "HowTo": {"required": ["name", "step"], "recommended": ["image", "totalTime"]},
}
DATE_PROPS = ("datePublished", "dateModified", "uploadDate", "startDate", "endDate", "foundingDate")
URL_PROPS = ("url", "logo", "image", "thumbnailUrl", "contentUrl")
PLACEHOLDER_RE = re.compile(r"lorem ipsum|example\.com|\{\{|\}\}|\byour company\b|\breplace\b|\btbd\b|\bxxx+\b", re.I)


def schema_family(t):
    if t in LOCAL_BUSINESS_TYPES:
        return "LocalBusiness"
    if t in ORG_TYPES:
        return "Organization"
    if t in ARTICLE_TYPES:
        return "Article"
    if t in WEBPAGE_TYPES:
        return "WebPage"
    return t


def _types(node):
    t = node.get("@type")
    items = t if isinstance(t, list) else [t]
    out = []
    for x in items:
        if isinstance(x, str) and x.strip():
            x = re.sub(r"^(https?://schema\.org/|schema:)", "", x.strip())
            out.append(x)
    return out


def _has(node, prop):
    v = node.get(prop)
    return v not in (None, "", [], {})


def _walk(obj, fn, depth=0):
    if depth > 12:
        return
    if isinstance(obj, dict):
        fn(obj)
        for v in obj.values():
            _walk(v, fn, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _walk(v, fn, depth + 1)


def _strings(obj, depth=0):
    if depth > 12:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not k.startswith("@"):
                yield from _strings(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v, depth + 1)


def _short_id(i):
    if not isinstance(i, str):
        return ""
    return "#" + i.split("#", 1)[1] if "#" in i else i[-40:]


def _format_address(d):
    if not isinstance(d, dict):
        return str(d)
    country = d.get("addressCountry")
    if isinstance(country, dict):
        country = country.get("name", "")
    parts = [d.get("streetAddress"), d.get("addressLocality"), d.get("addressRegion"), d.get("postalCode"), country]
    return ", ".join(str(p) for p in parts if p)


def analyze_structured(html, page_text, page_url, meta, headings, title):
    issues, items, blocks = [], [], []

    def add(level, msg, where="Page"):
        issues.append({"level": level, "msg": msg, "where": where})

    for i, m in enumerate(JSONLD_RE.finditer(html), 1):
        raw = m.group(1).strip()
        raw = re.sub(r"^\s*(<!--|//\s*<!\[CDATA\[)", "", raw)
        raw = re.sub(r"(-->|//\s*\]\]>)\s*$", "", raw).strip()
        if not raw:
            add("warning", f"JSON-LD block {i} is empty.", f"Block {i}")
            continue
        try:
            data = json.loads(raw, strict=False)
        except Exception as e:
            where = f" ({getattr(e, 'msg', 'parse error')} at line {getattr(e, 'lineno', '?')})"
            add("error", f"JSON-LD block {i} is not valid JSON{where}, so AI tools and search engines ignore it completely.",
                f"Block {i}")
            blocks.append({"valid": False})
            continue
        blocks.append({"valid": True, "data": data})
        for root in (data if isinstance(data, list) else [data]):
            if not isinstance(root, dict):
                continue
            ctx = root.get("@context", "")
            ctx_s = ctx if isinstance(ctx, str) else json.dumps(ctx)
            if not ctx:
                add("error", "Missing @context, so parsers can't tell this is schema.org data.", f"Block {i}")
            elif "schema.org" not in ctx_s:
                add("warning", f"@context is {ctx_s[:60]}, not schema.org.", f"Block {i}")
            graph = root.get("@graph")
            for n in (graph if isinstance(graph, list) else [root]):
                if isinstance(n, dict):
                    items.append(n)

    id_index = {}
    for b in blocks:
        if b["valid"]:
            _walk(b["data"], lambda n: id_index.setdefault(n["@id"], n) if isinstance(n.get("@id"), str) and len(n) > 2 else None)

    def resolve(v):
        if isinstance(v, dict) and set(v.keys()) <= {"@id", "@type"} and v.get("@id") in id_index:
            return id_index[v["@id"]]
        return v

    evaluated = []
    for n in items:
        types = _types(n)
        sid = _short_id(n.get("@id"))
        if not types:
            add("warning", "An item has no @type, so its meaning is unclear.", sid or "Untyped item")
            continue
        label = " / ".join(types)
        where = f"{label} {sid}".strip()
        fam = next((schema_family(t) for t in types if schema_family(t) in SCHEMA_RULES), None)
        req = SCHEMA_RULES[fam]["required"] if fam else []
        rec = SCHEMA_RULES[fam]["recommended"] if fam else []
        missing_req = [p for p in req if not _has(n, p)]
        missing_rec = [p for p in rec if not _has(n, p)]
        for p in missing_req:
            add("error", f'{label} is missing "{p}", a required property.', where)
        if missing_rec:
            add("suggestion", f"{label} could add: {', '.join(missing_rec)}.", where)

        if fam == "LocalBusiness" and _has(n, "address"):
            addr = resolve(n["address"])
            if isinstance(addr, str):
                add("warning", "The address is plain text. Use a PostalAddress with separate street, city, postal code and country.", where)
            elif isinstance(addr, dict):
                miss = [p for p in ("streetAddress", "addressLocality", "postalCode", "addressCountry") if not _has(addr, p)]
                if miss:
                    add("warning", f"The address is missing {', '.join(miss)}.", where)
        if fam == "FAQPage" and _has(n, "mainEntity"):
            qs = n["mainEntity"] if isinstance(n["mainEntity"], list) else [n["mainEntity"]]
            bad = 0
            for q in qs:
                q = resolve(q)
                ans = resolve(q.get("acceptedAnswer")) if isinstance(q, dict) else None
                if not (isinstance(q, dict) and q.get("name") and isinstance(ans, dict) and ans.get("text")):
                    bad += 1
            if bad:
                add("error", f"{bad} of {len(qs)} FAQ questions {'is' if bad == 1 else 'are'} missing a question name or an answer text.", where)
        if fam == "BreadcrumbList" and _has(n, "itemListElement"):
            els = n["itemListElement"] if isinstance(n["itemListElement"], list) else [n["itemListElement"]]
            bad = sum(1 for e in els if not (isinstance(e, dict) and "position" in e and (e.get("name") or isinstance(e.get("item"), dict))))
            if bad:
                add("warning", f"{bad} breadcrumb {'entry is' if bad == 1 else 'entries are'} missing a position or name.", where)
        if fam == "Product" and _has(n, "offers"):
            offers = n["offers"] if isinstance(n["offers"], list) else [n["offers"]]
            for o in offers:
                o = resolve(o)
                if isinstance(o, dict) and not ((o.get("price") or o.get("lowPrice")) and o.get("priceCurrency")):
                    add("warning", "An offer is missing price or priceCurrency.", where)
                    break
        for p in DATE_PROPS:
            v = n.get(p)
            if isinstance(v, str) and v and not re.match(r"^\d{4}-\d{2}-\d{2}", v):
                add("warning", f'"{p}" is "{v[:40]}", not an ISO date like 2026-05-31.', where)
        for p in URL_PROPS:
            v = n.get(p)
            if isinstance(v, str) and v and not v.startswith(("http://", "https://")):
                add("warning", f'"{p}" is a relative or invalid URL ("{v[:60]}"). Use a full https:// address.', where)
        same = n.get("sameAs")
        if same:
            links = same if isinstance(same, list) else [same]
            bad_links = [x for x in links if not (isinstance(x, str) and x.startswith(("http://", "https://")))]
            if bad_links:
                add("warning", f"{len(bad_links)} sameAs {'link is' if len(bad_links) == 1 else 'links are'} not a full URL: {', '.join(str(x)[:40] for x in bad_links[:3])}.", where)
        for sv in _strings(n):
            if PLACEHOLDER_RE.search(sv):
                add("warning", f'Possible placeholder text: "{sv[:60]}".', where)
                break
        if fam in ("Organization", "LocalBusiness"):
            nm = n.get("name")
            if isinstance(nm, str) and nm.strip() and nm.strip().lower() not in page_text.lower():
                add("suggestion", f'The name "{nm[:60]}" does not appear in the page text. AI tools trust facts more when the page and the structured data agree.', where)
            tel = n.get("telephone")
            if isinstance(tel, str):
                digits = re.sub(r"\D", "", tel)[-7:]
                if len(digits) == 7 and digits not in re.sub(r"\D", "", page_text):
                    add("suggestion", f'The phone number "{tel}" does not appear in the page text.', where)
        evaluated.append({"types": types, "id": sid, "family": fam,
                          "present": [p for p in req + rec if _has(n, p)],
                          "missing_required": missing_req, "missing_recommended": missing_rec,
                          "props": len([k for k in n if not k.startswith("@")])})

    fams = {e["family"] for e in evaluated}
    path_depth = len([x for x in urllib.parse.urlsplit(page_url).path.split("/") if x])
    if not blocks:
        add("error", "No JSON-LD structured data found. AI tools and search engines use it to confirm facts like your company name, address and services.")
    elif evaluated:
        if not ({"Organization", "LocalBusiness"} & fams):
            add("warning", "No Organization or LocalBusiness item. Add one (usually site-wide) so AI tools can confirm your name, logo, contact details and profiles.")
        if "WebSite" not in fams:
            add("suggestion", "No WebSite item. It tells AI tools your site's name and main address.")
        if "BreadcrumbList" not in fams and path_depth > 0:
            add("suggestion", "No BreadcrumbList item. Breadcrumbs show where this page sits in your site.")
    question_heads = [h for h in headings if h["text"].rstrip().endswith("?")]
    if len(question_heads) >= 2 and "FAQPage" not in fams:
        add("suggestion", f"{len(question_heads)} headings are questions, but there is no FAQPage item. Marking them up may help AI answer engines quote your answers.")

    facts = []

    def fact(label, v, src):
        v = resolve(v)
        if v in (None, "", [], {}):
            return
        if isinstance(v, dict):
            if v.get("@type") == "PostalAddress" or "streetAddress" in v:
                v = _format_address(v)
            else:
                v = v.get("name") or v.get("url") or v.get("contentUrl") or v.get("@id") or ""
        elif isinstance(v, list):
            vals = []
            for x in v[:10]:
                x = resolve(x)
                vals.append(str(x.get("name") or x.get("@id") or "") if isinstance(x, dict) else str(x))
            v = ", ".join(x for x in vals if x)
        if v:
            facts.append({"label": label, "value": str(v)[:300], "source": src})

    for n in items:
        types = _types(n)
        fam = next((schema_family(t) for t in types if schema_family(t) in SCHEMA_RULES), None)
        src = " / ".join(types)
        if fam in ("Organization", "LocalBusiness"):
            for prop, label in (("name", "Name"), ("legalName", "Legal name"), ("description", "Description"),
                                ("url", "Website"), ("logo", "Logo"), ("telephone", "Phone"), ("email", "Email"),
                                ("address", "Address"), ("areaServed", "Area served"), ("foundingDate", "Founded"),
                                ("priceRange", "Price range"), ("openingHours", "Opening hours"), ("sameAs", "Profiles")):
                fact(label, n.get(prop), src)
        elif fam == "WebSite":
            fact("Site name", n.get("name"), src)
        elif fam == "Article":
            fact("Headline", n.get("headline"), src)
            fact("Author", n.get("author"), src)
            fact("Published", n.get("datePublished"), src)
        elif fam == "Product":
            fact("Product", n.get("name"), src)
            fact("Brand", n.get("brand"), src)
            off = resolve(n.get("offers"))
            if isinstance(off, list) and off:
                off = resolve(off[0])
            if isinstance(off, dict):
                fact("Price", f"{off.get('price') or off.get('lowPrice') or ''} {off.get('priceCurrency') or ''}".strip(), src)
        elif fam == "Service":
            fact("Service", n.get("name"), src)
            fact("Service area", n.get("areaServed"), src)
        elif fam == "FAQPage":
            q = n.get("mainEntity")
            fact("FAQ questions", len(q) if isinstance(q, list) else (1 if q else 0), src)
    seen, uniq = set(), []
    for f in facts:
        k = (f["label"], f["value"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)

    suggested = ""
    if not ({"Organization", "LocalBusiness"} & fams):
        parts = urllib.parse.urlsplit(page_url)
        home = f"{parts.scheme}://{parts.netloc}/"
        name = meta.get("og:site_name") or (re.split(r"\s+[|\-–—]\s+", title)[-1].strip() if title else parts.netloc)
        snippet = {"@context": "https://schema.org", "@type": "Organization", "@id": home + "#organization",
                   "name": name, "url": home, "logo": "REPLACE with your logo URL"}
        if meta.get("og:image"):
            snippet["image"] = meta["og:image"]
        if meta.get("description"):
            snippet["description"] = meta["description"]
        snippet["sameAs"] = ["REPLACE with your LinkedIn URL", "REPLACE with your Facebook URL"]
        snippet["contactPoint"] = {"@type": "ContactPoint", "telephone": "REPLACE with your phone",
                                   "contactType": "customer service"}
        suggested = json.dumps(snippet, indent=2, ensure_ascii=False)

    jsonld = [b["data"] for b in blocks if b["valid"]]
    if len(json.dumps(jsonld)) > 80000:
        jsonld = []
    counts = {lvl: sum(1 for x in issues if x["level"] == lvl) for lvl in ("error", "warning", "suggestion")}
    order = {"error": 0, "warning": 1, "suggestion": 2}
    issues.sort(key=lambda x: order[x["level"]])
    return {"blocks": len(blocks), "items": evaluated, "types": sorted({t for e in evaluated for t in e["types"]}),
            "issues": issues, "counts": counts, "facts": uniq[:40], "suggested": suggested,
            "microdata_types": sorted(set(MICRODATA_RE.findall(html))), "jsonld": jsonld}


def analyze(url, bot, rp):
    bid, label, token, ua, note, _ = bot
    r = http_get(url, ua)
    res = {"id": bid, "label": label, "note": note, "ua": ua, "status": r["status"],
           "final_url": r["final_url"], "ms": r["ms"], "bytes": r["bytes"], "error": r["error"],
           "insecure_ssl": r["insecure_ssl"], "x_robots_tag": r["headers"].get("x-robots-tag", ""),
           "server": r["headers"].get("server", ""), "cf_cache": r["headers"].get("cf-cache-status", ""),
           "title": "", "meta": {}, "canonical": "", "headings": [], "words": 0, "text": "",
           "links": 0, "images": 0, "images_no_alt": 0, "counters": [], "challenge": False, "structured": None}
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
        try:
            res["structured"] = analyze_structured(html, text, url, p.meta, p.headings, res["title"])
        except Exception as e:
            res["structured"] = {"error": f"{type(e).__name__}: {e}", "blocks": 0, "items": [], "types": [],
                                 "issues": [], "counts": {"error": 0, "warning": 0, "suggestion": 0},
                                 "facts": [], "suggested": "", "microdata_types": [], "jsonld": []}
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


# ---------------------------------------------------------------- AI access
AI_AGENTS = [
    ("GPTBot", "OpenAI", "Collects training data for OpenAI models", "gptbot"),
    ("OAI-SearchBot", "OpenAI", "Builds ChatGPT search results", "oai-search"),
    ("ChatGPT-User", "OpenAI", "Opens pages when a ChatGPT user asks", "chatgpt-user"),
    ("ClaudeBot", "Anthropic", "Collects training data for Claude", "claudebot"),
    ("Claude-SearchBot", "Anthropic", "Builds Claude search results", "claude-search"),
    ("Claude-User", "Anthropic", "Opens pages when a Claude user asks", "claude-user"),
    ("PerplexityBot", "Perplexity", "Builds Perplexity search results", "perplexitybot"),
    ("Perplexity-User", "Perplexity", "Opens pages when a Perplexity user asks", "perplexity-user"),
    ("Googlebot", "Google", "Google Search, including AI Overviews", "googlebot"),
    ("Google-Extended", "Google", "Controls use in Gemini models; a robots.txt rule only, not a separate crawler", None),
    ("Bingbot", "Microsoft", "Bing search and Microsoft Copilot", "bingbot"),
    ("Applebot", "Apple", "Siri and Spotlight search", "applebot"),
    ("Applebot-Extended", "Apple", "Controls use in Apple's AI training; a robots.txt rule only", None),
    ("CCBot", "Common Crawl", "Open web dataset used by many AI labs", "ccbot"),
    ("meta-externalagent", "Meta", "Meta AI training and features", "meta"),
    ("Bytespider", "ByteDance", "ByteDance crawler", "bytespider"),
    ("Amazonbot", "Amazon", "Alexa and other Amazon services; robots.txt rule checked only", None),
]
META_ROBOTS_RE = re.compile(r'<meta\b[^>]*name\s*=\s*["\']robots["\'][^>]*content\s*=\s*["\']([^"\']*)', re.I)


def _normalize_url(url):
    url = (url or "").strip()
    if not url:
        raise BlockedURL("Enter a URL.")
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    check_public_url(url)
    return url


def _is_challenge(html_text):
    low = (html_text or "")[:20000].lower()
    return "cf-chl" in low or "just a moment..." in low or "attention required! | cloudflare" in low


def check_access(url):
    try:
        url = _normalize_url(url)
    except BlockedURL as e:
        return {"error": str(e)}, 400
    rp, robots = load_robots(url)
    browser = http_get(url, CHROME_UA)
    page_robots = " ".join(x for x in [", ".join(META_ROBOTS_RE.findall(browser["html"] or "")),
                                       browser["headers"].get("x-robots-tag", "")] if x)

    def test(agent):
        token, company, purpose, bid = agent
        try:
            allowed = rp.can_fetch(token, url)
        except Exception:
            allowed = None
        live = None
        if bid:
            r = http_get(url, BOT_BY_ID[bid][3])
            live = {"status": r["status"], "error": r["error"], "challenge": _is_challenge(r["html"]), "ms": r["ms"]}
        if allowed is False:
            verdict = "blocked_robots"
        elif live and (live["error"] or live["challenge"] or (live["status"] or 0) >= 400):
            verdict = "blocked_server"
        else:
            verdict = "allowed"
        return {"token": token, "company": company, "purpose": purpose, "robots_allowed": allowed,
                "live": live, "verdict": verdict}

    with ThreadPoolExecutor(max_workers=6) as ex:
        agents = list(ex.map(test, AI_AGENTS))
    return {"url": url, "robots": robots, "browser_status": browser["status"], "browser_error": browser["error"],
            "page_robots": page_robots, "agents": agents, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}, 200


# ---------------------------------------------------------------- llms.txt
LLMS_LINK_RE = re.compile(r"^\s*[-*]\s*\[([^\]]+)\]\(([^)\s]+)\)\s*(?::\s*(.*))?$")
LLMS_SKIP_SEGMENTS = {"category", "tag", "author", "page", "feed", "wp-content", "wp-json", "cart", "checkout", "my-account"}
LLMS_OPTIONAL_SEGMENTS = {"blog", "news", "post", "posts", "article", "articles", "insights", "updates", "press"}


def check_llms(url):
    try:
        url = _normalize_url(url)
    except BlockedURL as e:
        return {"error": str(e)}, 400
    parts = urllib.parse.urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    files = []
    for name in ("llms.txt", "llms-full.txt"):
        r = http_get(f"{origin}/{name}", CHROME_UA, accept="text/plain,text/markdown,*/*")
        body = r["html"] or ""
        looks_html = "<html" in body[:3000].lower() or "<!doctype html" in body[:300].lower()
        f = {"name": name, "url": f"{origin}/{name}", "status": r["status"], "error": r["error"],
             "content_type": r["headers"].get("content-type", ""), "bytes": r["bytes"], "exists": False, "text": "", "note": ""}
        if r["status"] == 200 and body.strip() and not looks_html:
            f["exists"] = True
            f["text"] = body[:200000]
        elif r["status"] == 200 and looks_html:
            f["note"] = "This address returns a web page, not a text file (often a page or a 'not found' page that still answers 200)."
        files.append(f)

    issues, sections, links = [], [], []

    def add(level, msg):
        issues.append({"level": level, "msg": msg, "where": "llms.txt"})

    main = files[0]
    if main["exists"]:
        lines = main["text"].replace("\r", "").split("\n")
        nonempty = [l for l in lines if l.strip()]
        if not nonempty or not re.match(r"^#\s+\S", nonempty[0]):
            add("error", "The file should start with one H1 title, like '# Company name'.")
        h1s = [l for l in lines if re.match(r"^#\s", l)]
        if len(h1s) > 1:
            add("warning", f"The file has {len(h1s)} H1 titles; the format expects exactly one.")
        if not any(l.lstrip().startswith(">") for l in nonempty[:6]):
            add("suggestion", "Add a short summary of the site as a quote right after the title (a line starting with '> ').")
        cur = None
        for l in lines:
            m = re.match(r"^##\s+(.+)", l)
            if m:
                cur = {"name": m.group(1).strip(), "links": 0}
                sections.append(cur)
                continue
            lm = LLMS_LINK_RE.match(l)
            if lm:
                links.append({"title": lm.group(1).strip(), "url": lm.group(2).strip(), "notes": (lm.group(3) or "").strip(),
                              "section": cur["name"] if cur else ""})
                if cur:
                    cur["links"] += 1
        if not sections:
            add("warning", "No '## Section' headings. The format groups links under H2 sections.")
        if not links:
            add("warning", "No links in the expected '- [Name](https://...): description' format.")
        rel = [l for l in links if not l["url"].startswith(("http://", "https://"))]
        if rel:
            add("warning", f"{len(rel)} link{' is' if len(rel) == 1 else 's are'} relative. Use full https:// addresses.")
        if links and sum(1 for l in links if not l["notes"]) > len(links) / 2:
            add("suggestion", "Most links have no description after the colon. A short note helps AI tools pick the right page.")
        ct = main["content_type"].lower()
        if ct and "text/plain" not in ct and "markdown" not in ct:
            add("suggestion", f"The file is served as '{main['content_type']}'. text/plain or text/markdown is expected.")
        to_check = [l for l in links if l["url"].startswith(("http://", "https://"))][:25]

        def chk(l):
            r = http_get(l["url"], CHROME_UA, timeout=15)
            l["status"] = r["status"]
            l["error"] = r["error"]

        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(chk, to_check))
        broken = [l for l in to_check if l.get("error") or (l.get("status") or 0) >= 400]
        if broken:
            add("error", f"{len(broken)} of {len(to_check)} checked links are broken or unreachable.")
        if len(links) > 25:
            add("suggestion", f"Only the first 25 of {len(links)} links were checked.")
    else:
        add("suggestion", "No llms.txt found. You can draft one from the site's pages below.")
    order = {"error": 0, "warning": 1, "suggestion": 2}
    issues.sort(key=lambda x: order[x["level"]])
    return {"origin": origin, "files": files, "issues": issues, "sections": sections, "links": links,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}, 200


def _clean(s, n=200):
    s = re.sub(r"\s+", " ", s or "").strip()
    return s if len(s) <= n else s[:n - 1].rsplit(" ", 1)[0] + "…"


def generate_llms(url):
    try:
        url = _normalize_url(url)
    except BlockedURL as e:
        return {"error": str(e)}, 400
    parts = urllib.parse.urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    urls, info = discover_urls(origin + "/", 40)
    home = http_get(origin + "/", CHROME_UA)
    hp = PageExtractor()
    try:
        hp.feed(home["html"] or "")
    except Exception:
        pass
    title = re.sub(r"\s+", " ", hp.title).strip()
    site_name = hp.meta.get("og:site_name") or (re.split(r"\s+[|\-–—]\s+", title)[-1].strip() if title else parts.hostname)
    summary = _clean(hp.meta.get("description") or hp.meta.get("og:description") or "", 300)

    def page_info(u):
        segs = [x for x in urllib.parse.urlsplit(u).path.split("/") if x]
        if segs and segs[0].lower() in LLMS_SKIP_SEGMENTS:
            return None
        r = http_get(u, CHROME_UA, timeout=15)
        if r["error"] or (r["status"] or 0) >= 400 or not r["html"]:
            return None
        p = PageExtractor()
        try:
            p.feed(r["html"])
        except Exception:
            pass
        if "noindex" in (p.meta.get("robots", "") + " " + r["headers"].get("x-robots-tag", "")).lower():
            return None
        t = re.sub(r"\s+", " ", p.title).strip()
        for sep in (" | ", " - ", " – ", " — "):
            if sep in t:
                head, tail = t.rsplit(sep, 1)
                if site_name and tail.strip().lower() == site_name.lower():
                    t = head.strip()
                    break
        return {"url": r["final_url"] or u, "title": t or u, "desc": _clean(p.meta.get("description") or p.meta.get("og:description") or ""),
                "segs": segs}

    with ThreadPoolExecutor(max_workers=6) as ex:
        pages = [p for p in ex.map(page_info, urls) if p]
    seen, uniq = set(), []
    for p in pages:
        if p["url"] not in seen:
            seen.add(p["url"])
            uniq.append(p)
    groups, optional = {}, []
    for p in uniq:
        segs = p["segs"]
        if segs and segs[0].lower() in LLMS_OPTIONAL_SEGMENTS:
            optional.append(p)
        elif len(segs) <= 1:
            groups.setdefault("Main pages", []).append(p)
        else:
            groups.setdefault(segs[0].replace("-", " ").replace("_", " ").title(), []).append(p)

    def line(p):
        return f"- [{p['title']}]({p['url']})" + (f": {p['desc']}" if p["desc"] else "")

    out = [f"# {site_name}", ""]
    if summary:
        out += [f"> {summary}", ""]
    for name in sorted(groups, key=lambda n: (n != "Main pages", n)):
        out += [f"## {name}", ""] + [line(p) for p in groups[name]] + [""]
    if optional:
        out += ["## Optional", ""] + [line(p) for p in optional] + [""]
    return {"markdown": "\n".join(out).strip() + "\n", "pages": len(uniq), "source": info["source"]}, 200


# ---------------------------------------------------------------- crawler visits (server logs)
LOG_MAX_BYTES = 150 * 1024 * 1024
LOG_MAX_LINES = 3000000
# UA token (lowercase), label, company, IP list key
LOG_BOTS = [
    ("gptbot", "GPTBot", "OpenAI", "openai-gptbot"),
    ("oai-searchbot", "OAI-SearchBot", "OpenAI", "openai-searchbot"),
    ("chatgpt-user", "ChatGPT-User", "OpenAI", "openai-chatgpt-user"),
    ("oai-adsbot", "OAI-AdsBot", "OpenAI", "openai-adsbot"),
    ("claudebot", "ClaudeBot", "Anthropic", None),
    ("claude-searchbot", "Claude-SearchBot", "Anthropic", None),
    ("claude-user", "Claude-User", "Anthropic", None),
    ("anthropic-ai", "anthropic-ai", "Anthropic", None),
    ("perplexitybot", "PerplexityBot", "Perplexity", "perplexitybot"),
    ("perplexity-user", "Perplexity-User", "Perplexity", "perplexity-user"),
    ("google-cloudvertexbot", "Google-CloudVertexBot", "Google", None),
    ("googlebot", "Googlebot", "Google", "googlebot"),
    ("bingbot", "Bingbot", "Microsoft", "bingbot"),
    ("applebot", "Applebot", "Apple", "applebot"),
    ("mistralai-user", "MistralAI-User", "Mistral", "mistralai-user"),
    ("ccbot", "CCBot", "Common Crawl", None),
    ("meta-externalagent", "Meta-ExternalAgent", "Meta", None),
    ("meta-externalfetcher", "Meta-ExternalFetcher", "Meta", None),
    ("bytespider", "Bytespider", "ByteDance", None),
    ("amazonbot", "Amazonbot", "Amazon", None),
    ("duckassistbot", "DuckAssistBot", "DuckDuckGo", None),
    ("cohere-ai", "cohere-ai", "Cohere", None),
    ("youbot", "YouBot", "You.com", None),
]
IP_LISTS = {
    "openai-gptbot": ["https://openai.com/gptbot.json"],
    "openai-searchbot": ["https://openai.com/searchbot.json"],
    "openai-chatgpt-user": ["https://openai.com/chatgpt-user.json"],
    "openai-adsbot": ["https://openai.com/adsbot.json"],
    "perplexitybot": ["https://www.perplexity.com/perplexitybot.json"],
    "perplexity-user": ["https://www.perplexity.com/perplexity-user.json"],
    "googlebot": ["https://developers.google.com/static/search/apis/ipranges/googlebot.json"],
    "bingbot": ["https://www.bing.com/toolbox/bingbot.json"],
    "applebot": ["https://search.developer.apple.com/applebot.json"],
    "mistralai-user": ["https://mistral.ai/mistralai-user-ips.json"],
    "cloudflare": ["https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"],
}
_IPLIST_CACHE = {"at": 0, "nets": {}, "errors": {}}
_IPLIST_LOCK = threading.Lock()
COMBINED_RE = re.compile(
    r'^(?:(?P<vhost>\S+)\s+)??(?P<ip>[0-9a-fA-F:.]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?:(?P<method>[A-Za-z]+)\s+(?P<path>\S+)[^"]*|[^"]*)"\s+(?P<status>\d{3})\s+\S+'
    r'(?:\s+"(?:[^"\\]|\\.)*"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?')
LOG_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
LOG_JSON_KEYS = {
    "ip": ("clientip", "client_ip", "remote_addr", "remoteaddr", "remote_ip", "ip", "c-ip", "clientaddress"),
    "ua": ("clientrequestuseragent", "http_user_agent", "user_agent", "useragent", "ua", "cs(user-agent)"),
    "path": ("clientrequesturi", "clientrequestpath", "request_uri", "uri", "path", "url", "request"),
    "status": ("edgeresponsestatus", "status", "response_status", "originresponsestatus", "sc-status"),
    "time": ("edgestarttimestamp", "timestamp", "@timestamp", "time", "time_local", "datetime", "date"),
}


def _collect_networks(obj, out, depth=0):
    if depth > 8:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _collect_networks(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _collect_networks(v, out, depth + 1)
    elif isinstance(obj, str):
        s = obj.strip()
        if s and (":" in s or "." in s) and len(s) < 60 and re.match(r"^[0-9a-fA-F:./]+$", s):
            try:
                out.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                pass


def _fetch_ip_list(key):
    nets, errors = [], []
    for url in IP_LISTS[key]:
        r = http_get(url, CHROME_UA, timeout=12, accept="application/json,text/plain,*/*")
        if r["error"] or r["status"] != 200:
            errors.append(r["error"] or f"HTTP {r['status']}")
            continue
        body = r["html"] or ""
        try:
            _collect_networks(json.loads(body), nets)
        except ValueError:
            _collect_networks(body.split(), nets)
    return key, nets, ("; ".join(errors) if errors and not nets else "")


def get_ip_lists():
    with _IPLIST_LOCK:
        fresh = time.time() - _IPLIST_CACHE["at"] < (12 * 3600 if not _IPLIST_CACHE["errors"] else 600)
        if not fresh:
            nets, errors = {}, {}
            with ThreadPoolExecutor(max_workers=6) as ex:
                for key, n, err in ex.map(_fetch_ip_list, list(IP_LISTS)):
                    if n:
                        nets[key] = n
                    else:
                        errors[key] = err or "No addresses found in the list."
            _IPLIST_CACHE.update({"at": time.time(), "nets": nets, "errors": errors})
        return _IPLIST_CACHE["nets"], _IPLIST_CACHE["errors"]


def _in_nets(addr, nets):
    return any(addr.version == n.version and addr in n for n in nets)


def _log_date(t):
    if t is None or t == "":
        return ""
    if isinstance(t, (int, float)) or (isinstance(t, str) and t.isdigit()):
        v = float(t)
        while v > 1e11:
            v /= 1000
        try:
            return time.strftime("%Y-%m-%d", time.gmtime(v))
        except Exception:
            return ""
    s = str(t)
    m = re.match(r"(\d{1,2})/([A-Za-z]{3})/(\d{4})", s)
    if m:
        return f"{m.group(3)}-{LOG_MONTHS.get(m.group(2).title(), 0):02d}-{int(m.group(1)):02d}"
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    return m.group(0) if m else ""


def _json_field(d, name):
    low = {k.lower(): v for k, v in d.items()}
    for k in LOG_JSON_KEYS[name]:
        if k in low and low[k] not in (None, ""):
            return low[k]
    return None


def parse_log_line(line):
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            d = json.loads(line)
        except ValueError:
            return None
        if not isinstance(d, dict):
            return None
        path = str(_json_field(d, "path") or "")
        if path.startswith(("GET ", "POST ", "HEAD ")):
            path = path.split(" ")[1] if len(path.split(" ")) > 1 else path
        if path.startswith(("http://", "https://")):
            sp = urllib.parse.urlsplit(path)
            path = sp.path + ("?" + sp.query if sp.query else "")
        try:
            status = int(_json_field(d, "status") or 0)
        except (TypeError, ValueError):
            status = 0
        return {"ip": str(_json_field(d, "ip") or ""), "ua": str(_json_field(d, "ua") or ""),
                "path": path or "/", "status": status, "date": _log_date(_json_field(d, "time"))}
    m = COMBINED_RE.match(line)
    if not m:
        return None
    ua = (m.group("ua") or "").replace('\\"', '"')
    return {"ip": m.group("ip"), "ua": ua, "path": m.group("path") or "/", "status": int(m.group("status")),
            "date": _log_date(m.group("time"))}


def analyze_log_lines(lines):
    nets, list_errors = get_ip_lists()
    cf = nets.get("cloudflare", [])
    stats = {"lines": 0, "parsed": 0, "unparsed": 0, "no_ua": 0, "first": "", "last": "", "truncated": False,
             "ai_visits": 0, "verified": 0, "fake": 0, "unknown": 0, "proxy": 0}
    bots, pages, errors, fakes, days = {}, {}, {}, {}, {}
    vcache = {}
    unparsed_sample = []
    for raw in lines:
        stats["lines"] += 1
        if stats["lines"] > LOG_MAX_LINES:
            stats["truncated"] = True
            break
        rec = parse_log_line(raw)
        if rec is None:
            if raw.strip():
                stats["unparsed"] += 1
                if len(unparsed_sample) < 3:
                    unparsed_sample.append(raw.strip()[:200])
            continue
        stats["parsed"] += 1
        date = rec["date"]
        if date:
            if not stats["first"] or date < stats["first"]:
                stats["first"] = date
            if date > stats["last"]:
                stats["last"] = date
        if not rec["ua"]:
            stats["no_ua"] += 1
            continue
        lu = rec["ua"].lower()
        bot = next((b for b in LOG_BOTS if b[0] in lu), None)
        if not bot:
            continue
        _, label, company, key = bot
        ck = (rec["ip"], key)
        if ck not in vcache:
            try:
                addr = ipaddress.ip_address(rec["ip"].strip("[]"))
            except ValueError:
                addr = None
            if addr is None:
                v = "unknown"
            elif cf and _in_nets(addr, cf):
                v = "proxy"
            elif key and key in nets:
                v = "verified" if _in_nets(addr, nets[key]) else "fake"
            else:
                v = "unknown"
            vcache[ck] = v
        verdict = vcache[ck]
        stats["ai_visits"] += 1
        stats[verdict] += 1
        b = bots.get(label)
        if b is None:
            b = bots[label] = {"label": label, "company": company, "key": key, "hits": 0, "verified": 0, "fake": 0,
                               "unknown": 0, "proxy": 0, "pages": set(), "errors": 0, "robots": 0, "first": "", "last": "",
                               "s2": 0, "s3": 0, "s4": 0, "s5": 0}
        b["hits"] += 1
        b[verdict] += 1
        day = days.setdefault(date or "unknown", {"real": 0, "fake": 0})
        if verdict == "fake":
            fakes[(rec["ip"], label)] = fakes.get((rec["ip"], label), 0) + 1
            day["fake"] += 1
            continue
        day["real"] += 1
        path = (rec["path"].split("?")[0] or "/")[:300]
        status = rec["status"]
        if len(b["pages"]) < 20000:
            b["pages"].add(path)
        if 200 <= status < 600:
            b["s" + str(status // 100)] = b.get("s" + str(status // 100), 0) + 1
        if path == "/robots.txt":
            b["robots"] += 1
        if date:
            if not b["first"] or date < b["first"]:
                b["first"] = date
            if date > b["last"]:
                b["last"] = date
        if status >= 400:
            b["errors"] += 1
            errors[(path, label, status)] = errors.get((path, label, status), 0) + 1
        if path != "/robots.txt" and not SKIP_EXT_RE.search(path):
            pg = pages.get(path)
            if pg is None:
                if len(pages) >= 50000:
                    continue
                pg = pages[path] = {"path": path, "hits": 0, "errors": 0, "bots": {}}
            pg["hits"] += 1
            pg["bots"][label] = pg["bots"].get(label, 0) + 1
            if status >= 400:
                pg["errors"] += 1
    bot_rows = []
    for b in sorted(bots.values(), key=lambda x: -x["hits"]):
        b["pages"] = len(b["pages"])
        b["verifiable"] = bool(b["key"] and b["key"] in nets)
        b["list_error"] = list_errors.get(b["key"], "") if b["key"] else ""
        b.pop("key", None)
        bot_rows.append(b)
    seen = {b["label"] for b in bot_rows}
    not_seen = []
    for _, label, company, _k in LOG_BOTS:
        if label not in seen and label not in [x["label"] for x in not_seen]:
            not_seen.append({"label": label, "company": company})
    page_rows = sorted(pages.values(), key=lambda x: -x["hits"])[:150]
    for p in page_rows:
        p["bots"] = sorted(p["bots"].items(), key=lambda x: -x[1])
    return {
        "stats": stats, "bots": bot_rows, "not_seen": not_seen, "pages": page_rows, "total_pages": len(pages),
        "errors": [{"path": k[0], "bot": k[1], "status": k[2], "count": v} for k, v in sorted(errors.items(), key=lambda x: -x[1])[:80]],
        "fakes": [{"ip": k[0], "bot": k[1], "count": v} for k, v in sorted(fakes.items(), key=lambda x: -x[1])[:40]],
        "days": [{"date": k, "real": v["real"], "fake": v["fake"]} for k, v in sorted(days.items())][-120:],
        "list_errors": {k: v for k, v in list_errors.items()}, "unparsed_sample": unparsed_sample,
        "analyzed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def analyze_log_upload(handler):
    try:
        length = int(handler.headers.get("Content-Length", 0))
    except ValueError:
        length = 0
    if length <= 0:
        return {"error": "The file is empty."}, 400
    if length > LOG_MAX_BYTES:
        return {"error": f"The file is too large. The limit is {LOG_MAX_BYTES // (1024 * 1024)} MB; compress it with gzip or upload a shorter period."}, 413
    buf = bytearray()
    remaining = length
    while remaining > 0:
        chunk = handler.rfile.read(min(1024 * 1024, remaining))
        if not chunk:
            break
        buf += chunk
        remaining -= len(chunk)
    name = urllib.parse.unquote(handler.headers.get("X-File-Name", "log"))[:200]
    raw = io.BytesIO(bytes(buf))
    stream = gzip.GzipFile(fileobj=raw) if bytes(buf[:2]) == b"\x1f\x8b" else raw
    try:
        text = io.TextIOWrapper(stream, encoding="utf-8", errors="replace")
        result = analyze_log_lines(text)
    except (OSError, EOFError) as e:
        return {"error": f"Could not read the file: {e}"}, 400
    result["file"] = {"name": name, "bytes": length, "gzip": bytes(buf[:2]) == b"\x1f\x8b"}
    if result["stats"]["parsed"] == 0:
        result["error"] = ("No log lines could be read. Supported formats: Apache or Nginx access logs (combined format, as "
                           "in cPanel raw access logs) and JSON lines such as Cloudflare logs.")
    return result, 200


# ---------------------------------------------------------------- projects
_PROJ_LOCK = threading.Lock()


def _projects_file():
    return os.path.join(DATA_DIR, "projects.json")


def load_projects():
    try:
        with open(_projects_file(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_projects(items):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = _projects_file() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    os.replace(tmp, _projects_file())


def _json_files_newest_first(d):
    try:
        return sorted((os.path.join(d, x) for x in os.listdir(d) if x.endswith(".json")), key=os.path.getmtime, reverse=True)
    except Exception:
        return []


def _site_key(u):
    parts = urllib.parse.urlsplit(u)
    h = _bare_host(u)
    return f"{h}:{parts.port}" if h and parts.port else h


def projects_with_latest():
    items = load_projects()
    scans, cites = {}, {}
    for p in _json_files_newest_first(_scan_dir()):
        try:
            with open(p, encoding="utf-8") as f:
                j = json.load(f)
            h = _site_key(j.get("url", ""))
            if h and h not in scans:
                res = j.get("results") or []
                scans[h] = {"id": j.get("id"), "started_at": j.get("started_at"), "status": j.get("status"),
                            "bot": j.get("bot_label"), "pages": len(res),
                            "errors": sum(1 for r in res if r.get("level") == "error"),
                            "warnings": sum(1 for r in res if r.get("level") == "warning")}
        except Exception:
            pass
    for p in _json_files_newest_first(_cite_dir()):
        try:
            with open(p, encoding="utf-8") as f:
                j = json.load(f)
            h = _clean_domain(j.get("domain", ""))
            if h and h not in cites:
                ok = [r for r in (j.get("results") or []) if not r.get("error") and r.get("brand")]
                cites[h] = {"id": j.get("id"), "started_at": j.get("started_at"), "status": j.get("status"),
                            "answers": len(ok), "cited": sum(1 for r in ok if r["brand"].get("cited")),
                            "named": sum(1 for r in ok if r["brand"].get("mentioned")),
                            "score": (j.get("summary") or cite_summary(j)).get("score")}
        except Exception:
            pass
    for it in items:
        it["latest"] = {"scan": scans.get(_site_key(it.get("site", ""))), "cite": cites.get(_bare_host(it.get("site", "")))}
    return {"projects": items, "storage_ok": storage_writable()}


def save_project(p):
    if not storage_writable():
        return {"error": f"The server cannot write to {DATA_DIR}, so projects can't be saved."}, 500
    name = str(p.get("name", "")).strip()[:80]
    if not name:
        return {"error": "Give the project a name."}, 400
    try:
        site = _normalize_url(str(p.get("site", "")))
    except BlockedURL as e:
        return {"error": str(e)}, 400
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    data = {"name": name, "site": site, "brands": _str_list(p.get("brands"), 10, 80),
            "competitors": _str_list(p.get("competitors"), 10, 120),
            "location": str(p.get("location", "")).strip()[:120],
            "questions": [x for x in (str(s).strip()[:300] for s in (p.get("questions") or []) if isinstance(s, str)) if x][:10],
            "updated_at": now}
    with _PROJ_LOCK:
        items = load_projects()
        pid = str(p.get("id") or "")
        existing = next((x for x in items if x.get("id") == pid), None) if pid else None
        if existing:
            existing.update(data)
            out = existing
        else:
            if len(items) >= 200:
                return {"error": "You have reached the limit of 200 projects."}, 400
            out = dict(data, id=secrets.token_hex(5), created_at=now)
            items.append(out)
        items.sort(key=lambda x: x.get("name", "").lower())
        _write_projects(items)
    return out, 200


def delete_project(pid):
    with _PROJ_LOCK:
        items = load_projects()
        keep = [x for x in items if x.get("id") != pid]
        if len(keep) != len(items):
            _write_projects(keep)
    return {"ok": True}, 200


# ---------------------------------------------------------------- AI citations
CITES = {}
_CITE_LOCK = threading.Lock()
SEARCH_ENGINES = ("auto", "native", "exa", "parallel", "perplexity", "firecrawl")
URL_IN_TEXT_RE = re.compile(r"https?://[^\s)\]>\"'<]+")
CITE_ID_RE = re.compile(r"^[a-f0-9]{12}$")


def _host(u):
    h = (urllib.parse.urlsplit(u).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _clean_domain(d):
    d = (d or "").strip().lower()
    if not d:
        return ""
    if "://" not in d:
        d = "http://" + d
    return _host(d)


def _domain_match(host, domain):
    return bool(host) and bool(domain) and (host == domain or host.endswith("." + domain))


def _parse_entity(entry):
    entry = entry.strip()
    m = re.match(r"^(.*?)\s*\(([^)]+)\)\s*$", entry)
    if m:
        return {"label": entry, "names": [m.group(1).strip()] if m.group(1).strip() else [], "domain": _clean_domain(m.group(2))}
    if "." in entry and " " not in entry:
        return {"label": entry, "names": [], "domain": _clean_domain(entry)}
    return {"label": entry, "names": [entry], "domain": ""}


def _entity_in(entity, text_low, hosts):
    rank = None
    if entity["domain"]:
        rank = next((i + 1 for i, h in enumerate(hosts) if _domain_match(h, entity["domain"])), None)
    mentioned = any(n and re.search(r"(?<!\w)" + re.escape(n.lower()) + r"(?!\w)", text_low) for n in entity["names"])
    if entity["domain"] and entity["domain"] in text_low:
        mentioned = True
    return {"mentioned": bool(mentioned), "cited": rank is not None, "rank": rank}


def _usage_count(usage, word):
    n = 0
    for k in ("server_tool_use", "server_tool_use_details"):
        v = (usage or {}).get(k)
        if isinstance(v, dict):
            n += sum(int(x) for kk, x in v.items() if word in kk and isinstance(x, (int, float)))
    return n


def ask_search(key, model, prompt, engine, location):
    params = {"engine": engine, "max_uses": 3, "max_results": 8}
    if location:
        params["user_location"] = dict({"type": "approximate"}, **location)
    payload = {"model": model, "temperature": 0.3,
               "messages": [{"role": "system", "content": "You are a helpful assistant. Search the web to answer with current information, and cite your sources."},
                            {"role": "user", "content": prompt}],
               "tools": [{"type": "openrouter:web_search", "parameters": params}]}
    req = urllib.request.Request(OPENROUTER_URL, data=json.dumps(payload).encode(), headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost", "X-Title": "AI Bot View Checker"})
    t0 = time.time()
    try:
        try:
            resp = urllib.request.urlopen(req, timeout=240)
        except urllib.error.URLError as e:
            if not isinstance(e, urllib.error.HTTPError) and "CERTIFICATE" in str(e.reason).upper():
                resp = urllib.request.urlopen(req, timeout=240, context=_UNVERIFIED_SSL)
            else:
                raise
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        try:
            msg = json.loads(msg).get("error", {}).get("message", msg)
        except Exception:
            pass
        if e.code == 403:
            msg += " Check that Web Search, and this engine, are allowed on OpenRouter's Tools page."
        elif e.code in (400, 404):
            msg += " This model may not support tool calling or this search engine; try another."
        return {"error": f"HTTP {e.code}: {msg}"[:600], "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[:600], "ms": int((time.time() - t0) * 1000)}
    if "error" in data:
        err = data["error"]
        return {"error": (err.get("message", str(err)) if isinstance(err, dict) else str(err))[:600],
                "ms": int((time.time() - t0) * 1000)}
    try:
        msg = data["choices"][0]["message"]
    except Exception:
        return {"error": "Unexpected response from OpenRouter.", "ms": int((time.time() - t0) * 1000)}
    content = msg.get("content") or ""
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    cites, seen = [], set()
    for a in msg.get("annotations") or []:
        if not isinstance(a, dict):
            continue
        c = a.get("url_citation") if isinstance(a.get("url_citation"), dict) else a
        u = c.get("url")
        if isinstance(u, str) and u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            cites.append({"url": u, "title": str(c.get("title") or "")[:200]})
    text_links = [u.rstrip(".,;:") for u in URL_IN_TEXT_RE.findall(content)]
    usage = data.get("usage") or {}
    return {"answer": content[:8000], "citations": cites[:40], "text_links": list(dict.fromkeys(text_links))[:40],
            "searches": _usage_count(usage, "search"), "tokens": usage.get("total_tokens"),
            "ms": int((time.time() - t0) * 1000)}


def _cite_public(job):
    return {k: v for k, v in job.items() if k not in ("stop", "key")}


def _cite_dir():
    return os.path.join(DATA_DIR, "cites")


def save_cite(job):
    if not storage_writable():
        return False
    d = _cite_dir()
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, job["id"] + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_cite_public(job), f)
    os.replace(tmp, os.path.join(d, job["id"] + ".json"))
    files = sorted((os.path.join(d, x) for x in os.listdir(d) if x.endswith(".json")), key=os.path.getmtime, reverse=True)
    for old in files[50:]:
        try:
            os.remove(old)
        except Exception:
            pass
    return True


def load_cite(cite_id):
    job = CITES.get(cite_id)
    if job:
        return _cite_public(job)
    if not CITE_ID_RE.match(cite_id or ""):
        return None
    try:
        with open(os.path.join(_cite_dir(), cite_id + ".json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def list_cites():
    keys = ("id", "domain", "status", "total", "done", "started_at")
    out = [{k: j.get(k) for k in keys} for j in list(CITES.values()) if j["status"] == "running"]
    try:
        d = _cite_dir()
        files = sorted((os.path.join(d, x) for x in os.listdir(d) if x.endswith(".json")), key=os.path.getmtime, reverse=True)[:30]
    except Exception:
        files = []
    for p in files:
        try:
            with open(p, encoding="utf-8") as f:
                j = json.load(f)
            out.append(dict({k: j.get(k) for k in keys}, summary=j.get("summary") or cite_summary(j)))
        except Exception:
            pass
    return {"runs": out}


def _run_cite(job):
    brand = {"label": job["domain"], "names": job["brands"], "domain": job["domain"]}
    comps = [_parse_entity(c) for c in job["competitors"]]

    def one(task):
        prompt, model = task
        r = ask_search(job["key"], model, prompt, job["engine"], job["location"])
        r.update({"prompt": prompt, "model": model})
        if not r.get("error"):
            hosts = []
            for u in [c["url"] for c in r["citations"]] + r["text_links"]:
                h = _host(u)
                if h and h not in hosts:
                    hosts.append(h)
            low = r["answer"].lower()
            r["hosts"] = hosts[:40]
            r["brand"] = _entity_in(brand, low, hosts)
            r["competitors"] = [dict(_entity_in(c, low, hosts), label=c["label"], domain=c["domain"]) for c in comps]
            if job.get("sentiment") and r["brand"]["mentioned"]:
                r["sentiment"], r["sentiment_reason"] = rate_sentiment(job["key"], model, job["brands"] or [job["domain"]],
                                                                      job["domain"], r["answer"])
        return r

    try:
        tasks = [(p, m) for p in job["prompts"] for m in job["models"]]
        job["total"] = len(tasks)
        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = {ex.submit(one, t): t for t in tasks}
            for f in as_completed(futs):
                try:
                    job["results"].append(f.result())
                except Exception as e:
                    p, m = futs[f]
                    job["results"].append({"prompt": p, "model": m, "error": f"{type(e).__name__}: {e}"})
                job["done"] += 1
                if job["stop"]:
                    for other in futs:
                        other.cancel()
                    break
        job["status"] = "stopped" if job["stop"] else "finished"
    except Exception as e:
        job["status"] = "failed"
        job["error"] = f"{type(e).__name__}: {e}"
    finally:
        job["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        job["summary"] = cite_summary(job)
        job["key"] = ""
        try:
            if save_cite(job):
                CITES.pop(job["id"], None)
        except Exception:
            pass
        done = [k for k, j in CITES.items() if j["status"] != "running"]
        for k in done[:-5]:
            CITES.pop(k, None)


def _str_list(v, max_items, max_len):
    if isinstance(v, str):
        v = re.split(r"[\n,]", v)
    if not isinstance(v, list):
        return []
    out = []
    for x in v:
        x = str(x).strip()[:max_len]
        if x and x not in out:
            out.append(x)
    return out[:max_items]


def start_cite(p):
    key = openrouter_key(p.get("key"))
    if not key:
        return {"error": "No OpenRouter API key. Save one in Settings first."}, 400
    domain = _clean_domain(str(p.get("domain", "")))
    if not domain or "." not in domain:
        return {"error": "Enter your site's domain, like example.com."}, 400
    prompts = [x for x in (str(s).strip()[:300] for s in (p.get("prompts") or []) if isinstance(s, str)) if x][:10]
    if not prompts:
        return {"error": "Add at least one question."}, 400
    models = _str_list(p.get("models"), 6, 200)
    if not models:
        return {"error": "Pick at least one model."}, 400
    engine = p.get("engine") if p.get("engine") in SEARCH_ENGINES else "auto"
    location = None
    loc = p.get("location")
    if isinstance(loc, dict):
        location = {k: str(loc.get(k, "")).strip()[:60] for k in ("city", "region", "country") if str(loc.get(k, "")).strip()}
        location = location or None
    with _CITE_LOCK:
        if any(j["status"] == "running" for j in CITES.values()):
            return {"error": "A citation test is already running. Wait for it to finish, or stop it first."}, 409
        job = {"id": secrets.token_hex(6), "domain": domain, "brands": _str_list(p.get("brands"), 10, 80),
               "competitors": _str_list(p.get("competitors"), 10, 120), "prompts": prompts, "models": models,
               "engine": engine, "location": location, "status": "running", "total": len(prompts) * len(models),
               "done": 0, "started_at": time.strftime("%Y-%m-%d %H:%M:%S"), "finished_at": "", "error": "",
               "results": [], "stop": False, "key": key, "sentiment": bool(p.get("sentiment", True))}
        CITES[job["id"]] = job
    threading.Thread(target=_run_cite, args=(job,), daemon=True).start()
    return {"id": job["id"]}, 200


# ---------------------------------------------------------------- AI helpers: score, sentiment, question ideas, outreach briefs
def or_chat(key, model, system, user, temperature=0.3, timeout=120):
    payload = {"model": model, "temperature": temperature,
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    req = urllib.request.Request(OPENROUTER_URL, data=json.dumps(payload).encode(), headers={
        "Authorization": f"Bearer {key}", "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost", "X-Title": "AI Bot View Checker"})
    try:
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.URLError as e:
            if not isinstance(e, urllib.error.HTTPError) and "CERTIFICATE" in str(e.reason).upper():
                resp = urllib.request.urlopen(req, timeout=timeout, context=_UNVERIFIED_SSL)
            else:
                raise
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")
        try:
            msg = json.loads(msg).get("error", {}).get("message", msg)
        except Exception:
            pass
        return None, f"HTTP {e.code}: {msg}"[:400]
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"[:400]
    if "error" in data:
        err = data["error"]
        return None, (err.get("message", str(err)) if isinstance(err, dict) else str(err))[:400]
    try:
        content = data["choices"][0]["message"]["content"] or ""
    except Exception:
        return None, "Unexpected response from OpenRouter."
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return content, None


def extract_json(text):
    if not text:
        return None
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.M)
    for pat in (r"\{.*\}", r"\[.*\]"):
        m = re.search(pat, t, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                pass
    return None


def answer_score(r):
    b = r.get("brand") or {}
    s = 0
    if b.get("mentioned"):
        s += 40 + {"positive": 20, "negative": 0}.get(r.get("sentiment"), 10)
    if b.get("cited"):
        rank = b.get("rank") or 9
        s += 40 if rank == 1 else 30 if rank == 2 else 20 if rank == 3 else 10
    return s


def cite_summary(job):
    ok = [r for r in (job.get("results") or []) if not r.get("error") and r.get("brand")]
    if not ok:
        return {"score": None, "answers": 0, "cited": 0, "named": 0, "positive": 0, "negative": 0}
    return {"score": round(sum(answer_score(r) for r in ok) / len(ok)), "answers": len(ok),
            "cited": sum(1 for r in ok if r["brand"].get("cited")), "named": sum(1 for r in ok if r["brand"].get("mentioned")),
            "positive": sum(1 for r in ok if r.get("sentiment") == "positive"),
            "negative": sum(1 for r in ok if r.get("sentiment") == "negative")}


def rate_sentiment(key, model, names, domain, answer):
    system = ("You judge how an AI assistant's answer describes one business. Reply with JSON only.")
    user = (f"Business: {', '.join(names)} ({domain})\n\nAnswer to judge:\n<<<\n{answer[:6000]}\n>>>\n\n"
            "How does the answer describe this business? Positive means it is recommended or praised; negative means "
            "it is criticised or warned against; neutral means it is only listed or mentioned.\n"
            'Return only JSON: {"sentiment": "positive" or "neutral" or "negative", "reason": "one short sentence"}')
    txt, err = or_chat(key, model, system, user, temperature=0, timeout=90)
    j = extract_json(txt) if not err else None
    if isinstance(j, dict) and j.get("sentiment") in ("positive", "neutral", "negative"):
        return j["sentiment"], str(j.get("reason", ""))[:300]
    return None, ""


def _page_excerpt(url, n=4000):
    r = http_get(url, CHROME_UA, timeout=15)
    if r["error"] or (r["status"] or 0) >= 400 or not r["html"]:
        return "", "", ""
    p = PageExtractor()
    try:
        p.feed(r["html"])
    except Exception:
        pass
    return re.sub(r"\s+", " ", p.title).strip()[:200], (p.meta.get("description") or "")[:400], p.text()[:n]


def suggest_questions(p):
    key = openrouter_key(None)
    if not key:
        return {"error": "No OpenRouter API key. Save one in Settings first."}, 400
    model = str(p.get("model") or "").strip()[:200]
    if not model:
        return {"error": "Pick a model."}, 400
    try:
        site = _normalize_url(str(p.get("site", "")))
    except BlockedURL as e:
        return {"error": str(e)}, 400
    brands = _str_list(p.get("brands"), 6, 80)
    personas = _str_list(p.get("personas"), 6, 60)
    location = str(p.get("location", "")).strip()[:120]
    try:
        count = max(4, min(20, int(p.get("count", 12))))
    except (TypeError, ValueError):
        count = 12
    title, desc, text = _page_excerpt(site, 3500)
    persona_line = (f"Spread the questions across these customer types and label each with one of them: {', '.join(personas)}."
                    if personas else "Label each question with a short customer type, for example 'homeowner' or 'property manager'.")
    system = "You help a marketing agency test how AI assistants answer real customer questions. Reply with JSON only."
    user = (f"Business website: {site}\nPage title: {title or '(unknown)'}\nDescription: {desc or '(none)'}\n"
            f"Location served: {location or 'not specified'}\nHomepage text (excerpt):\n<<<\n{text or '(the page could not be read)'}\n>>>\n\n"
            f"Write {count} questions that real potential customers would type into an AI assistant such as ChatGPT when looking "
            "for what this business offers. Mix intents: finding a provider, comparing options, cost, and problem or how-to "
            "questions. Include the location in some questions if one is given. Do NOT mention the business or brand name, so the "
            f"test shows whether AI recommends it on its own. {persona_line}\n"
            'Return only JSON: {"questions": [{"question": "...", "persona": "...", "intent": "find a provider or compare or cost or how-to or problem"}]}')
    txt, err = or_chat(key, model, system, user, temperature=0.7, timeout=150)
    if err:
        return {"error": err}, 502
    j = extract_json(txt)
    items = j.get("questions") if isinstance(j, dict) else j if isinstance(j, list) else None
    if not isinstance(items, list):
        return {"error": "The model did not return a usable list. Try again or pick another model."}, 502
    out, seen = [], set()
    low_brands = [b.lower() for b in brands if len(b) >= 3]
    for it in items:
        q = (it.get("question") if isinstance(it, dict) else it) or ""
        q = re.sub(r"\s+", " ", str(q)).strip()[:300]
        if not q or q.lower() in seen or any(b in q.lower() for b in low_brands):
            continue
        seen.add(q.lower())
        out.append({"question": q, "persona": str(it.get("persona", ""))[:60] if isinstance(it, dict) else "",
                    "intent": str(it.get("intent", ""))[:40] if isinstance(it, dict) else ""})
    if not out:
        return {"error": "No usable questions came back. Try again or pick another model."}, 502
    return {"questions": out[:count], "model": model}, 200


def outreach_brief(p):
    key = openrouter_key(None)
    if not key:
        return {"error": "No OpenRouter API key. Save one in Settings first."}, 400
    model = str(p.get("model") or "").strip()[:200]
    if not model:
        return {"error": "Pick a model."}, 400
    try:
        url = _normalize_url(str(p.get("url", "")))
    except BlockedURL as e:
        return {"error": str(e)}, 400
    domain = _clean_domain(str(p.get("domain", "")))
    brands = _str_list(p.get("brands"), 6, 80)
    comps = _str_list(p.get("competitors"), 10, 120)
    question = str(p.get("question", "")).strip()[:300]
    ptitle, _desc, text = _page_excerpt(url, 4000)
    title = ptitle or str(p.get("title", "")).strip()[:200]
    system = "You write short, practical outreach briefs for a marketing agency. Plain text only, no Markdown headings."
    user = (f"Our client: {', '.join(brands) or domain} ({domain})\n"
            f"AI assistants cited this page when answering: \"{question}\"\n"
            f"Page: {title or '(no title)'} - {url}\n"
            f"Competitors named in those AI answers: {', '.join(comps) or 'none'}\n"
            f"Page excerpt:\n<<<\n{text or '(the page could not be fetched)'}\n>>>\n\n"
            "Write a brief with four short parts: 1) what this page is and who seems to run it, based on the excerpt; "
            "2) why our client would fit on it; 3) the best approach, such as a listing request, a review, an expert quote, "
            "or a correction; 4) a first outreach email under 120 words. Do not invent facts about our client: use "
            "placeholders like [service] or [city] where details are missing.")
    txt, err = or_chat(key, model, system, user, temperature=0.5, timeout=150)
    if err:
        return {"error": err}, 502
    return {"brief": (txt or "").strip()[:6000], "model": model}, 200


# ---------------------------------------------------------------- site scan
SCANS = {}
_SCAN_LOCK = threading.Lock()
SCAN_MAX_PAGES = 200
SCAN_ID_RE = re.compile(r"^[a-f0-9]{12}$")
SKIP_EXT_RE = re.compile(r"\.(jpe?g|png|gif|webp|avif|svg|ico|pdf|zip|gz|rar|mp4|mp3|webm|mov|css|js|json|xml|txt|csv|docx?|xlsx?|pptx?)$", re.I)
LOC_RE = re.compile(r"<loc>\s*(?:<!\[CDATA\[)?\s*(.*?)\s*(?:\]\]>)?\s*</loc>", re.I | re.S)
HREF_RE = re.compile(r'<a\b[^>]*?\bhref\s*=\s*["\']([^"\'#]+)', re.I)


def _bare_host(u):
    h = (urllib.parse.urlsplit(u).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _page_like(u):
    p = urllib.parse.urlsplit(u)
    return p.scheme in ("http", "https") and not SKIP_EXT_RE.search(p.path)


def _is_sitemap(body):
    return "<urlset" in body or "<sitemapindex" in body


def discover_urls(start_url, limit):
    parts = urllib.parse.urlsplit(start_url)
    origin = f"{parts.scheme}://{parts.netloc}"
    host = _bare_host(start_url)
    given_sitemap = bool(re.search(r"\.xml(\.gz)?$", parts.path, re.I))
    if given_sitemap:
        queue = [start_url]
    else:
        queue = []
        r = http_get(origin + "/robots.txt", CHROME_UA, accept="text/plain,*/*")
        if r["status"] == 200 and r["html"]:
            queue = re.findall(r"(?im)^\s*sitemap\s*:\s*(\S+)", r["html"])
        if not queue:
            for cand in (origin + "/sitemap_index.xml", origin + "/sitemap.xml", origin + "/wp-sitemap.xml"):
                c = http_get(cand, CHROME_UA, accept="application/xml,text/xml,*/*")
                if c["status"] == 200 and _is_sitemap(c["html"] or ""):
                    queue = [cand]
                    break
    urls, seen, used = [], set(), []
    while queue and len(seen) < 40 and len(urls) < SCAN_MAX_PAGES * 5:
        sm = queue.pop(0)
        if sm in seen:
            continue
        seen.add(sm)
        r = http_get(sm, CHROME_UA, accept="application/xml,text/xml,*/*")
        body = r["html"] or ""
        if r["status"] != 200 or not _is_sitemap(body):
            continue
        used.append(sm)
        locs = [html_unescape(x).strip() for x in LOC_RE.findall(body)]
        if "<sitemapindex" in body:
            children = [x for x in locs if _bare_host(x) == host]
            children.sort(key=lambda x: 0 if "page" in x.lower() else 1)
            queue = children + queue
        else:
            urls += [u for u in locs if _bare_host(u) == host and _page_like(u)]
    urls = list(dict.fromkeys(u.split("#")[0] for u in urls))
    source = "sitemap"
    if not urls:
        source = "links"
        r = http_get(start_url, CHROME_UA)
        base = r["final_url"] or start_url
        found = [urllib.parse.urljoin(base, h.strip()) for h in HREF_RE.findall(r["html"] or "")]
        urls = list(dict.fromkeys([start_url] + [u.split("#")[0] for u in found if _bare_host(u) == host and _page_like(u)]))
    elif not given_sitemap and not any(urllib.parse.urlsplit(u).path in ("", "/") for u in urls):
        urls.insert(0, origin + "/")
    return urls[:limit], {"source": source, "sitemaps": used[:10], "found": len(urls)}


def _norm_num(v):
    return re.sub(r"[,\s]", "", str(v or ""))


def scan_page(url, bot, rp):
    r = analyze(url, bot, rp)
    s = r.get("structured") or {}
    status = r["status"] or 0
    ok_fetch = not r["error"] and not r["challenge"] and 0 < status < 400
    counters_bad = sum(1 for c in r["counters"] if c["to"] is not None and _norm_num(c["shown"]) != _norm_num(c["to"]))
    robots_meta = (r["meta"].get("robots", "") + " " + (r["x_robots_tag"] or "")).lower()
    issues = []

    def iss(level, code, msg):
        issues.append({"level": level, "code": code, "msg": msg})

    if r["error"]:
        iss("error", "fetch", f"Could not fetch: {r['error']}")
    elif r["challenge"]:
        iss("error", "blocked", f"Got a bot challenge page instead of the content (HTTP {status})")
    elif status >= 400:
        iss("error", "http", f"HTTP {status}")
    if r["robots_allowed"] is False:
        iss("error", "robots", f"robots.txt blocks {bot[1]}")
    if ok_fetch:
        if counters_bad:
            iss("error", "counters", f"{counters_bad} of {len(r['counters'])} animated counters show their starting value")
        if "noindex" in robots_meta:
            iss("warning", "noindex", "Marked noindex")
        if r["words"] < 100:
            iss("warning", "thin", f"Only {r['words']} words readable without JavaScript")
        if not r["title"]:
            iss("warning", "title", "No title")
        if not r["meta"].get("description"):
            iss("warning", "description", "No meta description")
        if not s.get("items"):
            iss("warning", "schema", "No structured data")
        elif (s.get("counts") or {}).get("error"):
            n = s["counts"]["error"]
            iss("warning", "schema_errors", f"{n} structured data error{'s' if n != 1 else ''}")
        final = (r["final_url"] or url).rstrip("/")
        if final != url.rstrip("/"):
            iss("info", "redirect", f"Redirects to {r['final_url']}")
    level = ("error" if any(i["level"] == "error" for i in issues)
             else "warning" if any(i["level"] == "warning" for i in issues) else "ok")
    return {"url": url, "final_url": r["final_url"], "status": r["status"], "ms": r["ms"], "words": r["words"],
            "title": (r["title"] or "")[:200], "counters": len(r["counters"]), "counters_bad": counters_bad,
            "schema_items": len(s.get("items") or []), "schema_errors": (s.get("counts") or {}).get("error", 0),
            "issues": issues, "level": level}


def _scan_public(job):
    return {k: v for k, v in job.items() if k != "stop"}


def _scan_dir():
    return os.path.join(DATA_DIR, "scans")


def save_scan(job):
    if not storage_writable():
        return False
    d = _scan_dir()
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, job["id"] + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(_scan_public(job), f)
    os.replace(tmp, os.path.join(d, job["id"] + ".json"))
    files = sorted((os.path.join(d, x) for x in os.listdir(d) if x.endswith(".json")), key=os.path.getmtime, reverse=True)
    for old in files[30:]:
        try:
            os.remove(old)
        except Exception:
            pass
    return True


def load_scan(scan_id):
    job = SCANS.get(scan_id)
    if job:
        return _scan_public(job)
    if not SCAN_ID_RE.match(scan_id or ""):
        return None
    try:
        with open(os.path.join(_scan_dir(), scan_id + ".json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def list_scans():
    keys = ("id", "url", "bot_label", "status", "total", "done", "started_at")
    out = [{k: j.get(k) for k in keys} for j in list(SCANS.values()) if j["status"] == "running"]
    try:
        d = _scan_dir()
        files = sorted((os.path.join(d, x) for x in os.listdir(d) if x.endswith(".json")), key=os.path.getmtime, reverse=True)[:20]
    except Exception:
        files = []
    for p in files:
        try:
            with open(p, encoding="utf-8") as f:
                j = json.load(f)
            out.append({k: j.get(k) for k in keys})
        except Exception:
            pass
    return {"scans": out}


def _run_scan(job):
    try:
        urls, info = discover_urls(job["url"], job["limit"])
        job.update(info)
        job["total"] = len(urls)
        if not urls:
            job["status"] = "failed"
            job["error"] = "No pages found: there is no sitemap, and the start page has no links to the same site."
            return
        rp, _ = load_robots(urls[0])
        bot = BOT_BY_ID[job["bot"]]
        job["phase"] = "checking"
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(scan_page, u, bot, rp): u for u in urls}
            for f in as_completed(futs):
                try:
                    job["results"].append(f.result())
                except Exception as e:
                    u = futs[f]
                    job["results"].append({"url": u, "final_url": u, "status": None, "ms": None, "words": 0, "title": "",
                                           "counters": 0, "counters_bad": 0, "schema_items": 0, "schema_errors": 0,
                                           "issues": [{"level": "error", "code": "fetch", "msg": f"Check failed: {type(e).__name__}: {e}"}],
                                           "level": "error"})
                job["done"] += 1
                if job["stop"]:
                    for other in futs:
                        other.cancel()
                    break
        job["status"] = "stopped" if job["stop"] else "finished"
    except Exception as e:
        job["status"] = "failed"
        job["error"] = f"{type(e).__name__}: {e}"
    finally:
        job["phase"] = "done"
        job["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            if save_scan(job):
                SCANS.pop(job["id"], None)
        except Exception:
            pass
        done = [k for k, j in SCANS.items() if j["status"] != "running"]
        for k in done[:-5]:
            SCANS.pop(k, None)


def start_scan(url, bot_id, limit):
    url = (url or "").strip()
    if not url:
        return {"error": "Enter a site or sitemap URL."}, 400
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    try:
        check_public_url(url)
    except BlockedURL as e:
        return {"error": str(e)}, 400
    if bot_id not in BOT_BY_ID:
        bot_id = "gptbot"
    try:
        limit = max(1, min(SCAN_MAX_PAGES, int(limit)))
    except Exception:
        limit = 50
    with _SCAN_LOCK:
        if any(j["status"] == "running" for j in SCANS.values()):
            return {"error": "A scan is already running. Wait for it to finish, or stop it first."}, 409
        job = {"id": secrets.token_hex(6), "url": url, "bot": bot_id, "bot_label": BOT_BY_ID[bot_id][1],
               "limit": limit, "status": "running", "phase": "discovering", "total": 0, "done": 0, "found": 0,
               "source": "", "sitemaps": [], "started_at": time.strftime("%Y-%m-%d %H:%M:%S"), "finished_at": "",
               "error": "", "results": [], "stop": False}
        SCANS[job["id"]] = job
    threading.Thread(target=_run_scan, args=(job,), daemon=True).start()
    return {"id": job["id"]}, 200


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


FETCH_ENGINES = ("openrouter", "native", "auto", "exa", "parallel", "firecrawl")
OPENROUTER_URL = os.environ.get("OPENROUTER_URL", "https://openrouter.ai/api/v1/chat/completions")


def ask_model(key, model, bot_label, url, text, question, mode="text", engine="openrouter"):
    key = openrouter_key(key)
    if not key:
        return {"model": model, "error": "No OpenRouter API key. Save one in Settings or set OPENROUTER_API_KEY."}
    truncated = False
    tools = None
    if mode == "fetch":
        engine = engine if engine in FETCH_ENGINES else "openrouter"
        host = urllib.parse.urlsplit(url).hostname or ""
        domains = sorted({host, host[4:] if host.startswith("www.") else host} - {""})
        system = (
            "You are an AI assistant with a web fetch tool. Fetch the exact URL the user gives you and answer "
            "the question using ONLY the content you fetched. Do not use outside knowledge about the site or company. "
            "Start your answer with one line: 'Fetch: succeeded' or 'Fetch: failed - <reason>'. "
            "If information is missing, unclear, or looks like a placeholder (such as 0), say so explicitly. "
            "Quote numbers exactly as they appear in the content."
        )
        user = f"URL: {url}\n\nFetch this page, then answer.\n\nQUESTION: {question}"
        tools = [{"type": "openrouter:web_fetch", "parameters": {
            "engine": engine, "max_uses": 3, "max_content_tokens": 30000, "allowed_domains": domains}}]
    else:
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
    payload = {"model": model, "temperature": 0.2,
               "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if tools:
        payload["tools"] = tools
    req = urllib.request.Request(OPENROUTER_URL, data=json.dumps(payload).encode(), headers={
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
        if mode == "fetch" and e.code == 403:
            msg += " Check that Web Fetch, and this engine, are allowed on OpenRouter's Tools page."
        elif mode == "fetch" and e.code in (400, 404):
            msg += " This model may not support tool calling; try another model."
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
            "usage": data.get("usage", {}), "truncated": truncated,
            "mode": mode, "engine": engine if mode == "fetch" else None}


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
            return self._send(200, read_web("login.html"), "text/html; charset=utf-8")
        if path == "/logout":
            return self._redirect("/login", f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
        if not self._authorized():
            return self._deny() if path.startswith("/api/") else self._redirect("/login")
        if path == "/":
            self._send(200, read_web("index.html"), "text/html; charset=utf-8")
        elif path in STATIC_FILES:
            name, ctype = STATIC_FILES[path]
            self._send(200, read_web(name), ctype)
        elif path == "/api/bots":
            self._json([{"id": b[0], "label": b[1], "note": b[4], "default": b[5]} for b in BOTS])
        elif path == "/api/models":
            self._json(list_models())
        elif path == "/api/settings":
            self._json(settings_public())
        elif path == "/api/scan/status":
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            job = load_scan((q.get("id") or [""])[0])
            self._json(job if job else {"error": "Scan not found. It may have been removed."}, 200 if job else 404)
        elif path == "/api/scan/list":
            self._json(list_scans())
        elif path == "/api/cite/status":
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            job = load_cite((q.get("id") or [""])[0])
            self._json(job if job else {"error": "Test not found. It may have been removed."}, 200 if job else 404)
        elif path == "/api/cite/list":
            self._json(list_cites())
        elif path == "/api/projects":
            self._json(projects_with_latest())
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/logs/analyze":
            if not self._authorized():
                return self._deny()
            try:
                body, code = analyze_log_upload(self)
            except Exception as e:
                body, code = {"error": f"{type(e).__name__}: {e}"}, 500
            return self._json(body, code)
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
                                            payload.get("text", ""), payload.get("question", ""),
                                            "fetch" if payload.get("mode") == "fetch" else "text",
                                            str(payload.get("engine", "openrouter"))))
            if path == "/api/questions":
                body, code = suggest_questions(payload)
                return self._json(body, code)
            if path == "/api/brief":
                body, code = outreach_brief(payload)
                return self._json(body, code)
            if path == "/api/projects/save":
                body, code = save_project(payload)
                return self._json(body, code)
            if path == "/api/projects/delete":
                body, code = delete_project(str(payload.get("id", "")))
                return self._json(body, code)
            if path == "/api/cite/start":
                body, code = start_cite(payload)
                return self._json(body, code)
            if path == "/api/cite/stop":
                job = CITES.get(str(payload.get("id", "")))
                if job and job["status"] == "running":
                    job["stop"] = True
                return self._json({"ok": True})
            if path == "/api/access":
                body, code = check_access(payload.get("url", ""))
                return self._json(body, code)
            if path == "/api/llms":
                body, code = check_llms(payload.get("url", ""))
                return self._json(body, code)
            if path == "/api/llms/generate":
                body, code = generate_llms(payload.get("url", ""))
                return self._json(body, code)
            if path == "/api/scan/start":
                body, code = start_scan(payload.get("url", ""), str(payload.get("bot", "gptbot")), payload.get("limit", 50))
                return self._json(body, code)
            if path == "/api/scan/stop":
                job = SCANS.get(str(payload.get("id", "")))
                if job and job["status"] == "running":
                    job["stop"] = True
                return self._json({"ok": True})
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

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
STATIC_FILES = {
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/app.js": ("app.js", "application/javascript; charset=utf-8"),
}


def read_web(name):
    with open(os.path.join(WEB_DIR, name), "rb") as f:
        return f.read()


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
