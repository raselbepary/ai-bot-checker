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
import glob
from html import escape as _he
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
import gzip
import io
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import select
import shutil
import smtplib
import socketserver
import subprocess
import tempfile
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


# ---------------------------------------------------------------- JavaScript gap (headless browser)
RENDER_LOCK = threading.Semaphore(1)
_PROXY = {"port": None}
_PROXY_LOCK = threading.Lock()
ALLOWED_PORTS = {80, 443, 8080, 8443}


def _resolve_public(host, port):
    """Resolve host and return one address to connect to; refuse private or reserved ones."""
    if not ALLOW_PRIVATE and port not in ALLOWED_PORTS:
        raise BlockedURL(f"Port {port} is not allowed.")
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        mapped = getattr(ip, "ipv4_mapped", None)
        if mapped:
            ip = mapped
        if not ALLOW_PRIVATE and not ip.is_global:
            raise BlockedURL(f"{host} points to a private or reserved address.")
        ips.append(str(ip))
    if not ips:
        raise BlockedURL(f"Could not resolve {host}.")
    return ips[0]


class _FilterProxy(socketserver.BaseRequestHandler):
    """A tiny HTTP proxy for the headless browser: every request goes through check of the destination address."""

    def handle(self):
        c = self.request
        c.settimeout(30)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = c.recv(4096)
                if not chunk:
                    return
                data += chunk
        except OSError:
            return
        head, _, rest = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, version = lines[0].split(" ", 2)
        except ValueError:
            return
        try:
            if method.upper() == "CONNECT":
                host, _, port = target.rpartition(":")
                host = host.strip("[]")
                port = int(port or 443)
                up = socket.create_connection((_resolve_public(host, port), port), timeout=20)
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    up.sendall(rest)
            else:
                p = urllib.parse.urlsplit(target)
                if p.scheme != "http" or not p.hostname:
                    raise BlockedURL("Unsupported request.")
                port = p.port or 80
                up = socket.create_connection((_resolve_public(p.hostname, port), port), timeout=20)
                path = (p.path or "/") + ("?" + p.query if p.query else "")
                hdrs = [h for h in lines[1:] if h and not h.lower().startswith(("proxy-connection:", "connection:", "keep-alive:"))]
                up.sendall((f"{method} {path} {version}\r\n" + "\r\n".join(hdrs) + "\r\nConnection: close\r\n\r\n").encode("latin-1") + rest)
            self._pipe(c, up)
        except (BlockedURL, OSError, ValueError):
            try:
                c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass

    @staticmethod
    def _pipe(a, b):
        try:
            while True:
                r, _, x = select.select([a, b], [], [a, b], 30)
                if x or not r:
                    return
                for s in r:
                    chunk = s.recv(65536)
                    if not chunk:
                        return
                    (b if s is a else a).sendall(chunk)
        except OSError:
            return
        finally:
            try:
                b.close()
            except OSError:
                pass


def _ensure_proxy():
    with _PROXY_LOCK:
        if not _PROXY["port"]:
            class _Server(socketserver.ThreadingTCPServer):
                daemon_threads = True
                allow_reuse_address = True
            srv = _Server(("127.0.0.1", 0), _FilterProxy)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            _PROXY["port"] = srv.server_address[1]
        return _PROXY["port"]


def _chrome_path():
    p = os.environ.get("CHROME_PATH")
    if p and os.path.exists(p):
        return p
    base = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
    for pattern in ("chromium_headless_shell-*/*/headless_shell", "chromium_headless_shell-*/*/chrome-headless-shell"):
        found = sorted(glob.glob(os.path.join(base, pattern)))
        if found:
            return found[-1]
    for name in ("chrome-headless-shell", "headless_shell", "chromium", "chromium-browser", "google-chrome"):
        w = shutil.which(name)
        if w:
            return w
    return None


def render_page(url, wait_ms=8000):
    chrome = _chrome_path()
    if not chrome:
        return None, "The headless browser is not installed on this server."
    if not RENDER_LOCK.acquire(timeout=60):
        return None, "Another page is being rendered right now. Try again in a minute."
    tmp = tempfile.mkdtemp(prefix="abvc-chrome-")
    try:
        port = _ensure_proxy()
        cmd = [chrome, "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run", "--no-default-browser-check",
               "--disable-extensions", "--disable-background-networking", "--disable-sync", "--mute-audio", "--hide-scrollbars",
               "--disable-crash-reporter", f"--user-data-dir={tmp}", f"--user-agent={CHROME_UA}", "--window-size=1366,3000",
               f"--proxy-server=http://127.0.0.1:{port}", "--proxy-bypass-list=<-loopback>",
               f"--virtual-time-budget={wait_ms}", "--dump-dom", url]
        if "headless" not in os.path.basename(chrome):
            cmd.insert(1, "--headless=new")
        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, timeout=75, env=dict(os.environ, HOME=tmp))
        out = proc.stdout.decode("utf-8", errors="replace")
        if not out.strip():
            return None, "The browser returned no content for this page."
        return {"html": out[:MAX_BYTES], "ms": int((time.time() - t0) * 1000)}, None
    except subprocess.TimeoutExpired:
        return None, "The page took too long to load in the browser (over 75 seconds)."
    except OSError as e:
        return None, f"The headless browser could not start: {e}"
    finally:
        RENDER_LOCK.release()
        shutil.rmtree(tmp, ignore_errors=True)


def _ntext(s):
    return re.sub(r"\s+", " ", s or "").strip().lower()


def _page_bits(html, base_url):
    pe = PageExtractor()
    try:
        pe.feed(html)
    except Exception:
        pass
    text = pe.text()
    host = _bare_host(base_url)
    links = set()
    for h in HREF_RE.findall(html):
        u = urllib.parse.urljoin(base_url, h.strip()).split("#")[0]
        if u.startswith(("http://", "https://")) and _bare_host(u) == host:
            links.add(u.rstrip("/") or u)
    return {"text": text, "words": _words(text), "headings": [x["text"] for x in pe.headings], "links": links,
            "jsonld": len(JSONLD_RE.findall(html)), "title": re.sub(r"\s+", " ", pe.title).strip(),
            "desc": pe.meta.get("description", ""), "counters": [c["shown"] for c in find_counters(html)]}


def js_gap(url):
    try:
        url = _normalize_url(url)
    except BlockedURL as e:
        return {"error": str(e)}, 400
    raw_r = http_get(url, CHROME_UA)
    if raw_r["error"]:
        return {"error": f"Could not fetch the page: {raw_r['error']}"}, 502
    base = raw_r["final_url"] or url
    rendered, err = render_page(base)
    if err:
        return {"error": err}, 503
    raw = _page_bits(raw_r["html"] or "", base)
    ren = _page_bits(rendered["html"], base)
    raw_norm, ren_norm = _ntext(raw["text"]), _ntext(ren["text"])
    js_only, seen = [], set()
    for line in ren["text"].split("\n"):
        n = _ntext(line)
        if not n or n in seen or (len(n) < 12 and not re.search(r"\d", n)):
            continue
        seen.add(n)
        if n not in raw_norm:
            js_only.append(line.strip()[:400])
    removed, seen = [], set()
    for line in raw["text"].split("\n"):
        n = _ntext(line)
        if not n or n in seen or len(n) < 12:
            continue
        seen.add(n)
        if n not in ren_norm:
            removed.append(line.strip()[:400])
    norm_num = lambda x: x.rstrip(",.").replace(",", "").replace("$", "")
    raw_nums = {norm_num(x) for x in NUMBER_RE.findall(raw["text"])}
    nums, seen = [], set()
    for m in NUMBER_RE.finditer(ren["text"]):
        v = norm_num(m.group(0))
        if len(v.replace(".", "")) < 2 or v in raw_nums or v in seen:
            continue
        seen.add(v)
        a, b = max(0, m.start() - 50), min(len(ren["text"]), m.end() + 50)
        nums.append({"number": m.group(0).rstrip(",."), "context": re.sub(r"\s+", " ", ren["text"][a:b]).strip()})
    visible = 100 if not ren["words"] else round(100 * min(1, raw["words"] / ren["words"]))
    return {"url": base, "status": raw_r["status"], "render_ms": rendered["ms"], "visible_pct": visible,
            "raw": {"words": raw["words"], "headings": len(raw["headings"]), "links": len(raw["links"]), "jsonld": raw["jsonld"],
                    "title": raw["title"], "desc": raw["desc"], "counters": raw["counters"]},
            "rendered": {"words": ren["words"], "headings": len(ren["headings"]), "links": len(ren["links"]), "jsonld": ren["jsonld"],
                         "title": ren["title"], "desc": ren["desc"], "counters": ren["counters"]},
            "js_only_text": js_only[:150], "js_only_numbers": nums[:60],
            "js_only_headings": [h for h in ren["headings"] if _ntext(h) not in raw_norm][:40],
            "js_only_links": sorted(ren["links"] - raw["links"])[:60], "removed_text": removed[:80],
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}, 200


# ---------------------------------------------------------------- AI readiness review
READY_SKIP = {"script", "style", "noscript", "template", "svg", "iframe", "head", "object", "canvas", "nav", "footer", "aside", "form"}
GREETING_RE = re.compile(r"^(welcome to|in today's|are you looking|looking for|have you ever|thank you for|hello|hi there)", re.I)
PHONE_RE = re.compile(r"(?<!\d)\+?\(?\d[\d\s().-]{8,}\d(?!\d)")
NUMBER_RE = re.compile(r"(?<![\w.])\$?\d[\d,]*(?:\.\d+)?")
DATE_TEXT_RE = re.compile(r"\b(updated|last updated|published|posted)\b[^.\n]{0,40}\b(19|20)\d\d\b", re.I)
BYLINE_RE = re.compile(r"\b[Bb]y\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+")


class ReadinessParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip = 0
        self.blocks = []
        self.cur = None
        self.lists = 0
        self.tables = 0
        self.times = []
        self.author_meta = ""
        self.rel_author = False

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "meta":
            name = (a.get("name") or a.get("property") or "").lower()
            if name in ("author", "article:author"):
                self.author_meta = a.get("content", "")[:120]
            elif name in ("article:modified_time", "article:published_time"):
                self.times.append(a.get("content", ""))
        if tag in ("a", "link") and "author" in a.get("rel", "").lower():
            self.rel_author = True
        if tag in READY_SKIP:
            self.skip += 1
            return
        if self.skip:
            return
        if tag in ("ul", "ol"):
            self.lists += 1
        elif tag == "table":
            self.tables += 1
        elif tag == "time" and a.get("datetime"):
            self.times.append(a["datetime"])
        if tag in ("h1", "h2", "h3", "h4", "h5", "h6", "p", "li") and self.cur is None:
            self.cur = [tag, []]

    def handle_endtag(self, tag):
        if tag in READY_SKIP:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        if self.cur and tag == self.cur[0]:
            text = re.sub(r"\s+", " ", "".join(self.cur[1])).strip()
            if text:
                self.blocks.append((tag, text))
            self.cur = None

    def handle_data(self, data):
        if not self.skip and self.cur is not None:
            self.cur[1].append(data)


def _words(s):
    return len(re.findall(r"\w+", s or ""))


def _readiness(url):
    try:
        url = _normalize_url(url)
    except BlockedURL as e:
        return {"error": str(e)}, 400, ""
    r = http_get(url, BOT_BY_ID["gptbot"][3])
    if r["error"]:
        return {"error": f"Could not fetch the page: {r['error']}"}, 502, ""
    if (r["status"] or 0) >= 400:
        return {"error": f"The page answered HTTP {r['status']} to GPTBot, so there is nothing to review. Check the AI access page."}, 502, ""
    html = r["html"] or ""
    pe = PageExtractor()
    rp = ReadinessParser()
    for parser in (pe, rp):
        try:
            parser.feed(html)
        except Exception:
            pass
    text = pe.text()
    words = _words(text)
    title = re.sub(r"\s+", " ", pe.title).strip()
    s = analyze_structured(html, text, url, pe.meta, pe.headings, title)
    counters = find_counters(html)
    bad_counters = sum(1 for c in counters if c["to"] is not None and _norm_num(c["shown"]) != _norm_num(c["to"]))
    blocks = rp.blocks
    heads = [(int(t[1:]), x) for t, x in blocks if t[0] == "h" and t[1:].isdigit()]
    checks = []

    def add(cat, label, status, detail):
        checks.append({"cat": cat, "label": label, "status": status, "detail": detail})

    # answer first
    h1_idx = next((i for i, (t, _) in enumerate(blocks) if t == "h1"), -1)
    intro, before = None, 0
    for i, (t, x) in enumerate(blocks):
        if i <= h1_idx:
            continue
        if t == "p" and _words(x) >= 8:
            intro = x
            break
        before += _words(x)
    cat = "Answer first"
    if intro is None:
        add(cat, "Clear opening paragraph", "fail", "No opening paragraph was found after the main heading. AI tools look for a short, direct answer near the top.")
    else:
        iw = _words(intro)
        if GREETING_RE.match(intro):
            add(cat, "Clear opening paragraph", "warn", f"The opening starts with a greeting (\"{intro[:60]}…\"). Start with a direct answer: who you are, what you do, where, and for whom.")
        elif before > 150:
            add(cat, "Clear opening paragraph", "warn", f"The first real paragraph comes after about {before} words of other content. Put a short summary right under the main heading.")
        elif iw < 15:
            add(cat, "Clear opening paragraph", "warn", f"The opening paragraph is very short ({iw} words). Two or three sentences that answer the page's main question work best.")
        elif iw > 90:
            add(cat, "Clear opening paragraph", "warn", f"The opening paragraph is long ({iw} words). Put the key answer in the first two sentences.")
        else:
            add(cat, "Clear opening paragraph", "pass", f"The page opens with a {iw}-word paragraph right after the main heading.")

    # structure
    cat = "Structure"
    h1s = [x for lvl, x in heads if lvl == 1]
    if not h1s:
        add(cat, "One main heading", "fail", "No main heading (H1) was found.")
    elif len(h1s) > 1:
        add(cat, "One main heading", "warn", f"The page has {len(h1s)} main headings (H1). Use one that states the page's topic.")
    else:
        add(cat, "One main heading", "pass", f"Main heading: “{h1s[0][:90]}”.")
    skips, prev = [], 0
    for lvl, x in heads:
        if prev and lvl > prev + 1:
            skips.append((prev, lvl, x))
        prev = lvl
    if skips:
        a, b, x = skips[0]
        add(cat, "Heading levels in order", "warn", f"Heading levels skip, for example H{a} followed by H{b} (“{x[:60]}”). Keep levels in order so the outline makes sense.")
    elif heads:
        add(cat, "Heading levels in order", "pass", "Heading levels follow a clear order.")
    h2 = sum(1 for lvl, _ in heads if lvl == 2)
    if (words > 400 and h2 < 2) or (h2 == 0 and words >= 200):
        add(cat, "Section headings", "warn", f"{'No' if not h2 else 'Only ' + str(h2)} section heading{'' if h2 == 1 else 's'} (H2) for {words:,} words. Clear sections help AI find the right part to quote.")
    else:
        add(cat, "Section headings", "pass", f"{h2} section headings (H2).")
    qh = sum(1 for _, x in heads if x.rstrip().endswith("?"))
    if qh:
        add(cat, "Question-style headings", "pass", f"{plural_py(qh, 'heading')} phrased as {'a question' if qh == 1 else 'questions'}.")
    elif words > 400:
        add(cat, "Question-style headings", "warn", "No headings are phrased as questions. Questions customers ask (for example “How much does … cost?”) help AI match the page to them.")
    paras = [x for t, x in blocks if t == "p" and _words(x) >= 8]
    if paras:
        longest = max(_words(x) for x in paras)
        if longest > 150:
            add(cat, "Readable paragraphs", "warn", f"The longest paragraph has {longest} words. Split long paragraphs so each one makes a single point.")
        else:
            add(cat, "Readable paragraphs", "pass", f"Paragraphs are a readable length (longest: {longest} words).")
    if rp.lists + rp.tables:
        add(cat, "Lists or tables", "pass", f"{plural_py(rp.lists, 'list')} and {plural_py(rp.tables, 'table')} in the content.")
    elif words > 400:
        add(cat, "Lists or tables", "warn", "No lists or tables in the content. Steps, features and comparisons are easier for AI to extract as lists or tables.")

    # facts
    cat = "Facts"
    if words < 150:
        add(cat, "Enough readable text", "fail", f"Only {words} words are readable without JavaScript.")
    elif words < 300:
        add(cat, "Enough readable text", "warn", f"{words} words are readable without JavaScript. Thin pages give AI little to quote.")
    else:
        add(cat, "Enough readable text", "pass", f"{words:,} words are readable without JavaScript.")
    if counters:
        if bad_counters:
            add(cat, "Animated counters", "fail", f"{bad_counters} of {len(counters)} animated counters show their starting value to AI crawlers.")
        else:
            add(cat, "Animated counters", "pass", f"All {len(counters)} animated counters show their final value.")
    nums = len(NUMBER_RE.findall(text))
    if nums >= 3:
        add(cat, "Concrete numbers", "pass", f"{nums} numbers in the text, such as years, counts or prices.")
    else:
        add(cat, "Concrete numbers", "warn", "Few concrete numbers. Specific facts such as years in business, projects completed or price ranges are what AI tends to quote.")
    m = PHONE_RE.search(text)
    if m and sum(ch.isdigit() for ch in m.group(0)) >= 9:
        add(cat, "Contact details as text", "pass", f"A phone number appears as text ({m.group(0).strip()[:24]}).")
    else:
        add(cat, "Contact details as text", "warn", "No phone number in the page text. Keep contact details in plain text, not only in images or buttons.")

    # trust and freshness
    cat = "Trust and freshness"
    js = json.dumps(s.get("jsonld") or [])
    if rp.times or '"dateModified"' in js or '"datePublished"' in js or DATE_TEXT_RE.search(text):
        add(cat, "Publish or update date", "pass", "The page shows when it was published or updated.")
    else:
        add(cat, "Publish or update date", "warn", "No publish or update date was found. A visible “Last updated” date and dateModified in structured data signal freshness.")
    articleish = any(t in ARTICLE_TYPES for e in s.get("items", []) for t in e["types"]) or bool(re.search(r"/(blog|news|insights|articles?|posts?)/", url))
    if rp.author_meta or rp.rel_author or '"author"' in js or BYLINE_RE.search(text):
        add(cat, "Author shown", "pass", "The page names an author.")
    elif articleish:
        add(cat, "Author shown", "warn", "No author was found on this article. A named author with a short bio builds trust.")
    if s.get("items"):
        errs = (s.get("counts") or {}).get("error", 0)
        add(cat, "Structured data", "warn" if errs else "pass",
            f"Types: {', '.join(s['types'][:6])}." + (f" {plural_py(errs, 'error')} found; see the Structured data page." if errs else ""))
    else:
        add(cat, "Structured data", "warn", "No structured data. Organization or LocalBusiness schema confirms who you are.")

    # basics
    cat = "Basics"
    tl = len(title)
    if not tl:
        add(cat, "Page title", "fail", "The page has no title.")
    elif tl > 65:
        add(cat, "Page title", "warn", f"The title is {tl} characters. Around 60 or fewer avoids it being cut off.")
    elif tl < 15:
        add(cat, "Page title", "warn", f"The title is only {tl} characters. Describe the page's topic and your brand.")
    else:
        add(cat, "Page title", "pass", f"“{title[:80]}”")
    desc = pe.meta.get("description", "")
    add(cat, "Meta description", "pass" if desc else "warn", desc[:160] if desc else "No meta description. A one-sentence summary helps search and AI tools describe the page.")
    robots = (pe.meta.get("robots", "") + " " + (r["headers"].get("x-robots-tag", "") or "")).lower()
    if "noindex" in robots:
        add(cat, "Can be indexed", "fail", "The page is marked noindex, so search engines and AI search may leave it out.")
    else:
        add(cat, "Can be indexed", "pass", "The page can be indexed.")
    if pe.images:
        add(cat, "Image descriptions", "warn" if pe.images_no_alt else "pass",
            f"{pe.images_no_alt} of {plural_py(pe.images, 'image')} {'has' if pe.images_no_alt == 1 else 'have'} no alt text." if pe.images_no_alt
            else ("The image has alt text." if pe.images == 1 else f"All {pe.images} images have alt text."))
    host = _bare_host(url)
    internal = len({h for h in (urllib.parse.urljoin(r["final_url"] or url, x) for x in HREF_RE.findall(html)) if _bare_host(h) == host})
    add(cat, "Internal links", "pass" if internal >= 3 else "warn",
        f"{internal} links to other pages on the site." if internal >= 3 else "Few links to other pages on the site. Linking related pages helps crawlers find and connect your content.")

    counts = {k: sum(1 for c in checks if c["status"] == k) for k in ("pass", "warn", "fail")}
    score = round(100 * (counts["pass"] + 0.5 * counts["warn"]) / max(1, len(checks)))
    result = {"url": url, "final_url": r["final_url"], "score": score, "counts": counts, "checks": checks,
              "schema": {"items": len(s.get("items") or []), "types": (s.get("types") or [])[:6],
                         "errors": (s.get("counts") or {}).get("error", 0)},
              "counters": {"total": len(counters), "bad": bad_counters},
              "outline": [{"level": lvl, "text": x[:160]} for lvl, x in heads[:80]], "intro": intro or "", "words": words,
              "title": title, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    return result, 200, text


def plural_py(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def review_readiness(url):
    res, code, _ = _readiness(url)
    return res, code


def readiness_ai(p):
    key = openrouter_key(None)
    if not key:
        return {"error": "No OpenRouter API key. Save one in Settings first."}, 400
    model = str(p.get("model") or "").strip()[:200]
    if not model:
        return {"error": "Pick a model."}, 400
    res, code, text = _readiness(str(p.get("url", "")))
    if code != 200:
        return res, code
    outline = "\n".join(f"{'  ' * (o['level'] - 1)}H{o['level']}: {o['text']}" for o in res["outline"][:40]) or "(no headings)"
    problems = "\n".join(f"- {c['label']}: {c['detail']}" for c in res["checks"] if c["status"] != "pass") or "- none"
    system = "You are an editor who makes web pages easy for AI assistants to understand and quote. Reply with JSON only."
    user = (f"Page: {res['final_url'] or res['url']}\nTitle: {res['title']}\nOutline:\n{outline}\n\nProblems found:\n{problems}\n\n"
            f"Page text as AI crawlers read it (excerpt):\n<<<\n{text[:9000]}\n>>>\n\n"
            "Using ONLY facts found in the page text (never invent numbers, names, prices or claims; write [placeholder] "
            "where a needed fact is missing), return JSON:\n"
            '{"main_question": "the main question this page should answer", '
            '"bluf": "a 2-3 sentence opening that answers it directly", '
            '"suggestions": [{"issue": "short name", "fix": "specific change, with rewritten text where useful"}], '
            '"faq": [{"q": "a question a customer would ask", "a": "a short answer taken from the page"}]}\n'
            "Give 3 to 6 suggestions and 3 to 5 FAQ items.")
    txt, err = or_chat(key, model, system, user, temperature=0.4, timeout=180)
    if err:
        return {"error": err}, 502
    j = extract_json(txt)
    if not isinstance(j, dict):
        return {"error": "The model did not return usable suggestions. Try again or pick another model."}, 502
    sug = [{"issue": str(x.get("issue", ""))[:120], "fix": str(x.get("fix", ""))[:1200]}
           for x in (j.get("suggestions") or []) if isinstance(x, dict) and (x.get("issue") or x.get("fix"))][:8]
    faq = [{"q": str(x.get("q", ""))[:300], "a": str(x.get("a", ""))[:800]}
           for x in (j.get("faq") or []) if isinstance(x, dict) and x.get("q")][:6]
    return {"main_question": str(j.get("main_question", ""))[:300], "bluf": str(j.get("bluf", ""))[:1200],
            "suggestions": sug, "faq": faq, "model": model}, 200


# ---------------------------------------------------------------- competitor comparison
CMP_BOTS = [("GPTBot", "gptbot"), ("ClaudeBot", "claudebot"), ("PerplexityBot", "perplexitybot"),
            ("OAI-SearchBot", "oai-search"), ("Googlebot", "googlebot")]
CMP_ID_RE = re.compile(r"^[a-f0-9]{12}$")


def _cmp_dir():
    return os.path.join(DATA_DIR, "compares")


def _can_fetch(rp, token, url):
    try:
        return rp.can_fetch(token, url)
    except Exception:
        return True


def compare_site(url):
    out = {"url": url, "host": _bare_host(url), "error": ""}
    res, code, _text = _readiness(url)
    if code != 200:
        out["error"] = res.get("error", "Could not review the page.")
        return out
    chk = {c["label"]: c for c in res["checks"]}
    out.update({"final_url": res["final_url"], "title": res["title"], "score": res["score"], "words": res["words"],
                "schema": res.get("schema") or {"items": 0, "types": [], "errors": 0},
                "counters": res.get("counters") or {"total": 0, "bad": 0},
                "opening": (chk.get("Clear opening paragraph") or {}).get("status", "fail"),
                "dated": (chk.get("Publish or update date") or {}).get("status") == "pass",
                "fails": res["counts"]["fail"], "warns": res["counts"]["warn"]})
    rp, robots = load_robots(url)
    out["robots_blocked"] = [label for label, _bid in CMP_BOTS if not _can_fetch(rp, label, url)]

    def live(bot):
        label, bid = bot
        r = http_get(url, BOT_BY_ID[bid][3])
        return label, bool(r["error"] or _is_challenge(r["html"]) or (r["status"] or 0) >= 400), r["ms"]

    with ThreadPoolExecutor(max_workers=3) as ex:
        lives = list(ex.map(live, CMP_BOTS[:3]))
    out["server_blocked"] = [label for label, bad, _ms in lives if bad]
    out["ms"] = lives[0][2]
    parts = urllib.parse.urlsplit(url)
    r = http_get(f"{parts.scheme}://{parts.netloc}/llms.txt", CHROME_UA, timeout=12, accept="text/plain,*/*")
    body = r["html"] or ""
    out["llms"] = bool(r["status"] == 200 and body.strip() and "<html" not in body[:3000].lower())
    out["sitemap"] = bool(robots.get("text") and re.search(r"(?im)^\s*sitemap\s*:", robots["text"]))
    return out


def run_compare(p):
    try:
        mine = _normalize_url(str(p.get("site", "")))
    except BlockedURL as e:
        return {"error": f"Your site: {e}"}, 400
    comps = []
    raw = p.get("competitors") or []
    if isinstance(raw, str):
        raw = raw.split("\n")
    for c in [str(x).strip() for x in raw if str(x).strip()][:5]:
        try:
            u = _normalize_url(c)
        except BlockedURL as e:
            return {"error": f"{c}: {e}"}, 400
        if _bare_host(u) != _bare_host(mine) and u not in comps:
            comps.append(u)
    if not comps:
        return {"error": "Add at least one competitor website that is different from yours."}, 400
    with ThreadPoolExecutor(max_workers=3) as ex:
        results = list(ex.map(compare_site, [mine] + comps))
    results[0]["you"] = True
    job = {"id": secrets.token_hex(6), "site": mine, "host": _bare_host(mine), "sites": results,
           "checked_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    if storage_writable():
        d = _cmp_dir()
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, job["id"] + ".json"), "w", encoding="utf-8") as f:
            json.dump(job, f)
        for old in _json_files_newest_first(d)[50:]:
            try:
                os.remove(old)
            except Exception:
                pass
    return job, 200


def list_compares():
    out = []
    for p in _json_files_newest_first(_cmp_dir())[:30]:
        try:
            with open(p, encoding="utf-8") as f:
                j = json.load(f)
            out.append({"id": j.get("id"), "site": j.get("site"), "host": j.get("host"),
                        "checked_at": j.get("checked_at"), "count": len(j.get("sites") or [])})
        except Exception:
            pass
    return {"runs": out}


def load_compare(cid):
    if not CMP_ID_RE.match(cid or ""):
        return None
    try:
        with open(os.path.join(_cmp_dir(), cid + ".json"), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------- client reports
REPORT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")
SCAN_LABELS = {"fetch": "Page could not be fetched", "blocked": "Bot challenge page instead of content", "http": "HTTP error",
               "robots": "Blocked by robots.txt", "counters": "Animated counters show their starting value",
               "noindex": "Marked noindex", "thin": "Little readable text without JavaScript", "title": "No page title",
               "description": "No meta description", "schema": "No structured data", "schema_errors": "Structured data errors",
               "redirect": "Redirects"}
STAT_TAG = {"pass": ("ok", "Good"), "warn": ("warn", "Improve"), "fail": ("bad", "Fix")}
CMP_ROWS = [("access", "AI crawlers allowed (of 5 main AI bots)"), ("score", "AI readiness score"),
            ("words", "Words readable without JavaScript"), ("opening", "Opening paragraph"), ("schema", "Structured data"),
            ("schemaErr", "Structured data errors"), ("counters", "Animated counters"), ("dated", "Shows a publish or update date"),
            ("llms", "llms.txt"), ("sitemap", "Sitemap listed in robots.txt")]
REPORT_CSS = """
:root{--ink:#18212b;--muted:#5e6b78;--line:#dce2e0;--soft:#f3f5f4;--accent:#0b7a6e;--ok:#17744a;--ok-bg:#e2f3e9;--bad:#b4261e;--bad-bg:#fbe7e5;--warn:#8a5800;--warn-bg:#fcf0d5;--na:#eef1f1}
*{box-sizing:border-box}
body{margin:0;background:#e9edec;color:var(--ink);font:14px/1.55 "Instrument Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
.bar{position:sticky;top:0;display:flex;justify-content:flex-end;gap:10px;padding:10px 16px;background:#13202b}
.bar a{color:#fff;background:var(--accent);text-decoration:none;font-weight:600;padding:7px 14px;border-radius:7px;font-size:14px}
.doc{max-width:900px;margin:24px auto;background:#fff;padding:44px 52px;border-radius:10px}
header.cover{border-bottom:2px solid var(--ink);padding-bottom:22px;margin-bottom:26px}
.agency{font-size:13px;color:var(--muted);font-weight:600;letter-spacing:.01em}
h1{font-size:30px;line-height:1.15;margin:14px 0 6px;letter-spacing:-.02em}
.client{font-size:18px;font-weight:600}
.meta{color:var(--muted);font-size:13.5px;margin-top:4px}
h2{font-size:19px;margin:34px 0 8px;letter-spacing:-.01em;break-after:avoid}
h3{font-size:15px;margin:20px 0 6px;break-after:avoid}
p{margin:6px 0}
.muted{color:var(--muted);font-size:13px}
.notes{background:var(--soft);border-left:3px solid var(--accent);padding:12px 16px;border-radius:0 8px 8px 0;margin-bottom:6px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:12px}
.tile{border:1px solid var(--line);border-radius:9px;padding:12px 14px;break-inside:avoid;border-top-width:4px}
.tile.ok{border-top-color:var(--ok)} .tile.warn{border-top-color:#d69e2e} .tile.bad{border-top-color:var(--bad)} .tile.na{border-top-color:var(--line)}
.tl{font-size:12px;color:var(--muted);font-weight:600} .tv{font-size:22px;font-weight:700;margin:2px 0;letter-spacing:-.01em} .ts{font-size:12px;color:var(--muted)}
ol.find{padding-left:20px;margin:8px 0} ol.find li{margin:0 0 9px;break-inside:avoid} ol.find .muted{display:block}
table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0 4px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);background:var(--soft)}
tr{break-inside:avoid}
td.num{white-space:nowrap;font-variant-numeric:tabular-nums}
td.best{background:var(--ok-bg)} td.worst{background:var(--bad-bg)}
.tag{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11.5px;font-weight:700;white-space:nowrap;background:var(--na);color:var(--muted)}
.tag.ok{background:var(--ok-bg);color:var(--ok)} .tag.bad{background:var(--bad-bg);color:var(--bad)} .tag.warn{background:var(--warn-bg);color:var(--warn)}
.url{word-break:break-all}
footer{margin-top:36px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted);font-size:12px}
@page{size:A4;margin:14mm}
@media print{body{background:#fff}.bar{display:none}.doc{margin:0;padding:0;max-width:none;border-radius:0}h2{margin-top:26px}}
@media (max-width:700px){.doc{margin:0;padding:24px 18px;border-radius:0}}
"""


def _reports_dir():
    return os.path.join(DATA_DIR, "reports")


def _latest_json(d, match):
    for p in _json_files_newest_first(d):
        try:
            with open(p, encoding="utf-8") as f:
                j = json.load(f)
        except Exception:
            continue
        if match(j):
            return j
    return None


def _pct(n, t):
    return f"{round(100 * n / t)}%" if t else "–"


def _tag(tone, text):
    return f'<span class="tag {tone}">{_he(text)}</span>'


def _tile(label, value, sub, tone):
    return (f'<div class="tile {tone}"><div class="tl">{_he(label)}</div><div class="tv">{_he(value)}</div>'
            f'<div class="ts">{_he(sub)}</div></div>')


def _cmp_metrics(s):
    if s.get("error"):
        return None
    blocked = sorted(set((s.get("robots_blocked") or []) + (s.get("server_blocked") or [])))
    sc = s.get("schema") or {"items": 0, "types": [], "errors": 0}
    ct = s.get("counters") or {"total": 0, "bad": 0}
    op = s.get("opening")
    return {
        "access": (f"{5 - len(blocked)} of 5" + (f" (blocked: {', '.join(blocked)})" if blocked else ""), 5 - len(blocked)),
        "score": (f"{s.get('score', 0)}/100", s.get("score", 0)),
        "words": (f"{s.get('words', 0):,}", s.get("words", 0)),
        "opening": ({"pass": "Direct answer", "warn": "Needs work"}.get(op, "Missing"), {"pass": 2, "warn": 1}.get(op, 0)),
        "schema": ((f"{sc['items']}: " + ", ".join(sc.get("types") or [])) if sc.get("items") else "None", 1 if sc.get("items") else 0),
        "schemaErr": (str(sc.get("errors", 0)) if sc.get("items") else "–", -sc.get("errors", 0) if sc.get("items") else None),
        "counters": ((f"{ct['bad']} of {ct['total']} stuck at start" if ct.get("bad") else f"{ct['total']} show final values")
                     if ct.get("total") else "None", -ct.get("bad", 0) if ct.get("total") else None),
        "dated": ("Yes" if s.get("dated") else "No", 1 if s.get("dated") else 0),
        "llms": ("Yes" if s.get("llms") else "No", 1 if s.get("llms") else 0),
        "sitemap": ("Yes" if s.get("sitemap") else "No", 1 if s.get("sitemap") else 0),
    }


def _cite_insights(j):
    ok = [r for r in (j.get("results") or []) if not r.get("error") and r.get("brand")]
    comps = (ok[0].get("competitors") or []) if ok else []
    sov = [(f"{j.get('domain', '')} (you)", sum(1 for r in ok if r["brand"].get("mentioned")), sum(1 for r in ok if r["brand"].get("cited")))]
    for i, c in enumerate(comps):
        xs = [(r.get("competitors") or [])[i] for r in ok if len(r.get("competitors") or []) > i]
        sov.append((c.get("label", ""), sum(1 for x in xs if x.get("mentioned")), sum(1 for x in xs if x.get("cited"))))
    dom = j.get("domain", "")
    comp_domains = [c.get("domain") for c in comps if c.get("domain")]

    def whose(h):
        if _domain_match(h, dom):
            return "You"
        return "Competitor" if any(_domain_match(h, d) for d in comp_domains) else "Third party"

    hosts, opps = {}, {}
    for r in ok:
        for h in set(r.get("hosts") or []):
            hosts[h] = hosts.get(h, 0) + 1
            if not r["brand"].get("cited") and whose(h) == "Third party":
                opps[h] = opps.get(h, 0) + 1
    top = [(h, n, whose(h)) for h, n in sorted(hosts.items(), key=lambda x: -x[1])[:8]]
    return len(ok), sov, top, sorted(opps.items(), key=lambda x: -x[1])[:5]


def render_report(proj, agency, contact, notes, access, ready, scan, cite, cmpj, created_label):
    findings, tiles, sections = [], [], []

    # AI readiness of the homepage (fresh)
    if ready:
        sc = ready["score"]
        tiles.append(_tile("AI readiness (homepage)", f"{sc}/100", f"{ready['counts']['fail']} to fix, {ready['counts']['warn']} to improve",
                           "ok" if sc >= 75 else "warn" if sc >= 50 else "bad"))
        order = {"fail": 0, "warn": 1, "pass": 2}
        for c in sorted([c for c in ready["checks"] if c["status"] != "pass"], key=lambda c: order[c["status"]])[:6]:
            findings.append(("high" if c["status"] == "fail" else "medium", f"Homepage: {c['label']}", c["detail"]))
        rows = "".join(f'<tr><td style="width:80px">{_tag(*STAT_TAG[c["status"]])}</td><td><strong>{_he(c["label"])}</strong>'
                       f'<div class="muted">{_he(c["detail"])}</div></td></tr>'
                       for c in sorted(ready["checks"], key=lambda c: order[c["status"]]))
        sections.append(("AI readiness of the homepage",
                         '<p class="muted">How easy the homepage is for AI tools to understand and quote, as GPTBot receives it.</p>'
                         f'<table><tbody>{rows}</tbody></table>'))
    else:
        tiles.append(_tile("AI readiness (homepage)", "–", "Could not be checked", "na"))

    # AI crawler access (fresh)
    if access:
        agents = access["agents"]
        ok_n = sum(1 for a in agents if a["verdict"] == "allowed")
        tiles.append(_tile("AI crawler access", f"{ok_n} of {len(agents)}", "AI crawlers allowed",
                           "ok" if ok_n == len(agents) else "warn" if ok_n >= len(agents) - 2 else "bad"))
        for a in agents:
            if a["verdict"] != "allowed":
                findings.append(("high", f"{a['token']} ({a['company']}) cannot read the site",
                                 "Blocked by robots.txt." if a["verdict"] == "blocked_robots" else "Blocked by the server or firewall (error or challenge page)."))
        verdict = {"allowed": ("ok", "Allowed"), "blocked_robots": ("bad", "Blocked by robots.txt"), "blocked_server": ("bad", "Blocked by server")}
        rows = "".join(f'<tr><td><strong>{_he(a["token"])}</strong></td><td>{_he(a["company"])}</td><td class="muted">{_he(a["purpose"])}</td>'
                       f'<td>{_tag(*verdict.get(a["verdict"], ("na", a["verdict"])))}</td></tr>' for a in agents)
        sections.append(("AI crawler access",
                         '<p class="muted">Whether each AI crawler may read the site (robots.txt) and actually gets the page from the server.</p>'
                         f'<table><thead><tr><th>Crawler</th><th>Company</th><th>Used for</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table>'))
    else:
        tiles.append(_tile("AI crawler access", "–", "Could not be checked", "na"))

    # Site scan (latest saved)
    if scan:
        res = scan.get("results") or []
        t = len(res)
        e = sum(1 for r in res if r.get("level") == "error")
        w = sum(1 for r in res if r.get("level") == "warning")
        tiles.append(_tile("Site scan", f"{e} · {w}", f"pages with errors · warnings, of {t} checked",
                           "ok" if not e and not w else "warn" if not e else "bad"))
        codes = {}
        for r in res:
            for i in r.get("issues") or []:
                c = codes.setdefault(i["code"], [i["level"], 0])
                c[1] += 1
        ranked = sorted(codes.items(), key=lambda x: ({"error": 0, "warning": 1}.get(x[1][0], 2), -x[1][1]))
        for code, (lvl, n) in ranked:
            if lvl in ("error", "warning") and code != "redirect":
                findings.append(("high" if lvl == "error" else "medium", f"Site scan: {SCAN_LABELS.get(code, code)}", f"Found on {n} of {t} pages."))
        lvl_tag = {"error": ("bad", "Error"), "warning": ("warn", "Warning"), "info": ("na", "Info")}
        irows = "".join(f'<tr><td>{_tag(*lvl_tag.get(lvl, ("na", lvl)))}</td><td>{_he(SCAN_LABELS.get(code, code))}</td><td class="num">{n} of {t}</td></tr>'
                        for code, (lvl, n) in ranked) or '<tr><td colspan="3">No issues found.</td></tr>'
        worst = [r for r in res if r.get("level") == "error"][:10]
        prow = "".join(f'<tr><td class="url">{_he(r["url"])}</td><td class="muted">{_he("; ".join(i["msg"] for i in r.get("issues") or [] if i["level"] == "error"))}</td></tr>' for r in worst)
        sections.append(("Site scan",
                         f'<p class="muted">{t} pages checked as {_he(scan.get("bot_label") or "an AI crawler")} on {_he((scan.get("started_at") or "")[:10])}.</p>'
                         f'<h3>Issues by type</h3><table><thead><tr><th>Level</th><th>Issue</th><th>Pages</th></tr></thead><tbody>{irows}</tbody></table>'
                         + (f'<h3>Pages with errors</h3><table><thead><tr><th>Page</th><th>Errors</th></tr></thead><tbody>{prow}</tbody></table>' if worst else "")))
    else:
        tiles.append(_tile("Site scan", "–", "No scan yet", "na"))

    # AI citations (latest saved)
    if cite:
        summ = cite.get("summary") or cite_summary(cite)
        n, sov, top, opps = _cite_insights(cite)
        score = summ.get("score")
        tiles.append(_tile("AI visibility", f"{score}/100" if score is not None else "–", f"cited in {_pct(summ['cited'], summ['answers'])} of AI answers",
                           "na" if score is None else "ok" if score >= 50 else "warn" if score >= 20 else "bad"))
        if summ["answers"] and summ["cited"] / summ["answers"] < 0.3:
            findings.append(("high", "AI assistants rarely cite the site", f"Cited as a source in {summ['cited']} of {summ['answers']} answers to customer questions."))
        for h, c in opps[:3]:
            findings.append(("medium", f"Get listed or mentioned on {h}", f"AI assistants cited it in {c} answers where the site was not cited."))
        qs = "".join(f"<li>{_he(q)}</li>" for q in cite.get("prompts") or [])
        srows = "".join(f'<tr><td><strong>{_he(lab)}</strong></td><td class="num">{m} ({_pct(m, n)})</td><td class="num">{c} ({_pct(c, n)})</td></tr>' for lab, m, c in sov)
        trows = "".join(f'<tr><td>{_he(h)}</td><td class="num">{c} of {n}</td><td>{_he(w)}</td></tr>' for h, c, w in top)
        sections.append(("Visibility in AI answers",
                         f'<p class="muted">{n} answers from {len(cite.get("models") or [])} AI models with live web search, tested on {_he((cite.get("started_at") or "")[:10])}. '
                         'Visibility score: up to 40 points when an answer names the business, up to 40 when it cites the site, up to 20 for positive wording.</p>'
                         f'<h3>Questions tested</h3><ul>{qs}</ul>'
                         f'<h3>Share of voice</h3><table><thead><tr><th>Brand</th><th>Named in answers</th><th>Cited as a source</th></tr></thead><tbody>{srows}</tbody></table>'
                         + (f'<h3>Sources AI cited most</h3><table><thead><tr><th>Website</th><th>Cited in</th><th>Whose site</th></tr></thead><tbody>{trows}</tbody></table>' if top else "")))
    else:
        tiles.append(_tile("AI visibility", "–", "No citation test yet", "na"))

    # Competitors (latest saved)
    if cmpj:
        sites = cmpj.get("sites") or []
        ms = [_cmp_metrics(s) for s in sites]
        mine, behind = ms[0] if ms else None, []
        if mine:
            for key, label in CMP_ROWS:
                if mine[key][1] is None:
                    continue
                better = [(s["host"], m[key][0]) for s, m in zip(sites[1:], ms[1:]) if m and m[key][1] is not None and m[key][1] > mine[key][1]]
                if better:
                    behind.append((label, mine[key][0], better))
        tiles.append(_tile("Competitors", f"Behind on {len(behind)}", f"of {len(CMP_ROWS)} checks, vs {len(sites) - 1} competitors",
                           "ok" if not behind else "warn" if len(behind) <= 3 else "bad"))
        for label, yours, better in behind[:4]:
            findings.append(("medium", f"Competitors ahead: {label}", f"This site: {yours}. " + "; ".join(f"{h}: {v}" for h, v in better) + "."))
        head = "".join(f'<th>{"This site: " if s.get("you") else ""}{_he(s["host"])}</th>' for s in sites)
        body = ""
        for key, label in CMP_ROWS:
            vals = [m[key][1] for m in ms if m and m[key][1] is not None]
            best, worst = (max(vals), min(vals)) if vals else (None, None)
            cells = ""
            for m in ms:
                if not m:
                    cells += "<td>–</td>"
                    continue
                v = m[key][1]
                cls = "" if v is None or best == worst else "best" if v == best else "worst" if v == worst else ""
                cells += f'<td class="{cls}">{_he(m[key][0])}</td>'
            body += f'<tr><td class="muted">{_he(label)}</td>{cells}</tr>'
        sections.append(("Competitor comparison",
                         f'<p class="muted">Checked on {_he((cmpj.get("checked_at") or "")[:10])}. Best result per row in green, weakest in red.</p>'
                         f'<div style="overflow-x:auto"><table><thead><tr><th>Check</th>{head}</tr></thead><tbody>{body}</tbody></table></div>'))
    else:
        tiles.append(_tile("Competitors", "–", "No comparison yet", "na"))

    findings.sort(key=lambda f: 0 if f[0] == "high" else 1)
    find_html = ("".join(f'<li>{_tag("bad" if sev == "high" else "warn", "High" if sev == "high" else "Medium")} <strong>{_he(t)}</strong>'
                         f'<span class="muted">{_he(d)}</span></li>' for sev, t, d in findings[:14])
                 or "<li>No significant issues found. Keep monitoring as the site and AI tools change.</li>")
    notes_html = "".join(f"<p>{_he(p)}</p>" for p in re.split(r"\n\s*\n", notes.strip()) if p.strip())
    by = _he(agency) + (f" · {_he(contact)}" if contact else "")
    body = "".join(f"<h2>{_he(t)}</h2>{h}" for t, h in sections)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>AI visibility report: {_he(proj['name'])}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;600;700&display=swap">
<style>{REPORT_CSS}</style></head><body>
<div class="bar"><a href="__PDF__">Download PDF</a></div>
<div class="doc">
<header class="cover"><div class="agency">{by}</div><h1>AI visibility report</h1>
<div class="client">{_he(proj['name'])}</div><div class="meta">{_he(proj['site'])} · {_he(created_label)}</div></header>
{f'<div class="notes">{notes_html}</div>' if notes_html else ''}
<h2 style="margin-top:8px">At a glance</h2><div class="tiles">{''.join(tiles)}</div>
<h2>Key findings</h2><ol class="find">{find_html}</ol>
{body}
<footer>How this report was made: crawler access and homepage readiness were checked when the report was created; the site scan,
AI answer test and competitor comparison are the most recent saved runs, on the dates shown. Checks are made from the agency's server
using each crawler's user agent, so they show what crawlers receive today, not what AI tools have stored from earlier visits.
AI answers vary from run to run.</footer>
</div></body></html>"""


def build_report(p):
    if not storage_writable():
        return {"error": f"The server cannot write to {DATA_DIR}, so reports can't be saved."}, 500
    proj = next((x for x in load_projects() if x.get("id") == str(p.get("project_id", ""))), None)
    if not proj:
        return {"error": "Choose a client project first."}, 400
    site = proj["site"]
    st = load_settings()
    agency = (st.get("agency_name") or "").strip() or "Prepared for you"
    contact = (st.get("agency_contact") or "").strip()
    notes = str(p.get("notes") or "")[:4000]
    with ThreadPoolExecutor(max_workers=2) as ex:
        fa = ex.submit(check_access, site)
        fr = ex.submit(_readiness, site)
        access, acode = fa.result()
        rres, rcode, _ = fr.result()
    key, host = _site_key(site), _bare_host(site)
    scan = _latest_json(_scan_dir(), lambda j: _site_key(j.get("url", "")) == key and j.get("results"))
    cite = _latest_json(_cite_dir(), lambda j: _clean_domain(j.get("domain", "")) == host and j.get("results"))
    cmpj = _latest_json(_cmp_dir(), lambda j: _bare_host(j.get("site", "")) == host)
    tm = time.localtime()
    label = f"{tm.tm_mday} {time.strftime('%B %Y', tm)}"
    html_doc = render_report(proj, agency, contact, notes, access if acode == 200 else None, rres if rcode == 200 else None,
                             scan, cite, cmpj, label)
    rid = re.sub(r"[^A-Za-z0-9_-]", "", secrets.token_urlsafe(24))[:32]
    html_doc = html_doc.replace("__PDF__", f"/r/{rid}.pdf")
    d = _reports_dir()
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, rid + ".html"), "w", encoding="utf-8") as f:
        f.write(html_doc)
    meta = {"id": rid, "project_id": proj["id"], "name": proj["name"], "site": site, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "has": {"scan": bool(scan), "cite": bool(cite), "compare": bool(cmpj), "access": acode == 200, "readiness": rcode == 200}}
    with open(os.path.join(d, rid + ".json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    return meta, 200


def list_reports(project_id):
    out = []
    for p in _json_files_newest_first(_reports_dir()):
        try:
            with open(p, encoding="utf-8") as f:
                j = json.load(f)
        except Exception:
            continue
        if not project_id or j.get("project_id") == project_id:
            out.append(j)
    return {"reports": out[:50]}


def delete_report(rid):
    if REPORT_ID_RE.match(rid or ""):
        for ext in (".html", ".json", ".pdf"):
            try:
                os.remove(os.path.join(_reports_dir(), rid + ext))
            except OSError:
                pass
    return {"ok": True}, 200


def report_pdf(rid):
    """Return PDF bytes for a saved report, rendering it with the headless browser the first time."""
    d = _reports_dir()
    src, out = os.path.join(d, rid + ".html"), os.path.join(d, rid + ".pdf")
    if os.path.exists(out) and os.path.getmtime(out) >= os.path.getmtime(src):
        with open(out, "rb") as f:
            return f.read(), None
    chrome = _chrome_path()
    if not chrome:
        return None, "The PDF engine is not installed on this server. Use your browser's Print, then Save as PDF."
    if not RENDER_LOCK.acquire(timeout=60):
        return None, "The server is busy rendering another page. Try again in a minute."
    tmp = tempfile.mkdtemp(prefix="abvc-pdf-")
    try:
        port = _ensure_proxy()
        tmp_pdf = os.path.join(tmp, "report.pdf")
        cmd = [chrome, "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run", "--disable-extensions",
               "--disable-background-networking", "--disable-crash-reporter", f"--user-data-dir={tmp}",
               f"--proxy-server=http://127.0.0.1:{port}", "--virtual-time-budget=4000",
               "--no-pdf-header-footer", "--print-to-pdf-no-header", f"--print-to-pdf={tmp_pdf}", "file://" + src]
        if "headless" not in os.path.basename(chrome):
            cmd.insert(1, "--headless=new")
        subprocess.run(cmd, capture_output=True, timeout=90, env=dict(os.environ, HOME=tmp))
        if not os.path.exists(tmp_pdf) or os.path.getsize(tmp_pdf) < 500:
            return None, "The PDF could not be created. Use your browser's Print, then Save as PDF."
        shutil.copyfile(tmp_pdf, out)
        with open(out, "rb") as f:
            return f.read(), None
    except subprocess.TimeoutExpired:
        return None, "Creating the PDF took too long. Use your browser's Print, then Save as PDF."
    finally:
        RENDER_LOCK.release()
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- email (SMTP)
EMAIL_RE = re.compile(r"^[^@\s,;<>]+@[^@\s,;<>]+\.[^@\s,;<>]+$")
SMTP_SECURITY = ("starttls", "ssl", "none")


def smtp_config():
    c = load_settings().get("smtp") or {}
    try:
        port = int(os.environ.get("SMTP_PORT") or c.get("port") or 587)
    except ValueError:
        port = 587
    sec = os.environ.get("SMTP_SECURITY") or c.get("security") or "starttls"
    return {"host": os.environ.get("SMTP_HOST") or c.get("host", ""), "port": port,
            "security": sec if sec in SMTP_SECURITY else "starttls",
            "user": os.environ.get("SMTP_USER") or c.get("user", ""),
            "password": os.environ.get("SMTP_PASSWORD") or c.get("password", ""),
            "from": os.environ.get("SMTP_FROM") or c.get("from", "")}


def smtp_public():
    c = smtp_config()
    return {"host": c["host"], "port": c["port"], "security": c["security"], "user": c["user"], "from": c["from"],
            "password_set": bool(c["password"]), "ready": bool(c["host"] and c["from"])}


def parse_emails(v):
    return [x for x in re.split(r"[,;\s]+", str(v or "")) if x and EMAIL_RE.match(x)][:5]


def send_email(to_list, subject, text, html_body=None):
    c = smtp_config()
    if not (c["host"] and c["from"]):
        return "Email is not set up. Add your mail server in Settings."
    if not to_list:
        return "No valid recipient addresses."
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = c["from"]
    msg["To"] = ", ".join(to_list)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()
    msg.set_content(text)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    try:
        ctx = ssl.create_default_context()
        if c["security"] == "ssl":
            srv = smtplib.SMTP_SSL(c["host"], c["port"], timeout=25, context=ctx)
        else:
            srv = smtplib.SMTP(c["host"], c["port"], timeout=25)
            srv.ehlo()
            if c["security"] == "starttls":
                srv.starttls(context=ctx)
                srv.ehlo()
        with srv:
            if c["user"]:
                srv.login(c["user"], c["password"])
            srv.send_message(msg)
        return None
    except smtplib.SMTPAuthenticationError:
        return "The mail server rejected the username or password. For Gmail or Google Workspace, use an app password."
    except (smtplib.SMTPException, OSError, ValueError) as e:
        return f"Could not send email: {type(e).__name__}: {e}"[:300]


# ---------------------------------------------------------------- monitoring
MON_RUNNING = {}
MON_FREQ = {"daily": 86400, "weekly": 7 * 86400}
MON_ID_RE = re.compile(r"^[a-f0-9]{10}$")
SCAN_ALERT_CODES = {"fetch", "blocked", "http", "robots", "counters", "noindex"}


def _mon_file(pid):
    return os.path.join(DATA_DIR, "monitor", pid + ".json")


def _mon_state(pid):
    try:
        with open(_mon_file(pid), encoding="utf-8") as f:
            st = json.load(f)
        return st if isinstance(st, dict) else {}
    except Exception:
        return {}


def _mon_write(pid, st):
    os.makedirs(os.path.dirname(_mon_file(pid)), exist_ok=True)
    tmp = _mon_file(pid) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(tmp, _mon_file(pid))


def monitor_defaults(m):
    m = dict(m or {})
    m.setdefault("enabled", False)
    m.setdefault("frequency", "weekly")
    m.setdefault("scan", True)
    m.setdefault("scan_limit", 50)
    m.setdefault("cite", False)
    m.setdefault("emails", "")
    m.setdefault("notify", "changes")
    m.setdefault("next_run", 0)
    m.setdefault("last_run", "")
    m.setdefault("last_summary", "")
    return m


def _update_project_monitor(pid, fn):
    with _PROJ_LOCK:
        items = load_projects()
        for it in items:
            if it.get("id") == pid:
                it["monitor"] = fn(monitor_defaults(it.get("monitor")))
                _write_projects(items)
                return it
    return None


def save_monitor(p, app_url):
    pid = str(p.get("project_id", ""))
    if not storage_writable():
        return {"error": f"The server cannot write to {DATA_DIR}."}, 500
    if not any(x.get("id") == pid for x in load_projects()):
        return {"error": "Choose a client project first."}, 400
    emails = parse_emails(p.get("emails"))
    enabled = bool(p.get("enabled"))
    if enabled and not emails:
        return {"error": "Add at least one email address for alerts."}, 400
    freq = p.get("frequency") if p.get("frequency") in MON_FREQ else "weekly"
    try:
        limit = int(p.get("scan_limit", 50))
    except (TypeError, ValueError):
        limit = 50

    def upd(m):
        start = enabled and (not m["enabled"] or m["frequency"] != freq or not m["next_run"])
        m.update({"enabled": enabled, "frequency": freq, "scan": bool(p.get("scan", True)), "scan_limit": max(10, min(100, limit)),
                  "cite": bool(p.get("cite")), "emails": ", ".join(emails), "notify": "always" if p.get("notify") == "always" else "changes"})
        if start:
            m["next_run"] = time.time() + 120
        if not enabled:
            m["next_run"] = 0
        return m

    proj = _update_project_monitor(pid, upd)
    if app_url:
        save_settings({"app_url": app_url})
    return {"monitor": proj["monitor"], "smtp_ready": smtp_public()["ready"]}, 200


def _wait_job(store_dict, job_id, loader, timeout):
    end = time.time() + timeout
    while time.time() < end:
        j = store_dict.get(job_id)
        if not j or j.get("status") != "running":
            return loader(job_id)
        time.sleep(4)
    return None


def _start_when_free(start_fn, timeout=1800):
    end = time.time() + timeout
    while True:
        res, code = start_fn()
        if code == 200 or code != 409 or time.time() > end:
            return res, code
        time.sleep(30)


def diff_snapshots(prev, cur):
    out = []

    def add(kind, text):
        out.append({"kind": kind, "text": text})

    if not prev:
        return [{"kind": "info", "text": "First check: this sets the starting point for future comparisons."}]
    pa, ca = prev.get("access") or {}, cur.get("access") or {}
    for tok, v in ca.items():
        pv = pa.get(tok)
        if pv == "allowed" and v != "allowed":
            add("worse", f"{tok} is now blocked ({'by robots.txt' if v == 'blocked_robots' else 'by the server or firewall'}).")
        elif pv and pv != "allowed" and v == "allowed":
            add("better", f"{tok} can read the site again.")
    if "readiness" in cur and "readiness" in prev:
        d = cur["readiness"] - prev["readiness"]
        if d <= -10:
            add("worse", f"Homepage AI readiness dropped from {prev['readiness']} to {cur['readiness']}.")
        elif d >= 10:
            add("better", f"Homepage AI readiness rose from {prev['readiness']} to {cur['readiness']}.")
        for f in sorted(set(cur.get("readiness_fails") or []) - set(prev.get("readiness_fails") or [])):
            add("worse", f"New homepage problem: {f}.")
    ps, cs = prev.get("scan"), cur.get("scan")
    if ps and cs:
        comparable = abs(cs["pages"] - ps["pages"]) <= max(2, 0.2 * ps["pages"])
        if not comparable:
            add("info", f"The scan checked {plural_py(cs['pages'], 'page')} this time and {ps['pages']} last time, so the totals are not compared.")
        elif cs["errors"] > ps["errors"]:
            add("worse", f"Pages with errors went from {ps['errors']} to {cs['errors']} (of {cs['pages']} checked).")
        elif cs["errors"] < ps["errors"]:
            add("better", f"Pages with errors went down from {ps['errors']} to {cs['errors']}.")
        for code, n in sorted(cs["codes"].items()):
            pn = ps["codes"].get(code, 0)
            if code in SCAN_ALERT_CODES and n > pn:
                add("worse", f"{SCAN_LABELS.get(code, code)}: now on {plural_py(n, 'page')}, was {pn}.")
        new_pages = [u for u in cs["error_pages"] if u not in set(ps["error_pages"])]
        if new_pages:
            add("worse", "New pages with errors: " + ", ".join(new_pages[:5]) + (f" and {len(new_pages) - 5} more" if len(new_pages) > 5 else "") + ".")
    pc, cc = prev.get("cite"), cur.get("cite")
    if pc and cc and pc.get("score") is not None and cc.get("score") is not None:
        d = cc["score"] - pc["score"]
        if d <= -10:
            add("worse", f"AI visibility score dropped from {pc['score']} to {cc['score']}.")
        elif d >= 10:
            add("better", f"AI visibility score rose from {pc['score']} to {cc['score']}.")
    if not out:
        add("same", "No changes since the last check.")
    return out


def _summary_line(snap):
    parts = []
    if snap.get("access"):
        a = snap["access"]
        parts.append(f"{sum(1 for v in a.values() if v == 'allowed')} of {len(a)} AI crawlers allowed")
    if "readiness" in snap:
        parts.append(f"homepage readiness {snap['readiness']}/100")
    if snap.get("scan"):
        s = snap["scan"]
        parts.append(f"{s['errors']} of {s['pages']} pages with errors")
    if snap.get("cite") and snap["cite"].get("score") is not None:
        parts.append(f"AI visibility {snap['cite']['score']}/100")
    return "; ".join(parts)


def _monitor_email(proj, run, app_url):
    worse = [c["text"] for c in run["changes"] if c["kind"] == "worse"]
    better = [c["text"] for c in run["changes"] if c["kind"] == "better"]
    subject = (f"[AI monitor] {proj['name']}: {len(worse)} problem{'s' if len(worse) != 1 else ''} found" if worse
               else f"[AI monitor] {proj['name']}: no new problems")
    lines = [f"AI visibility check for {proj['name']} ({proj['site']}), {run['at']}.", ""]
    if worse:
        lines += ["What got worse:"] + [f"  - {x}" for x in worse] + [""]
    if better:
        lines += ["What improved:"] + [f"  - {x}" for x in better] + [""]
    if not worse and not better:
        lines += [run["changes"][0]["text"] if run["changes"] else "No changes.", ""]
    if run["errors"]:
        lines += ["Notes:"] + [f"  - {x}" for x in run["errors"]] + [""]
    lines += [f"Current state: {run['summary']}." if run["summary"] else ""]
    if app_url:
        lines += ["", f"Open the tool: {app_url.rstrip('/')}/#/monitor"]
    li = lambda xs, color: "".join(f'<li style="margin:4px 0;color:{color}">{_he(x)}</li>' for x in xs)
    html_body = (f'<div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;font-size:14px;color:#18212b;max-width:620px">'
                 f'<h2 style="font-size:18px;margin:0 0 4px">{_he(proj["name"])}</h2>'
                 f'<div style="color:#5e6b78;margin-bottom:14px">{_he(proj["site"])} · checked {_he(run["at"])}</div>'
                 + (f'<h3 style="font-size:15px;margin:12px 0 4px">What got worse</h3><ul>{li(worse, "#b4261e")}</ul>' if worse else "")
                 + (f'<h3 style="font-size:15px;margin:12px 0 4px">What improved</h3><ul>{li(better, "#17744a")}</ul>' if better else "")
                 + ("" if worse or better else f'<p>{_he(run["changes"][0]["text"] if run["changes"] else "No changes.")}</p>')
                 + (f'<h3 style="font-size:15px;margin:12px 0 4px">Notes</h3><ul>{li(run["errors"], "#5e6b78")}</ul>' if run["errors"] else "")
                 + (f'<p style="color:#5e6b78">Current state: {_he(run["summary"])}.</p>' if run["summary"] else "")
                 + (f'<p><a href="{_he(app_url.rstrip("/"))}/#/monitor" style="color:#0b7a6e">Open the tool</a></p>' if app_url else "")
                 + "</div>")
    return subject, "\n".join(lines), html_body


def run_monitor(pid):
    proj = next((x for x in load_projects() if x.get("id") == pid), None)
    if not proj:
        MON_RUNNING.pop(pid, None)
        return
    m = monitor_defaults(proj.get("monitor"))
    site = proj["site"]
    t0 = time.time()
    snap, errors = {}, []
    try:
        MON_RUNNING[pid] = "Checking AI crawler access"
        access, code = check_access(site)
        if code == 200:
            snap["access"] = {a["token"]: a["verdict"] for a in access["agents"]}
        else:
            errors.append(f"Crawler access could not be checked: {access.get('error', '')}")
        MON_RUNNING[pid] = "Reviewing the homepage"
        ready, rcode, _ = _readiness(site)
        if rcode == 200:
            snap["readiness"] = ready["score"]
            snap["readiness_fails"] = [c["label"] for c in ready["checks"] if c["status"] == "fail"]
        else:
            errors.append(f"The homepage could not be reviewed: {ready.get('error', '')}")
        if m["scan"]:
            MON_RUNNING[pid] = "Scanning the site"
            res, code = _start_when_free(lambda: start_scan(site, "gptbot", m["scan_limit"]))
            if code == 200:
                job = _wait_job(SCANS, res["id"], load_scan, 2700)
                if job and job.get("results"):
                    rows = job["results"]
                    codes = {}
                    for r in rows:
                        for c in {i["code"] for i in r.get("issues") or []}:
                            codes[c] = codes.get(c, 0) + 1
                    snap["scan"] = {"id": res["id"], "pages": len(rows), "errors": sum(1 for r in rows if r.get("level") == "error"),
                                    "warnings": sum(1 for r in rows if r.get("level") == "warning"), "codes": codes,
                                    "error_pages": [r["url"] for r in rows if r.get("level") == "error"][:100]}
                else:
                    errors.append("The site scan did not finish" + (f": {job.get('error')}" if job and job.get("error") else "."))
            else:
                errors.append(f"The site scan could not start: {res.get('error', '')}")
        if m["cite"]:
            models = (load_settings().get("models") or [])[:3]
            prompts = proj.get("questions") or []
            if not openrouter_key(None) or not models or not prompts or "." not in _bare_host(site):
                errors.append("The citation test was skipped: it needs an OpenRouter key and models in Settings, and questions on the project.")
            else:
                MON_RUNNING[pid] = "Running the citation test"
                loc = [x.strip() for x in (proj.get("location") or "").split(",")]
                payload = {"domain": _bare_host(site), "brands": proj.get("brands") or [], "competitors": proj.get("competitors") or [],
                           "prompts": prompts, "models": models, "engine": "auto", "sentiment": True,
                           "location": {"city": loc[0], "region": loc[1] if len(loc) > 1 else "", "country": loc[2] if len(loc) > 2 else ""} if loc[0] else None}
                res, code = _start_when_free(lambda: start_cite(payload))
                if code == 200:
                    job = _wait_job(CITES, res["id"], load_cite, 2700)
                    if job and job.get("results"):
                        snap["cite"] = dict(cite_summary(job), id=res["id"])
                    else:
                        errors.append("The citation test did not finish.")
                else:
                    errors.append(f"The citation test could not start: {res.get('error', '')}")
    except Exception as e:
        errors.append(f"Monitoring stopped early: {type(e).__name__}: {e}")
    st = _mon_state(pid)
    prev = st.get("snapshot") or {}
    changes = diff_snapshots(prev, snap)
    merged = dict(prev)
    merged.update(snap)
    run = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "changes": changes, "errors": errors, "summary": _summary_line(merged),
           "secs": int(time.time() - t0), "email": ""}
    worse = [c for c in changes if c["kind"] == "worse"]
    recipients = parse_emails(m["emails"])
    if recipients and (m["notify"] == "always" or worse):
        subject, text, html_body = _monitor_email(proj, run, load_settings().get("app_url", ""))
        err = send_email(recipients, subject, text, html_body)
        run["email"] = f"Not sent: {err}" if err else f"Sent to {', '.join(recipients)}"
    elif recipients:
        run["email"] = "Not sent: nothing got worse"
    st["snapshot"] = merged
    st["runs"] = ([run] + (st.get("runs") or []))[:50]
    _mon_write(pid, st)
    label = (f"{len(worse)} problem{'s' if len(worse) != 1 else ''}" if worse
             else "First check" if changes and changes[0]["kind"] == "info" else "No new problems")

    def upd(mm):
        mm["last_run"] = run["at"]
        mm["last_summary"] = label
        if mm["enabled"]:
            mm["next_run"] = time.time() + MON_FREQ.get(mm["frequency"], MON_FREQ["weekly"])
        return mm

    _update_project_monitor(pid, upd)
    MON_RUNNING.pop(pid, None)


def _run_monitor_safe(pid):
    try:
        run_monitor(pid)
    except Exception as e:
        print(f"Monitoring error for {pid}: {type(e).__name__}: {e}", flush=True)
    finally:
        MON_RUNNING.pop(pid, None)


def _monitor_loop():
    time.sleep(20)
    while True:
        try:
            now = time.time()
            for proj in load_projects():
                m = proj.get("monitor") or {}
                if m.get("enabled") and m.get("next_run", 0) and m["next_run"] <= now and proj["id"] not in MON_RUNNING:
                    MON_RUNNING[proj["id"]] = "Starting"
                    _run_monitor_safe(proj["id"])
        except Exception as e:
            print(f"Monitoring loop error: {type(e).__name__}: {e}", flush=True)
        time.sleep(60)


def monitor_overview():
    out = []
    for p in load_projects():
        m = monitor_defaults(p.get("monitor"))
        out.append({"id": p["id"], "name": p["name"], "site": p["site"], "monitor": m, "running": MON_RUNNING.get(p["id"], "")})
    return {"projects": out, "smtp": smtp_public(), "now": time.time()}


def run_monitor_now(pid):
    if not any(x.get("id") == pid for x in load_projects()):
        return {"error": "Choose a client project first."}, 400
    if pid in MON_RUNNING:
        return {"error": "A check is already running for this client."}, 409
    MON_RUNNING[pid] = "Starting"
    threading.Thread(target=_run_monitor_safe, args=(pid,), daemon=True).start()
    return {"ok": True}, 200


# ---------------------------------------------------------------- client portal
PORTAL_COOKIE = "abvc_portal"
PORTAL_ID_RE = re.compile(r"^[a-f0-9]{12}$")
_PORTAL_LOCK = threading.Lock()
PORTAL_CSS = REPORT_CSS + """
.top{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 22px;background:#13202b;color:#e8eef2;font-size:14px}
.top a{color:#e8eef2}
.top strong{font-weight:650}
.trend{display:flex;align-items:flex-end;gap:8px;height:120px;border-bottom:1px solid var(--line);margin-top:12px}
.trend div{flex:1 0 22px;max-width:52px;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:100%}
.trend span{display:block;width:100%;background:var(--accent);border-radius:3px 3px 0 0}
.trend em{font-style:normal;font-size:11.5px;color:var(--muted);margin-bottom:2px}
.dates{display:flex;justify-content:space-between;font-size:11.5px;color:var(--muted);margin-top:4px}
ul.runs{list-style:none;padding:0;margin:8px 0}
ul.runs li{border-bottom:1px solid var(--line);padding:10px 0}
ul.runs ul{margin:6px 0 0;padding-left:0;list-style:none} ul.runs ul li{border:0;padding:3px 0}
.preview{background:#fcf0d5;color:#8a5800;text-align:center;padding:8px;font-size:13px;font-weight:600}
"""


def _portal_file():
    return os.path.join(DATA_DIR, "portal_users.json")


def load_portal_users():
    try:
        with open(_portal_file(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _write_portal_users(items):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = _portal_file() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items, f)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    os.replace(tmp, _portal_file())


def _hash_pw(pw, salt_hex):
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt_hex), 200000).hex()


def _new_password():
    return "-".join(secrets.token_urlsafe(5).replace("_", "x").replace("-", "y") for _ in range(3))


def _portal_public(u):
    return {k: u.get(k) for k in ("id", "project_id", "name", "email", "created_at", "last_login", "disabled")}


def portal_users_for(project_id):
    return {"users": [_portal_public(u) for u in load_portal_users() if u.get("project_id") == project_id]}


def _set_password(u, pw):
    u["salt"] = secrets.token_hex(16)
    u["hash"] = _hash_pw(pw, u["salt"])


def add_portal_user(p):
    if not storage_writable():
        return {"error": f"The server cannot write to {DATA_DIR}."}, 500
    pid = str(p.get("project_id", ""))
    if not any(x.get("id") == pid for x in load_projects()):
        return {"error": "Choose a client project first."}, 400
    email = str(p.get("email", "")).strip().lower()[:200]
    name = str(p.get("name", "")).strip()[:80] or email
    if not EMAIL_RE.match(email):
        return {"error": "Enter a valid email address."}, 400
    pw = _new_password()
    with _PORTAL_LOCK:
        users = load_portal_users()
        if any(u.get("email") == email for u in users):
            return {"error": "That email already has a portal login."}, 409
        u = {"id": secrets.token_hex(6), "project_id": pid, "name": name, "email": email,
             "created_at": time.strftime("%Y-%m-%d %H:%M:%S"), "last_login": "", "disabled": False}
        _set_password(u, pw)
        users.append(u)
        _write_portal_users(users)
    return {"user": _portal_public(u), "password": pw}, 200


def update_portal_user(uid, action, value=None):
    if not PORTAL_ID_RE.match(uid or ""):
        return {"error": "Login not found."}, 404
    with _PORTAL_LOCK:
        users = load_portal_users()
        u = next((x for x in users if x.get("id") == uid), None)
        if not u:
            return {"error": "Login not found."}, 404
        out = {"ok": True}
        if action == "reset":
            pw = _new_password()
            _set_password(u, pw)
            out = {"user": _portal_public(u), "password": pw}
        elif action == "disable":
            u["disabled"] = bool(value)
        elif action == "delete":
            users = [x for x in users if x.get("id") != uid]
        _write_portal_users(users)
    return out, 200


def _portal_secret():
    base = os.environ.get("SESSION_SECRET") or APP_PASSWORD or "local"
    return hashlib.sha256(("abvc-portal|" + base).encode()).digest()


def make_portal_session(u):
    exp = str(int(time.time()) + SESSION_DAYS * 86400)
    sig = hmac.new(_portal_secret(), f"{u['id']}.{exp}.{u['hash'][:16]}".encode(), hashlib.sha256).hexdigest()
    return f"{u['id']}.{exp}.{sig}"


def portal_user_from_token(token):
    try:
        uid, exp, sig = token.split(".", 2)
        if int(exp) < time.time() or not PORTAL_ID_RE.match(uid):
            return None
        u = next((x for x in load_portal_users() if x.get("id") == uid), None)
        if not u or u.get("disabled"):
            return None
        good = hmac.new(_portal_secret(), f"{uid}.{exp}.{u['hash'][:16]}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        if not any(p.get("id") == u.get("project_id") for p in load_projects()):
            return None
        return u
    except Exception:
        return None


def portal_login(email, pw):
    email = (email or "").strip().lower()
    u = next((x for x in load_portal_users() if x.get("email") == email and not x.get("disabled")), None)
    if not u or not hmac.compare_digest(_hash_pw(pw or "", u["salt"]), u["hash"]):
        return None
    if not any(p.get("id") == u.get("project_id") for p in load_projects()):
        return None
    with _PORTAL_LOCK:
        users = load_portal_users()
        for x in users:
            if x.get("id") == u["id"]:
                x["last_login"] = time.strftime("%Y-%m-%d %H:%M:%S")
        _write_portal_users(users)
    return u


def render_portal(proj, viewer, preview=False):
    host, key = _bare_host(proj["site"]), _site_key(proj["site"])
    st = load_settings()
    agency = (st.get("agency_name") or "").strip()
    contact = (st.get("agency_contact") or "").strip()
    cites = []
    for path in _json_files_newest_first(_cite_dir()):
        try:
            with open(path, encoding="utf-8") as f:
                j = json.load(f)
        except Exception:
            continue
        if _clean_domain(j.get("domain", "")) == host and j.get("results"):
            cites.append(j)
            if len(cites) >= 12:
                break
    scan = _latest_json(_scan_dir(), lambda j: _site_key(j.get("url", "")) == key and j.get("results"))
    cmpj = _latest_json(_cmp_dir(), lambda j: _bare_host(j.get("site", "")) == host)
    mon = _mon_state(proj["id"])
    snap = mon.get("snapshot") or {}
    runs = (mon.get("runs") or [])[:15]
    reports = list_reports(proj["id"])["reports"][:20]

    tiles = []
    if cites:
        s0 = cites[0].get("summary") or cite_summary(cites[0])
        sub = f"cited in {_pct(s0['cited'], s0['answers'])} of AI answers"
        if len(cites) > 1:
            s1 = cites[1].get("summary") or cite_summary(cites[1])
            if s0.get("score") is not None and s1.get("score") is not None:
                d = s0["score"] - s1["score"]
                sub = f"{'+' if d > 0 else ''}{d} since {(cites[1].get('started_at') or '')[:10]}"
        sc = s0.get("score")
        tiles.append(_tile("AI visibility", f"{sc}/100" if sc is not None else "–", sub,
                           "na" if sc is None else "ok" if sc >= 50 else "warn" if sc >= 20 else "bad"))
    else:
        tiles.append(_tile("AI visibility", "–", "Not tested yet", "na"))
    if "readiness" in snap:
        r = snap["readiness"]
        tiles.append(_tile("Homepage AI readiness", f"{r}/100", "from the latest check", "ok" if r >= 75 else "warn" if r >= 50 else "bad"))
    else:
        tiles.append(_tile("Homepage AI readiness", "–", "Not checked yet", "na"))
    if snap.get("access"):
        a = snap["access"]
        ok_n = sum(1 for v in a.values() if v == "allowed")
        tiles.append(_tile("AI crawler access", f"{ok_n} of {len(a)}", "AI crawlers can read the site",
                           "ok" if ok_n == len(a) else "warn" if ok_n >= len(a) - 2 else "bad"))
    else:
        tiles.append(_tile("AI crawler access", "–", "Not checked yet", "na"))
    if scan:
        res = scan.get("results") or []
        e = sum(1 for x in res if x.get("level") == "error")
        w = sum(1 for x in res if x.get("level") == "warning")
        tiles.append(_tile("Site scan", f"{e} · {w}", f"pages with errors · warnings, of {len(res)}, {(scan.get('started_at') or '')[:10]}",
                           "ok" if not e and not w else "warn" if not e else "bad"))
    else:
        tiles.append(_tile("Site scan", "–", "Not scanned yet", "na"))
    if cmpj:
        sites = cmpj.get("sites") or []
        ms = [_cmp_metrics(s) for s in sites]
        behind = 0
        if ms and ms[0]:
            for k, _label in CMP_ROWS:
                if ms[0][k][1] is None:
                    continue
                if any(m and m[k][1] is not None and m[k][1] > ms[0][k][1] for m in ms[1:]):
                    behind += 1
        tiles.append(_tile("Against competitors", f"Behind on {behind}", f"of {len(CMP_ROWS)} checks, {(cmpj.get('checked_at') or '')[:10]}",
                           "ok" if not behind else "warn" if behind <= 3 else "bad"))

    scored = [(c.get("started_at") or "", (c.get("summary") or cite_summary(c)).get("score")) for c in reversed(cites)]
    scored = [(d, s) for d, s in scored if s is not None]
    trend = ""
    if len(scored) >= 2:
        bars = "".join(f'<div title="{_he(d[:10])}: {s}"><em>{s}</em><span style="height:{max(3, s)}%"></span></div>' for d, s in scored)
        trend = (f'<h2>AI visibility over time</h2><p class="muted">Visibility score from each test of the questions customers ask AI assistants.</p>'
                 f'<div class="trend">{bars}</div><div class="dates"><span>{_he(scored[0][0][:10])}</span><span>{_he(scored[-1][0][:10])}</span></div>')

    if reports:
        rows = "".join(f'<tr><td class="num">{_he(r["created_at"][:10])}</td><td><a href="/r/{_he(r["id"])}" target="_blank" rel="noopener">Open report</a></td>'
                       f'<td><a href="/r/{_he(r["id"])}.pdf">Download PDF</a></td></tr>' for r in reports)
        reports_html = f'<table><thead><tr><th>Date</th><th></th><th></th></tr></thead><tbody>{rows}</tbody></table>'
    else:
        reports_html = '<p class="muted">No reports yet.</p>'

    kinds = {"worse": ("bad", "Worse"), "better": ("ok", "Better"), "same": ("na", "Same"), "info": ("na", "Note")}
    if runs:
        items = ""
        for r in runs:
            worse = sum(1 for c in r.get("changes") or [] if c["kind"] == "worse")
            first = bool(r.get("changes")) and r["changes"][0]["text"].startswith("First check")
            head = _tag("bad" if worse else "na" if first else "ok", f"{worse} problem{'s' if worse != 1 else ''}" if worse else "Starting point" if first else "No new problems")
            lis = "".join(f'<li>{_tag(*kinds.get(c["kind"], ("na", c["kind"])))} {_he(c["text"])}</li>' for c in r.get("changes") or [])
            items += f'<li><strong>{_he(r["at"][:16])}</strong> {head}<div class="muted">{_he(r.get("summary") or "")}</div><ul>{lis}</ul></li>'
        runs_html = f'<ul class="runs">{items}</ul>'
    else:
        runs_html = '<p class="muted">Automatic checks have not run yet.</p>'

    by = _he(agency) + (f" · {_he(contact)}" if contact else "")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow"><title>{_he(proj['name'])}: AI visibility</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Instrument+Sans:wght@400;600;700&display=swap">
<style>{PORTAL_CSS}</style></head><body>
{'<div class="preview">Preview: this is what the client sees.</div>' if preview else ''}
<div class="top"><span><strong>{_he(agency or 'AI visibility')}</strong></span><span>{_he(viewer)}{'' if preview else ' · <a href="/portal/logout">Sign out</a>'}</span></div>
<div class="doc">
<header class="cover"><div class="agency">{by}</div><h1>AI visibility</h1>
<div class="client">{_he(proj['name'])}</div><div class="meta">{_he(proj['site'])}</div></header>
<h2 style="margin-top:8px">At a glance</h2><div class="tiles">{''.join(tiles)}</div>
{trend}
<h2>Reports</h2>{reports_html}
<h2>Monitoring history</h2><p class="muted">Each automatic check is compared with the one before it.</p>{runs_html}
<footer>Checks show what AI crawlers and assistants receive from the website at the time of each check. AI answers vary from run to run.
{(' Questions? Contact ' + _he(agency) + (' · ' + _he(contact) if contact else '') + '.') if agency else ''}</footer>
</div></body></html>"""


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
            "storage_ok": storage_writable(), "auth": bool(APP_PASSWORD),
            "agency_name": s.get("agency_name", ""), "agency_contact": s.get("agency_contact", ""),
            "smtp": smtp_public()}


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
        if path.startswith("/r/"):
            rid = path[3:]
            pdf = rid.endswith(".pdf")
            rid = rid[:-4] if pdf else rid
            src = os.path.join(_reports_dir(), rid + ".html")
            if not REPORT_ID_RE.match(rid) or not os.path.exists(src):
                return self._send(404, "Report not found", "text/plain; charset=utf-8")
            hdrs = {"X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "no-referrer"}
            if pdf:
                data, err = report_pdf(rid)
                if err:
                    return self._send(503, err, "text/plain; charset=utf-8", hdrs)
                try:
                    with open(os.path.join(_reports_dir(), rid + ".json"), encoding="utf-8") as f:
                        meta = json.load(f)
                    fname = re.sub(r"[^A-Za-z0-9.-]+", "-", f"AI-visibility-report-{meta.get('name', 'client')}-{meta.get('created_at', '')[:10]}") + ".pdf"
                except Exception:
                    fname = "AI-visibility-report.pdf"
                hdrs["Content-Disposition"] = f'attachment; filename="{fname}"'
                return self._send(200, data, "application/pdf", hdrs)
            with open(src, encoding="utf-8") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8", hdrs)
        if path in ("/portal", "/portal/"):
            hdrs = {"X-Robots-Tag": "noindex, nofollow", "Referrer-Policy": "same-origin"}
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            preview = (q.get("preview") or [""])[0]
            if preview and self._authorized():
                proj = next((x for x in load_projects() if x.get("id") == preview), None)
                if proj:
                    return self._send(200, render_portal(proj, "Preview", True), "text/html; charset=utf-8", hdrs)
            user = portal_user_from_token(self._cookie(PORTAL_COOKIE))
            proj = next((x for x in load_projects() if user and x.get("id") == user.get("project_id")), None)
            if not user or not proj:
                return self._redirect("/portal/login")
            return self._send(200, render_portal(proj, user.get("name") or user.get("email")), "text/html; charset=utf-8", hdrs)
        if path == "/portal/login":
            if portal_user_from_token(self._cookie(PORTAL_COOKIE)):
                return self._redirect("/portal")
            agency = _he((load_settings().get("agency_name") or "").strip() or "Client portal")
            page = read_web("portal_login.html").decode("utf-8").replace("__AGENCY__", agency)
            return self._send(200, page, "text/html; charset=utf-8", {"X-Robots-Tag": "noindex, nofollow"})
        if path == "/portal/logout":
            return self._redirect("/portal/login", f"{PORTAL_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
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
        elif path == "/api/portal/users":
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            self._json(portal_users_for((q.get("project") or [""])[0]))
        elif path == "/api/monitor":
            self._json(monitor_overview())
        elif path == "/api/monitor/runs":
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            pid = (q.get("project") or [""])[0]
            self._json({"runs": (_mon_state(pid).get("runs") or []) if MON_ID_RE.match(pid) else [], "running": MON_RUNNING.get(pid, "")})
        elif path == "/api/reports":
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            self._json(list_reports((q.get("project") or [""])[0]))
        elif path == "/api/compare/list":
            self._json(list_compares())
        elif path == "/api/compare/get":
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            job = load_compare((q.get("id") or [""])[0])
            self._json(job if job else {"error": "Comparison not found."}, 200 if job else 404)
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

        if path == "/api/portal/login":
            ip = self._client_ip()
            if not login_allowed(ip):
                return self._json({"error": "Too many failed attempts. Try again in 15 minutes."}, 429)
            user = portal_login(str(payload.get("email", "")), str(payload.get("password", "")))
            if user:
                cookie = (f"{PORTAL_COOKIE}={make_portal_session(user)}; Path=/; Max-Age={SESSION_DAYS * 86400}; "
                          f"HttpOnly; SameSite=Lax" + ("; Secure" if self._secure() else ""))
                return self._json({"ok": True}, headers={"Set-Cookie": cookie})
            record_login_fail(ip)
            time.sleep(0.6)
            return self._json({"error": "Wrong email or password."}, 401)
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
            if path == "/api/portal/users/add":
                body, code = add_portal_user(payload)
                return self._json(body, code)
            if path == "/api/portal/users/reset":
                body, code = update_portal_user(str(payload.get("id", "")), "reset")
                return self._json(body, code)
            if path == "/api/portal/users/disable":
                body, code = update_portal_user(str(payload.get("id", "")), "disable", payload.get("disabled"))
                return self._json(body, code)
            if path == "/api/portal/users/delete":
                body, code = update_portal_user(str(payload.get("id", "")), "delete")
                return self._json(body, code)
            if path == "/api/monitor/save":
                host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or ""
                app_url = (f"{'https' if self._secure() else 'http'}://{host}" if host else "")
                body, code = save_monitor(payload, app_url)
                return self._json(body, code)
            if path == "/api/monitor/run":
                body, code = run_monitor_now(str(payload.get("project_id", "")))
                return self._json(body, code)
            if path == "/api/email/test":
                to = parse_emails(payload.get("to"))
                if not to:
                    return self._json({"error": "Enter a valid email address."}, 400)
                err = send_email(to, "Test email from AI Bot View Checker",
                                 "This is a test. Monitoring alerts will arrive like this.",
                                 "<p>This is a test. Monitoring alerts will arrive like this.</p>")
                return self._json({"error": err} if err else {"ok": True, "to": to}, 502 if err else 200)
            if path == "/api/report":
                body, code = build_report(payload)
                return self._json(body, code)
            if path == "/api/reports/delete":
                body, code = delete_report(str(payload.get("id", "")))
                return self._json(body, code)
            if path == "/api/compare":
                body, code = run_compare(payload)
                return self._json(body, code)
            if path == "/api/jsgap":
                body, code = js_gap(payload.get("url", ""))
                return self._json(body, code)
            if path == "/api/readiness":
                body, code = review_readiness(payload.get("url", ""))
                return self._json(body, code)
            if path == "/api/readiness/ai":
                body, code = readiness_ai(payload)
                return self._json(body, code)
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
                for k in ("agency_name", "agency_contact"):
                    if k in payload:
                        updates[k] = str(payload.get(k) or "").strip()[:160] or None
                if isinstance(payload.get("smtp"), dict):
                    sm, old = payload["smtp"], dict(load_settings().get("smtp") or {})
                    try:
                        port = max(1, min(65535, int(sm.get("port") or 587)))
                    except (TypeError, ValueError):
                        port = 587
                    new = {"host": str(sm.get("host") or "").strip()[:200], "port": port,
                           "security": sm.get("security") if sm.get("security") in SMTP_SECURITY else "starttls",
                           "user": str(sm.get("user") or "").strip()[:200], "from": str(sm.get("from") or "").strip()[:200],
                           "password": old.get("password", "")}
                    if sm.get("clear_password"):
                        new["password"] = ""
                    elif sm.get("password"):
                        new["password"] = str(sm["password"])[:300]
                    updates["smtp"] = new
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
    if storage_writable():
        threading.Thread(target=_monitor_loop, daemon=True).start()
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
