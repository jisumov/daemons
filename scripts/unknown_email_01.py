"""...you can fake it, infiltrate it, corporate it, little actor..."""

import email
import sys
import re
import os
import time
import quopri
import base64
import hashlib
import ipaddress
import requests
import tldextract
from urllib.parse import urlparse, quote
from email.parser import HeaderParser
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import timezone, date
from dotenv import load_dotenv

load_dotenv()

# --- Config -------------------------------------------------------------------

_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

URLSCAN_SUBMIT_THROTTLE = 2
URLSCAN_POLL_INTERVAL = 4
URLSCAN_MAX_WAIT = 60
HTTP_TIMEOUT = 30

VT_THROTTLE = 15
VT_MAX_LOOKUPS = 12
VT_REANALYZE = False
VT_REANALYZE_POLL = 4
VT_REANALYZE_MAX_WAIT = 45
VT_URL_SUBMIT_POLL = 4
VT_URL_SUBMIT_MAX_WAIT = 60

DEEPDIVE_MAX_AGE_DAYS = 365

_SKIPPED_ATTACHMENT_MAINTYPES = ('image', 'video', 'audio')
ABUSEIPDB_MAX_AGE_DAYS = 90
ABUSEIPDB_MAX_IPS = 15

_ALLOWED_API_HOSTS = (
    'urlscan.io', 'rdap.org', 'otx.alienvault.com',
    'www.virustotal.com', 'api.abuseipdb.com',
)

SCORE_SUSPICIOUS = 10
SCORE_MALICIOUS = 50
OTX_SUSPICIOUS_PULSES = 1
ABUSE_SUSPICIOUS = 25
ABUSE_MALICIOUS = 75

# Display label for every verdict — single source of truth for the tags.
_LABELS = {
    "Clean": "CLEAN ✅",
    "Suspicious": "SUSPICIOUS ⚠️",
    "NeedsReview": "NEEDS REVIEW 👀",
    "Malicious": "MALICIOUS 📛",
    "WhitelistSkip": "SKIPPED ⏭️",
    "Unknown": "UNKNOWN ❔",
}

_VERDICT_ORDER = {
    "WhitelistSkip": 0, "Clean": 1, "Suspicious": 2,
    "Malicious": 3, "Unknown": 4, "NeedsReview": 5,
}

SRC_OTX = "AlienVault OTX"
SRC_URLSCAN = "URLScan.io"
SRC_GSB = "Google Safe Browsing"
SRC_VT = "VirusTotal"
SRC_ABUSE = "AbuseIPDB"
SRC_RDAP = "RDAP"


# --- Safe transport -----------------------------------------------------------

def _safe_request(method, url, **kwargs):
    """Single choke point for ALL outbound traffic. Refuses non-API hosts so the
    tool can never be tricked into fetching a target URL directly."""
    host = (urlparse(url).hostname or '').lower()
    if not any(host == a or host.endswith('.' + a) for a in _ALLOWED_API_HOSTS):
        raise ValueError(f"Blocked request to non-API host: {url}")
    kwargs.setdefault('timeout', HTTP_TIMEOUT)
    return requests.request(method, url, **kwargs)


# --- Formatting helpers -------------------------------------------------------

def defang(text):
    if not text or text == "Not Found":
        return text
    text = re.sub(r'(?i)http', 'hxxp', text)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                  lambda m: m.group(0).replace('.', '[.]'), text)
    text = re.sub(r'(?<!\bheader)(?<!\bsmtp)(?<!\bcompauth)\.(?=[a-zA-Z]{2,}\b)', '[.]', text)
    return text


def decode_mime_words(header_string):
    if not header_string:
        return "Not Found"
    final = ""
    for word, encoding in decode_header(header_string):
        if isinstance(word, bytes):
            try:
                final += word.decode(encoding or "utf-8")
            except (LookupError, UnicodeDecodeError):
                final += word.decode("utf-8", errors="replace")
        else:
            final += word
    return " ".join(final.split())


def convert_to_utc(date_string):
    if not date_string or date_string == "Not Found":
        return "Not Found"
    try:
        dt = parsedate_to_datetime(date_string)
        if dt is None:
            return " ".join(date_string.split())
        return dt.astimezone(timezone.utc).strftime('%d-%m-%Y %H:%M:%S [UTC]')
    except (TypeError, ValueError):
        return " ".join(date_string.split())


def get_status_emoji(status):
    status = status.lower()
    return {
        'pass': f"{status} ✅", 'fail': f"{status} ❌", 'softfail': f"{status} ⚠️",
        'temperror': f"{status} 🛠️", 'permerror': f"{status} 🛠️",
        'none': f"{status} ❔", 'neutral': f"{status} ❔",
    }.get(status, status or 'unknown')


def parse_auth_results(auth_header):
    if not auth_header or auth_header == "Not Found":
        return "None ❔"
    lines = []
    for part in (p.strip() for p in auth_header.split(';') if p.strip()):
        m = re.search(r'^(spf|dkim|dmarc|compauth|arc)=([a-zA-Z0-9]+)', part, re.IGNORECASE)
        if m:
            proto, status = m.group(1).lower(), m.group(2).lower()
            part = re.sub(r'^(spf|dkim|dmarc|compauth|arc)=[a-zA-Z0-9]+',
                          f"{proto}={get_status_emoji(status)}", part, flags=re.IGNORECASE)
        lines.append("* " + part)
    return defang("\n".join(lines))


def extract_domain(email_address):
    if not email_address or email_address == "Not Found":
        return None
    _, addr = parseaddr(email_address)
    if '@' in addr:
        return addr.split('@')[-1].strip().lower() or None
    return None


def verdict_label(v):
    return _LABELS.get(v, _LABELS["Unknown"])


def _join(sources):
    """'A' / 'A and B' / 'A, B and C' — for the dynamic 'Flagged by ...' text."""
    sources = list(dict.fromkeys(s for s in sources if s))
    if len(sources) <= 1:
        return sources[0] if sources else ""
    return ", ".join(sources[:-1]) + " and " + sources[-1]


def _sort_records(records, verdict_key='verdict'):
    """Group by verdict (CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN, NEEDS REVIEW,
    then anything else), alphabetical within. One tuple sort, both layers."""
    return sorted(records,
                  key=lambda r: (_VERDICT_ORDER.get(r.get(verdict_key), 99),
                                 r['observable'].lower()))


# --- Observable filtering -----------------------------------------------------

def extract_host(observable):
    if not observable:
        return None
    if "://" in observable:
        host = urlparse(observable).hostname
    else:
        host = observable.split('/')[0].split(':')[0]
    return host.lower() if host else None


def _is_private_ip(host):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_reserved
            or ip.is_link_local or ip.is_multicast)


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


_HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$')


def registrable_domain(host):
    if not host:
        return None
    host = host.split(':')[0].strip().lower().rstrip('.')
    if _is_ip(host):
        return host
    ext = _TLD_EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return None


def is_scannable(observable):
    host = extract_host(observable)
    if not host or _is_private_ip(host):
        return False
    if _is_ip(host):
        return True
    if not _HOSTNAME_RE.match(host):
        return False
    return not host.endswith(('.local', '.internal', '.lan', '.localdomain', '.home.arpa'))


# --- RDAP creation date -------------------------------------------------------

def _normalize_date(value):
    if isinstance(value, list) and value:
        value = value[0]
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().split('T')[0]


_CREATION_KEYS = {
    'creationdate', 'createddate', 'created', 'createdate',
    'registered', 'registrationdate', 'registrationtime', 'domaincreated',
}
_DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def _search_creation_date(node):
    found = []

    def walk(n):
        if isinstance(n, dict):
            action = n.get('eventAction') or n.get('action')
            if isinstance(action, str) and action.lower() == 'registration':
                d = _normalize_date(n.get('eventDate') or n.get('date'))
                if d:
                    found.append(d)
            for key, val in n.items():
                if isinstance(key, str) and key.lower() in _CREATION_KEYS:
                    d = _normalize_date(val)
                    if d:
                        found.append(d)
                walk(val)
        elif isinstance(n, list):
            for item in n:
                walk(item)

    walk(node)
    dated = [d for d in found if _DATE_RE.match(d)]
    return min(dated) if dated else (found[0] if found else None)


def _iso_to_ddmmyyyy(iso):
    if not iso:
        return "Not Found"
    if _DATE_RE.match(iso):
        y, m, d = iso.split('-')
        return f"{d}-{m}-{y}"
    return iso


_RDAP_CACHE = {}


def rdap_creation_date(apex_domain):
    if not apex_domain or _is_ip(apex_domain):
        return None
    if apex_domain in _RDAP_CACHE:
        return _RDAP_CACHE[apex_domain]
    result = None
    try:
        resp = _safe_request('GET', f'https://rdap.org/domain/{quote(apex_domain)}',
                             headers={'Accept': 'application/rdap+json'}, allow_redirects=True)
        if resp.status_code == 200:
            result = _search_creation_date(resp.json())
    except (requests.RequestException, ValueError):
        result = None
    _RDAP_CACHE[apex_domain] = result
    return result


# --- URLScan.io ---------------------------------------------------------------

def _urlscan_headers():
    return {'API-Key': os.getenv('URLSCAN_DAEMON'), 'Content-Type': 'application/json'}


def submit_scan(observable, headers):
    try:
        resp = _safe_request('POST', 'https://urlscan.io/api/v1/scan/', headers=headers,
                             json={"url": observable, "visibility": "unlisted"})
    except (requests.RequestException, ValueError):
        return {"status": "error", "message": "submit error ❌"}
    if resp.status_code == 200:
        body = resp.json()
        return {"status": "submitted", "api": body.get('api'), "result": body.get('result')}
    if resp.status_code == 400:
        return {"status": "error", "message": "n/a (blocked from scanning or invalid target)"}
    return {"status": "error", "message": f"submit failed (HTTP {resp.status_code}) ❌"}


def poll_result(api_url, headers):
    if not api_url:
        return None, "no result API URL ❌"
    deadline = time.time() + URLSCAN_MAX_WAIT
    while time.time() < deadline:
        try:
            resp = _safe_request('GET', api_url, headers=headers)
        except (requests.RequestException, ValueError):
            return None, "network error ⚠️"
        if resp.status_code == 200:
            return resp.json(), None
        if resp.status_code == 404:          # not ready yet
            time.sleep(URLSCAN_POLL_INTERVAL)
            continue
        return None, f"result HTTP {resp.status_code} ❌"
    return None, "timeout ⏳ (scan still processing)"


def _gsb_malicious(res_data):
    gsb = (((res_data.get('meta') or {}).get('processors') or {}).get('gsb') or {}).get('data')
    if isinstance(gsb, dict):
        return bool(gsb.get('matches'))
    if isinstance(gsb, list):
        return len(gsb) > 0
    return False


def get_screenshot_url(res_data):
    task = res_data.get('task') or {}
    url = task.get('screenshotURL')
    if url:
        return url
    uuid = task.get('uuid')
    return f"https://urlscan.io/screenshots/{uuid}.png" if uuid else None


# --- AlienVault OTX -----------------------------------------------------------

def _otx_headers():
    return {'X-OTX-API-KEY': os.getenv('ALIENVAULT_DAEMON'), 'Accept': 'application/json'}


_OTX_CACHE = {}


def _otx_link(itype, indicator):
    kind = 'ip' if itype in ('IPv4', 'IPv6') else 'domain'
    return f"https://otx.alienvault.com/indicator/{kind}/{indicator}"


def otx_lookup(observable, headers):
    """Conservative OTX verdict: whitelisted -> Clean, pulses>=threshold ->
    Suspicious, otherwise Clean. Pulse membership alone is never Malicious."""
    host = extract_host(observable)
    if not host:
        return {"verdict": "Unknown", "pulses": None, "whitelisted": False, "link": None}
    if _is_ip(host):
        itype, indicator = ('IPv6' if ':' in host else 'IPv4'), host
    else:
        itype, indicator = 'domain', (registrable_domain(host) or host)

    key = (itype, indicator)
    if key in _OTX_CACHE:
        return _OTX_CACHE[key]

    out = {"verdict": "Unknown", "pulses": None, "whitelisted": False,
           "link": _otx_link(itype, indicator)}
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{itype}/{quote(indicator)}/general"
        resp = _safe_request('GET', url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            pulses = (data.get('pulse_info') or {}).get('count')
            whitelisted = bool(data.get('validation'))
            out["pulses"], out["whitelisted"] = pulses, whitelisted
            if not whitelisted and isinstance(pulses, int) and pulses >= OTX_SUSPICIOUS_PULSES:
                out["verdict"] = "Suspicious"
            else:
                out["verdict"] = "Clean"
    except (requests.RequestException, ValueError):
        pass
    _OTX_CACHE[key] = out
    return out


# --- VirusTotal ---------------------------------------------------------------

def _vt_headers():
    return {'x-apikey': os.getenv('VIRUSTOTAL_DAEMON'), 'Accept': 'application/json'}


def _vt_object_endpoint(observable):
    """Return (api_url, gui_url, kind) for a URL / IP / domain."""
    host = extract_host(observable)
    if observable.startswith(('http://', 'https://')):
        url_id = base64.urlsafe_b64encode(observable.encode()).decode().strip('=')
        return (f"https://www.virustotal.com/api/v3/urls/{url_id}",
                f"https://www.virustotal.com/gui/url/{url_id}", 'urls')
    if _is_ip(host):
        return (f"https://www.virustotal.com/api/v3/ip_addresses/{host}",
                f"https://www.virustotal.com/gui/ip-address/{host}", 'ip_addresses')
    dom = registrable_domain(host) or host
    return (f"https://www.virustotal.com/api/v3/domains/{dom}",
            f"https://www.virustotal.com/gui/domain/{dom}", 'domains')


def _vt_verdict_from_stats(stats):
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    total = sum(v for v in stats.values() if isinstance(v, int))
    if malicious > 0:
        verdict = "Malicious"
    elif suspicious > 0:
        verdict = "Suspicious"
    else:
        verdict = "Clean"
    return verdict, malicious, suspicious, total


def _poll_vt_analysis(analysis_id, headers, max_wait, poll):
    """Wait (bounded) for a VT analysis to finish. Returns True on completion."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = _safe_request(
                'GET', f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers)
            status = (((r.json() or {}).get('data') or {}).get('attributes') or {}).get('status')
            if status == 'completed':
                return True
        except (requests.RequestException, ValueError):
            return False
        time.sleep(poll)
    return False


def vt_reanalyze(observable, headers):
    """Ask VT to refresh an existing report and wait (bounded) for it to complete."""
    api = _vt_object_endpoint(observable)[0]
    try:
        resp = _safe_request('POST', f"{api}/analyse", headers=headers)
        analysis_id = ((resp.json() or {}).get('data') or {}).get('id')
    except (requests.RequestException, ValueError):
        return False
    if not analysis_id:
        return False
    return _poll_vt_analysis(analysis_id, headers,
                             VT_REANALYZE_MAX_WAIT, VT_REANALYZE_POLL)


def vt_submit_url(url, headers):
    """Submit a never-seen URL so an analysis is triggered, then wait (bounded)
    for it to finish. This mirrors what the VT website's URL-search box does
    — without this step a brand-new URL returns 404 forever via the read API."""
    try:
        sub_headers = {**headers, 'Content-Type': 'application/x-www-form-urlencoded'}
        resp = _safe_request('POST', 'https://www.virustotal.com/api/v3/urls',
                             headers=sub_headers, data={'url': url})
        if resp.status_code not in (200, 201):
            return False
        analysis_id = ((resp.json() or {}).get('data') or {}).get('id')
    except (requests.RequestException, ValueError):
        return False
    if not analysis_id:
        return False
    return _poll_vt_analysis(analysis_id, headers,
                             VT_URL_SUBMIT_MAX_WAIT, VT_URL_SUBMIT_POLL)


def vt_lookup(observable, headers, reanalyze=False, allow_submit=False):
    api, gui, kind = _vt_object_endpoint(observable)
    reanalyzed = vt_reanalyze(observable, headers) if reanalyze else False
    out = {"verdict": "Unknown", "malicious": 0, "suspicious": 0, "total": 0,
           "reputation": None, "gui": gui, "absent": False,
           "reanalyzed": reanalyzed, "submitted": False}
    try:
        resp = _safe_request('GET', api, headers=headers)
        # URL VT has never seen → submit it (same as searching it on the site),
        # wait for the analysis to finish, then re-fetch.
        if resp.status_code == 404 and kind == 'urls' and allow_submit:
            if vt_submit_url(observable, headers):
                out["submitted"] = True
                resp = _safe_request('GET', api, headers=headers)
        if resp.status_code == 200:
            data = resp.json().get('data') or {}
            attrs = data.get('attributes') or {}
            verdict, malicious, suspicious, total = _vt_verdict_from_stats(
                attrs.get('last_analysis_stats') or {})
            out.update(verdict=verdict, malicious=malicious, suspicious=suspicious,
                       total=total, reputation=attrs.get('reputation'))
            if kind == 'urls' and data.get('id'):
                out["gui"] = f"https://www.virustotal.com/gui/url/{data['id']}"
        elif resp.status_code == 404:
            out["absent"], out["verdict"] = True, "No VT record"
    except (requests.RequestException, ValueError):
        pass
    return out


def vt_file_lookup(sha256, headers):
    """Read-only VT report for a file hash. Never uploads."""
    out = {"verdict": "Unknown", "malicious": 0, "suspicious": 0, "total": 0,
           "gui": f"https://www.virustotal.com/gui/file/{sha256}", "absent": False}
    try:
        resp = _safe_request('GET', f"https://www.virustotal.com/api/v3/files/{sha256}",
                             headers=headers)
        if resp.status_code == 200:
            attrs = (resp.json().get('data') or {}).get('attributes') or {}
            verdict, malicious, suspicious, total = _vt_verdict_from_stats(
                attrs.get('last_analysis_stats') or {})
            out.update(verdict=verdict, malicious=malicious, suspicious=suspicious, total=total)
        elif resp.status_code == 404:
            out["absent"], out["verdict"] = True, "No VT record"
    except (requests.RequestException, ValueError):
        pass
    return out


# --- AbuseIPDB ----------------------------------------------------------------

def _abuseipdb_headers():
    return {'Key': os.getenv('ABUSEIPDB_DAEMON'), 'Accept': 'application/json'}


def abuseipdb_check(ip, headers):
    out = {"score": None, "reports": None, "country": None, "usage": None, "isp": None,
           "whitelisted": False, "verdict": "Unknown",
           "link": f"https://www.abuseipdb.com/check/{ip}"}
    try:
        resp = _safe_request('GET', 'https://api.abuseipdb.com/api/v2/check', headers=headers,
                             params={'ipAddress': ip, 'maxAgeInDays': ABUSEIPDB_MAX_AGE_DAYS})
        if resp.status_code == 200:
            data = (resp.json() or {}).get('data') or {}
            out.update(score=data.get('abuseConfidenceScore'), reports=data.get('totalReports'),
                       country=data.get('countryName'), usage=data.get('usageType'),
                       isp=data.get('isp'), whitelisted=bool(data.get('isWhitelisted')))
            score = out["score"] or 0
            if out["whitelisted"] or score < ABUSE_SUSPICIOUS:
                out["verdict"] = "Clean"
            elif score >= ABUSE_MALICIOUS:
                out["verdict"] = "Malicious"
            else:
                out["verdict"] = "Suspicious"
    except (requests.RequestException, ValueError):
        pass
    return out


# --- Per-source record builders -----------------------------------------------

def build_url_record(url, urlscan_outcome):
    """Verdict for a URL comes from URLScan.io (+ its GSB processor)."""
    res_data = None
    urlscan_field, gsb_field, note, verdict = "n/a", None, None, "Unknown"
    result_url = screenshot = None
    flagged_by, cleared_by = [], []

    if urlscan_outcome and urlscan_outcome["status"] == "submitted":
        result_url = urlscan_outcome.get("result")
        res_data, status_text = poll_result(urlscan_outcome.get("api"), _urlscan_headers())
        if res_data is None:
            urlscan_field = note = status_text
    elif urlscan_outcome:
        urlscan_field = note = urlscan_outcome["message"]

    if res_data is not None:
        verdicts = res_data.get('verdicts') or {}
        overall = verdicts.get('overall') or {}
        urlscan_v = verdicts.get('urlscan') or {}
        us_malicious = bool(overall.get('malicious') or urlscan_v.get('malicious'))
        score = overall.get('score', urlscan_v.get('score'))
        gsb_malicious = _gsb_malicious(res_data)
        screenshot = get_screenshot_url(res_data)
        urlscan_field = "malicious" if us_malicious else "clean"
        gsb_field = "malicious" if gsb_malicious else "clean"

        if us_malicious or gsb_malicious or (isinstance(score, (int, float)) and score >= SCORE_MALICIOUS):
            verdict = "Malicious"
        elif isinstance(score, (int, float)) and score >= SCORE_SUSPICIOUS:
            verdict = "Suspicious"
        else:
            verdict = "Clean"

        if us_malicious or (isinstance(score, (int, float)) and score >= SCORE_SUSPICIOUS):
            flagged_by.append(SRC_URLSCAN)
        else:
            cleared_by.append(SRC_URLSCAN)
        if gsb_malicious:
            flagged_by.append(SRC_GSB)
        else:
            cleared_by.append(SRC_GSB)

    return {'kind': 'url', 'observable': url, 'verdict': verdict,
            'first_source': SRC_URLSCAN,
            'urlscan_field': urlscan_field, 'gsb_field': gsb_field,
            'result_url': result_url, 'screenshot': screenshot,
            'note': note, 'flagged_by': flagged_by, 'cleared_by': cleared_by}


def build_whitelisted_url_record(url, parent_domain):
    """URL skipped because its registrable domain is whitelisted in AlienVault OTX."""
    return {'kind': 'url', 'observable': url, 'verdict': "WhitelistSkip",
            'first_source': SRC_OTX,
            'urlscan_field': f"Skipped (parent domain whitelisted in {SRC_OTX})",
            'gsb_field': None, 'result_url': None, 'screenshot': None,
            'note': f"parent domain {parent_domain} whitelisted in {SRC_OTX}",
            'flagged_by': [], 'cleared_by': []}


def build_domain_record(domain, otx_headers):
    """Verdict for a domain comes from AlienVault OTX. Creation date (RDAP) is
    context only."""
    otx = otx_lookup(domain, otx_headers)
    verdict = otx['verdict']
    flagged_by = [SRC_OTX] if verdict in ("Suspicious", "Malicious") else []
    cleared_by = [SRC_OTX] if verdict == "Clean" else []
    created_iso = None if _is_ip(domain) else rdap_creation_date(domain)
    return {'kind': 'domain', 'observable': domain, 'verdict': verdict,
            'first_source': SRC_OTX, 'otx': otx,
            'created': _iso_to_ddmmyyyy(created_iso), 'created_iso': created_iso,
            'note': "inconclusive" if verdict == "Unknown" else None,
            'whitelisted': bool(otx.get('whitelisted')),
            'flagged_by': flagged_by, 'cleared_by': cleared_by}


def build_ip_record(ip, abuse_headers, is_sender=False):
    """Verdict for an IP comes from AbuseIPDB."""
    ab = abuseipdb_check(ip, abuse_headers)
    verdict = ab['verdict']
    flagged_by = [SRC_ABUSE] if verdict in ("Suspicious", "Malicious") else []
    cleared_by = [SRC_ABUSE] if verdict == "Clean" else []
    return {'kind': 'ip', 'observable': ip, 'verdict': verdict,
            'first_source': SRC_ABUSE, 'abuseipdb': ab,
            'is_sender': is_sender,
            'whitelisted': bool(ab.get('whitelisted')),
            'flagged_by': flagged_by, 'cleared_by': cleared_by}


# --- Per-section line formatters ----------------------------------------------

def format_url_line(rec):
    fields = [f"URLScan: {rec['urlscan_field']}"]
    if rec.get('gsb_field') is not None:
        fields.append(f"GSB: {rec['gsb_field']}")
    if rec.get('result_url'):
        fields.append(f"[Report]({rec['result_url']})")
    if rec.get('screenshot'):
        fields.append(f"[Screenshot]({rec['screenshot']})")
    return f"* *{defang(rec['observable'])}*: **{verdict_label(rec['verdict'])}** | " + " | ".join(fields)


def format_domain_line(rec):
    otx = rec['otx']
    wl = "**Whitelisted 🏳️** | " if otx.get('whitelisted') else ""
    pulses = otx.get('pulses')
    otx_txt = f"{wl}OTX: {otx.get('verdict', 'Unknown')} ({pulses if pulses is not None else 0} pulses)"
    fields = [otx_txt, f"Created: {rec['created']}"]
    if otx.get('link'):
        fields.append(f"[{SRC_OTX}]({otx['link']})")
    return f"* *{defang(rec['observable'])}*: **{verdict_label(rec['verdict'])}** | " + " | ".join(fields)


def format_ip_line(rec):
    ab = rec['abuseipdb']
    tag = " _(SPF sender)_" if rec.get('is_sender') else ""
    extra = [f"AbuseIPDB: {ab['score']}/100"]
    if ab["reports"] is not None:
        extra.append(f"Reports: {ab['reports']}")
    if ab["country"]:
        extra.append(f"Country: {ab['country']}")
    if ab["usage"]:
        extra.append(f"Usage Type: {ab['usage']}")
    if ab["isp"]:
        extra.append(f"ISP: {ab['isp']}")
    if ab["whitelisted"]:
        extra.append("Whitelisted")
    extra.append(f"[{SRC_ABUSE}]({ab['link']})")
    return f"* *{defang(rec['observable'])}*{tag}: **{verdict_label(rec['verdict'])}** | " + " | ".join(extra)


def format_two_source_line(rec):
    """Verbose, source-prefixed second-factor line — every piece of data is
    tagged with where it came from (VirusTotal, RDAP)."""
    vt = rec['vt']
    parts = [f"{SRC_VT} verdict: {vt['verdict']}"]
    if not vt.get('absent'):
        parts.append(f"{SRC_VT} vendors: {vt['malicious']}/{vt['total']} malicious")
        if vt.get('suspicious'):
            parts.append(f"{SRC_VT} suspicious vendors: {vt['suspicious']}")
        if vt.get('reputation') is not None:
            parts.append(f"{SRC_VT} community score: {vt['reputation']}")
    if rec.get('kind') != 'ip':
        parts.append(f"{SRC_RDAP} creation date: {_iso_to_ddmmyyyy(rec.get('created_iso_dd'))}")
    if vt.get('submitted'):
        parts.append(f"{SRC_VT}: submitted on-demand")
    parts.append(f"[{SRC_VT}]({vt['gui']})")
    return (f"* *{defang(rec['observable'])}* — **{verdict_label(rec['combined_verdict'])}** | "
            + " | ".join(parts))


# --- IP extraction ------------------------------------------------------------

_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_RE = re.compile(r'\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b')


def _public_ip(token):
    try:
        ipobj = ipaddress.ip_address(token)
    except ValueError:
        return None
    if (ipobj.is_private or ipobj.is_loopback or ipobj.is_reserved
            or ipobj.is_link_local or ipobj.is_multicast or ipobj.is_unspecified):
        return None
    return str(ipobj)


def find_sender_ip(headers):
    auth = headers.get('Authentication-Results', '') or ''
    m = re.search(r'client-ip=([0-9A-Fa-f:.]+)', auth) or re.search(r'sender IP is ([0-9.]+)', auth)
    return _public_ip(m.group(1)) if m else None


def collect_ips(headers):
    """Public IPs from Received / Authentication-Results / X-*-IP headers, SPF
    sender first."""
    text_parts = []
    for name in ('Received', 'Authentication-Results', 'X-Originating-IP',
                 'X-Sender-IP', 'X-SenderIP', 'X-Source-IP'):
        text_parts.extend(headers.get_all(name) or [])
    blob = "\n".join(text_parts)

    ordered, seen = [], set()
    sender = find_sender_ip(headers)
    if sender:
        ordered.append(sender)
        seen.add(sender)
    for token in _IPV4_RE.findall(blob) + _IPV6_RE.findall(blob):
        ip = _public_ip(token)
        if ip and ip not in seen:
            seen.add(ip)
            ordered.append(ip)
    return ordered, sender


# --- Attachments --------------------------------------------------------------

def hash_attachments(raw_bytes):
    """SHA-256 / MD5 of MIME parts already inside the message (nothing is
    downloaded). Parses from *bytes* so binary parts aren't corrupted through a
    text codec. Inline images (referenced by Content-ID) are hashed too."""
    try:
        msg = email.message_from_bytes(raw_bytes)
    except Exception:
        return []
    out = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disp = part.get_content_disposition() or ''
        # Skip the plain-text / HTML body; hash everything else carrying bytes.
        if part.get_content_maintype() == 'text' and not filename and disp != 'attachment':
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None
        if not payload:
            continue
        cid = part.get('Content-ID')
        name = decode_mime_words(filename) if filename else \
            (f"(inline {cid.strip('<>')})" if cid else "(unnamed)")
        out.append({'filename': name, 'content_type': part.get_content_type(),
                    'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                    'md5': hashlib.md5(payload).hexdigest()})
    return out


# --- Orchestration ------------------------------------------------------------

def decode_qp_for_urls(text):
    try:
        return quopri.decodestring(text.encode('utf-8', 'replace')).decode('utf-8', 'replace')
    except Exception:
        return text


def collect_observables(raw_header_text, headers):
    decoded = decode_qp_for_urls(raw_header_text)
    urls, hosts = set(), set()
    for hdr in ('From', 'Return-Path', 'Reply-To'):
        dom = extract_domain(headers.get(hdr, ''))
        if dom:
            hosts.add(dom)
    for u in re.findall(r'(?i)\bhttps?://[^\s<>"\'{}|\\^`]+', decoded):
        clean_url = u.rstrip('.,;:!?)]([\'"<>')
        urls.add(clean_url)
        host = extract_host(clean_url)
        if host:
            hosts.add(host)
    url_obs = sorted(u for u in urls if is_scannable(u))
    domain_obs = {apex for host in hosts
                  if (apex := registrable_domain(host)) and is_scannable(apex)}
    return url_obs, sorted(domain_obs)


def _is_dangerous_attachment(content_type, filename):
    """Images / video / audio are merely listed; everything else (pdf, office,
    archives, executables, scripts, octet-stream, ...) is worth a VT lookup."""
    maintype = (content_type or '').split('/')[0].lower()
    return maintype not in _SKIPPED_ATTACHMENT_MAINTYPES


def _within_one_year(created_iso):
    """True only for a valid date inside the last DEEPDIVE_MAX_AGE_DAYS days."""
    try:
        y, m, d = map(int, created_iso.split('-'))
        return (date.today() - date(y, m, d)).days < DEEPDIVE_MAX_AGE_DAYS
    except (ValueError, TypeError, AttributeError):
        return False


def _record_created_iso(rec):
    """Creation date for a deep-dive target. IPs don't have one; for a URL we
    use its registrable domain (RDAP result is cached so it's usually free)."""
    if rec.get('kind') == 'ip':
        return None
    if 'created_iso' in rec:
        return rec['created_iso']
    host = extract_host(rec['observable'])
    apex = registrable_domain(host) if host else None
    return rdap_creation_date(apex) if apex else None


def deepdive_escalation(vt, created_iso, kind='domain'):
    """Triggers that push an item to NEEDS REVIEW. Each trigger names the
    source it came from (so 'community score -3' reads as 'VirusTotal
    community score -3' downstream)."""
    triggers = []
    vendors = (vt.get('malicious') or 0) + (vt.get('suspicious') or 0)
    if vendors:
        triggers.append(f"{vendors} {SRC_VT} vendor detection"
                        + ("s" if vendors != 1 else ""))
    rep = vt.get('reputation')
    if isinstance(rep, int) and rep < 0:
        triggers.append(f"{SRC_VT} community score {rep}")
    # RDAP only makes sense for domains/URLs, not IPs.
    if kind != 'ip':
        if not created_iso:
            triggers.append(f"{SRC_RDAP}: creation date not found")
        elif _within_one_year(created_iso):
            triggers.append(f"{SRC_RDAP}: registered within the last year")
    return triggers


# --- Manual Lookups reason building -------------------------------------------

def _first_factor_detail(rec):
    """Verbose, source-tagged detail for whichever tool produced the first-
    factor verdict on this record."""
    if rec['kind'] == 'ip':
        ab = rec['abuseipdb']
        score = ab.get('score', 0) or 0
        reports = ab.get('reports', 0) or 0
        return f"{SRC_ABUSE} {score}/100 ({reports} reports)"
    if rec['kind'] == 'domain':
        otx = rec.get('otx', {})
        pulses = otx.get('pulses', 0) or 0
        return f"{SRC_OTX} ({pulses} pulses)"
    # url
    bits = []
    if rec.get('urlscan_field') == 'malicious':
        bits.append(f"{SRC_URLSCAN} flagged malicious")
    elif rec.get('urlscan_field') == 'clean':
        bits.append(f"{SRC_URLSCAN} clean")
    elif rec.get('urlscan_field'):
        bits.append(f"{SRC_URLSCAN}: {rec['urlscan_field']}")
    if rec.get('gsb_field') == 'malicious':
        bits.append(f"{SRC_GSB} flagged malicious")
    return "; ".join(bits) if bits else f"{SRC_URLSCAN}: inconclusive"


def build_manual_reason(rec):
    """Manual Lookups reason: every contributing source gets a mention, so a
    reader can see which tool flagged what and which tool cleared it."""
    parts = []
    first_verdict = rec['verdict']
    detail = _first_factor_detail(rec)

    if first_verdict in ("Suspicious", "Malicious"):
        parts.append(f"Flagged by {detail}")
    elif first_verdict == "Unknown":
        parts.append(f"{detail} — inconclusive")
    elif first_verdict == "Clean":
        # Only reached when VT escalated despite a clean first factor.
        parts.append(f"Cleared by {detail}")

    # Second-factor (VT) signal — present iff Two-Source Verification ran.
    if 'vt' in rec:
        vt = rec['vt']
        if vt.get('absent'):
            parts.append(f"{SRC_VT}: no record")
        elif rec.get('triggers'):
            parts.append("; ".join(rec['triggers']))
        else:
            vendors = f"{vt.get('malicious', 0)}/{vt.get('total', 0)} malicious"
            parts.append(f"{SRC_VT}: clean ({vendors})")

    return "; ".join(parts) if parts else "inconclusive"


def manual_verdict(rec):
    """Verdict shown in Manual Lookups. NeedsReview wins when the deep-dive
    escalated; otherwise the first-factor verdict stands."""
    if rec.get('combined_verdict') == 'NeedsReview':
        return 'NeedsReview'
    return rec['verdict']


def needs_manual_review(rec):
    """An item belongs in Manual Lookups if ANY source raised a concern, even
    when a later source disagreed."""
    if rec['verdict'] == 'WhitelistSkip':
        return False
    if rec['verdict'] in ('Suspicious', 'Malicious', 'Unknown'):
        return True
    if rec.get('combined_verdict') == 'NeedsReview':
        return True
    return False


def _attachment_manual_entry(att):
    """Build a Manual Lookups row for an attachment with a worrying VT result.
    Clean attachments and ones we never looked up (image/video/audio) return
    None and stay out of the list."""
    vt = att.get('vt')
    if not vt:
        return None
    name = att['filename']
    if vt.get('absent'):
        return {'observable': name, 'verdict': 'Unknown',
                'reason': (f"{SRC_VT}: no record (file hash unseen — "
                           f"manual upload to {SRC_VT} may be needed)")}
    if vt['verdict'] in ('Suspicious', 'Malicious'):
        return {'observable': name, 'verdict': vt['verdict'],
                'reason': (f"Flagged by {SRC_VT} "
                           f"({vt.get('malicious', 0)}/{vt.get('total', 0)} malicious)")}
    return None


# --- The main pipeline --------------------------------------------------------

def run_osint(raw_header_text, headers, url_obs, domain_obs, raw_bytes):
    us_headers = _urlscan_headers()
    otx_headers = _otx_headers()
    vt_headers = _vt_headers()
    abuse_headers = _abuseipdb_headers()
    print()

    # --- Domains: AlienVault OTX is the sole first-factor verdict source ---
    domain_records = [build_domain_record(d, otx_headers) for d in domain_obs]
    whitelisted_apexes = {r['observable'] for r in domain_records if r.get('whitelisted')}

    print("### Domains")
    print("---")
    if domain_records:
        for r in _sort_records(domain_records):
            print(format_domain_line(r))
    else:
        print("*No domains found.*")

    # --- URLs: URLScan.io is the sole first-factor verdict source ---
    pending = {}
    for u in url_obs:
        if registrable_domain(extract_host(u)) in whitelisted_apexes:
            continue
        pending[u] = submit_scan(u, us_headers)
        time.sleep(URLSCAN_SUBMIT_THROTTLE)

    url_records = []
    for u in url_obs:
        apex = registrable_domain(extract_host(u))
        if apex in whitelisted_apexes:
            url_records.append(build_whitelisted_url_record(u, apex))
        else:
            url_records.append(build_url_record(u, pending.get(u)))

    print("---")
    print("### URLs")
    print("---")
    if url_records:
        for r in _sort_records(url_records):
            print(format_url_line(r))
    else:
        print("*No URLs found.*")

    # --- IPs: AbuseIPDB is the sole first-factor verdict source ---
    print("---")
    print("### IPs")
    print("---")
    ips, sender = collect_ips(headers)
    ips = ips[:ABUSEIPDB_MAX_IPS]
    ip_records = [build_ip_record(ip, abuse_headers, is_sender=(ip == sender))
                  for ip in ips]
    if not ip_records:
        print("*No public IPs found in headers.*")
    for r in _sort_records(ip_records):
        print(format_ip_line(r))

    # --- Two-Source Verification: push every non-clean first-factor item
    # (URL / domain / IP) through VirusTotal as the independent second source.
    print("---")
    print("### Two-Source Verification")
    print("---")

    candidates = [r for r in (domain_records + url_records + ip_records)
                  if r['verdict'] in ('Malicious', 'Suspicious', 'Unknown')]
    _sev = {'Malicious': 0, 'Suspicious': 1, 'Unknown': 2}
    candidates.sort(key=lambda r: (_sev.get(r['verdict'], 3), r['observable'].lower()))
    top_n, overflow = candidates[:VT_MAX_LOOKUPS], candidates[VT_MAX_LOOKUPS:]

    if not candidates:
        print("*Nothing to verify — every indicator came back clean from its first-factor source.*")
    else:
        verified = []
        for i, rec in enumerate(top_n):
            if i:
                time.sleep(VT_THROTTLE)
            allow_submit = (rec['kind'] == 'url')
            vt = vt_lookup(rec['observable'], vt_headers,
                           reanalyze=VT_REANALYZE, allow_submit=allow_submit)
            created_iso = _record_created_iso(rec)
            triggers = deepdive_escalation(vt, created_iso, rec['kind'])

            rec['vt'] = vt
            rec['vt_verdict'] = vt['verdict']
            rec['created_iso_dd'] = created_iso
            rec['triggers'] = triggers
            rec['combined_verdict'] = 'NeedsReview' if triggers else 'Clean'
            if vt['verdict'] in ('Suspicious', 'Malicious') and SRC_VT not in rec['flagged_by']:
                rec['flagged_by'].append(SRC_VT)
            elif vt['verdict'] == 'Clean' and SRC_VT not in rec['cleared_by']:
                rec['cleared_by'].append(SRC_VT)
            verified.append(rec)

        for rec in _sort_records(verified, verdict_key='combined_verdict'):
            print(format_two_source_line(rec))

        for rec in overflow:
            print(f"* *{defang(rec['observable'])}* — **{verdict_label(rec['verdict'])}** "
                  f"(beyond top {VT_MAX_LOOKUPS}; check {SRC_VT} manually)")

    print("---")
    print("### Attachments")
    print("---")
    atts = hash_attachments(raw_bytes)
    if not atts:
        print("*No file attachments found. (Remote images referenced by the email "
              "are listed under URLs, not here.)*")
    for j, a in enumerate(atts):
        line = (f"* *{defang(a['filename'])}* ({a['content_type']}, {a['size']} bytes) | "
                f"SHA-256: `{a['sha256']}`")
        if _is_dangerous_attachment(a['content_type'], a['filename']):
            if j:
                time.sleep(VT_THROTTLE)
            vf = vt_file_lookup(a['sha256'], vt_headers)
            a['vt'] = vf
            if vf.get('absent'):
                line += f" | {SRC_VT}: No record"
            else:
                line += f" | {SRC_VT}: {vf['verdict']} ({vf['malicious']}/{vf['total']} malicious)"
            line += f" | [{SRC_VT}]({vf['gui']})"
        print(line)

    print("---")
    print("### Manual Lookups")
    print("---")

    manual = []
    for rec in url_records + domain_records + ip_records:
        if needs_manual_review(rec):
            manual.append({'observable': rec['observable'],
                           'verdict': manual_verdict(rec),
                           'reason': build_manual_reason(rec)})
    for a in atts:
        entry = _attachment_manual_entry(a)
        if entry:
            manual.append(entry)

    seen, deduped = set(), []
    for m in manual:
        if m['observable'] in seen:
            continue
        seen.add(m['observable'])
        deduped.append(m)
    deduped.sort(key=lambda m: (_VERDICT_ORDER.get(m['verdict'], 99),
                                 m['observable'].lower()))

    if deduped:
        for m in deduped:
            print(f"* *{defang(m['observable'])}* — **{verdict_label(m['verdict'])}** — {m['reason']}")
    else:
        print("*Nothing requires manual review.*")


def analyze_headers(raw_header_text, raw_bytes=None):
    if raw_bytes is None:
        raw_bytes = raw_header_text.encode('utf-8', 'surrogateescape')
    headers = HeaderParser().parsestr(raw_header_text)

    print("# Headers Analysis")
    print("---")
    print("## Message Metadata")
    print(f"* **From:** {defang(decode_mime_words(headers.get('From')))}")
    print(f"* **To:** {defang(decode_mime_words(headers.get('To')))}")
    print(f"* **Subject:** {defang(decode_mime_words(headers.get('Subject')))}")
    print(f"* **Date:** {convert_to_utc(headers.get('Date', 'Not Found'))}")
    print(f"* **Reply-To:** {defang(decode_mime_words(headers.get('Reply-To', 'Not Found')))}")
    print(f"* **Return-Path:** {defang(decode_mime_words(headers.get('Return-Path', 'Not Found')))}")
    print(f"* **Message-ID:** {' '.join(headers.get('Message-ID', 'Not Found').split())}")
    print("---")
    print("## Authentication Results")
    print("---")
    print("```")
    print(parse_auth_results(" ".join(headers.get('Authentication-Results', 'Not Found').split())))
    print("```")
    print("---")

    url_obs, domain_obs = collect_observables(raw_header_text, headers)
    print("## OSINT Lookups")
    print("---")
    run_osint(raw_header_text, headers, url_obs, domain_obs, raw_bytes)


if __name__ == "__main__":
    print("Paste the raw email below.")
    print("Tip: paste the FULL message (headers + body) so attachments can be hashed; "
          "headers-only also works for everything except attachment hashing.")
    print("When finished, press Enter to go to a new line, then press Ctrl+D to run the analysis:\n")
    raw_bytes = sys.stdin.buffer.read()
    raw_input_text = raw_bytes.decode('utf-8', errors='surrogateescape')
    if raw_input_text.strip():
        analyze_headers(raw_input_text, raw_bytes)
    else:
        print("\nNo headers provided. Exiting daemon.")