"""...you can fake it, infiltrate it, corporate it, little actor..."""

import email
import sys
import re
import os
import time
import quopri
import base64
import ipaddress
from urllib.parse import urlparse, quote

import requests
from email.parser import HeaderParser
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr
from datetime import timezone, date
from dotenv import load_dotenv

load_dotenv()

try:
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:
    _TLD_EXTRACT = None

_MULTI_SUFFIXES = {
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'org.nz', 'com.br', 'com.mx', 'com.tr', 'com.cn',
    'co.in', 'co.za', 'co.kr', 'com.sg', 'com.hk',
}

# --- Network / API config -----------------------------------------------------
URLSCAN_SUBMIT_THROTTLE = 2
URLSCAN_POLL_INTERVAL = 4
URLSCAN_MAX_WAIT = 90
HTTP_TIMEOUT = 30

VT_THROTTLE = 15
VT_MAX_LOOKUPS = 8
ABUSEIPDB_MAX_AGE_DAYS = 90
ABUSEIPDB_MAX_IPS = 15

_ALLOWED_API_HOSTS = (
    'urlscan.io', 'rdap.org', 'otx.alienvault.com',
    'www.virustotal.com', 'api.abuseipdb.com',
)

# --- Verdict thresholds -------------------------------------------------------
SCORE_SUSPICIOUS = 10
SCORE_MALICIOUS = 50
RECENT_DAYS = 90
OTX_SUSPICIOUS_PULSES = 3
ABUSE_SUSPICIOUS = 25
ABUSE_MALICIOUS = 75

NOISE_HOSTS = {
    "w3.org", "www.w3.org", "schema.org", "schemas.microsoft.com",
    "schemas.xmlsoap.org", "purl.org", "ns.adobe.com",
}


# --- Safe transport -----------------------------------------------------------

def _host_allowed(url):
    host = (urlparse(url).hostname or '').lower()
    return any(host == a or host.endswith('.' + a) for a in _ALLOWED_API_HOSTS)


def _safe_request(method, url, **kwargs):
    """Single choke point for ALL outbound traffic. Refuses non-API hosts so the
    tool can never be tricked into fetching a target URL directly."""
    if not _host_allowed(url):
        raise ValueError(f"Blocked request to non-API host: {url}")
    kwargs.setdefault('timeout', HTTP_TIMEOUT)
    return requests.request(method, url, **kwargs)


# --- Formatting helpers -------------------------------------------------------

def defang(text):
    if not text or text == "Not Found":
        return text
    text = re.sub(r'(?i)http', 'hxxp', text)

    def defang_ip(match):
        return match.group(0).replace('.', '[.]')
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', defang_ip, text)
    text = re.sub(r'(?<!\bheader)(?<!\bsmtp)(?<!\bcompauth)\.(?=[a-zA-Z]{2,}\b)', '[.]', text)
    return text


def decode_mime_words(header_string):
    if not header_string:
        return "Not Found"
    decoded_words = decode_header(header_string)
    final_string = ""
    for word, encoding in decoded_words:
        if isinstance(word, bytes):
            charset = encoding if encoding else "utf-8"
            try:
                final_string += word.decode(charset)
            except (LookupError, UnicodeDecodeError):
                final_string += word.decode("utf-8", errors="replace")
        else:
            final_string += word
    return " ".join(final_string.split())


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
    if status == 'pass':
        return f"{status} ✅"
    elif status == 'fail':
        return f"{status} ❌"
    elif status == 'softfail':
        return f"{status} ⚠️"
    elif status in ['temperror', 'permerror']:
        return f"{status} 🛠️"
    elif status in ['none', 'neutral']:
        return f"{status} ❔"
    else:
        return f"{status if status else 'unknown'} ➖"


def parse_auth_results(auth_header):
    if not auth_header or auth_header == "Not Found":
        return "None ❔"
    parts = [p.strip() for p in auth_header.split(';') if p.strip()]
    formatted_lines = []
    for part in parts:
        match = re.search(r'^(spf|dkim|dmarc|compauth|arc)=([a-zA-Z0-9]+)', part, re.IGNORECASE)
        if match:
            protocol = match.group(1).lower()
            status_word = match.group(2).lower()
            formatted_status = get_status_emoji(status_word)
            clean_part = re.sub(
                r'^(spf|dkim|dmarc|compauth|arc)=[a-zA-Z0-9]+',
                f"{protocol}={formatted_status}", part, flags=re.IGNORECASE,
            )
            formatted_lines.append("* " + clean_part)
        else:
            formatted_lines.append("* " + part)
    return defang("\n".join(formatted_lines))


def extract_domain(email_address):
    if not email_address or email_address == "Not Found":
        return None
    _, addr = parseaddr(email_address)
    if '@' in addr:
        return addr.split('@')[-1].strip().lower() or None
    return None


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
    if _TLD_EXTRACT is not None:
        ext = _TLD_EXTRACT(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return None
    parts = host.split('.')
    if len(parts) < 2:
        return None
    last2 = '.'.join(parts[-2:])
    if len(parts) >= 3 and last2 in _MULTI_SUFFIXES:
        return '.'.join(parts[-3:])
    return last2


def is_scannable(observable):
    host = extract_host(observable)
    if not host:
        return False
    if host in NOISE_HOSTS:
        return False
    if _is_private_ip(host):
        return False
    if _is_ip(host):
        return True
    if not _HOSTNAME_RE.match(host):
        return False
    if host.endswith(('.local', '.internal', '.lan', '.localdomain', '.home.arpa')):
        return False
    return True


# --- Date helpers -------------------------------------------------------------

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
    if dated:
        return min(dated)
    return found[0] if found else None


def _iso_to_ddmmyyyy(iso):
    if not iso:
        return "Not Found"
    if _DATE_RE.match(iso):
        y, m, d = iso.split('-')
        return f"{d}-{m}-{y}"
    return iso


def _age_days(iso):
    if not iso or not _DATE_RE.match(iso):
        return None
    try:
        return (date.today() - date.fromisoformat(iso)).days
    except (TypeError, ValueError):
        return None


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


def creation_date_iso(res_data, apex=None):
    date_iso = None
    if isinstance(res_data, dict):
        meta = res_data.get('meta')
        date_iso = _search_creation_date(meta) if meta else None
        if not date_iso:
            for key in ('whois', 'rdap'):
                date_iso = _search_creation_date(res_data.get(key))
                if date_iso:
                    break
        if not apex:
            apex = ((res_data.get('page') or {}).get('apexDomain')
                    or (res_data.get('task') or {}).get('apexDomain'))
    if not date_iso and apex:
        date_iso = rdap_creation_date(apex)
    return date_iso


# --- URLScan.io ---------------------------------------------------------------

def _urlscan_headers():
    key = os.getenv('URLSCAN_DAEMON')
    return {'API-Key': key, 'Content-Type': 'application/json'} if key else None


def submit_scan(observable, headers):
    data = {"url": observable, "visibility": "unlisted"}
    try:
        resp = _safe_request('POST', 'https://urlscan.io/api/v1/scan/', headers=headers, json=data)
    except (requests.RequestException, ValueError) as e:
        return {"status": "error", "message": f"Submit error ❌ ({e})"}
    if resp.status_code == 200:
        try:
            body = resp.json()
        except ValueError:
            return {"status": "error", "message": "Invalid JSON on submit ❌"}
        return {"status": "submitted", "api": body.get('api'),
                "result": body.get('result'), "uuid": body.get('uuid')}
    if resp.status_code == 400:
        return {"status": "error", "message": "Skipped ⏭️ (blocked from scanning or invalid target)"}
    if resp.status_code == 429:
        return {"status": "error", "message": "Rate limit exceeded ❌"}
    if resp.status_code in (401, 403):
        return {"status": "error", "message": "Auth failed ❌ (check URLSCAN_DAEMON)"}
    return {"status": "error", "message": f"Submit failed (HTTP {resp.status_code}) ❌"}


def poll_result(api_url, headers):
    if not api_url:
        return None, "No result API URL returned ❌"
    deadline = time.time() + URLSCAN_MAX_WAIT
    while time.time() < deadline:
        try:
            resp = _safe_request('GET', api_url, headers=headers)
        except (requests.RequestException, ValueError) as e:
            return None, f"Network error ⚠️ ({e})"
        if resp.status_code == 200:
            try:
                return resp.json(), None
            except ValueError:
                return None, "Invalid JSON in result ⚠️"
        elif resp.status_code == 404:
            time.sleep(URLSCAN_POLL_INTERVAL)
            continue
        elif resp.status_code == 410:
            return None, "Result deleted (410) 🗑️"
        elif resp.status_code == 429:
            time.sleep(URLSCAN_POLL_INTERVAL * 2)
            continue
        else:
            return None, f"Result HTTP {resp.status_code} ❌"
    return None, "Timeout ⏳ (scan still processing)"


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
    key = os.getenv('ALIENVAULT_DAEMON')
    return {'X-OTX-API-KEY': key, 'Accept': 'application/json'} if key else None


_OTX_CACHE = {}
_OTX_LABS_AUTHORS = ('alienvault', 'levelblue')


def _otx_link(itype, indicator):
    kind = 'ip' if itype in ('IPv4', 'IPv6') else 'domain'
    return f"https://otx.alienvault.com/indicator/{kind}/{indicator}"


def otx_lookup(observable, headers):
    """Queries OTX 'general' and derives a verdict the way the OTX UI does:
    LevelBlue Labs pulse membership or malware_families -> Malicious;
    validation (whitelist) -> Clean; else by pulse count."""
    if not headers:
        return None
    host = extract_host(observable)
    if not host:
        return None
    if _is_ip(host):
        itype = 'IPv6' if ':' in host else 'IPv4'
        indicator = host
    else:
        itype = 'domain'
        indicator = registrable_domain(host) or host

    cache_key = (itype, indicator)
    if cache_key in _OTX_CACHE:
        return _OTX_CACHE[cache_key]

    out = {"pulses": None, "whitelisted": False, "malware": [], "labs": False,
           "verdict": "Unknown", "reason": "", "error": None,
           "link": _otx_link(itype, indicator), "indicator": indicator, "itype": itype}
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/{itype}/{quote(indicator)}/general"
        resp = _safe_request('GET', url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            pinfo = data.get('pulse_info') or {}
            out["pulses"] = pinfo.get('count')
            out["whitelisted"] = bool(data.get('validation'))
            malware = set()
            labs = False
            for pulse in (pinfo.get('pulses') or []):
                author = ((pulse.get('author') or {}).get('username')
                          or pulse.get('author_name') or '')
                if any(a in author.lower() for a in _OTX_LABS_AUTHORS):
                    labs = True
                for fam in (pulse.get('malware_families') or []):
                    name = fam.get('display_name') or fam.get('id') if isinstance(fam, dict) else fam
                    if name:
                        malware.add(str(name))
            out["malware"] = sorted(malware)
            out["labs"] = labs

            pulses = out["pulses"]
            if labs:
                out["verdict"], out["reason"] = "Malicious", "LevelBlue Labs pulse"
            elif malware:
                out["verdict"], out["reason"] = "Malicious", "malware: " + ", ".join(sorted(malware)[:3])
            elif out["whitelisted"]:
                out["verdict"], out["reason"] = "Clean", "whitelisted"
            elif isinstance(pulses, int) and pulses >= OTX_SUSPICIOUS_PULSES:
                out["verdict"], out["reason"] = "Suspicious", f"{pulses} pulses"
            else:
                out["verdict"], out["reason"] = "Clean", f"{pulses or 0} pulses"
        elif resp.status_code in (401, 403):
            out["error"] = "auth failed (check ALIENVAULT_DAEMON)"
        else:
            out["error"] = f"HTTP {resp.status_code}"
    except (requests.RequestException, ValueError) as e:
        out["error"] = str(e)

    _OTX_CACHE[cache_key] = out
    return out

# --- VirusTotal ---------------------------------------------------------------

def _vt_headers():
    key = os.getenv('VIRUSTOTAL_DAEMON')
    return {'x-apikey': key, 'Accept': 'application/json'} if key else None


def vt_lookup(observable, headers):
    """Reads an existing VT report (never submits). Returns a dict or None."""
    if not headers:
        return None
    host = extract_host(observable)
    is_url = observable.startswith(('http://', 'https://'))

    if is_url:
        url_id = base64.urlsafe_b64encode(observable.encode()).decode().strip('=')
        api = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        gui = f"https://www.virustotal.com/gui/url/{url_id}"
    elif _is_ip(host):
        api = f"https://www.virustotal.com/api/v3/ip_addresses/{host}"
        gui = f"https://www.virustotal.com/gui/ip-address/{host}"
    else:
        dom = registrable_domain(host) or host
        api = f"https://www.virustotal.com/api/v3/domains/{dom}"
        gui = f"https://www.virustotal.com/gui/domain/{dom}"

    out = {"verdict": "Unknown", "malicious": 0, "suspicious": 0, "total": 0,
           "reputation": None, "gui": gui, "absent": False, "error": None}
    try:
        resp = _safe_request('GET', api, headers=headers)
        if resp.status_code == 200:
            attrs = (resp.json().get('data') or {}).get('attributes') or {}
            stats = attrs.get('last_analysis_stats') or {}
            out["malicious"] = stats.get('malicious', 0)
            out["suspicious"] = stats.get('suspicious', 0)
            out["total"] = sum(v for v in stats.values() if isinstance(v, int))
            out["reputation"] = attrs.get('reputation')
            if is_url:
                rid = (resp.json().get('data') or {}).get('id')
                if rid:
                    out["gui"] = f"https://www.virustotal.com/gui/url/{rid}"
            if out["malicious"] > 0:
                out["verdict"] = "Malicious"
            elif out["suspicious"] > 0:
                out["verdict"] = "Suspicious"
            else:
                out["verdict"] = "Clean"
        elif resp.status_code == 404:
            out["absent"] = True
            out["verdict"] = "No VT record"
        elif resp.status_code == 429:
            out["error"] = "rate limited"
        elif resp.status_code in (401, 403):
            out["error"] = "auth failed (check VIRUSTOTAL_DAEMON)"
        else:
            out["error"] = f"HTTP {resp.status_code}"
    except (requests.RequestException, ValueError) as e:
        out["error"] = str(e)
    return out


# --- AbuseIPDB ----------------------------------------------------------------

def _abuseipdb_headers():
    key = os.getenv('ABUSEIPDB_DAEMON')
    return {'Key': key, 'Accept': 'application/json'} if key else None


def abuseipdb_check(ip, headers):
    out = {"score": None, "reports": None, "country": None, "isp": None,
           "whitelisted": False, "verdict": "Unknown", "error": None,
           "link": f"https://www.abuseipdb.com/check/{ip}"}
    try:
        resp = _safe_request('GET', 'https://api.abuseipdb.com/api/v2/check', headers=headers,
                             params={'ipAddress': ip, 'maxAgeInDays': ABUSEIPDB_MAX_AGE_DAYS})
        if resp.status_code == 200:
            data = (resp.json() or {}).get('data') or {}
            out["score"] = data.get('abuseConfidenceScore')
            out["reports"] = data.get('totalReports')
            out["country"] = data.get('countryCode')
            out["isp"] = data.get('isp')
            out["whitelisted"] = bool(data.get('isWhitelisted'))
            score = out["score"] or 0
            if out["whitelisted"]:
                out["verdict"] = "CLEAN ✅"
            elif score >= ABUSE_MALICIOUS:
                out["verdict"] = "MALICIOUS ❌"
            elif score >= ABUSE_SUSPICIOUS:
                out["verdict"] = "SUSPICIOUS ⚠️"
            else:
                out["verdict"] = "CLEAN ✅"
        elif resp.status_code in (401, 403):
            out["error"] = "auth failed (check ABUSEIPDB_DAEMON)"
        elif resp.status_code == 429:
            out["error"] = "rate limited"
        else:
            out["error"] = f"HTTP {resp.status_code}"
    except (requests.RequestException, ValueError) as e:
        out["error"] = str(e)
    return out


# --- Verdict logic ------------------------------------------------------------

def compute_verdict(sig):
    mal, susp = [], []
    if sig.get('urlscan_malicious'):
        mal.append("urlscan flagged malicious")
    if sig.get('gsb_malicious'):
        mal.append("Google Safe Browsing hit")
    score = sig.get('score')
    if isinstance(score, (int, float)):
        if score >= SCORE_MALICIOUS:
            mal.append(f"urlscan score {score}")
        elif score >= SCORE_SUSPICIOUS:
            susp.append(f"urlscan score {score}")
    otx = sig.get('otx') or {}
    if otx.get('verdict') == 'Malicious':
        mal.append("OTX " + (otx.get('reason') or 'malicious'))
    elif otx.get('verdict') == 'Suspicious':
        susp.append("OTX " + (otx.get('reason') or 'suspicious'))
    age = sig.get('age_days')
    if isinstance(age, int) and age <= RECENT_DAYS:
        susp.append(f"domain created {age}d ago")
    if mal:
        return "MALICIOUS ❌", mal + susp
    if susp:
        return "SUSPICIOUS ⚠️", susp
    return "CLEAN ✅", []


def build_record(observable, urlscan_outcome, otx_headers):
    res_data = None
    urlscan_field = "n/a"
    result_url = None
    gsb_field = None
    score = None

    if urlscan_outcome is not None:
        if urlscan_outcome["status"] == "submitted":
            result_url = urlscan_outcome.get("result")
            res_data, status_text = poll_result(urlscan_outcome.get("api"), _urlscan_headers())
            if res_data is None:
                urlscan_field = status_text
        else:
            urlscan_field = urlscan_outcome["message"]

    us_malicious = gsb_malicious = False
    screenshot = None
    if res_data is not None:
        verdicts = res_data.get('verdicts') or {}
        overall = verdicts.get('overall') or {}
        urlscan_v = verdicts.get('urlscan') or {}
        us_malicious = bool(overall.get('malicious') or urlscan_v.get('malicious'))
        score = overall.get('score', urlscan_v.get('score'))
        gsb_malicious = _gsb_malicious(res_data)
        urlscan_field = "malicious" if us_malicious else "clean"
        gsb_field = "malicious" if gsb_malicious else "clean"
        screenshot = get_screenshot_url(res_data)

    apex = registrable_domain(extract_host(observable))
    otx = otx_lookup(observable, otx_headers)
    created_iso = creation_date_iso(res_data, apex)
    age = _age_days(created_iso)

    label, reasons = compute_verdict({
        'urlscan_malicious': us_malicious, 'gsb_malicious': gsb_malicious,
        'score': score, 'otx': otx, 'age_days': age,
    })

    return {
        'observable': observable,
        'is_url': observable.startswith(('http://', 'https://')),
        'label': label, 'reasons': reasons,
        'urlscan_field': urlscan_field, 'gsb_field': gsb_field, 'score': score,
        'otx': otx, 'created': _iso_to_ddmmyyyy(created_iso),
        'result_url': result_url, 'screenshot': screenshot,
    }


def format_line(rec):
    fields = [f"URLScan: {rec['urlscan_field']}"]
    if rec['gsb_field'] is not None:
        fields.append(f"GSB: {rec['gsb_field']}")

    otx = rec['otx']
    if otx is not None:
        if otx.get('error'):
            fields.append(f"OTX: lookup error ({otx['error']})")
        else:
            pulses = otx.get('pulses')
            otx_txt = f"OTX: {otx.get('verdict', 'Unknown')} ({pulses if pulses is not None else 0} pulses)"
            if otx.get('malware'):
                otx_txt += " malware: " + ", ".join(otx['malware'][:3])
            fields.append(otx_txt)

    if isinstance(rec['score'], (int, float)):
        fields.append(f"Score: {rec['score']}")
    fields.append(f"Created: {rec['created']}")

    if rec['result_url']:
        fields.append(f"[Report]({rec['result_url']})")
    if rec['screenshot']:
        fields.append(f"[Screenshot]({rec['screenshot']})")
    if otx is not None and otx.get('link'):
        fields.append(f"[OTX]({otx['link']})")

    line = f"* *{defang(rec['observable'])}*: **{rec['label']}** | " + " | ".join(fields)
    if rec['label'] != "CLEAN ✅" and rec['reasons']:
        line += f" | _{'; '.join(rec['reasons'])}_"
    return line


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
    if m:
        return _public_ip(m.group(1))
    return None


def collect_ips(headers):
    """Public IPs from Received / Authentication-Results / X-*-IP headers.
    Returns an ordered list with the SPF sender IP first when identifiable."""
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
    observables = {u for u in urls if is_scannable(u)}
    for host in hosts:
        apex = registrable_domain(host)
        if apex and is_scannable(apex):
            observables.add(apex)
    return sorted(observables)


def run_osint(raw_header_text, headers, observables):
    us_headers = _urlscan_headers()
    otx_headers = _otx_headers()
    vt_headers = _vt_headers()
    abuse_headers = _abuseipdb_headers()

    notes = []
    if not us_headers:
        notes.append("URLSCAN_DAEMON not set — urlscan skipped")
    if not otx_headers:
        notes.append("ALIENVAULT_DAEMON not set — OTX skipped")
    if not vt_headers:
        notes.append("VIRUSTOTAL_DAEMON not set — VT deep-dive skipped")
    if not abuse_headers:
        notes.append("ABUSEIPDB_DAEMON not set — IP reputation skipped")
    for n in notes:
        print(f"* *Note:* {n}. ⚠️")
    print()

    # URLScan submissions up-front so scans run in parallel.
    pending = {}
    if us_headers:
        for obs in observables:
            pending[obs] = submit_scan(obs, us_headers)
            time.sleep(URLSCAN_SUBMIT_THROTTLE)

    records = [build_record(obs, pending.get(obs), otx_headers) for obs in observables]
    url_records = sorted([r for r in records if r['is_url']], key=lambda r: r['observable'].lower())
    domain_records = sorted([r for r in records if not r['is_url']], key=lambda r: r['observable'].lower())

    print("### URLs")
    if url_records:
        for rec in url_records:
            print(format_line(rec))
    else:
        print("*No URLs found.*")

    print("\n### Domains")
    if domain_records:
        for rec in domain_records:
            print(format_line(rec))
    else:
        print("*No domains found.*")

    # IPs via AbuseIPDB
    print("\n### IPs")
    ips, sender = collect_ips(headers)
    ips = ips[:ABUSEIPDB_MAX_IPS]
    if not ips:
        print("*No public IPs found in headers.*")
    elif not abuse_headers:
        print("*ABUSEIPDB_DAEMON not set — skipping IP reputation. The following "
              "public IPs were seen:* " + ", ".join(defang(ip) for ip in ips))
    else:
        for ip in ips:
            ab = abuseipdb_check(ip, abuse_headers)
            tag = " _(SPF sender)_" if ip == sender else ""
            if ab["error"]:
                print(f"* *{defang(ip)}*{tag}: AbuseIPDB lookup error ({ab['error']})")
                continue
            extra = []
            extra.append(f"AbuseIPDB: {ab['score']}/100")
            if ab["reports"] is not None:
                extra.append(f"reports: {ab['reports']}")
            if ab["country"]:
                extra.append(f"CC: {ab['country']}")
            if ab["isp"]:
                extra.append(f"ISP: {ab['isp']}")
            if ab["whitelisted"]:
                extra.append("whitelisted")
            extra.append(f"[AbuseIPDB]({ab['link']})")
            print(f"* *{defang(ip)}*{tag}: **{ab['verdict']}** | " + " | ".join(extra))

    # VirusTotal deep-dive on flagged URLs/domains
    print("\n### Interesting URLs & Domains")
    standouts = [r for r in records if r['label'] != "CLEAN ✅"]
    standouts.sort(key=lambda r: 0 if r['label'].startswith("MALICIOUS") else 1)
    if not standouts:
        print(f"*Nothing stood out — all {len(records)} URLs/domains look clean.*")
    elif not vt_headers:
        print(f"*{len(standouts)} item(s) flagged for review (VIRUSTOTAL_DAEMON not set):*")
        for r in standouts:
            print(f"* *{defang(r['observable'])}* — **{r['label']}**: {'; '.join(r['reasons'])}")
    else:
        todo = standouts[:VT_MAX_LOOKUPS]
        overflow = standouts[VT_MAX_LOOKUPS:]
        print(f"*VirusTotal deep-dive on {len(todo)} flagged item(s) "
              f"(max 4/min, prioritised by severity):*\n")
        for i, rec in enumerate(todo):
            if i:
                time.sleep(VT_THROTTLE)
            vt = vt_lookup(rec['observable'], vt_headers)
            parts = [f"VT: {vt['verdict']}"]
            if not vt.get('absent') and not vt.get('error'):
                parts.append(f"{vt['malicious']}/{vt['total']} malicious")
                if vt.get('suspicious'):
                    parts.append(f"{vt['suspicious']} suspicious")
                if vt.get('reputation') is not None:
                    parts.append(f"reputation {vt['reputation']}")
            if vt.get('error'):
                parts = [f"VT: lookup error ({vt['error']})"]
            parts.append(f"[VirusTotal]({vt['gui']})")
            print(f"* *{defang(rec['observable'])}* — **{rec['label']}** | "
                  + " | ".join(parts) + f" | _{'; '.join(rec['reasons'])}_")
        for rec in overflow:
            print(f"* *{defang(rec['observable'])}* — **{rec['label']}** "
                  f"(VT skipped, over 4/min cap): _{'; '.join(rec['reasons'])}_")


def analyze_headers(raw_header_text):
    headers = HeaderParser().parsestr(raw_header_text)

    print("# Headers Analysis")
    print("---")

    from_addr = defang(decode_mime_words(headers.get('From')))
    to_addr = defang(decode_mime_words(headers.get('To')))
    reply_to = defang(decode_mime_words(headers.get('Reply-To', 'Not Found')))
    return_path = defang(decode_mime_words(headers.get('Return-Path', 'Not Found')))
    subject = defang(decode_mime_words(headers.get('Subject')))
    utc_date = convert_to_utc(headers.get('Date', 'Not Found'))
    msg_id = " ".join(headers.get('Message-ID', 'Not Found').split())
    auth_flat = " ".join(headers.get('Authentication-Results', 'Not Found').split())
    auth_results_formatted = parse_auth_results(auth_flat)

    print("## Message Metadata")
    print(f"* **From:** {from_addr}")
    print(f"* **To:** {to_addr}")
    print(f"* **Subject:** {subject}")
    print(f"* **Date:** {utc_date}")
    print(f"* **Reply-To:** {reply_to}")
    print(f"* **Return-Path:** {return_path}")
    print(f"* **Message-ID:** {msg_id}")
    print("---")
    print("## Authentication Results")
    print("---")
    print("```")
    print(auth_results_formatted)
    print("```")
    print("---")

    observables = collect_observables(raw_header_text, headers)
    print("## OSINT Lookups")
    print("*(Passive lookups only — urlscan/RDAP/OTX/VirusTotal/AbuseIPDB APIs; "
          "no target is visited directly. Waiting for all scans, sorted alphabetically...)*")
    print("---")
    run_osint(raw_header_text, headers, observables)


if __name__ == "__main__":
    print("Paste the raw email headers below.")
    print("When finished, press Enter to go to a new line, then press Ctrl+D to run the analysis:\n")
    raw_input_text = sys.stdin.read()
    if raw_input_text.strip():
        analyze_headers(raw_input_text)
    else:
        print("\nNo headers provided. Exiting daemon.")