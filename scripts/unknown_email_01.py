"""...you can fake it, infiltrate it, corporate it, little actor..."""

import email
import sys
import re
import os
import time
import socket
import quopri
import base64
import hashlib
import functools
import ipaddress
import unicodedata
import requests
import tldextract
import urllib3
from urllib.parse import urlparse, urlunparse, urljoin, quote, unquote, parse_qs
from email.parser import HeaderParser
from email.header import decode_header
from email.utils import parsedate_to_datetime, parseaddr, getaddresses
from datetime import timezone, date
from dotenv import load_dotenv

load_dotenv()

# --- TLS verification switch --------------------------------------------------
VERIFY_TLS = True

if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Config -------------------------------------------------------------------

_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

URLSCAN_SUBMIT_THROTTLE = 2
URLSCAN_POLL_INTERVAL = 4
URLSCAN_MAX_WAIT = 120
HTTP_TIMEOUT = 20

VT_THROTTLE = 15
VT_MAX_LOOKUPS = 12
VT_REANALYZE = False
VT_REANALYZE_POLL = 4
VT_REANALYZE_MAX_WAIT = 45
VT_URL_SUBMIT_POLL = 4
VT_URL_SUBMIT_MAX_WAIT = 60
VT_STALE_MAX_AGE_DAYS = 365

DEEPDIVE_MAX_AGE_DAYS = 365

MAX_INPUT_BYTES = 2_000_000

RDAP_MAX_HOPS = 5

# --- Effective-URL discovery ---------------------------------------------------
FOLLOW_EFFECTIVE_URLS = True
DISCOVERY_MAX_URLS = 5
DISCOVERY_MAX_ROUNDS = 2
FORCE_TWO_SOURCE_ON_DISCOVERED = True

_SKIPPED_ATTACHMENT_MAINTYPES = ('image', 'video', 'audio')
ABUSEIPDB_MAX_AGE_DAYS = 90
ABUSEIPDB_MAX_IPS = 15

_ALLOWED_API_HOSTS = (
    'urlscan.io', 'rdap.org', 'otx.alienvault.com',
    'www.virustotal.com', 'api.abuseipdb.com',
)

_REQUIRED_ENV = ('URLSCAN_DAEMON', 'ALIENVAULT_DAEMON',
                 'VIRUSTOTAL_DAEMON', 'ABUSEIPDB_DAEMON')

# --- Analyst-maintained whitelist (URL skip-list) -----------------------------
WHITELISTED_DOMAINS = {
    "outlook.com",
    "microsoft.com",
    "facebook.com",
    "*.instagram.com",
}

# --- Private-scan escalation (URLScan.io visibility) ---------------------------
PRIVATE_SCAN_KEYWORDS = {
    "unsub", "token", "login", "signin", "password", "reset",
    "verify", "invoice", "otp", "sso",
}
PRIVATE_SCAN_MIN_TOKEN_LENGTH = 4

SCORE_SUSPICIOUS = 10
SCORE_MALICIOUS = 50
OTX_SUSPICIOUS_PULSES = 1
ABUSE_SUSPICIOUS = 25
ABUSE_MALICIOUS = 75

WATCHLIST_PREVIEW_TITLE = "Watchlist Preview"
WATCHLIST_REVIEW_TITLE = "Watchlist Review"

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
SRC_WHITELIST = "Analyst Whitelist"

# --- Precompiled patterns (compiled once at import, reused on every call) ------

_DEFANG_HTTP_RE = re.compile(r'(?i)http')
_DEFANG_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_DEFANG_DOT_RE = re.compile(
    r'(?<!\bheader)(?<!\bsmtp)(?<!\bcompauth)\.(?![a-zA-Z0-9._%+-]*@)(?=[a-zA-Z]{2,}\b)')

_TERMINAL_CTRL_RE = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]')

_AUTH_PROTO_RE = re.compile(r'^(spf|dkim|dmarc|compauth|arc)=([a-zA-Z0-9]+)', re.IGNORECASE)
_COMPAUTH_REASON_RE = re.compile(r'reason=(\d+)')

_HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$')
_DATE_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')

_URL_RE = re.compile(r'(?i)\bhttps?://[^\s<>"\'{}|\\^`]+')

_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_RE = re.compile(r'\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b')
_CLIENT_IP_RE = re.compile(r'client-ip=([0-9A-Fa-f:.]+)')
_SENDER_IP_RE = re.compile(r'sender IP is ([0-9.]+)')

_SCL_RE = re.compile(r'\bSCL:(-?\d+)', re.IGNORECASE)
_BCL_RE = re.compile(r'\bBCL:(\d+)', re.IGNORECASE)

_DKIM_STATUS_RE = re.compile(r'dkim=([a-zA-Z]+)', re.IGNORECASE)
_DKIM_SIGNING_DOMAIN_RE = re.compile(r'header\.d=([A-Za-z0-9.\-]+)', re.IGNORECASE)

_EMAIL_IN_TEXT_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
_DOMAIN_IN_TEXT_RE = re.compile(r'\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b')

_LOCAL_PART_SEPARATOR_RE = re.compile(r'[._+\-]')


# --- Unicode sanitisation (evasion defence) -----------------------------------

def strip_terminal_controls(text):
    return _TERMINAL_CTRL_RE.sub('', text) if text else text


def strip_invisibles(text):
    return ''.join(ch for ch in text if unicodedata.category(ch) != 'Cf') if text else text


def invisible_char_names(text):
    return sorted({unicodedata.name(ch, f"U+{ord(ch):04X}")
                   for ch in (text or '') if unicodedata.category(ch) == 'Cf'})


# --- Safe transport -----------------------------------------------------------

def _safe_request(method, url, **kwargs):
    request_hostname = (urlparse(url).hostname or '').lower()
    if not any(request_hostname == allowed_api_host
               or request_hostname.endswith('.' + allowed_api_host)
               for allowed_api_host in _ALLOWED_API_HOSTS):
        raise ValueError(f"Blocked request to non-API host: {url}")
    kwargs.setdefault('timeout', HTTP_TIMEOUT)
    kwargs.setdefault('verify', VERIFY_TLS)
    kwargs.setdefault('allow_redirects', False)
    return requests.request(method, url, **kwargs)


def _host_is_public(hostname):
    if not hostname:
        return False
    try:
        address_infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError):
        return False
    for address_info in address_infos:
        resolved_ip = address_info[4][0].split('%')[0]
        try:
            ip_object = ipaddress.ip_address(resolved_ip)
        except ValueError:
            return False
        if (ip_object.is_private or ip_object.is_loopback or ip_object.is_reserved
                or ip_object.is_link_local or ip_object.is_multicast
                or ip_object.is_unspecified):
            return False
    return True


def _rdap_get(url):
    for _hop in range(RDAP_MAX_HOPS):
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https' or not _host_is_public(parsed_url.hostname):
            return None
        rdap_response = requests.get(
            url, headers={'Accept': 'application/rdap+json'},
            timeout=HTTP_TIMEOUT, verify=VERIFY_TLS, allow_redirects=False)
        if rdap_response.status_code in (301, 302, 303, 307, 308):
            location = rdap_response.headers.get('Location')
            if not location:
                return None
            url = urljoin(url, location)
            continue
        return rdap_response
    return None


# --- Formatting helpers -------------------------------------------------------

def defang(text):
    if not text or text == "Not Found":
        return text
    text = strip_terminal_controls(text)
    text = _DEFANG_HTTP_RE.sub('hxxp', text)
    text = _DEFANG_IPV4_RE.sub(lambda ipv4_match: ipv4_match.group(0).replace('.', '[.]'),
                               text)
    text = _DEFANG_DOT_RE.sub('[.]', text)
    return text


def decode_mime_words(header_string):
    if not header_string:
        return "Not Found"
    decoded_text = ""
    for encoded_word, charset_name in decode_header(header_string):
        if isinstance(encoded_word, bytes):
            try:
                decoded_text += encoded_word.decode(charset_name or "utf-8")
            except (LookupError, UnicodeDecodeError):
                decoded_text += encoded_word.decode("utf-8", errors="replace")
        else:
            decoded_text += encoded_word
    return " ".join(decoded_text.split())


def convert_to_utc(date_string):
    if not date_string or date_string == "Not Found":
        return "Not Found"
    try:
        parsed_datetime = parsedate_to_datetime(date_string)
        if parsed_datetime is None:
            return " ".join(date_string.split())
        return parsed_datetime.astimezone(timezone.utc).strftime('%d-%m-%Y %H:%M:%S [UTC]')
    except (TypeError, ValueError):
        return " ".join(date_string.split())


def get_status_emoji(status_text):
    status_text = status_text.lower()
    return {
        'pass': f"{status_text} ✅", 'fail': f"{status_text} ❌", 'softfail': f"{status_text} ⚠️",
        'temperror': f"{status_text} 🛠️", 'permerror': f"{status_text} 🛠️",
        'none': f"{status_text} ❔", 'neutral': f"{status_text} ❔",
        'bestguesspass': f"{status_text} 👀",
        'softpass': f"{status_text} 👀",
        'unknown': f"{status_text} ❔",
        'policy': f"{status_text} ⚠️",
        'error': f"{status_text} 🛠️",
    }.get(status_text, f"{status_text} 👀" if status_text else "unknown ❔")


def parse_auth_results(auth_header):
    if not auth_header or auth_header == "Not Found":
        return "None ❔"
    formatted_lines = []
    for auth_part in (raw_part.strip() for raw_part in auth_header.split(';') if raw_part.strip()):
        proto_status_match = _AUTH_PROTO_RE.search(auth_part)
        if proto_status_match:
            protocol_name = proto_status_match.group(1).lower()
            status_value = proto_status_match.group(2).lower()
            auth_part = _AUTH_PROTO_RE.sub(f"{protocol_name}={get_status_emoji(status_value)}",
                                           auth_part)
            if protocol_name == 'compauth':
                reason_match = _COMPAUTH_REASON_RE.search(auth_part)
                if reason_match:
                    reason_gloss, _reason_emoji = _compauth_reason_info(reason_match.group(1))
                    auth_part = f"{auth_part} ({reason_gloss})"
        formatted_lines.append("* " + auth_part)
    return defang("\n".join(formatted_lines))


def extract_domain(email_address):
    if not email_address or email_address == "Not Found":
        return None
    _display_name, parsed_address = parseaddr(email_address)
    if '@' in parsed_address:
        return parsed_address.split('@')[-1].strip().lower() or None
    return None


def verdict_label(verdict):
    return _LABELS.get(verdict, _LABELS["Unknown"])


def _sort_records(records, verdict_key='verdict'):
    return sorted(records,
                  key=lambda record: (_VERDICT_ORDER.get(record.get(verdict_key), 99),
                                      record['observable'].lower()))


# --- Observable filtering -----------------------------------------------------

@functools.lru_cache(maxsize=None)
def extract_host(observable):
    if not observable:
        return None
    if "://" in observable:
        hostname = urlparse(observable).hostname
    else:
        hostname = observable.split('/')[0].split(':')[0]
    return hostname.lower() if hostname else None


def unwrap_safelink(url):
    try:
        parsed_url = urlparse(url)
    except ValueError:
        return None
    wrapper_hostname = (parsed_url.hostname or '').lower()
    if not wrapper_hostname.endswith('safelinks.protection.outlook.com'):
        return None
    target_url = (parse_qs(parsed_url.query).get('url') or [None])[0]
    if not target_url:
        return None
    target_url = target_url.strip().rstrip('.,;:!?)]([\'"<>')
    return target_url if target_url.lower().startswith(('http://', 'https://')) else None


def _is_private_ip(hostname):
    try:
        ip_object = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return (ip_object.is_private or ip_object.is_loopback or ip_object.is_reserved
            or ip_object.is_link_local or ip_object.is_multicast)


def _is_ip(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


@functools.lru_cache(maxsize=None)
def registrable_domain(hostname):
    if not hostname:
        return None
    hostname = hostname.split(':')[0].strip().lower().rstrip('.')
    if _is_ip(hostname):
        return hostname
    extracted_parts = _TLD_EXTRACT(hostname)
    if extracted_parts.domain and extracted_parts.suffix:
        return f"{extracted_parts.domain}.{extracted_parts.suffix}"
    return None


_CONFUSABLE_SCRIPTS = {'LATIN', 'CYRILLIC', 'GREEK', 'ARMENIAN', 'CHEROKEE'}


def _label_scripts(label):
    label_scripts = set()
    for character in label:
        if character.isalpha():
            try:
                label_scripts.add(unicodedata.name(character).split()[0])
            except ValueError:
                pass
    return label_scripts


def _idna_encode(hostname):
    try:
        return hostname.encode('idna').decode('ascii')
    except Exception:
        return None


@functools.lru_cache(maxsize=None)
def normalized_host(hostname):
    if not hostname:
        return None, ()
    normalization_flags = []
    nfkc_form = unicodedata.normalize('NFKC', hostname)
    normalized = nfkc_form.strip().lower().rstrip('.')
    if nfkc_form != hostname:
        normalization_flags.append(
            f"compatibility chars normalized (NFKC): "
            f"{defang(hostname)} → {defang(normalized)}")
    for label in normalized.split('.'):
        mixed = _label_scripts(label) & _CONFUSABLE_SCRIPTS
        if len(mixed) > 1:
            normalization_flags.append(
                f"mixed-script label \"{defang(label)}\" "
                f"({'+'.join(sorted(mixed))}) — possible homoglyph")
            break
    if normalized.isascii():
        return normalized, tuple(normalization_flags)
    punycode = _idna_encode(normalized)
    if punycode:
        if normalization_flags:
            normalization_flags.append(f"scannable form: {punycode}")
        return punycode, tuple(normalization_flags)
    return None, tuple(normalization_flags)


def _rehost_url(url, new_host):
    try:
        parsed_url = urlparse(url)
        new_netloc = new_host
        if parsed_url.port:
            new_netloc = f"{new_host}:{parsed_url.port}"
        if parsed_url.username:
            userinfo = parsed_url.username
            if parsed_url.password:
                userinfo += f":{parsed_url.password}"
            new_netloc = f"{userinfo}@{new_netloc}"
        return urlunparse((parsed_url.scheme, new_netloc, parsed_url.path or '',
                           parsed_url.params, parsed_url.query, parsed_url.fragment))
    except (ValueError, UnicodeError):
        return url


def _build_whitelist(whitelist_entries):
    exact_hosts, wildcard_suffixes = set(), set()
    for whitelist_entry in whitelist_entries:
        if not whitelist_entry:
            continue
        entry_text = str(whitelist_entry).strip().lower()
        is_wildcard_entry = entry_text.startswith('*.')
        if is_wildcard_entry:
            entry_text = entry_text[2:]
        normalized_host = extract_host(entry_text) or entry_text
        normalized_host = normalized_host.split(':')[0].strip().lower().rstrip('.')
        if not normalized_host:
            continue
        (wildcard_suffixes if is_wildcard_entry else exact_hosts).add(normalized_host)
    return exact_hosts, wildcard_suffixes


def match_whitelist(hostname, exact_hosts, wildcard_suffixes):
    if not hostname:
        return None
    if hostname in exact_hosts:
        return hostname
    for wildcard_suffix in wildcard_suffixes:
        if hostname == wildcard_suffix or hostname.endswith('.' + wildcard_suffix):
            return f"*.{wildcard_suffix}"
    return None


# --- Private-scan escalation (runs AFTER the whitelist skip) --------------------

def collect_recipient_tokens(parsed_headers):
    recipient_tokens = set()
    raw_recipient_headers = []
    for recipient_header_name in ('To', 'Cc', 'Delivered-To', 'X-Original-To'):
        raw_recipient_headers.extend(parsed_headers.get_all(recipient_header_name) or [])
    for _display_name, recipient_address in getaddresses(raw_recipient_headers):
        recipient_address = recipient_address.strip().lower()
        if '@' not in recipient_address:
            continue
        recipient_tokens.add(recipient_address)
        local_part = recipient_address.split('@', 1)[0]
        candidate_fragments = [local_part, _LOCAL_PART_SEPARATOR_RE.sub('', local_part)]
        candidate_fragments.extend(_LOCAL_PART_SEPARATOR_RE.split(local_part))
        for candidate_fragment in candidate_fragments:
            if len(candidate_fragment) >= PRIVATE_SCAN_MIN_TOKEN_LENGTH:
                recipient_tokens.add(candidate_fragment)
    return recipient_tokens


def private_scan_reason(url, recipient_tokens):
    lowered_url_forms = {url.lower(), unicodedata.normalize('NFKC', url).lower()}
    try:
        decoded_url = unquote(url)
        lowered_url_forms.add(decoded_url.lower())
        lowered_url_forms.add(unicodedata.normalize('NFKC', decoded_url).lower())
    except Exception:
        pass
    for scan_keyword in sorted(PRIVATE_SCAN_KEYWORDS):
        if any(scan_keyword in lowered_url for lowered_url in lowered_url_forms):
            return f"contains keyword '{scan_keyword}'"
    for recipient_token in sorted(recipient_tokens, key=lambda token: (-len(token), token)):
        if any(recipient_token in lowered_url for lowered_url in lowered_url_forms):
            return f"contains recipient identifier '{recipient_token}'"
    return None


def is_scannable(observable):
    hostname = extract_host(observable)
    if not hostname or _is_private_ip(hostname):
        return False
    if _is_ip(hostname):
        return True
    if not _HOSTNAME_RE.match(hostname):
        return False
    return not hostname.endswith(('.local', '.internal', '.lan', '.localdomain', '.home.arpa'))


# --- RDAP creation date -------------------------------------------------------

def _normalize_date(date_value):
    if isinstance(date_value, list) and date_value:
        date_value = date_value[0]
    if not isinstance(date_value, str) or not date_value.strip():
        return None
    return date_value.strip().split('T')[0]


_CREATION_KEYS = {
    'creationdate', 'createddate', 'created', 'createdate',
    'registered', 'registrationdate', 'registrationtime', 'domaincreated',
}


def _search_creation_date(rdap_document):
    found_dates = []

    def walk(current_node):
        if isinstance(current_node, dict):
            event_action = current_node.get('eventAction') or current_node.get('action')
            if isinstance(event_action, str) and event_action.lower() == 'registration':
                normalized_date = _normalize_date(current_node.get('eventDate')
                                                  or current_node.get('date'))
                if normalized_date:
                    found_dates.append(normalized_date)
            for node_key, node_value in current_node.items():
                if isinstance(node_key, str) and node_key.lower() in _CREATION_KEYS:
                    normalized_date = _normalize_date(node_value)
                    if normalized_date:
                        found_dates.append(normalized_date)
                walk(node_value)
        elif isinstance(current_node, list):
            for list_item in current_node:
                walk(list_item)

    walk(rdap_document)
    iso_formatted_dates = [found_date for found_date in found_dates
                           if _DATE_RE.match(found_date)]
    return min(iso_formatted_dates) if iso_formatted_dates else \
        (found_dates[0] if found_dates else None)


def _iso_to_ddmmyyyy(iso_date):
    if not iso_date:
        return "Not Found"
    if _DATE_RE.match(iso_date):
        year_text, month_text, day_text = iso_date.split('-')
        return f"{day_text}-{month_text}-{year_text}"
    return iso_date


_RDAP_CACHE = {}


def rdap_creation_date(apex_domain):
    if not apex_domain or _is_ip(apex_domain):
        return None
    if apex_domain in _RDAP_CACHE:
        return _RDAP_CACHE[apex_domain]
    creation_date_iso = None
    try:
        rdap_response = _rdap_get(f'https://rdap.org/domain/{quote(apex_domain)}')
        if rdap_response is not None and rdap_response.status_code == 200:
            creation_date_iso = _search_creation_date(rdap_response.json())
    except (requests.RequestException, ValueError):
        creation_date_iso = None
    _RDAP_CACHE[apex_domain] = creation_date_iso
    return creation_date_iso


# --- URLScan.io ---------------------------------------------------------------

_NON_NETWORK_SCHEMES = ('data:', 'blob:', 'about:', 'chrome:', 'chrome-error:',
                        'chrome-extension:', 'javascript:', 'filesystem:')


def _urlscan_headers():
    return {'API-Key': os.getenv('URLSCAN_DAEMON'), 'Content-Type': 'application/json'}


def submit_scan(observable, api_headers, visibility="unlisted"):
    try:
        submit_response = _safe_request('POST', 'https://urlscan.io/api/v1/scan/',
                                        headers=api_headers,
                                        json={"url": observable, "visibility": visibility})
    except (requests.RequestException, ValueError):
        return {"status": "error", "message": "submit error ❌"}
    if submit_response.status_code == 200:
        response_body = submit_response.json()
        return {"status": "submitted", "api": response_body.get('api'),
                "result": response_body.get('result')}
    if submit_response.status_code == 400:
        return {"status": "error", "message": "n/a (blocked from scanning or invalid target)"}
    return {"status": "error", "message": f"submit failed (HTTP {submit_response.status_code}) ❌"}


def poll_result(result_api_url, api_headers):
    if not result_api_url:
        return None, "no result API URL ❌"
    polling_deadline = time.time() + URLSCAN_MAX_WAIT
    while time.time() < polling_deadline:
        try:
            poll_response = _safe_request('GET', result_api_url, headers=api_headers)
        except (requests.RequestException, ValueError):
            time.sleep(URLSCAN_POLL_INTERVAL)
            continue
        if poll_response.status_code == 200:
            return poll_response.json(), None
        if (poll_response.status_code == 404 or poll_response.status_code == 429
                or poll_response.status_code >= 500):
            time.sleep(URLSCAN_POLL_INTERVAL)
            continue
        return None, f"result HTTP {poll_response.status_code} ❌"
    return None, "timeout ⏳ (scan still processing)"


def _gsb_malicious(scan_result_data):
    gsb_data = (((scan_result_data.get('meta') or {}).get('processors') or {})
                .get('gsb') or {}).get('data')
    if isinstance(gsb_data, dict):
        return bool(gsb_data.get('matches'))
    if isinstance(gsb_data, list):
        return len(gsb_data) > 0
    return False


def get_screenshot_url(scan_result_data):
    task_info = scan_result_data.get('task') or {}
    screenshot_url = task_info.get('screenshotURL')
    if screenshot_url:
        return screenshot_url
    scan_uuid = task_info.get('uuid')
    return f"https://urlscan.io/screenshots/{scan_uuid}.png" if scan_uuid else None


def _canonical_url(url):
    try:
        parsed_url = urlparse((url or '').strip())
    except ValueError:
        return (url or '').strip().lower()
    url_scheme = (parsed_url.scheme or 'https').lower()
    network_location = parsed_url.netloc.lower()
    url_path = parsed_url.path or '/'
    if url_path != '/':
        url_path = url_path.rstrip('/') or '/'
    return urlunparse((url_scheme, network_location, url_path,
                       parsed_url.params, parsed_url.query, ''))


def urlscan_effective_url(scan_result_data):
    page_url = ((scan_result_data.get('page') or {}).get('url') or '').strip()
    return page_url if page_url.lower().startswith(('http://', 'https://')) else None


def urlscan_redirect_chain(scan_result_data, submitted_url):
    navigation_hops = [submitted_url]
    hop_initiators = []
    for redirect_entry in (scan_result_data.get('data') or {}).get('redirects') or []:
        redirect_target = (redirect_entry.get('to') or '').strip()
        if (redirect_target.lower().startswith(('http://', 'https://'))
                and _canonical_url(redirect_target) != _canonical_url(navigation_hops[-1])):
            navigation_hops.append(redirect_target)
            hop_initiators.append(redirect_entry.get('initiator'))
    effective_url = urlscan_effective_url(scan_result_data)
    if effective_url and _canonical_url(effective_url) != _canonical_url(navigation_hops[-1]):
        navigation_hops.append(effective_url)
        hop_initiators.append(None)
    return navigation_hops, [hop_initiator for hop_initiator in hop_initiators if hop_initiator]


def _is_network_request(recorded_request):
    request_block = recorded_request.get('request') or {}
    request_url = ((request_block.get('request') or {}).get('url') or '').strip().lower()
    document_url = (request_block.get('documentURL') or '').strip().lower()
    if not request_url.startswith(('http://', 'https://')):
        return False
    return not document_url.startswith(_NON_NETWORK_SCHEMES)


def urlscan_primary_error(scan_result_data):
    page_url = ((scan_result_data.get('page') or {}).get('url')
                or (scan_result_data.get('task') or {}).get('url') or '').strip().lower()
    fallback_error = None
    for recorded_request in (scan_result_data.get('data') or {}).get('requests') or []:
        request_block = recorded_request.get('request') or {}
        failure_block = (recorded_request.get('response') or {}).get('failed') or {}
        error_text = failure_block.get('errorText')
        if not error_text or failure_block.get('canceled'):
            continue
        request_url = ((request_block.get('request') or {}).get('url') or '').strip().lower()
        if request_block.get('primaryRequest') or (page_url and request_url == page_url):
            return error_text
        if request_block.get('type') == 'Document' and fallback_error is None:
            fallback_error = error_text
    return fallback_error


def urlscan_scan_failed(scan_result_data):
    result_lists = scan_result_data.get('lists') or {}
    page_info = scan_result_data.get('page') or {}
    network_data = scan_result_data.get('data') or {}

    contacted_ip = bool(result_lists.get('ips')) or bool(page_info.get('ip'))
    has_http_status = page_info.get('status') is not None

    got_response_bytes = False
    for recorded_request in network_data.get('requests') or []:
        if not _is_network_request(recorded_request):
            continue
        response_block = recorded_request.get('response') or {}
        if response_block.get('failed'):
            continue
        inner_response = response_block.get('response') or {}
        if (inner_response.get('status') is not None
                or (inner_response.get('encodedDataLength') or 0) > 0
                or (response_block.get('dataLength') or 0) > 0
                or (response_block.get('encodedDataLength') or 0) > 0):
            got_response_bytes = True
            break

    if not (contacted_ip or has_http_status or got_response_bytes):
        return True
    return (bool(urlscan_primary_error(scan_result_data))
            and not contacted_ip and not has_http_status)


# --- AlienVault OTX -----------------------------------------------------------

def _otx_headers():
    return {'X-OTX-API-KEY': os.getenv('ALIENVAULT_DAEMON'), 'Accept': 'application/json'}


_OTX_CACHE = {}


def _otx_link(indicator_type, indicator_value):
    indicator_kind = 'ip' if indicator_type in ('IPv4', 'IPv6') else 'domain'
    return f"https://otx.alienvault.com/indicator/{indicator_kind}/{indicator_value}"


def otx_lookup(observable, api_headers):
    hostname = extract_host(observable)
    if not hostname:
        return {"verdict": "Unknown", "pulses": None, "whitelisted": False, "link": None}
    if _is_ip(hostname):
        indicator_type, indicator_value = ('IPv6' if ':' in hostname else 'IPv4'), hostname
    else:
        indicator_type, indicator_value = 'domain', (registrable_domain(hostname) or hostname)

    cache_key = (indicator_type, indicator_value)
    if cache_key in _OTX_CACHE:
        return _OTX_CACHE[cache_key]

    lookup_result = {"verdict": "Unknown", "pulses": None, "whitelisted": False,
                     "link": _otx_link(indicator_type, indicator_value)}
    try:
        general_endpoint_url = (f"https://otx.alienvault.com/api/v1/indicators/"
                                f"{indicator_type}/{quote(indicator_value)}/general")
        otx_response = _safe_request('GET', general_endpoint_url, headers=api_headers)
        if otx_response.status_code == 200:
            response_data = otx_response.json()
            pulse_count = (response_data.get('pulse_info') or {}).get('count')
            is_otx_whitelisted = bool(response_data.get('validation'))
            lookup_result["pulses"] = pulse_count
            lookup_result["whitelisted"] = is_otx_whitelisted
            if (not is_otx_whitelisted and isinstance(pulse_count, int)
                    and pulse_count >= OTX_SUSPICIOUS_PULSES):
                lookup_result["verdict"] = "Suspicious"
            else:
                lookup_result["verdict"] = "Clean"
    except (requests.RequestException, ValueError):
        pass
    _OTX_CACHE[cache_key] = lookup_result
    return lookup_result


# --- VirusTotal ---------------------------------------------------------------

def _vt_headers():
    return {'x-apikey': os.getenv('VIRUSTOTAL_DAEMON'), 'Accept': 'application/json'}


def _vt_normalize_url(url):
    try:
        parsed_url = urlparse(url)
    except ValueError:
        return url
    url_scheme = (parsed_url.scheme or 'http').lower()
    network_location = parsed_url.netloc.lower()
    url_path = parsed_url.path or '/'
    return urlunparse((url_scheme, network_location, url_path,
                       parsed_url.params, parsed_url.query, parsed_url.fragment))


def _vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip('=')


def _vt_url_endpoints(observable):
    endpoint_pairs, seen_url_ids = [], set()
    for candidate_url in (_vt_normalize_url(observable), observable):
        url_id = _vt_url_id(candidate_url)
        if url_id in seen_url_ids:
            continue
        seen_url_ids.add(url_id)
        endpoint_pairs.append((f"https://www.virustotal.com/api/v3/urls/{url_id}",
                               f"https://www.virustotal.com/gui/url/{url_id}"))
    return endpoint_pairs


def _vt_object_endpoint(observable):
    hostname = extract_host(observable)
    if observable.startswith(('http://', 'https://')):
        api_url, gui_url = _vt_url_endpoints(observable)[0]
        return (api_url, gui_url, 'urls')
    if _is_ip(hostname):
        return (f"https://www.virustotal.com/api/v3/ip_addresses/{hostname}",
                f"https://www.virustotal.com/gui/ip-address/{hostname}", 'ip_addresses')
    apex_domain = registrable_domain(hostname) or hostname
    return (f"https://www.virustotal.com/api/v3/domains/{apex_domain}",
            f"https://www.virustotal.com/gui/domain/{apex_domain}", 'domains')


def _vt_verdict_from_stats(analysis_stats):
    malicious_count = analysis_stats.get('malicious', 0)
    suspicious_count = analysis_stats.get('suspicious', 0)
    total_count = sum(stat_value for stat_value in analysis_stats.values()
                      if isinstance(stat_value, int))
    if malicious_count > 0:
        verdict = "Malicious"
    elif suspicious_count > 0:
        verdict = "Suspicious"
    else:
        verdict = "Clean"
    return verdict, malicious_count, suspicious_count, total_count


def _poll_vt_analysis(analysis_id, api_headers, max_wait_seconds, poll_interval_seconds):
    polling_deadline = time.time() + max_wait_seconds
    while time.time() < polling_deadline:
        try:
            analysis_response = _safe_request(
                'GET', f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=api_headers)
            analysis_status = (((analysis_response.json() or {}).get('data') or {})
                               .get('attributes') or {}).get('status')
            if analysis_status == 'completed':
                return True
        except (requests.RequestException, ValueError):
            return False
        time.sleep(poll_interval_seconds)
    return False


def _vt_reanalyze_api(api_url, api_headers):
    try:
        reanalyze_response = _safe_request('POST', f"{api_url}/analyse",
                                           headers=api_headers)
        analysis_id = ((reanalyze_response.json() or {}).get('data') or {}).get('id')
    except (requests.RequestException, ValueError):
        return False
    if not analysis_id:
        return False
    return _poll_vt_analysis(analysis_id, api_headers,
                             VT_REANALYZE_MAX_WAIT, VT_REANALYZE_POLL)


def _vt_stale(last_analysis_epoch):
    if not last_analysis_epoch:
        return False
    try:
        return (time.time() - float(last_analysis_epoch)) > VT_STALE_MAX_AGE_DAYS * 86400
    except (TypeError, ValueError):
        return False


def vt_submit_url(url, api_headers):
    try:
        submit_headers = {**api_headers, 'Content-Type': 'application/x-www-form-urlencoded'}
        submit_response = _safe_request('POST', 'https://www.virustotal.com/api/v3/urls',
                                        headers=submit_headers, data={'url': url})
        if submit_response.status_code not in (200, 201):
            return False
        analysis_id = ((submit_response.json() or {}).get('data') or {}).get('id')
    except (requests.RequestException, ValueError):
        return False
    if not analysis_id:
        return False
    return _poll_vt_analysis(analysis_id, api_headers,
                             VT_URL_SUBMIT_MAX_WAIT, VT_URL_SUBMIT_POLL)


def vt_lookup(observable, api_headers, reanalyze=False, allow_submit=False):
    api_url, gui_url, object_kind = _vt_object_endpoint(observable)
    lookup_result = {"verdict": "Unknown", "malicious": 0, "suspicious": 0, "total": 0,
                     "reputation": None, "gui": gui_url, "absent": False,
                     "reanalyzed": False, "submitted": False, "stale": False}

    if reanalyze:
        lookup_result["reanalyzed"] = _vt_reanalyze_api(api_url, api_headers)

    candidate_endpoints = (_vt_url_endpoints(observable) if object_kind == 'urls'
                           else [(api_url, gui_url)])

    report_response = None
    selected_api_url, selected_gui_url = candidate_endpoints[0]
    for candidate_api_url, candidate_gui_url in candidate_endpoints:
        try:
            candidate_response = _safe_request('GET', candidate_api_url,
                                               headers=api_headers)
        except (requests.RequestException, ValueError):
            continue
        report_response = candidate_response
        selected_api_url, selected_gui_url = candidate_api_url, candidate_gui_url
        if candidate_response.status_code == 200:
            break

    if ((report_response is None or report_response.status_code == 404)
            and object_kind == 'urls' and allow_submit):
        if vt_submit_url(_vt_normalize_url(observable), api_headers):
            lookup_result["submitted"] = True
            selected_api_url, selected_gui_url = candidate_endpoints[0]
            try:
                report_response = _safe_request('GET', selected_api_url,
                                                headers=api_headers)
            except (requests.RequestException, ValueError):
                report_response = None

    if report_response is None:
        return lookup_result

    try:
        if report_response.status_code == 200:
            report_data = report_response.json().get('data') or {}
            report_attributes = report_data.get('attributes') or {}
            if _vt_stale(report_attributes.get('last_analysis_date')):
                lookup_result["stale"] = True
                if _vt_reanalyze_api(selected_api_url, api_headers):
                    lookup_result["reanalyzed"] = True
                    try:
                        refreshed_response = _safe_request('GET', selected_api_url,
                                                           headers=api_headers)
                        if refreshed_response.status_code == 200:
                            report_data = refreshed_response.json().get('data') or {}
                            report_attributes = report_data.get('attributes') or {}
                    except (requests.RequestException, ValueError):
                        pass
            verdict, malicious_count, suspicious_count, total_count = _vt_verdict_from_stats(
                report_attributes.get('last_analysis_stats') or {})
            lookup_result.update(verdict=verdict, malicious=malicious_count,
                                 suspicious=suspicious_count, total=total_count,
                                 reputation=report_attributes.get('reputation'),
                                 gui=selected_gui_url)
            if object_kind == 'urls' and report_data.get('id'):
                lookup_result["gui"] = f"https://www.virustotal.com/gui/url/{report_data['id']}"
        elif report_response.status_code == 404:
            lookup_result["absent"], lookup_result["verdict"] = True, "No VT record"
    except (requests.RequestException, ValueError):
        pass
    return lookup_result


def vt_file_lookup(sha256_digest, api_headers):
    lookup_result = {"verdict": "Unknown", "malicious": 0, "suspicious": 0, "total": 0,
                     "gui": f"https://www.virustotal.com/gui/file/{sha256_digest}",
                     "absent": False}
    try:
        file_report_response = _safe_request(
            'GET', f"https://www.virustotal.com/api/v3/files/{sha256_digest}",
            headers=api_headers)
        if file_report_response.status_code == 200:
            report_attributes = ((file_report_response.json().get('data') or {})
                                 .get('attributes') or {})
            verdict, malicious_count, suspicious_count, total_count = _vt_verdict_from_stats(
                report_attributes.get('last_analysis_stats') or {})
            lookup_result.update(verdict=verdict, malicious=malicious_count,
                                 suspicious=suspicious_count, total=total_count)
        elif file_report_response.status_code == 404:
            lookup_result["absent"], lookup_result["verdict"] = True, "No VT record"
    except (requests.RequestException, ValueError):
        pass
    return lookup_result


# --- AbuseIPDB ----------------------------------------------------------------

def _abuseipdb_headers():
    return {'Key': os.getenv('ABUSEIPDB_DAEMON'), 'Accept': 'application/json'}


def abuseipdb_check(ip_address_text, api_headers):
    check_result = {"score": None, "reports": None, "country": None, "usage": None,
                    "isp": None, "whitelisted": False, "verdict": "Unknown",
                    "link": f"https://www.abuseipdb.com/check/{ip_address_text}"}
    try:
        abuse_response = _safe_request('GET', 'https://api.abuseipdb.com/api/v2/check',
                                       headers=api_headers,
                                       params={'ipAddress': ip_address_text,
                                               'maxAgeInDays': ABUSEIPDB_MAX_AGE_DAYS})
        if abuse_response.status_code == 200:
            abuse_data = (abuse_response.json() or {}).get('data') or {}
            check_result.update(score=abuse_data.get('abuseConfidenceScore'),
                                reports=abuse_data.get('totalReports'),
                                country=abuse_data.get('countryName'),
                                usage=abuse_data.get('usageType'),
                                isp=abuse_data.get('isp'),
                                whitelisted=bool(abuse_data.get('isWhitelisted')))
            abuse_confidence_score = check_result["score"] or 0
            if check_result["whitelisted"] or abuse_confidence_score < ABUSE_SUSPICIOUS:
                check_result["verdict"] = "Clean"
            elif abuse_confidence_score >= ABUSE_MALICIOUS:
                check_result["verdict"] = "Malicious"
            else:
                check_result["verdict"] = "Suspicious"
    except (requests.RequestException, ValueError):
        pass
    return check_result


# --- Per-source record builders -----------------------------------------------

def build_url_record(url, urlscan_outcome, private_scan_note=None):
    scan_result_data = None
    urlscan_field, gsb_field, note, verdict = "n/a", None, None, "Unknown"
    report_url = screenshot_url = None
    effective_url = redirect_scope = redirect_via = None
    redirect_chain = []
    flagged_by, cleared_by = [], []

    if urlscan_outcome and urlscan_outcome["status"] == "submitted":
        report_url = urlscan_outcome.get("result")
        scan_result_data, poll_status_text = poll_result(urlscan_outcome.get("api"),
                                                         _urlscan_headers())
        if scan_result_data is None:
            urlscan_field = note = poll_status_text
    elif urlscan_outcome:
        urlscan_field = note = urlscan_outcome["message"]

    if scan_result_data is not None:
        screenshot_url = get_screenshot_url(scan_result_data)
        redirect_chain, hop_initiators = urlscan_redirect_chain(scan_result_data, url)
        if len(redirect_chain) > 1:
            effective_url = redirect_chain[-1]
            submitted_apex = registrable_domain(extract_host(url))
            effective_apex = registrable_domain(extract_host(effective_url))
            redirect_scope = ("off-domain" if submitted_apex != effective_apex
                              else "same-domain")
            redirect_via = ", ".join(dict.fromkeys(hop_initiators)) or None
        if urlscan_scan_failed(scan_result_data):
            primary_error = urlscan_primary_error(scan_result_data)
            urlscan_field = (f"could not scan ({primary_error})" if primary_error
                             else "could not scan (site unreachable)")
            note = ("urlscan could not load the site"
                    + (f" — {primary_error}" if primary_error else "")
                    + " (DNS/network failure, weak TLS, "
                      "or HTTP authentication required)")
            verdict = "Unknown"
        else:
            verdicts_block = scan_result_data.get('verdicts') or {}
            overall_verdict = verdicts_block.get('overall') or {}
            urlscan_verdict = verdicts_block.get('urlscan') or {}
            urlscan_flagged_malicious = bool(overall_verdict.get('malicious')
                                             or urlscan_verdict.get('malicious'))
            urlscan_score = overall_verdict.get('score', urlscan_verdict.get('score'))
            gsb_flagged_malicious = _gsb_malicious(scan_result_data)
            urlscan_field = "malicious" if urlscan_flagged_malicious else "clean"
            gsb_field = "malicious" if gsb_flagged_malicious else "clean"

            if (urlscan_flagged_malicious or gsb_flagged_malicious
                    or (isinstance(urlscan_score, (int, float))
                        and urlscan_score >= SCORE_MALICIOUS)):
                verdict = "Malicious"
            elif isinstance(urlscan_score, (int, float)) and urlscan_score >= SCORE_SUSPICIOUS:
                verdict = "Suspicious"
            else:
                verdict = "Clean"

            if urlscan_flagged_malicious or (isinstance(urlscan_score, (int, float))
                                             and urlscan_score >= SCORE_SUSPICIOUS):
                flagged_by.append(SRC_URLSCAN)
            else:
                cleared_by.append(SRC_URLSCAN)
            if gsb_flagged_malicious:
                flagged_by.append(SRC_GSB)
            else:
                cleared_by.append(SRC_GSB)

    return {'kind': 'url', 'observable': url, 'verdict': verdict,
            'first_source': SRC_URLSCAN,
            'urlscan_field': urlscan_field, 'gsb_field': gsb_field,
            'result_url': report_url, 'screenshot': screenshot_url,
            'note': note, 'private_scan': private_scan_note,
            'effective_url': effective_url, 'redirect_chain': redirect_chain,
            'redirect_scope': redirect_scope, 'redirect_via': redirect_via,
            'offsite_redirect': redirect_scope == "off-domain",
            'offsite_landing': False,
            'discovered_from': None, 'force_two_source': False,
            'flagged_by': flagged_by, 'cleared_by': cleared_by}


def build_whitelisted_url_record(url, url_hostname, matched_whitelist_entry):
    return {'kind': 'url', 'observable': url, 'verdict': "WhitelistSkip",
            'first_source': SRC_WHITELIST,
            'urlscan_field': f"Skipped (host matches {matched_whitelist_entry} in {SRC_WHITELIST})",
            'gsb_field': None, 'result_url': None, 'screenshot': None,
            'note': f"host {url_hostname} matches whitelist entry {matched_whitelist_entry}",
            'private_scan': None,
            'effective_url': None, 'redirect_chain': [], 'redirect_scope': None,
            'redirect_via': None, 'offsite_redirect': False,
            'offsite_landing': False,
            'discovered_from': None, 'force_two_source': False,
            'flagged_by': [], 'cleared_by': []}


def build_domain_record(domain, otx_api_headers):
    otx_result = otx_lookup(domain, otx_api_headers)
    verdict = otx_result['verdict']
    flagged_by = [SRC_OTX] if verdict in ("Suspicious", "Malicious") else []
    cleared_by = [SRC_OTX] if verdict == "Clean" else []
    created_iso = None if _is_ip(domain) else rdap_creation_date(domain)
    return {'kind': 'domain', 'observable': domain, 'verdict': verdict,
            'first_source': SRC_OTX, 'otx': otx_result,
            'created': _iso_to_ddmmyyyy(created_iso), 'created_iso': created_iso,
            'note': "inconclusive" if verdict == "Unknown" else None,
            'whitelisted': bool(otx_result.get('whitelisted')),
            'flagged_by': flagged_by, 'cleared_by': cleared_by}


def build_ip_record(ip_address_text, abuse_api_headers, is_sender=False):
    abuse_result = abuseipdb_check(ip_address_text, abuse_api_headers)
    verdict = abuse_result['verdict']
    flagged_by = [SRC_ABUSE] if verdict in ("Suspicious", "Malicious") else []
    cleared_by = [SRC_ABUSE] if verdict == "Clean" else []
    return {'kind': 'ip', 'observable': ip_address_text, 'verdict': verdict,
            'first_source': SRC_ABUSE, 'abuseipdb': abuse_result,
            'is_sender': is_sender,
            'whitelisted': bool(abuse_result.get('whitelisted')),
            'flagged_by': flagged_by, 'cleared_by': cleared_by}


# --- Per-section line formatters ----------------------------------------------

def format_url_line(record):
    line_fields = []
    if record.get('discovered_from'):
        line_fields.append(f"↩️ Effective URL of {defang(record['discovered_from'])}")
    line_fields.append(f"URLScan: {record['urlscan_field']}")
    if record.get('private_scan'):
        line_fields.append(f"🔒 Private scan ({record['private_scan']})")
    if record.get('gsb_field') is not None:
        line_fields.append(f"GSB: {record['gsb_field']}")
    if record.get('effective_url'):
        redirect_detail = record.get('redirect_scope') or "redirect"
        if record.get('redirect_via'):
            redirect_detail += f", via {record['redirect_via']}"
        hop_count = max(len(record.get('redirect_chain') or []) - 1, 1)
        if hop_count > 1:
            redirect_detail += f", {hop_count} hops"
        line_fields.append(f"↪️ Effective URL: {defang(record['effective_url'])} "
                           f"({redirect_detail})")
    if record.get('result_url'):
        line_fields.append(f"[Report]({record['result_url']})")
    if record.get('screenshot'):
        line_fields.append(f"[Screenshot]({record['screenshot']})")
    return (f"* *{defang(record['observable'])}*: **{verdict_label(record['verdict'])}** | "
            + " | ".join(line_fields))


def format_domain_line(record):
    otx_result = record['otx']
    whitelist_prefix = "**Whitelisted 🏳️** | " if otx_result.get('whitelisted') else ""
    pulse_count = otx_result.get('pulses')
    otx_text = (f"{whitelist_prefix}OTX: {otx_result.get('verdict', 'Unknown')} "
                f"({pulse_count if pulse_count is not None else 0} pulses)")
    line_fields = [otx_text, f"Created: {record['created']}"]
    if otx_result.get('link'):
        line_fields.append(f"[{SRC_OTX}]({otx_result['link']})")
    return (f"* *{defang(record['observable'])}*: **{verdict_label(record['verdict'])}** | "
            + " | ".join(line_fields))


def format_ip_line(record):
    abuse_result = record['abuseipdb']
    sender_tag = " _(SPF sender)_" if record.get('is_sender') else ""
    line_fields = [f"AbuseIPDB: {abuse_result['score']}/100"]
    if abuse_result["reports"] is not None:
        line_fields.append(f"Reports: {abuse_result['reports']}")
    if abuse_result["country"]:
        line_fields.append(f"Country: {abuse_result['country']}")
    if abuse_result["usage"]:
        line_fields.append(f"Usage Type: {abuse_result['usage']}")
    if abuse_result["isp"]:
        line_fields.append(f"ISP: {abuse_result['isp']}")
    if abuse_result["whitelisted"]:
        line_fields.append("Whitelisted")
    line_fields.append(f"[{SRC_ABUSE}]({abuse_result['link']})")
    return (f"* *{defang(record['observable'])}*{sender_tag}: "
            f"**{verdict_label(record['verdict'])}** | " + " | ".join(line_fields))


def format_two_source_line(record):
    vt_result = record['vt']
    line_parts = [f"{SRC_VT} verdict: {vt_result['verdict']}"]
    if not vt_result.get('absent'):
        line_parts.append(f"{SRC_VT} vendors: {vt_result['malicious']}/{vt_result['total']} malicious")
        if vt_result.get('suspicious'):
            line_parts.append(f"{SRC_VT} suspicious vendors: {vt_result['suspicious']}")
        if vt_result.get('reputation') is not None:
            line_parts.append(f"{SRC_VT} community score: {vt_result['reputation']}")
    if record.get('kind') != 'ip':
        line_parts.append(f"{SRC_RDAP} creation date: {_iso_to_ddmmyyyy(record.get('created_iso_dd'))}")
    if vt_result.get('submitted'):
        line_parts.append(f"{SRC_VT}: submitted on-demand")
    if vt_result.get('reanalyzed'):
        line_parts.append(f"{SRC_VT}: reanalyzed (report was >1y old)")
    line_parts.append(f"[{SRC_VT}]({vt_result['gui']})")
    return (f"* *{defang(record['observable'])}* — **{verdict_label(record['combined_verdict'])}** | "
            + " | ".join(line_parts))


# --- IP extraction ------------------------------------------------------------

def _public_ip(ip_token):
    try:
        ip_object = ipaddress.ip_address(ip_token)
    except ValueError:
        return None
    if (ip_object.is_private or ip_object.is_loopback or ip_object.is_reserved
            or ip_object.is_link_local or ip_object.is_multicast or ip_object.is_unspecified):
        return None
    return str(ip_object)


def find_sender_ip(parsed_headers):
    auth_results_text = parsed_headers.get('Authentication-Results', '') or ''
    sender_ip_match = (_CLIENT_IP_RE.search(auth_results_text)
                       or _SENDER_IP_RE.search(auth_results_text))
    return _public_ip(sender_ip_match.group(1)) if sender_ip_match else None


def collect_ips(parsed_headers):
    header_text_parts = []
    for ip_header_name in ('Received', 'Authentication-Results', 'X-Originating-IP',
                           'X-Sender-IP', 'X-SenderIP', 'X-Source-IP'):
        header_text_parts.extend(parsed_headers.get_all(ip_header_name) or [])
    combined_header_text = "\n".join(header_text_parts)

    ordered_public_ips, seen_ips = [], set()
    sender_ip = find_sender_ip(parsed_headers)
    if sender_ip:
        ordered_public_ips.append(sender_ip)
        seen_ips.add(sender_ip)
    for ip_token in (_IPV4_RE.findall(combined_header_text)
                     + _IPV6_RE.findall(combined_header_text)):
        public_ip = _public_ip(ip_token)
        if public_ip and public_ip not in seen_ips:
            seen_ips.add(public_ip)
            ordered_public_ips.append(public_ip)
    return ordered_public_ips, sender_ip


# --- Attachments --------------------------------------------------------------

def hash_attachments(raw_message_bytes):
    try:
        parsed_message = email.message_from_bytes(raw_message_bytes)
    except Exception:
        return []
    attachment_records = []
    for message_part in parsed_message.walk():
        if message_part.is_multipart():
            continue
        attachment_filename = message_part.get_filename()
        content_disposition = message_part.get_content_disposition() or ''
        if (message_part.get_content_maintype() == 'text' and not attachment_filename
                and content_disposition != 'attachment'):
            continue
        try:
            decoded_payload = message_part.get_payload(decode=True)
        except Exception:
            decoded_payload = None
        if not decoded_payload:
            continue
        content_id = message_part.get('Content-ID')
        attachment_name = decode_mime_words(attachment_filename) if attachment_filename else \
            (f"(inline {content_id.strip('<>')})" if content_id else "(unnamed)")
        attachment_records.append({'filename': attachment_name,
                                   'content_type': message_part.get_content_type(),
                                   'size': len(decoded_payload),
                                   'sha256': hashlib.sha256(decoded_payload).hexdigest()})
    return attachment_records


# --- Orchestration helpers ------------------------------------------------------

def decode_qp_for_urls(text):
    try:
        return quopri.decodestring(text.encode('utf-8', 'replace')).decode('utf-8', 'replace')
    except Exception:
        return text


def scan_invisibles(raw_header_text):
    decoded_text = decode_qp_for_urls(raw_header_text)
    invisible_lines, seen_hits = [], set()
    for character_index, character in enumerate(decoded_text):
        if unicodedata.category(character) == 'Cf':
            character_name = unicodedata.name(character, f"U+{ord(character):04X}")
            context_window = decoded_text[max(0, character_index - 12):character_index + 12]
            context_window = context_window.replace(character, '\u27e8?\u27e9')
            hit_key = (character_name, context_window)
            if hit_key not in seen_hits:
                seen_hits.add(hit_key)
                invisible_lines.append(f"  * {character_name} — near `{defang(context_window)}`")
    return invisible_lines


def collect_observables(raw_header_text, parsed_headers):
    decoded_text = strip_invisibles(decode_qp_for_urls(raw_header_text))
    found_urls, found_hostnames = set(), set()
    lookalike_notes, seen_note_keys = [], set()

    def record_flags(original_host, host_flags):
        for host_flag in host_flags:
            note_key = (original_host, host_flag)
            if note_key not in seen_note_keys:
                seen_note_keys.add(note_key)
                lookalike_notes.append(f"  * {defang(original_host)}: {host_flag}")

    for sender_header_name in ('From', 'Return-Path', 'Reply-To'):
        sender_domain = extract_domain(strip_invisibles(parsed_headers.get(sender_header_name, '')))
        if sender_domain:
            scannable_host, host_flags = normalized_host(sender_domain)
            record_flags(sender_domain, host_flags)
            found_hostnames.add(scannable_host or sender_domain)
    for raw_url in _URL_RE.findall(decoded_text):
        cleaned_url = raw_url.rstrip('.,;:!?)]([\'"<>')
        unwrapped_target_url = unwrap_safelink(cleaned_url)
        if unwrapped_target_url:
            cleaned_url = unwrapped_target_url
        url_hostname = extract_host(cleaned_url)
        if url_hostname:
            scannable_host, host_flags = normalized_host(url_hostname)
            record_flags(url_hostname, host_flags)
            if scannable_host and scannable_host != url_hostname:
                cleaned_url = _rehost_url(cleaned_url, scannable_host)
            found_hostnames.add(scannable_host or url_hostname)
        found_urls.add(cleaned_url)
    url_observables = sorted(found_url for found_url in found_urls if is_scannable(found_url))
    domain_observables = {apex_domain for found_hostname in found_hostnames
                          if (apex_domain := registrable_domain(found_hostname))
                          and is_scannable(apex_domain)}
    return url_observables, sorted(domain_observables), lookalike_notes


def _is_dangerous_attachment(content_type, filename):
    main_content_type = (content_type or '').split('/')[0].lower()
    return main_content_type not in _SKIPPED_ATTACHMENT_MAINTYPES


def _within_one_year(created_iso):
    try:
        year_number, month_number, day_number = map(int, created_iso.split('-'))
        elapsed_days = (date.today() - date(year_number, month_number, day_number)).days
        return elapsed_days < DEEPDIVE_MAX_AGE_DAYS
    except (ValueError, TypeError, AttributeError):
        return False


def _record_created_iso(record):
    if record.get('kind') == 'ip':
        return None
    if 'created_iso' in record:
        return record['created_iso']
    record_hostname = extract_host(record['observable'])
    apex_domain = registrable_domain(record_hostname) if record_hostname else None
    return rdap_creation_date(apex_domain) if apex_domain else None


def deepdive_escalation(vt_result, created_iso, kind='domain'):
    escalation_triggers = []
    vendor_detection_count = ((vt_result.get('malicious') or 0)
                              + (vt_result.get('suspicious') or 0))
    if vendor_detection_count:
        escalation_triggers.append(f"{vendor_detection_count} {SRC_VT} vendor detection"
                                   + ("s" if vendor_detection_count != 1 else ""))
    community_reputation = vt_result.get('reputation')
    if isinstance(community_reputation, int) and community_reputation < 0:
        escalation_triggers.append(f"{SRC_VT} community score {community_reputation}")
    if kind != 'ip':
        if not created_iso:
            escalation_triggers.append(f"{SRC_RDAP}: creation date not found")
        elif _within_one_year(created_iso):
            escalation_triggers.append(f"{SRC_RDAP}: registered within the last year")
    return escalation_triggers


# --- Two-source reconciliation ------------------------------------------------

def two_source_verdict(first_verdict, vt_result, kind):
    vt_record_absent = vt_result.get('absent')
    vt_verdict = None if vt_record_absent else vt_result.get('verdict')

    if vt_verdict == 'Malicious' or first_verdict == 'Malicious':
        return 'Suspicious' if kind == 'ip' else 'Malicious'
    if vt_verdict == 'Suspicious' or first_verdict == 'Suspicious':
        return 'NeedsReview'
    if first_verdict == 'Clean':
        return 'Clean'
    if vt_verdict == 'Clean':
        return 'NeedsReview'
    return 'Unknown'


# --- Watchlist reason building ------------------------------------------------

def _first_factor_detail(record):
    if record['kind'] == 'ip':
        abuse_result = record['abuseipdb']
        abuse_confidence_score = abuse_result.get('score', 0) or 0
        report_count = abuse_result.get('reports', 0) or 0
        return f"{SRC_ABUSE} {abuse_confidence_score}/100 ({report_count} reports)"
    if record['kind'] == 'domain':
        otx_result = record.get('otx', {})
        pulse_count = otx_result.get('pulses', 0) or 0
        return f"{SRC_OTX} ({pulse_count} pulses)"
    detail_bits = []
    if record.get('urlscan_field') == 'malicious':
        detail_bits.append(f"{SRC_URLSCAN} flagged malicious")
    elif record.get('urlscan_field') == 'clean':
        detail_bits.append(f"{SRC_URLSCAN} clean")
    elif record.get('urlscan_field'):
        detail_bits.append(f"{SRC_URLSCAN}: {record['urlscan_field']}")
    if record.get('gsb_field') == 'malicious':
        detail_bits.append(f"{SRC_GSB} flagged malicious")
    return "; ".join(detail_bits) if detail_bits else f"{SRC_URLSCAN}: inconclusive"


def build_watchlist_reason(record):
    reason_parts = []
    first_verdict = record['verdict']
    first_factor_text = _first_factor_detail(record)

    if first_verdict in ("Suspicious", "Malicious"):
        reason_parts.append(f"Flagged by {first_factor_text}")
    elif first_verdict == "Unknown":
        reason_parts.append(f"{first_factor_text} — inconclusive")
    elif first_verdict == "Clean":
        reason_parts.append(f"First factor clean ({first_factor_text})")

    if 'vt' in record:
        vt_result = record['vt']
        if vt_result.get('absent'):
            reason_parts.append(f"{SRC_VT}: no record")
        elif record.get('triggers'):
            reason_parts.append("; ".join(record['triggers']))
        else:
            vendor_summary = f"{vt_result.get('malicious', 0)}/{vt_result.get('total', 0)} malicious"
            reason_parts.append(f"{SRC_VT}: {str(vt_result.get('verdict', '')).lower()} ({vendor_summary})")

    if record.get('effective_url'):
        reason_parts.append(f"{SRC_URLSCAN}: redirects "
                            f"({record.get('redirect_scope') or 'redirect'}) to "
                            f"{defang(record['effective_url'])}")
    if record.get('discovered_from'):
        landing_scope = "off-domain " if record.get('offsite_landing') else ""
        reason_parts.append(f"{SRC_URLSCAN}: {landing_scope}effective URL of "
                            f"{defang(record['discovered_from'])}")

    if record.get('kind') == 'url' and record.get('domain_otx'):
        domain_otx_result = record['domain_otx']
        apex_domain = record.get('apex') or extract_host(record['observable'])
        pulse_count = domain_otx_result.get('pulses')
        reason_parts.append(f"{SRC_OTX} for {defang(apex_domain)}: "
                            f"{domain_otx_result.get('verdict', 'Unknown')} "
                            f"({pulse_count if pulse_count is not None else 0} pulses)")

    if record.get('recent') and not any('within the last year' in reason_part
                                        for reason_part in reason_parts):
        created_display = _iso_to_ddmmyyyy(record.get('created_iso_dd'))
        reason_parts.append(f"{SRC_RDAP}: registered within the last year ({created_display})")

    return "; ".join(reason_parts) if reason_parts else "inconclusive"


def watchlist_verdict(record):
    combined_verdict = record.get('combined_verdict')
    if combined_verdict in ('Malicious', 'Suspicious', 'Unknown', 'NeedsReview'):
        return combined_verdict
    if record['verdict'] == 'Clean' and (record.get('recent')
                                         or record.get('offsite_redirect')
                                         or record.get('offsite_landing')):
        return 'NeedsReview'
    return record['verdict']


def needs_watchlist(record):
    if record['verdict'] == 'WhitelistSkip':
        return False
    if record['verdict'] in ('Suspicious', 'Malicious', 'Unknown'):
        return True
    if record.get('combined_verdict') in ('Suspicious', 'Malicious', 'Unknown', 'NeedsReview'):
        return True
    if record.get('recent'):
        return True
    if record.get('offsite_redirect') or record.get('offsite_landing'):
        return True
    return False


def _attachment_watch_entry(attachment_record):
    vt_result = attachment_record.get('vt')
    if not vt_result:
        return None
    attachment_name = attachment_record['filename']
    if vt_result.get('absent'):
        return {'observable': attachment_name, 'verdict': 'Unknown',
                'reason': (f"{SRC_VT}: no record (file hash unseen — "
                           f"manual upload to {SRC_VT} may be needed)")}
    if vt_result['verdict'] in ('Suspicious', 'Malicious'):
        return {'observable': attachment_name, 'verdict': vt_result['verdict'],
                'reason': (f"Flagged by {SRC_VT} "
                           f"({vt_result.get('malicious', 0)}/{vt_result.get('total', 0)} malicious)")}
    return None


# --- Header indicators (anti-spam scores, alignment, display-name) ------------

def get_scl(parsed_headers):
    header_value = parsed_headers.get('X-MS-Exchange-Organization-SCL')
    if header_value is not None:
        try:
            return int(str(header_value).strip())
        except (TypeError, ValueError):
            pass
    for antispam_header_name in ('X-Forefront-Antispam-Report', 'X-Microsoft-Antispam'):
        scl_match = _SCL_RE.search(parsed_headers.get(antispam_header_name, '') or '')
        if scl_match:
            return int(scl_match.group(1))
    return None


def get_bcl(parsed_headers):
    for antispam_header_name in ('X-Microsoft-Antispam', 'X-Forefront-Antispam-Report'):
        bcl_match = _BCL_RE.search(parsed_headers.get(antispam_header_name, '') or '')
        if bcl_match:
            return int(bcl_match.group(1))
    return None


def _scl_label(scl_value):
    if scl_value < 0:
        return f"{scl_value} — bypassed spam filtering (allow-listed / internal) ✅"
    if scl_value <= 1:
        return f"{scl_value} — not spam ✅"
    if scl_value <= 4:
        return f"{scl_value} — undetermined ❔"
    if scl_value <= 6:
        return f"{scl_value} — spam ⚠️"
    return f"{scl_value} — high-confidence spam 📛"


def _bcl_label(bcl_value):
    if bcl_value == 0:
        return f"{bcl_value} — not from a bulk sender ✅"
    if bcl_value <= 3:
        return f"{bcl_value} — low bulk-complaint level ✅"
    if bcl_value <= 7:
        return f"{bcl_value} — moderate bulk-complaint level ⚠️"
    return f"{bcl_value} — high bulk-complaint level 📛"


def _compauth_reason_info(reason_code):
    reason_code = str(reason_code)
    specific_reason_codes = {
        '000': ('composite auth failed — sender published DMARC and it failed (explicit fail)', '❌'),
        '001': ('composite auth failed — implicit fail (no usable SPF/DKIM/DMARC)', '❌'),
        '002': ('overridden by an org policy / mail-flow rule', '⚠️'),
        '010': ('DMARC failed; the domain policy is p=reject/quarantine', '❌'),
        '100': ('passed — no DMARC record; composite auth passed via SPF and/or DKIM', '✅'),
    }
    if reason_code in specific_reason_codes:
        return specific_reason_codes[reason_code]
    if reason_code.startswith('1'):
        return ('composite authentication passed', '✅')
    if reason_code.startswith('2'):
        return ('passed, but the sender was allow-listed / overridden', '⚠️')
    if reason_code.startswith('3'):
        return ('failed, but delivered due to an allow-list / override', '⚠️')
    if reason_code.startswith('0'):
        return ('composite authentication failed', '❌')
    return ('see Microsoft compauth reason-code reference', '👀')


def _dkim_alignment_line(parsed_headers, from_hostname):
    auth_results_text = " ".join(
        " ".join(parsed_headers.get_all('Authentication-Results') or []).split())
    if not auth_results_text:
        return None
    dkim_signatures = []
    for auth_part in auth_results_text.split(';'):
        auth_part = auth_part.strip()
        status_match = _DKIM_STATUS_RE.match(auth_part)
        if not status_match:
            continue
        signing_domain_match = _DKIM_SIGNING_DOMAIN_RE.search(auth_part)
        signing_domain = (signing_domain_match.group(1).lower().rstrip('.')
                          if signing_domain_match else None)
        dkim_signatures.append((status_match.group(1).lower(), signing_domain))
    if not dkim_signatures:
        return None
    if not from_hostname:
        return "* **DKIM alignment:** From domain unknown ❔"
    from_registrable_domain = registrable_domain(from_hostname)
    passing_signatures = [dkim_signature for dkim_signature in dkim_signatures
                          if dkim_signature[0] == 'pass' and dkim_signature[1]]
    strict_aligned = [dkim_signature for dkim_signature in passing_signatures
                      if dkim_signature[1] == from_hostname]
    relaxed_aligned = [dkim_signature for dkim_signature in passing_signatures
                       if registrable_domain(dkim_signature[1])
                       and registrable_domain(dkim_signature[1]) == from_registrable_domain]
    if strict_aligned:
        return (f"* **DKIM alignment:** aligned — strict ✅ "
                f"(header.d={defang(strict_aligned[0][1])} ↔ From {defang(from_hostname)})")
    if relaxed_aligned:
        return (f"* **DKIM alignment:** aligned — relaxed ✅ "
                f"(header.d={defang(relaxed_aligned[0][1])} ↔ From {defang(from_hostname)}; "
                f"same org domain {defang(from_registrable_domain)}, subdomains differ)")
    signed_domains_text = ", ".join(f"{defang(dkim_signature[1])} [{dkim_signature[0]}]"
                                    for dkim_signature in dkim_signatures
                                    if dkim_signature[1]) or "n/a"
    return (f"* **DKIM alignment:** not aligned ⚠️ "
            f"(no passing DKIM matched From {defang(from_hostname)}; "
            f"signed by {signed_domains_text})")


def _decode_idna(hostname):
    try:
        return hostname.encode('ascii').decode('idna')
    except Exception:
        return None


def _display_name_flags(display_name, from_registrable_domain):
    spoofing_flags, seen_domains = [], set()
    if not display_name:
        return spoofing_flags
    for embedded_email in _EMAIL_IN_TEXT_RE.findall(display_name):
        embedded_domain = registrable_domain(embedded_email.split('@')[-1].lower())
        if (embedded_domain and from_registrable_domain
                and embedded_domain != from_registrable_domain
                and embedded_domain not in seen_domains):
            seen_domains.add(embedded_domain)
            spoofing_flags.append(f"display name embeds the address {defang(embedded_email)} "
                                  f"(domain {defang(embedded_domain)} ≠ actual sender "
                                  f"{defang(from_registrable_domain)})")
    for mentioned_domain in _DOMAIN_IN_TEXT_RE.findall(display_name):
        embedded_domain = registrable_domain(mentioned_domain.lower())
        if (embedded_domain and from_registrable_domain
                and embedded_domain != from_registrable_domain
                and embedded_domain not in seen_domains):
            seen_domains.add(embedded_domain)
            spoofing_flags.append(f"display name mentions the domain {defang(mentioned_domain)} "
                                  f"(≠ actual sender {defang(from_registrable_domain)})")
    return spoofing_flags


def _mixed_script_flags(from_hostname, display_name):
    spoofing_flags = []
    candidate_hostnames = set()
    if from_hostname:
        candidate_hostnames.add(from_hostname)
    for mentioned_domain in _DOMAIN_IN_TEXT_RE.findall(display_name or ''):
        candidate_hostnames.add(mentioned_domain.lower())
    for candidate_hostname in sorted(candidate_hostnames):
        scripts = set()
        for character in candidate_hostname:
            if character.isalpha():
                try:
                    scripts.add(unicodedata.name(character).split()[0])
                except ValueError:
                    pass
        interesting = scripts & {"LATIN", "CYRILLIC", "GREEK"}
        if len(interesting) > 1:
            spoofing_flags.append(f"mixed-script host {defang(candidate_hostname)} "
                                  f"({', '.join(sorted(interesting)).title()}) "
                                  f"— possible homograph / look-alike")
    return spoofing_flags


def _punycode_flags(from_hostname, display_name):
    spoofing_flags, candidate_hostnames = [], set()
    if from_hostname:
        candidate_hostnames.add(from_hostname)
    for mentioned_domain in _DOMAIN_IN_TEXT_RE.findall(display_name or ''):
        candidate_hostnames.add(mentioned_domain.lower())
    for candidate_hostname in sorted(candidate_hostnames):
        if any(hostname_label.startswith('xn--')
               for hostname_label in candidate_hostname.split('.')):
            decoded_hostname = _decode_idna(candidate_hostname)
            decoded_suffix = f" → decodes to \u201c{decoded_hostname}\u201d" if decoded_hostname else ""
            spoofing_flags.append(f"punycode/IDN domain {defang(candidate_hostname)}{decoded_suffix} "
                                  f"— possible homograph / look-alike")
    return spoofing_flags


def build_indicators_block(parsed_headers):
    indicator_lines = []
    raw_from_header = parsed_headers.get('From', '') or ''

    invisible_names = invisible_char_names(raw_from_header)
    sanitised_from_header = strip_invisibles(raw_from_header)

    from_display_name, from_address = parseaddr(sanitised_from_header)
    from_display_name = decode_mime_words(from_display_name) if from_display_name else ''
    if from_display_name == "Not Found":
        from_display_name = ''
    from_display_name = strip_invisibles(from_display_name)
    from_hostname = from_address.split('@')[-1].lower() if '@' in from_address else ''
    from_registrable = registrable_domain(from_hostname)

    if invisible_names:
        indicator_lines.append(f"* **Invisible characters:** {', '.join(invisible_names)} "
                               f"in From 📛 — evasion attempt (zero-width / bidi / format chars)")

    scl_value = get_scl(parsed_headers)
    if scl_value is not None:
        indicator_lines.append(f"* **SCL (Spam Confidence Level):** {_scl_label(scl_value)}")
    bcl_value = get_bcl(parsed_headers)
    if bcl_value is not None:
        indicator_lines.append(f"* **BCL (Bulk Complaint Level):** {_bcl_label(bcl_value)}")

    alignment_line = _dkim_alignment_line(parsed_headers, from_hostname)
    if alignment_line:
        indicator_lines.append(alignment_line)

    return_path_domain = registrable_domain(
        extract_domain(strip_invisibles(parsed_headers.get('Return-Path', ''))) or '')
    reply_to_domain = registrable_domain(
        extract_domain(strip_invisibles(parsed_headers.get('Reply-To', ''))) or '')
    if return_path_domain:
        if return_path_domain == from_registrable:
            indicator_lines.append(f"* **From ↔ Return-Path:** aligned ✅ "
                                   f"(same org domain {defang(from_registrable)})")
        else:
            indicator_lines.append(f"* **From ↔ Return-Path:** mismatch ⚠️ "
                                   f"(From {defang(from_registrable)} vs Return-Path "
                                   f"{defang(return_path_domain)})")
    if reply_to_domain:
        if reply_to_domain == from_registrable:
            indicator_lines.append(f"* **From ↔ Reply-To:** aligned ✅ "
                                   f"(same org domain {defang(from_registrable)})")
        else:
            indicator_lines.append(f"* **From ↔ Reply-To:** mismatch ⚠️ "
                                   f"(From {defang(from_registrable)} vs Reply-To "
                                   f"{defang(reply_to_domain)})")

    spoofing_flags = (_display_name_flags(from_display_name, from_registrable)
                      + _punycode_flags(from_hostname, from_display_name)
                      + _mixed_script_flags(from_hostname, from_display_name))
    if spoofing_flags:
        indicator_lines.append("* **Display-name check:** spoofing indicators 📛")
        for spoofing_flag in spoofing_flags:
            indicator_lines.append(f"  * {spoofing_flag}")
    elif from_registrable:
        displayed_name = defang(from_display_name) if from_display_name else "(no display name)"
        indicator_lines.append(f"* **Display-name check:** no look-alike detected ✅ "
                               f"(\"{displayed_name}\" / {defang(from_registrable)})")

    return indicator_lines


# --- URL scanning batches ---------------------------------------------------

def submit_url_batch(urls_to_scan, api_headers, recipient_tokens,
                     exact_whitelist_hosts, wildcard_whitelist_suffixes,
                     throttle_first=False):
    pending_submissions = {}
    needs_throttle = throttle_first
    for url_observable in urls_to_scan:
        if match_whitelist(extract_host(url_observable), exact_whitelist_hosts,
                           wildcard_whitelist_suffixes):
            continue
        escalation_reason = private_scan_reason(url_observable, recipient_tokens)
        scan_visibility = "private" if escalation_reason else "unlisted"
        if needs_throttle:
            time.sleep(URLSCAN_SUBMIT_THROTTLE)
        needs_throttle = True
        pending_submissions[url_observable] = {
            'outcome': submit_scan(url_observable, api_headers,
                                   visibility=scan_visibility),
            'private_reason': escalation_reason,
        }
    return pending_submissions


def build_url_record_batch(urls_to_scan, pending_submissions,
                           exact_whitelist_hosts, wildcard_whitelist_suffixes,
                           discovered_from=None):
    url_records = []
    for url_observable in urls_to_scan:
        url_hostname = extract_host(url_observable)
        matched_whitelist_entry = match_whitelist(url_hostname, exact_whitelist_hosts,
                                                  wildcard_whitelist_suffixes)
        if matched_whitelist_entry:
            url_record = build_whitelisted_url_record(url_observable, url_hostname,
                                                      matched_whitelist_entry)
        else:
            pending_submission = pending_submissions.get(url_observable) or {}
            url_record = build_url_record(
                url_observable, pending_submission.get('outcome'),
                private_scan_note=pending_submission.get('private_reason'))
        if discovered_from:
            parent_info = discovered_from.get(url_observable) or {}
            url_record['discovered_from'] = parent_info.get('parent')
            url_record['offsite_landing'] = parent_info.get('scope') == "off-domain"
            url_record['force_two_source'] = (FORCE_TWO_SOURCE_ON_DISCOVERED
                                              and url_record['verdict'] != 'WhitelistSkip')
        url_records.append(url_record)
    return url_records


def next_effective_urls(source_records, already_seen_urls, remaining_budget):
    discovered_urls, discovered_from = [], {}
    if not FOLLOW_EFFECTIVE_URLS or remaining_budget <= 0:
        return discovered_urls, discovered_from
    for source_record in source_records:
        effective_url = source_record.get('effective_url')
        if not effective_url or len(discovered_urls) >= remaining_budget:
            continue
        canonical_key = _canonical_url(effective_url)
        if canonical_key in already_seen_urls or not is_scannable(effective_url):
            continue
        already_seen_urls.add(canonical_key)
        discovered_urls.append(effective_url)
        discovered_from[effective_url] = {'parent': source_record['observable'],
                                          'scope': source_record.get('redirect_scope')}
    return discovered_urls, discovered_from


# --- The main pipeline --------------------------------------------------------

def run_osint(parsed_headers, url_observables, domain_observables, raw_message_bytes):
    urlscan_api_headers = _urlscan_headers()
    otx_api_headers = _otx_headers()
    vt_api_headers = _vt_headers()
    abuse_api_headers = _abuseipdb_headers()
    print()

    # --- Domains: AlienVault OTX is the sole first-factor verdict source ---
    domain_records = [build_domain_record(domain_observable, otx_api_headers)
                      for domain_observable in domain_observables]

    exact_whitelist_hosts, wildcard_whitelist_suffixes = _build_whitelist(WHITELISTED_DOMAINS)

    print("### Domains")
    print("---")
    if domain_records:
        for domain_record in _sort_records(domain_records):
            print(format_domain_line(domain_record))
    else:
        print("*No domains found.*")

    # --- URLs: URLScan.io is the sole first-factor verdict source ---
    recipient_tokens = collect_recipient_tokens(parsed_headers)
    pending_submissions = submit_url_batch(url_observables, urlscan_api_headers,
                                           recipient_tokens, exact_whitelist_hosts,
                                           wildcard_whitelist_suffixes)
    url_records = build_url_record_batch(url_observables, pending_submissions,
                                         exact_whitelist_hosts,
                                         wildcard_whitelist_suffixes)

    seen_url_keys = {_canonical_url(url_observable) for url_observable in url_observables}
    discovery_budget = DISCOVERY_MAX_URLS
    frontier_records = url_records
    discovered_url_records = []
    for _discovery_round in range(DISCOVERY_MAX_ROUNDS):
        discovered_urls, discovered_from = next_effective_urls(
            frontier_records, seen_url_keys, discovery_budget)
        if not discovered_urls:
            break
        discovery_budget -= len(discovered_urls)
        discovered_pending = submit_url_batch(discovered_urls, urlscan_api_headers,
                                              recipient_tokens, exact_whitelist_hosts,
                                              wildcard_whitelist_suffixes,
                                              throttle_first=True)
        frontier_records = build_url_record_batch(discovered_urls, discovered_pending,
                                                  exact_whitelist_hosts,
                                                  wildcard_whitelist_suffixes,
                                                  discovered_from=discovered_from)
        discovered_url_records.extend(frontier_records)
    url_records.extend(discovered_url_records)

    print("---")
    print("### URLs")
    print("---")
    if url_records:
        for url_record in _sort_records(url_records):
            print(format_url_line(url_record))
    else:
        print("*No URLs found.*")

    known_apex_domains = {domain_record['observable'] for domain_record in domain_records}
    redirect_domain_records = []
    for discovered_record in discovered_url_records:
        apex_domain = registrable_domain(extract_host(discovered_record['observable']))
        if (apex_domain and apex_domain not in known_apex_domains
                and is_scannable(apex_domain)):
            known_apex_domains.add(apex_domain)
            redirect_domain_records.append(build_domain_record(apex_domain,
                                                               otx_api_headers))
    if redirect_domain_records:
        print("---")
        print("### Domains (via redirects)")
        print("---")
        for redirect_domain_record in _sort_records(redirect_domain_records):
            print(format_domain_line(redirect_domain_record))
        domain_records.extend(redirect_domain_records)

    # --- IPs: AbuseIPDB is the sole first-factor verdict source ---
    print("---")
    print("### IPs")
    print("---")
    public_ips, sender_ip = collect_ips(parsed_headers)
    public_ips = public_ips[:ABUSEIPDB_MAX_IPS]
    ip_records = [build_ip_record(public_ip, abuse_api_headers,
                                  is_sender=(public_ip == sender_ip))
                  for public_ip in public_ips]
    if not ip_records:
        print("*No public IPs found in headers.*")
    for ip_record in _sort_records(ip_records):
        print(format_ip_line(ip_record))

    print("---")
    print("### Two-Source Verification")
    print("---")

    verification_candidates = [record for record in (domain_records + url_records + ip_records)
                               if record['verdict'] in ('Malicious', 'Suspicious', 'Unknown')
                               or record.get('force_two_source')]
    _severity_rank = {'Malicious': 0, 'Suspicious': 1, 'Unknown': 2}
    verification_candidates.sort(key=lambda record: (_severity_rank.get(record['verdict'], 3),
                                                     record['observable'].lower()))
    top_candidates = verification_candidates[:VT_MAX_LOOKUPS]
    overflow_candidates = verification_candidates[VT_MAX_LOOKUPS:]

    if not verification_candidates:
        print("*Nothing to verify — every indicator came back clean from its first-factor source.*")
    else:
        verified_records = []
        for lookup_index, candidate_record in enumerate(top_candidates):
            if lookup_index:
                time.sleep(VT_THROTTLE)
            allow_submit = (candidate_record['kind'] == 'url')
            vt_result = vt_lookup(candidate_record['observable'], vt_api_headers,
                                  reanalyze=VT_REANALYZE, allow_submit=allow_submit)
            created_iso = _record_created_iso(candidate_record)
            escalation_triggers = deepdive_escalation(vt_result, created_iso,
                                                      candidate_record['kind'])

            candidate_record['vt'] = vt_result
            candidate_record['vt_verdict'] = vt_result['verdict']
            candidate_record['created_iso_dd'] = created_iso
            candidate_record['triggers'] = escalation_triggers
            candidate_record['combined_verdict'] = two_source_verdict(
                candidate_record['verdict'], vt_result, candidate_record['kind'])
            if (vt_result['verdict'] in ('Suspicious', 'Malicious')
                    and SRC_VT not in candidate_record['flagged_by']):
                candidate_record['flagged_by'].append(SRC_VT)
            elif vt_result['verdict'] == 'Clean' and SRC_VT not in candidate_record['cleared_by']:
                candidate_record['cleared_by'].append(SRC_VT)
            verified_records.append(candidate_record)

        for verified_record in _sort_records(verified_records, verdict_key='combined_verdict'):
            print(format_two_source_line(verified_record))

        for overflow_record in overflow_candidates:
            print(f"* *{defang(overflow_record['observable'])}* — "
                  f"**{verdict_label(overflow_record['verdict'])}** "
                  f"(beyond top {VT_MAX_LOOKUPS}; check {SRC_VT} manually)")

    print("---")
    print("### Attachments")
    print("---")
    attachment_records = hash_attachments(raw_message_bytes)
    if not attachment_records:
        print("*No file attachments found. (Remote images referenced by the email "
              "are listed under URLs, not here.)*")
    vt_file_lookup_done = False
    for attachment_record in attachment_records:
        attachment_line = (f"* *{defang(attachment_record['filename'])}* "
                           f"({attachment_record['content_type']}, "
                           f"{attachment_record['size']} bytes) | "
                           f"SHA-256: `{attachment_record['sha256']}`")
        if _is_dangerous_attachment(attachment_record['content_type'],
                                    attachment_record['filename']):
            if vt_file_lookup_done:
                time.sleep(VT_THROTTLE)
            vt_file_lookup_done = True
            file_vt_result = vt_file_lookup(attachment_record['sha256'], vt_api_headers)
            attachment_record['vt'] = file_vt_result
            if file_vt_result.get('absent'):
                attachment_line += f" | {SRC_VT}: No record"
            else:
                attachment_line += (f" | {SRC_VT}: {file_vt_result['verdict']} "
                                    f"({file_vt_result['malicious']}/"
                                    f"{file_vt_result['total']} malicious)")
            attachment_line += f" | [{SRC_VT}]({file_vt_result['gui']})"
        print(attachment_line)

    print("---")
    print(f"### {WATCHLIST_PREVIEW_TITLE}")
    print("---")

    otx_results_by_apex = {domain_record['observable']: domain_record.get('otx')
                           for domain_record in domain_records}
    for record in domain_records + url_records:
        if record['verdict'] == 'WhitelistSkip':
            continue
        if record['kind'] == 'url':
            apex_domain = registrable_domain(extract_host(record['observable']))
            record['apex'] = apex_domain
            record['domain_otx'] = otx_results_by_apex.get(apex_domain)
        created_iso = record.get('created_iso_dd')
        if created_iso is None:
            created_iso = _record_created_iso(record)
            record['created_iso_dd'] = created_iso
        record['recent'] = bool(created_iso and _within_one_year(created_iso))

    watch_entries = []
    for record in url_records + domain_records + ip_records:
        if needs_watchlist(record):
            watch_entries.append({'observable': record['observable'],
                                  'verdict': watchlist_verdict(record),
                                  'reason': build_watchlist_reason(record)})
    for attachment_record in attachment_records:
        attachment_entry = _attachment_watch_entry(attachment_record)
        if attachment_entry:
            watch_entries.append(attachment_entry)

    seen_observables, deduped_watch_entries = set(), []
    for watch_entry in watch_entries:
        if watch_entry['observable'] in seen_observables:
            continue
        seen_observables.add(watch_entry['observable'])
        deduped_watch_entries.append(watch_entry)
    deduped_watch_entries.sort(key=lambda entry: (_VERDICT_ORDER.get(entry['verdict'], 99),
                                                  entry['observable'].lower()))

    if deduped_watch_entries:
        for watch_entry in deduped_watch_entries:
            print(f"* *{defang(watch_entry['observable'])}* — "
                  f"**{verdict_label(watch_entry['verdict'])}** — {watch_entry['reason']}")
    else:
        print("*Nothing on the watchlist.*")

    print("---")
    print(f"### {WATCHLIST_REVIEW_TITLE}")
    print("---")
    if deduped_watch_entries:
        for watch_entry in deduped_watch_entries:
            print(f"* *{defang(watch_entry['observable'])}* — "
                  f"**{verdict_label(watch_entry['verdict'])}**")
    else:
        print("*Nothing on the watchlist.*")


def analyze_headers(raw_header_text, raw_message_bytes=None):
    if raw_message_bytes is None:
        raw_message_bytes = raw_header_text.encode('utf-8', 'surrogateescape')

    if len(raw_header_text) > MAX_INPUT_BYTES:
        raw_header_text = raw_header_text[:MAX_INPUT_BYTES]
        print(f"> ⚠️ Input truncated to {MAX_INPUT_BYTES:,} chars for analysis.\n")

    parsed_headers = HeaderParser().parsestr(raw_header_text)

    print("# Headers Analysis")
    print("---")
    print("## Message Metadata")
    print(f"* **From:** {defang(decode_mime_words(parsed_headers.get('From')))}")
    print(f"* **To:** {defang(decode_mime_words(parsed_headers.get('To')))}")
    print(f"* **Subject:** {defang(decode_mime_words(parsed_headers.get('Subject')))}")
    print(f"* **Date:** {convert_to_utc(parsed_headers.get('Date', 'Not Found'))}")
    print(f"* **Reply-To:** {defang(decode_mime_words(parsed_headers.get('Reply-To', 'Not Found')))}")
    print(f"* **Return-Path:** {defang(decode_mime_words(parsed_headers.get('Return-Path', 'Not Found')))}")
    print(f"* **Message-ID:** {strip_terminal_controls(' '.join(parsed_headers.get('Message-ID', 'Not Found').split()))}")
    print("---")
    print("## Authentication Results")
    print("---")
    print("```")
    print(parse_auth_results(strip_terminal_controls(
        " ".join(parsed_headers.get('Authentication-Results', 'Not Found').split()))))
    print("```")
    print("---")

    indicator_lines = build_indicators_block(parsed_headers)
    if indicator_lines:
        print("## Anti-Spam & Spoofing Indicators")
        print("---")
        for indicator_line in indicator_lines:
            print(indicator_line)
        print("---")

    invisible_hits = scan_invisibles(raw_header_text)
    if invisible_hits:
        print("## Invisible / Format Characters")
        print("---")
        print("* **Detected in message body/headers 📛** — evasion attempt "
              "(zero-width / bidi / format chars):")
        for invisible_hit in invisible_hits:
            print(invisible_hit)
        print("---")

    url_observables, domain_observables, lookalike_notes = collect_observables(
        raw_header_text, parsed_headers)
    if lookalike_notes:
        print("## Look-alike / Normalized Hosts")
        print("---")
        print("* **Host normalization applied 📛** — homoglyph / compatibility "
              "characters detected and mapped to their scannable form:")
        for lookalike_note in lookalike_notes:
            print(lookalike_note)
        print("---")
    print("## OSINT Lookups")
    print("---")
    run_osint(parsed_headers, url_observables, domain_observables, raw_message_bytes)


if __name__ == "__main__":
    missing_env = [env_var for env_var in _REQUIRED_ENV if not os.getenv(env_var)]
    if missing_env:
        print(f"Missing required environment variables: {', '.join(missing_env)}",
              file=sys.stderr)
        print("Set them (e.g. in your .env) before running.", file=sys.stderr)
        sys.exit(1)

    print("Paste the raw email below.")
    print("Tip: paste the FULL message (headers + body) so attachments can be hashed; "
          "headers-only also works for everything except attachment hashing.")
    print("Or run non-interactively:  python header_analyzer.py < sample.eml")
    print("When finished, press Enter to go to a new line, then press Ctrl+D to run the analysis:\n")
    raw_message_bytes = sys.stdin.buffer.read()
    raw_input_text = raw_message_bytes.decode('utf-8', errors='surrogateescape')
    if raw_input_text.strip():
        analyze_headers(raw_input_text, raw_message_bytes)
    else:
        print("\nNo headers provided. Exiting daemon.")