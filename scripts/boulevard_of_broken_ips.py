"""...I run a localhost, the only IP that I have ever known..."""

import argparse
import csv
import ipaddress
import os
import sys
import time
import requests
from collections import defaultdict
from dotenv import load_dotenv

load_dotenv()


# ---------------------------------------------------------------------------
# Outbound safety: the ONLY URLs this tool may ever contact.
# ---------------------------------------------------------------------------
ALLOWED_PREFIXES = ("https://api.abuseipdb.com/", "https://www.virustotal.com/")

# Human-facing result pages (used only to build Markdown links, never fetched).
ABUSE_GUI = "https://www.abuseipdb.com/check/{ip}"
VT_GUI = "https://www.virustotal.com/gui/ip-address/{ip}"


def safe_get(session, url, **request_kwargs):
    """A requests.get that refuses any URL outside the allowlist. This is the
    structural guarantee that we never connect to an analyzed IP."""
    if not url.startswith(ALLOWED_PREFIXES):
        raise ValueError(f"Refusing to connect to non-allowlisted URL: {url!r}")
    return session.get(url, **request_kwargs)


def valid_ip_literal(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Column detection
# ---------------------------------------------------------------------------
COLUMN_ALIASES = {
    "ip":       ["ip address", "ip", "ipaddress", "ip_address", "client ip"],
    "user":     ["user", "user display name", "user name", "display name"],
    "username": ["username", "upn", "user principal name", "sign-in identifier"],
    "location": ["location"],
    "status":   ["status", "sign-in error code", "result"],
}


def find_column(fieldnames, column_key):
    normalized_headers = {
        header_name.lower().strip(): header_name for header_name in fieldnames
    }
    for candidate_alias in COLUMN_ALIASES[column_key]:
        if candidate_alias in normalized_headers:
            return normalized_headers[candidate_alias]
    return None


# ---------------------------------------------------------------------------
# Load & aggregate sign-in rows
# ---------------------------------------------------------------------------
def load_signins(path):
    with open(path, newline="", encoding="utf-8-sig") as csv_file:
        reader = csv.DictReader(csv_file)
        fieldnames = reader.fieldnames or []

        columns = {
            column_key: find_column(fieldnames, column_key)
            for column_key in COLUMN_ALIASES
        }
        if not columns["ip"]:
            sys.exit(
                "Could not find an IP column in the CSV.\n"
                f"Headers seen: {fieldnames}\n"
                "Add the right header to COLUMN_ALIASES['ip'] if needed."
            )

        signins_by_ip = defaultdict(lambda: {
            "count": 0, "users": set(), "usernames": set(),
            "locations": set(), "statuses": set(),
        })

        for signin_row in reader:
            ip_address = (signin_row.get(columns["ip"]) or "").strip()
            if not ip_address:
                continue
            ip_record = signins_by_ip[ip_address]
            ip_record["count"] += 1
            if columns["user"] and signin_row.get(columns["user"]):
                ip_record["users"].add(signin_row[columns["user"]].strip())
            if columns["username"] and signin_row.get(columns["username"]):
                ip_record["usernames"].add(signin_row[columns["username"]].strip())
            if columns["location"] and signin_row.get(columns["location"]):
                ip_record["locations"].add(signin_row[columns["location"]].strip())
            if columns["status"] and signin_row.get(columns["status"]):
                ip_record["statuses"].add(signin_row[columns["status"]].strip())

    return signins_by_ip, columns


def classify_ip(ip_address):
    try:
        ip_object = ipaddress.ip_address(ip_address)
    except ValueError:
        return "invalid"
    if (ip_object.is_private or ip_object.is_loopback or ip_object.is_link_local
            or ip_object.is_reserved or ip_object.is_multicast):
        return "private"
    return "public"


# ---------------------------------------------------------------------------
# Reputation sources
# ---------------------------------------------------------------------------
def query_abuseipdb(ip_address, api_key, session, max_age=90, timeout=20):
    if not valid_ip_literal(ip_address):
        return {"_error": "abuseipdb: skipped, not a valid IP literal"}
    try:
        response = safe_get(
            session,
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip_address, "maxAgeInDays": max_age},
            timeout=timeout,
        )
        if response.status_code == 429:
            return {"_error": "abuseipdb: rate limited (429)"}
        if response.status_code in (401, 403):
            return {"_error": f"abuseipdb: auth failed ({response.status_code}) -- check ABUSEIPDB_DAEMON"}
        response.raise_for_status()
        abuse_data = response.json().get("data", {})
        return {
            "abuse_score": abuse_data.get("abuseConfidenceScore"),
            "abuse_country": abuse_data.get("countryCode"),
            "abuse_isp": abuse_data.get("isp"),
            "abuse_usage_type": abuse_data.get("usageType"),
            "abuse_total_reports": abuse_data.get("totalReports"),
            "abuse_last_reported": abuse_data.get("lastReportedAt") or "",
        }
    except requests.RequestException as request_error:
        return {"_error": f"abuseipdb: {request_error}"}


def query_virustotal(ip_address, api_key, session, timeout=20):
    if not valid_ip_literal(ip_address):
        return {"_error": "virustotal: skipped, not a valid IP literal"}
    try:
        response = safe_get(
            session,
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        if response.status_code == 429:
            return {"_error": "virustotal: rate limited (429)"}
        if response.status_code in (401, 403):
            return {"_error": f"virustotal: auth failed ({response.status_code}) -- check VIRUSTOTAL_DAEMON"}
        response.raise_for_status()
        attributes = response.json().get("data", {}).get("attributes", {})
        analysis_stats = attributes.get("last_analysis_stats", {})
        return {
            "vt_malicious": analysis_stats.get("malicious"),
            "vt_suspicious": analysis_stats.get("suspicious"),
            "vt_harmless": analysis_stats.get("harmless"),
            "vt_reputation": attributes.get("reputation"),
            "vt_as_owner": attributes.get("as_owner"),
        }
    except requests.RequestException as request_error:
        return {"_error": f"virustotal: {request_error}"}


def enrich(ip_address, args, session):
    reputation = {
        "abuse_score": None, "abuse_country": None, "abuse_isp": None,
        "abuse_usage_type": None, "abuse_total_reports": None, "abuse_last_reported": None,
        "vt_malicious": None, "vt_suspicious": None, "vt_harmless": None,
        "vt_reputation": None, "vt_as_owner": None, "errors": [],
    }
    if not args.no_abuse and args.abuse_key:
        abuse_result = query_abuseipdb(ip_address, args.abuse_key, session)
        if "_error" in abuse_result:
            reputation["errors"].append(abuse_result["_error"])
        else:
            reputation.update(abuse_result)
    if not args.no_vt and args.vt_key:
        virustotal_result = query_virustotal(ip_address, args.vt_key, session)
        if "_error" in virustotal_result:
            reputation["errors"].append(virustotal_result["_error"])
        else:
            reputation.update(virustotal_result)
    return reputation


def verdict(reputation, abuse_threshold=25):
    abuse_score = reputation.get("abuse_score")
    vt_malicious_count = reputation.get("vt_malicious")
    if ((isinstance(abuse_score, int) and abuse_score >= abuse_threshold)
            or (isinstance(vt_malicious_count, int) and vt_malicious_count >= 1)):
        return "NEEDS REVIEW 👀"
    if ((isinstance(abuse_score, int) and abuse_score > 0)
            or (isinstance(vt_malicious_count, int) and vt_malicious_count == 0
                and reputation.get("vt_suspicious"))):
        return "low"
    return "CLEAN ✅"


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------
def md_escape(value):
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def md_table(headers, rows):
    """Build a padded (shell-readable) Markdown table."""
    if rows:
        columns = list(zip(*([headers] + rows)))
    else:
        columns = [[header] for header in headers]
    column_widths = [max(len(str(cell)) for cell in column) for column in columns]

    def format_row(row_cells):
        padded_cells = [
            str(cell).ljust(column_widths[column_index])
            for column_index, cell in enumerate(row_cells)
        ]
        return "| " + " | ".join(padded_cells) + " |"

    separator = "| " + " | ".join("-" * width for width in column_widths) + " |"
    body_lines = [format_row(row) for row in rows]
    return "\n".join([format_row(headers), separator] + body_lines)


def truncate(text, max_length=42):
    text = str(text)
    return text if len(text) <= max_length else text[: max_length - 1] + "\u2026"


def render_report(rows, meta):
    report_lines = []
    report_lines.append("# Entra ID Sign-in IP Reputation Report\n")
    report_lines.append(f"- **Source CSV:** `{meta['input']}`")
    report_lines.append(f"- **Generated:** {meta['generated']}")
    report_lines.append(f"- **Unique IPs:** {meta['unique']} "
                        f"(queried {meta['queried']}, skipped {meta['skipped']} private/invalid)")
    report_lines.append(f"- **Sources:** AbuseIPDB {meta['abuse']}, VirusTotal {meta['vt']}")
    report_lines.append(f"- **Flagged for review:** {meta['flagged']}\n")

    headers = ["Verdict", "IP", "Sign-ins", "Account(s)", "Status", "Location(s)",
               "Abuse", "VT mal/susp", "Owner / ISP", "Links"]
    table_rows = []
    for report_row in rows:
        links = (f"[AbuseIPDB]({ABUSE_GUI.format(ip=report_row['ip'])}) · "
                 f"[VirusTotal]({VT_GUI.format(ip=report_row['ip'])})")
        abuse_score_display = "-" if report_row["abuse_score"] is None else str(report_row["abuse_score"])
        vt_display = "-"
        if report_row["vt_malicious"] is not None or report_row["vt_suspicious"] is not None:
            vt_display = f"{report_row['vt_malicious'] or 0}/{report_row['vt_suspicious'] or 0}"
        owner_display = report_row["vt_as_owner"] or report_row["abuse_isp"] or "-"
        table_rows.append([
            md_escape(report_row["verdict"]),
            md_escape(report_row["ip"]),
            md_escape(report_row["signin_count"]),
            md_escape(truncate(report_row["users"] or "-")),
            md_escape(report_row["statuses"] or "-"),
            md_escape(truncate(report_row["locations"] or "-")),
            md_escape(abuse_score_display),
            md_escape(vt_display),
            md_escape(truncate(owner_display, 28)),
            links,
        ])
    report_lines.append(md_table(headers, table_rows))

    rows_with_errors = [report_row for report_row in rows if report_row["errors"]]
    if rows_with_errors:
        report_lines.append("\n## Lookup errors\n")
        for report_row in rows_with_errors:
            report_lines.append(f"- `{report_row['ip']}`: {md_escape(report_row['errors'])}")

    if meta["skipped_list"]:
        report_lines.append("\n## Skipped (private / invalid, not queried)\n")
        report_lines.append(", ".join(
            f"`{skipped_ip}`" for skipped_ip, _classification in sorted(meta["skipped_list"])
        ))

    report_lines.append("")
    return "\n".join(report_lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Enrich Entra ID sign-in IPs with AbuseIPDB + VirusTotal (Markdown output).")
    parser.add_argument("-i", "--input", required=True, help="Entra sign-in CSV export")
    parser.add_argument("-o", "--output", help="Optional path to also write the Markdown report")
    parser.add_argument("--delay", type=float, default=16.0,
                        help="Seconds between IP lookups (default 16 to respect VirusTotal free 4/min)")
    parser.add_argument("--abuse-threshold", type=int, default=25,
                        help="AbuseIPDB confidence score at/above which an IP is flagged REVIEW")
    parser.add_argument("--no-abuse", action="store_true", help="Skip AbuseIPDB")
    parser.add_argument("--no-vt", action="store_true", help="Skip VirusTotal")
    parser.add_argument("--include-private", action="store_true",
                        help="Also query private/reserved IPs (off by default)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show exactly which API URLs WOULD be contacted; make no network requests")
    args = parser.parse_args()

    args.abuse_key = os.environ.get("ABUSEIPDB_DAEMON")
    args.vt_key = os.environ.get("VIRUSTOTAL_DAEMON")

    if not args.dry_run:
        if not args.no_abuse and not args.abuse_key:
            print("WARN: ABUSEIPDB_DAEMON not found -- AbuseIPDB lookups skipped.", file=sys.stderr)
        if not args.no_vt and not args.vt_key:
            print("WARN: VIRUSTOTAL_DAEMON not found -- VirusTotal lookups skipped.", file=sys.stderr)

    abuse_on = not args.no_abuse and (bool(args.abuse_key) or args.dry_run)
    vt_on = not args.no_vt and (bool(args.vt_key) or args.dry_run)
    if not abuse_on and not vt_on:
        sys.exit("No reputation source available: both sources are disabled or missing keys.")

    signins_by_ip, columns = load_signins(args.input)
    print(f"Loaded sign-ins for {len(signins_by_ip)} unique IP(s) from {args.input}", file=sys.stderr)
    print("Detected columns: { "
          + ", ".join(
              f"{column_key}={column_name!r}"
              for column_key, column_name in columns.items() if column_name
          )
          + " }", file=sys.stderr)

    ips_to_query, skipped_ips = [], []
    for ip_address in signins_by_ip:
        ip_classification = classify_ip(ip_address)
        if ip_classification == "public" or (ip_classification == "private" and args.include_private):
            ips_to_query.append((ip_address, ip_classification))
        else:
            skipped_ips.append((ip_address, ip_classification))
    ips_to_query.sort()

    if args.dry_run:
        print("\n--- DRY RUN: no network traffic will be generated ---", file=sys.stderr)
        print(f"Allowlisted endpoints: {list(ALLOWED_PREFIXES)}", file=sys.stderr)
        print(f"Would query {len(ips_to_query)} public IP(s). For each, the requests would be:", file=sys.stderr)
        for ip_address, _classification in ips_to_query:
            if abuse_on:
                print(f"  GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}", file=sys.stderr)
            if vt_on:
                print(f"  GET https://www.virustotal.com/api/v3/ip_addresses/{ip_address}", file=sys.stderr)
        print("\nNote: the analyzed IPs are only ever request PARAMETERS to the two "
              "allowlisted APIs above -- never connection destinations.", file=sys.stderr)
        return

    print(f"Querying {len(ips_to_query)} IP(s); skipping {len(skipped_ips)} private/invalid.", file=sys.stderr)

    session = requests.Session()
    report_rows, flagged_count = [], 0
    for query_index, (ip_address, ip_classification) in enumerate(ips_to_query):
        reputation = enrich(ip_address, args, session)
        ip_verdict = verdict(reputation, args.abuse_threshold)
        if ip_verdict == "NEEDS REVIEW 👀":
            flagged_count += 1
        signin_info = signins_by_ip[ip_address]
        report_rows.append({
            "ip": ip_address, "ip_type": ip_classification, "verdict": ip_verdict,
            "signin_count": signin_info["count"],
            "users": "; ".join(sorted(signin_info["usernames"] or signin_info["users"])),
            "statuses": "; ".join(sorted(signin_info["statuses"])),
            "locations": "; ".join(sorted(signin_info["locations"])),
            "abuse_score": reputation.get("abuse_score"), "abuse_isp": reputation.get("abuse_isp"),
            "vt_malicious": reputation.get("vt_malicious"), "vt_suspicious": reputation.get("vt_suspicious"),
            "vt_as_owner": reputation.get("vt_as_owner"),
            "errors": "; ".join(reputation.get("errors", [])),
        })
        print(f"  [{query_index + 1}/{len(ips_to_query)}] {ip_address:<16} -> {ip_verdict}", file=sys.stderr)
        if query_index < len(ips_to_query) - 1:
            time.sleep(args.delay)

    verdict_sort_order = {"NEEDS REVIEW 👀": 0, "low": 1, "CLEAN ✅": 2}
    report_rows.sort(key=lambda report_row: (
        verdict_sort_order.get(report_row["verdict"], 3), -report_row["signin_count"]
    ))

    meta = {
        "input": args.input,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "unique": len(signins_by_ip), "queried": len(ips_to_query), "skipped": len(skipped_ips),
        "abuse": "on" if abuse_on else "off", "vt": "on" if vt_on else "off",
        "flagged": flagged_count, "skipped_list": skipped_ips,
    }
    report = render_report(report_rows, meta)

    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as report_file:
            report_file.write(report)
        print(f"\nAlso wrote report to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()