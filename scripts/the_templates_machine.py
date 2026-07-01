"""...goin' around like a resolver, it's been decided how we glue..."""

import re
import sys
from email.parser import HeaderParser
from email.utils import parseaddr

# --- Defang -------------------------------------------------------------------

def defang(text):
    """Make URLs / domains / IPs click-safe. For email addresses ONLY the
    domain is defanged (name.surname@email.com -> name.surname@email[.]com): the
    (?![local]*@) lookahead skips any dot that sits in the local-part before an
    @. Kept in sync with the analyzer's defang()."""
    if not text or text == "Not Found":
        return text
    text = re.sub(r'(?i)http', 'hxxp', text)
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                  lambda m: m.group(0).replace('.', '[.]'), text)
    text = re.sub(
        r'(?<!\bheader)(?<!\bsmtp)(?<!\bcompauth)\.(?![a-zA-Z0-9._%+-]*@)(?=[a-zA-Z]{2,}\b)',
        '[.]', text)
    return text


# --- Defender XDR -------------------------------------------------------------
# Only <DEFANGED_SENDER> and <DEFANGED_RECIPIENT> get auto-filled; every other
# placeholder (counts, subjects, screenshots, users, the optional [ ... ] click
# block) is left exactly as written for the analyst to complete by hand.
DEFENDER_XDR_TEMPLATE = """# Defender XDR
---
* The sender <DEFANGED_SENDER> delivered <NUMBER> email(s) in the last month. [The subject(s) included "<SUBJECT_1>", "<SUBJECT_2>", among others.]
---
* {No|NUMBER} URL click(s) {was|were} found over the last month.
  <SCREENSHOT_EXPLORER>
  <SCREENSHOT_HUNTING>
---
[ 
* The URL click(s) {was|were} performed by:
  * <USER_1>
  * <USER_2>
---
* The following are the targeted URL(s):
  * <DEFANGED_URL> - **Clicked by <USER>**
]
* The user <DEFANGED_RECIPIENT> (<BUNIT>) has received <NUMBER> email(s) from <DEFANGED_SENDER> during the last month.
  <SCREENSHOT_EXPLORER>
---
* There was [not] interaction with <DEFANGED_SENDER> for the last month.
  <SCREENSHOT_EXPLORER>"""


def build_defender_xdr(headers):
    """Fill ONLY the sender/recipient placeholders from the parsed headers,
    leaving the rest of the template untouched. Uses str.replace (not .format)
    so the literal {No|NUMBER} / {was|were} braces survive verbatim."""
    sender = defang(parseaddr(headers.get('From', ''))[1]) or "<DEFANGED_SENDER>"
    recipient = defang(parseaddr(headers.get('To', ''))[1]) or "<DEFANGED_RECIPIENT>"
    return (DEFENDER_XDR_TEMPLATE
            .replace('<DEFANGED_SENDER>', sender)
            .replace('<DEFANGED_RECIPIENT>', recipient))


# --- Registry -----------------------------------------------------------------
# (title, builder) pairs in render order. Add new templates here and they will
# be rendered automatically. `title` is metadata for you (each template usually
# carries its own header), keeping the registry self-documenting as it grows.
TEMPLATES = [
    ("Defender XDR", build_defender_xdr),
]


def build_all(headers):
    """Render every registered template, separated by blank lines."""
    return "\n\n".join(builder(headers) for _title, builder in TEMPLATES)


if __name__ == "__main__":
    print("Paste the raw email (headers are enough) below.")
    print("When finished, press Enter to go to a new line, then press Ctrl+D to "
          "render the templates:\n")
    raw = sys.stdin.buffer.read().decode('utf-8', errors='surrogateescape')
    if raw.strip():
        headers = HeaderParser().parsestr(raw)
        print()
        print(build_all(headers))
    else:
        print("\nNo input provided. Exiting.")