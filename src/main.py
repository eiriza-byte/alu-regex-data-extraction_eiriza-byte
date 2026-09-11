import json
import re
from pathlib import Path

raw_file = Path("input/raw-text.txt")
output_file = Path("output/sample-output.json")
#regex for emails
email = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
#regex for credit cards and those that have been redacted
card = re.compile(r"\b(?:\d[ -]?){13,19}\b")
Redacted = re.compile(r"(?:\*{2,4}[ -]?){2,4}\d{4}\b")
#regex for phone numbers
phone = re.compile(r"(?:\+d{1,3}[\s.-]?)?"
        r"(?:\(\d{2,4}\)[\s.-]?)?"
        r"\d{2,4}[\s.-]\d{3,4}[\s.-]\d{3,4}"
)
#regex for the url links
url = re.compile(r"(?:https?://|www\.)[^\s<>\"'\\]+")
#this part detects attacks
threats = {
    "script_injection": re.compile(r"<script\b", re.IGNORECASE),
    "inline_js_handler": re.compile(
        r"\bon(?:click|error|load|mouseover)\s*=", re.IGNORECASE
    ),
    "javascript_uri": re.compile(r"javascript:", re.IGNORECASE),
    "sql_injection": re.compile(
        r"(?:;|--|')\s*(?:DROP|DELETE|SELECT|UNION)\b", re.IGNORECASE
    ),
}
#a list that stores alu emails as tuples
alu_domain = [
    ("alumni", "@alumni.alueducation.com"),
    ("si", "@si.alueducation.com"),
    ("official", "@alueducation.com"),
]
#this is a dictionary that matches card names to the start of their card numbers
card_prefix = {
    "Visa": re.compile(r"^4"),
    "Mastercard": re.compile(r"^5[1-5]"),
    "Amex": re.compile(r"^3[47]"),
    "Discover": re.compile(r"^6011|^65"),
}
def load_ticket(path):
    #checks if ticket exists at path
    if not path.exists():
        print(f" Could not find ticket export at: {path}")
        return None
    return path.read_text(encoding="utf-8")

def luhn_check(digits):    
    total = 0
    for position, character in enumerate(reversed(digits)):
        value = int(character)
        if position % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0
#returns the card's owner name thats matches a prefix
def card_issuer(digits):
    for issuer_name, prefix_pattern in card_prefix.items():
        if prefix_pattern.match(digits):
            return issuer_name
    return None
#this decides whether an email is real
def identify_alu_address(email):
    #rejects a domain like alueducation.com.evil.net
    lowered = email.lower()
    for category, required_ending in alu_domain:
        if lowered.endswith(required_ending):
            return category
    if "alueducation" in lowered:
        return "lookalike"
    return None
def hide_email(email):
    local_part, _, domain_part = email.partition("@")
    if len(local_part) <= 1:
        blurred = "*"
    else:
        blurred = local_part[0] + "*" * (len(local_part) - 1)
    return f"{blurred}@{domain_part}"
def hide_card(digits):
    return "*" * (len(digits) - 4) + digits[-4:]
 
 
def hide_phone(raw_phone):
    digits = re.sub(r"\D", "", raw_phone)
    return "***-***-" + digits[-4:]
 
#this looks for attack patterns in the data
def scan_for_threats(full_text):
    alerts = []
    for line in full_text.splitlines():
        for threat_name, pattern in threats.items():
            if pattern.search(line):
                alerts.append({
                    "threat": threat_name,
                    "line_excerpt": line.strip()[:100],
                })
    return alerts
 
 
def collect_emails(full_text):
    results = []
    for match in email.finditer(full_text):
        address = match.group()
        alu_status = identify_alu_address(address)
        results.append({
            "masked": hide_email(address),
            "alu_category": alu_status,
            "is_verified_alu": alu_status in ("official", "alumni", "si"),
        })
    return results
def collect_cards(full_text):
    results = []
    redacted_spans = [m.span() for m in Redacted.finditer(full_text)]
 
    for match in card.finditer(full_text):
        inside_redacted_zone = any(
            match.start() < end and match.end() > start
            for start, end in redacted_spans
        )
        if inside_redacted_zone:
            continue
 
        digits = re.sub(r"[ -]", "", match.group())
        if not (13 <= len(digits) <= 19):
            continue
 
        issuer = card_issuer(digits)
        valid = luhn_check(digits)
        if issuer is None and not valid:
            continue  # neither a known prefix nor a valid checksum
 
        results.append({
            "masked": hide_card(digits),
            "issuer": issuer or "unrecognised",
            "passes_luhn": valid,
        })
 
    return results, [m.span() for m in card.finditer(full_text)]
 
 
def collect_phones(full_text, spans_to_avoid):
    """spans_to_avoid keeps this from matching a slice of a card number."""
    results = []
    for match in phone.finditer(full_text):
        overlaps_a_card = any(
            match.start() < end and match.end() > start
            for start, end in spans_to_avoid
        )
        if overlaps_a_card:
            continue
 
        digit_count = len(re.sub(r"\D", "", match.group()))
        if digit_count < 7:
            continue
 
        results.append(hide_phone(match.group()))
    return results
 
 
def collect_links(full_text):
    results = []
    for match in url.finditer(full_text):
        link = match.group().rstrip(".,;")
        looks_phishy = bool(
            re.search(r"verify-login|verify-now|\.local\b", link, re.IGNORECASE)
        )
        results.append({"link": link, "flagged_as_phishing_style": looks_phishy})
    return results
 
 
def scan_ticket_export():
    full_text = load_ticket(raw_file)
    if full_text is None:
        return
 
    emails_found = collect_emails(full_text)
    cards_found, card_spans = collect_cards(full_text)
    phones_found = collect_phones(full_text, card_spans)
    links_found = collect_links(full_text)
    threats_found = scan_for_threats(full_text)
 
    report = {
        "source_file": str(raw_file),
        "emails": emails_found,
        "card_numbers": cards_found,
        "phone_numbers": phones_found,
        "links": links_found,
        "security_alerts": threats_found,
        "totals": {
            "emails": len(emails_found),
            "card_numbers": len(cards_found),
            "phone_numbers": len(phones_found),
            "links": len(links_found),
            "security_alerts": len(threats_found),
        },
    }
 
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
 
    print(f"Scanned {raw_file} - results written to {output_file}")
    for label, count in report["totals"].items():
        print(f"  {label}: {count}")
 
 
if __name__ == "__main__":
    scan_ticket_export()
 
