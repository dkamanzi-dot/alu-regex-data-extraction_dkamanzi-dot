"""main.py - Data Extraction & Secure Validation Assignment"""

import re
import os
import json


base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
input_path = os.path.join(base_dir, "input", "raw-text.txt")

with open(input_path, "r") as f:
    text = f.read()

print("File loaded successfully")


# --- SECURITY ---

BAD_PATTERNS = [
    "or 1=1", "' or '1'='1", "drop table", "select * from", "delete from",
    "insert into", "update set", "union select", "; --",
    "xp_cmdshell", "waitfor delay",
    "<script", "<iframe", "<img", "<svg", "onerror=", "onload=",
    "onclick=", "onmouseover=", "javascript:", "data:text/html",
    "eval(", "document.cookie", "document.write", "alert(",
    "fromcharcode",
    "../", "..\\", "/etc/passwd", "/etc/shadow", "file:///", "%2e%2e%2f",
    "; rm -rf", "$(", "`whoami`", "&& curl", "| nc ",
    "%00",
]

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "scam", "malicious", "evil", "phish", "fraud", "hack", "stealer",
    "malware", "trojan", "not-a-scam",
]


def is_suspicious_domain(domain):
    domain = domain.lower()
    return any(keyword in domain for keyword in SUSPICIOUS_DOMAIN_KEYWORDS)


def has_suspicious_domain(url):
    domain_match = re.search(r"https?://([^/\s]+)", url, re.IGNORECASE)
    if not domain_match:
        return False
    return is_suspicious_domain(domain_match.group(1))


def is_malicious(chunk):
    lowered = chunk.lower()
    return any(pattern.lower() in lowered for pattern in BAD_PATTERNS)


def containing_paragraph(text, pos):
    start = text.rfind("\n\n", 0, pos)
    start = 0 if start == -1 else start + 2
    end = text.find("\n\n", pos)
    end = len(text) if end == -1 else end
    return text[start:end]


def mask_card(digits):
    return "**** **** **** " + digits[-4:]


def mask_phone(raw_phone):
    digits_only = re.sub(r"\D", "", raw_phone)
    if len(digits_only) <= 3:
        return "*" * len(digits_only)
    return "*" * (len(digits_only) - 3) + digits_only[-3:]


def mask_email(email):
    local, _, domain = email.partition("@")
    if len(local) <= 1:
        return local + "*@" + domain
    return local[0] + "*" * (len(local) - 1) + "@" + domain


# --- HASHTAGS ---

hashtag_pattern = r"#[a-zA-Z][a-zA-Z0-9_]*"
hashtags = []
for m in re.finditer(hashtag_pattern, text):
    ctx = containing_paragraph(text, m.start())
    if not is_malicious(ctx):
        hashtags.append(m.group())

print("\n--- Hashtags ---")
for tag in hashtags:
    print(tag)


# --- CURRENCY AMOUNTS ---

currency_pattern = (
    r"(?:RWF|USD|EUR|GBP)\s?\d[\d,]*(?:\.\d{2})?"
    r"|[$€£]\s?\d[\d,]*(?:\.\d{2})?"
    r"|\d[\d,]*(?:\.\d{2})?\s?(?:RWF|USD|EUR|GBP)"
)
currencies = []
for m in re.finditer(currency_pattern, text, re.IGNORECASE):
    ctx = containing_paragraph(text, m.start())
    if not is_malicious(ctx):
        currencies.append(m.group())

print("\n--- Currency Amounts ---")
for amount in currencies:
    print(amount)


# --- URLS ---

url_pattern = r"https?://[^\s\"'<>]+"
valid_urls = []
rejected_urls = []
seen_urls = set()
for m in re.finditer(url_pattern, text):
    url = m.group().rstrip(".,;:!?)")
    if url in seen_urls:
        continue
    seen_urls.add(url)
    ctx = containing_paragraph(text, m.start())
    if is_malicious(ctx) or is_malicious(url) or has_suspicious_domain(url):
        rejected_urls.append(url)
    else:
        valid_urls.append(url)

print("\n--- Valid URLs ---")
for url in valid_urls:
    print(url)
print("\n--- Rejected URLs ---")
for url in rejected_urls:
    print(url)


# --- PHONE NUMBERS ---

phone_pattern = (
    r"(?<!\w)(\+\d{1,3}[\s.-]?)?"
    r"(\(?\d{2,4}\)?[\s.-]?)?"
    r"\d{3,4}[\s.-]?\d{3,4}"
    r"(?:[\s.-]?\d{2,4})?"
    r"(?!\w)"
)
all_phones = re.finditer(phone_pattern, text)
valid_phones = []
rejected_phones = []
seen_phone_digits = set()
for m in all_phones:
    phone = m.group().strip().split("\n")[0].strip()
    ctx = containing_paragraph(text, m.start())
    digits_only = re.sub(r"\D", "", phone)

    if digits_only in seen_phone_digits:
        continue

    if is_malicious(ctx):
        rejected_phones.append(phone)
    elif len(digits_only) == 0:
        continue
    elif len(set(digits_only)) == 1:
        rejected_phones.append(phone)
    elif 7 <= len(digits_only) <= 15:
        valid_phones.append(mask_phone(phone))
    else:
        rejected_phones.append(phone)

    seen_phone_digits.add(digits_only)

print("\n--- Valid Phone Numbers (Masked) ---")
for phone in valid_phones:
    print(phone)
print("\n--- Rejected Phone Numbers ---")
for phone in rejected_phones:
    print(phone)


# --- CREDIT CARDS ---

card_pattern = r"\d{4}[\s\-]?\d{4,6}[\s\-]?\d{4,6}[\s\-]?\d{0,4}"
all_cards = re.finditer(card_pattern, text)
valid_cards = []
rejected_cards = []
seen_card_digits = set()
for m in all_cards:
    card = m.group()
    ctx = containing_paragraph(text, m.start())
    digits_only = re.sub(r"\D", "", card)

    if digits_only in seen_card_digits:
        continue
    seen_card_digits.add(digits_only)

    if is_malicious(ctx):
        rejected_cards.append(card.strip())
    elif len(digits_only) not in (15, 16):
        rejected_cards.append(card.strip())
    elif len(set(digits_only)) == 1:
        rejected_cards.append(card.strip())
    else:
        valid_cards.append(mask_card(digits_only))

print("\n--- Valid Credit Cards (Masked) ---")
for card in valid_cards:
    print(card)
print("\n--- Rejected Credit Cards ---")
for card in rejected_cards:
    print(card)


# --- EMAILS ---

email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
all_emails = list(set(re.findall(email_pattern, text)))
valid_emails = []
rejected_emails = []
alu_official = []
alu_alumni = []
alu_si = []
for email in all_emails:
    ctx_idx = text.find(email)
    ctx = containing_paragraph(text, ctx_idx) if ctx_idx != -1 else email

    if is_malicious(ctx):
        rejected_emails.append(email)
    elif "@@" in email:
        rejected_emails.append(email)
    elif ".." in email:
        rejected_emails.append(email)
    elif len(email) > 254:
        rejected_emails.append(email)
    elif is_suspicious_domain(email.split("@")[-1]):
        rejected_emails.append(email)
    else:
        valid_emails.append(mask_email(email))
        if email.endswith("@si.alueducation.com"):
            alu_si.append(mask_email(email))
        elif email.endswith("@alumni.alueducation.com"):
            alu_alumni.append(mask_email(email))
        elif email.endswith("@alueducation.com"):
            alu_official.append(mask_email(email))

print("\n--- Valid Emails (Masked) ---")
for email in valid_emails:
    print(email)
print("\n--- ALU Official ---")
for email in alu_official:
    print(email)
print("\n--- ALU Alumni ---")
for email in alu_alumni:
    print(email)
print("\n--- ALU SI ---")
for email in alu_si:
    print(email)
print("\n--- Rejected Emails ---")
for email in rejected_emails:
    print(email)


# --- SAVE RESULTS ---

results = {
    "hashtags": hashtags,
    "currency_amounts": currencies,
    "urls": {
        "valid": valid_urls,
        "rejected": rejected_urls
    },
    "phone_numbers": {
        "valid": valid_phones,
        "rejected": rejected_phones
    },
    "credit_cards": {
        "valid": valid_cards,
        "rejected": rejected_cards
    },
    "emails": {
        "valid": valid_emails,
        "alu_official": alu_official,
        "alu_alumni": alu_alumni,
        "alu_si": alu_si,
        "rejected": rejected_emails
    }
}

output_path = os.path.join(base_dir, "output", "sample-output.json")
with open(output_path, "w") as f:
    json.dump(results, f, indent=2)

print("\n--- Done ---")
print(f"Results saved to {output_path}")