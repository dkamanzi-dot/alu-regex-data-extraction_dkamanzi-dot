# ALU Regex Data Extraction & Secure Validation

A Python program that reads messy, realistic text (support ticket exports)
and extracts six types of structured data using regex, validates each
match, and rejects anything that looks unsafe rather than trusting it
automatically.

## Data types extracted

- **Emails** — classified into ALU Official (`@alueducation.com`), ALU
  Alumni (`@alumni.alueducation.com`), ALU SI (`@si.alueducation.com`), or
  external
- **Credit card numbers** — masked, showing only the last 4 digits
- **Phone numbers** — with or without a leading `+` country code
- **URLs**
- **Currency amounts** — RWF, USD, EUR, GBP, and `$` `€` `£` symbols
- **Hashtags**

## Folder structure

```
alu-regex-data-extraction_dkamanzi-dot/
├── input/
│   └── raw-text.txt        # sample raw text input
├── src/
│   └── main.py               # extraction, validation, and security logic
├── output/
│   └── sample-output.json    # generated report
└── README.md
```

## How to run

Requires Python 3.7+, standard library only — nothing to install.

```bash
cd src
python3 main.py
```

This reads `../input/raw-text.txt`, prints a console summary, and writes
`../output/sample-output.json`.

## How it works

Each data type is extracted with a regex, then validated in Python:

| Data type    | Regex matches                                                | Validation                                                                 |
|--------------|---------------------------------------------------------------|------------------------------------------------------------------------------|
| Email        | `local-part@domain.tld`                                       | Rejects `@@`, `..`, length > 254; classified by domain (SI → Alumni → Official, most specific checked first) |
| Credit card  | 15–16 digit sequences, optionally grouped with spaces/dashes  | Rejects wrong length and all-identical-digit numbers (e.g. `0000...0000`)   |
| Phone number | Optional country code, optional area code, grouped digits     | Rejects numbers outside 7–15 digits, and all-identical-digit numbers        |
| URL          | `http://` or `https://` followed by non-whitespace characters | Trailing sentence punctuation stripped; rejected if domain looks suspicious |
| Currency     | Currency code/symbol before or after a number                 | Requires an actual digit, not just a currency code next to a stray comma    |
| Hashtag      | `#` followed by a letter, then letters/digits/underscores      | —                                                                             |

## Security handling

- **`BAD_PATTERNS`** — a list of known attack signatures covering SQL
  injection, XSS/script injection, path traversal, command injection, and
  null-byte tricks.
- **Paragraph-level rejection** — every match is checked against the
  *entire message* it came from (`containing_paragraph()`), not just the
  matched text itself. If a message contains any hostile pattern, every
  value extracted from that message is rejected, not just the payload
  itself. This matters because an attack string is often placed next to a
  legitimate-looking value rather than inside it.
- **Suspicious domain check** — separate from attack-pattern detection,
  `is_suspicious_domain()` rejects URLs and emails on domains containing
  words like `scam`, `evil`, `fraud`, `phish`, `hack`. This is a
  lightweight safety net for obviously-named unsafe domains, not real
  threat intelligence — a genuine phishing domain is unlikely to spell out
  "scam" in its name, and that limitation is intentional rather than an
  oversight.
- **Deduplication** — the same phone number, card number, or URL appearing
  more than once in the text is only reported once.
- **Masking** — credit cards show only the last 4 digits, phone numbers
  only the last 3, and emails have their local part starred out while
  keeping the domain visible (needed to confirm ALU classification). No
  full, unmasked sensitive value is ever written to the console or to
  `sample-output.json`.

## Known limitations

- Credit card validation checks length and rejects all-identical-digit
  numbers, but does not run a full Luhn checksum — a fake number that
  happens to be the right length will pass.
- The suspicious-domain list is a small, explicit keyword list, not real
  domain reputation data.
- Phone and credit card regexes can overlap on long digit sequences (a
  16-digit card number can also get picked up as a phone-number candidate
  and correctly rejected there for being too long) — this shows up as the
  same number appearing in both a rejected phone list and a valid card
  list, which is expected behavior rather than a bug.
- Currency parsing does not handle amounts spelled out in words (e.g.
  "five hundred dollars") or negative amounts.

## Sample input and output

`input/raw-text.txt` is a set of realistic, messy support tickets covering
billing, alumni requests, security alerts, invoices, and enrollment, mixed
with a few deliberately unsafe entries (fake cards, injection attempts,
suspicious domains) to demonstrate the validation logic actually rejecting
things. `output/sample-output.json` is the exact result of running
`main.py` against that file.
