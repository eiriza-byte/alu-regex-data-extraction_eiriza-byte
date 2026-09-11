# ALU Regex Data Extraction & Secure Validation

## What this does

This program reads a raw text file and pulls out four types of data using regex:

- Email addresses
- Credit card numbers
- Phone numbers
- URLs 

It also scans the text for signs of an attack — things like script
tags, SQL injection attempts, and suspicious `javascript:` links —
and reports those separately instead of treating them as normal data.

## ALU email validation

Emails ending in these domains are marked as verified ALU addresses:
- `@alueducation.com`
- `@alumni.alueducation.com`
- `@si.alueducation.com`

## Security handling

- Credit card numbers and emails are masked before being saved to the
  output file (e.g. a card shows as `****-****-****-1234`, not the
  full number).
- Card numbers are checked against the Luhn algorithm so fake numbers can be flagged.
- Already-redacted card numbers in the source text (like
  `**** **** **** 5678`) are recognized and skipped, not
  reconstructed.

## Project structure

\```
alu-regex-data-extraction_eiriza-byte/
├── input/
│   └── raw-text.txt      
├── src/
│   └── main.py            
├── output/
│   └── sample-output.json 
└── README.md
\```

## How to run it

Run using python3:

python3 src/main.py
\```

This reads `input/raw-text.txt` and writes the results to
`output/sample-output.json`. It also prints a short summarry, for example:

\```
Scanned input/raw-text.txt - results written to output/sample-output.json
  emails: 9
  card_numbers: 4
  phone_numbers: 5
  links: 9
  security_alerts: 5
\```

