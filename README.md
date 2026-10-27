# Bulk Email Verifier

A small Flask platform that checks up to 10,000 emails for bounce risk.

## Run

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

Upload a CSV or XLSX (uses the `email` column, or the first column) or paste a list, then download results as CSV.

## Checks (per address)

1. Syntax (single @, dot placement, allowed special characters, valid domain labels and TLD)
2. Domain existence (DNS)
3. MX record (falls back to A record if no MX, rejects null MX)
4. Catch-all detection (probes a random impossible mailbox, cached per domain)
5. SMTP ping (EHLO, MAIL FROM, RCPT TO; no email is sent)

## Result labels

| Status  | Meaning |
|---------|---------|
| valid   | Mailbox accepted by the server, domain is not catch-all |
| invalid | Bad syntax, dead domain, no MX, or mailbox rejected (5xx) |
| risky   | Catch-all domain, so the mailbox cannot be confirmed |
| unknown | Timeout, greylisting (4xx), or SMTP unavailable |

## Important: port 25

SMTP ping needs outbound port 25. Many home ISPs and cloud providers (AWS, GCP, Azure) block it. The app detects this at the start of each job. If blocked, steps 1-3 still run and the rest show as `unknown` with a banner. For full accuracy, run on a VPS that allows port 25 and set `helo` and `mail_from` in `verifier.py` to a domain you control with a matching reverse DNS.

## Tuning

- `WORKERS` in `app.py` (default 40 threads)
- `MAX_EMAILS` in `app.py` (default 10,000)
- Only verify lists you are permitted to email, and keep volume modest so mail servers do not blacklist your IP.
