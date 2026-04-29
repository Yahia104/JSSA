# JSSA — JavaScript Security Analyzer v3.0

> Advanced static analysis tool that scans JavaScript files and remote bundles for security vulnerabilities, exposed secrets, and dangerous coding patterns.

---

## What It Does

JSSA performs **17 independent scan modules** on any `.js` file or live URL and classifies every finding by severity (`CRITICAL → INFO`) with a matching CWE identifier. It is designed for:

- **Bug bounty recon** — quickly triage a target's exposed JS bundles for secrets and endpoints.
- **Secure code review** — catch dangerous patterns before they reach production.
- **Penetration testing** — enumerate API keys, auth flows, third-party integrations, and internal URLs in one pass.

---

## Scan Modules

| Module | What It Detects | Max Severity |
|---|---|---|
| **API Keys & Secrets** | Google, AWS, Stripe, GitHub, Slack, Twilio, SendGrid, Mailgun, Mailchimp, HubSpot, Shopify, Square, PayPal, Algolia, Mapbox, Cloudinary, Pusher, Datadog, NPM, OpenAI, Anthropic, Supabase, generic high-entropy keys | CRITICAL |
| **Access / Refresh Tokens** | Hardcoded access tokens, refresh tokens, session tokens, CSRF tokens, bearer tokens, JWT tokens — in assignments, object literals, function calls, and Authorization headers | CRITICAL |
| **Firebase** | Full `firebaseConfig` blocks and individual fields (apiKey, databaseURL, storageBucket, appId, etc.) | CRITICAL |
| **Private Keys / Certificates** | RSA, EC, SSH (OpenSSH), PKCS#8, and PGP private key blocks | CRITICAL |
| **Hardcoded Credentials** | Plaintext passwords, database passwords, secrets, private keys, and usernames | CRITICAL |
| **JWT Tokens** | Hardcoded `eyJ…` tokens embedded directly in code | HIGH |
| **DOM XSS** | Dangerous sinks (`innerHTML`, `outerHTML`, `eval`, `document.write`, `new Function`, `setTimeout(string)`, jQuery `.html()`, `createContextualFragment`, etc.) with source-proximity analysis to assign confidence | HIGH |
| **postMessage Attacks** | Message listeners with missing `event.origin` / `event.source` checks; wildcard `*` postMessage calls; data flowing into dangerous sinks | CRITICAL |
| **Prototype Pollution** | `__proto__` access, `Object.prototype` mutations, dynamic key writes, unsafe deep merges, lodash `_.set` / `_.merge`, `JSON.parse` directly assigned | CRITICAL |
| **Dangerous Functions** | `eval`, `new Function`, `execScript`, `setTimeout(string)`, `innerHTML`, `dangerouslySetInnerHTML`, Angular `bypassSecurityTrust`, Vue `v-html`, XHR / WebSocket usage | CRITICAL |
| **CORS Misconfiguration** | Wildcard `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Credentials: true`, `cors({ origin: true })` | HIGH |
| **OAuth / Auth Configs** | `client_id`, `client_secret`, `tenant_id`, redirect URIs, OAuth scopes | CRITICAL |
| **Sentry DSN** | Exposed Sentry ingest URLs with embedded auth key | HIGH |
| **Third-Party Integrations** | GTM, Google Analytics (UA + GA4), Mixpanel, Amplitude, Segment, Hotjar, FullStory, Intercom, Heap, Sentry, Bugsnag, Rollbar, LogRocket, Stripe, PayPal, Braintree, Auth0, Okta, AWS Cognito, Google Maps, Mapbox | INFO–MEDIUM |
| **Sensitive Endpoints** | API paths containing `admin`, `internal`, `debug`, `backup`, `secret`, `private`, `password`, `actuator`, `graphql`, `swagger`, etc. | HIGH |
| **URLs** | Localhost / internal URLs, dev/staging URLs, API and auth URLs, external URLs | INFO–MEDIUM |
| **Storage Usage** | `localStorage` / `sessionStorage` reads and writes — flags sensitive keys (token, password, secret, auth) stored in browser storage | HIGH |

---

## Installation

No external dependencies — uses Python's standard library only.

```bash
git clone https://github.com/your-username/JSSA.git
cd JSSA
python JSSA.py --help
```

Requires **Python 3.8+**.

---

## Usage

```bash
# Scan a local JS file
python jssa.py app.js

# Scan a remote JS bundle (URL)
python jssa.py https://example.com/static/bundle.js

# Scan a list of URLs or file paths (one per line)
python jssa.py -l targets.txt

# Verbose mode — print each finding in real-time as it is discovered
python jssa.py app.js -v

# Save output to a JSON report
python jssa.py app.js -o report.json --json

# Save output as a bug bounty submission report (plain text)
python jssa.py app.js -o report.txt --bb-report

# Combine flags — verbose scan of a remote URL, JSON output
python jssa.py https://example.com/bundle.js -v -o out.json --json

# Scan multiple URLs and produce a single combined bug bounty report
python jssa.py -l urls.txt -o full_report.txt --bb-report
```

### All Flags

| Flag | Description |
|---|---|
| `target` | Path to a local `.js` file **or** a full `https://` URL |
| `-l FILE` / `--list FILE` | Path to a text file with one JS file path or URL per line (lines starting with `#` are ignored) |
| `-v` / `--verbose` | Print each finding immediately as it is found during the scan |
| `-o FILE` / `--output FILE` | Write the final report to this file |
| `--json` | Output format: structured JSON (works with `-o`) |
| `--bb-report` | Output format: plain-text bug bounty submission report (works with `-o`) |

---

## Output Formats

### Terminal (default)

Color-coded, grouped by severity with emoji indicators, CWE IDs, and line numbers.

```
🔴 CRITICAL (3)
  ▸ [API Keys] AWS Access Key ID [CWE-798] L12
    AKIAIOSFODNN7EXAMPLE
  ▸ [Firebase] Firebase Config Block [CWE-312] L45
    ...

🟠 HIGH (7)
  ▸ [DOM XSS] DOM XSS Sink: innerHTML assignment [CWE-79] L88
    [Confidence:HIGH] Line 88: el.innerHTML = location.hash.slice(1)
```

### JSON (`--json`)

Machine-readable output with metadata and a flat `findings` array — easy to pipe into other tools or dashboards.

```json
{
  "meta": {
    "source": "bundle.js",
    "size_bytes": 84321,
    "lines": 1200,
    "scan_time": "2025-04-29T14:00:00",
    "total": 14,
    "by_severity": { "CRITICAL": 2, "HIGH": 5, "MEDIUM": 4, "LOW": 2, "INFO": 1 }
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "API Keys",
      "title": "AWS Access Key ID",
      "detail": "AKIAIOSFODNN7EXAMPLE",
      "evidence": "awsKey = 'AKIAIOSFODNN7EXAMPLE'",
      "line": 12,
      "cwe": "CWE-798"
    }
  ]
}
```

### Bug Bounty Report (`--bb-report`)

Formatted plain text ready to paste directly into a bug bounty platform submission, with an executive summary and full per-finding breakdown.

---

## False Positive Reduction

JSSA applies several heuristics to reduce noise before reporting a finding:

- Strips `//` and `/* */` comments before scanning credential and token patterns.
- Skips values shorter than 6 characters or composed of only 1–2 unique characters.
- Maintains a blocklist of common placeholder strings (`your-key-here`, `changeme`, `xxx`, `placeholder`, etc.).
- Ignores matches that look like bare variable names (all lowercase letters, no digits).
- Deduplicates identical findings within the same scan.

---

## Severity Reference

| Level | Meaning |
|---|---|
| **CRITICAL** | Directly exploitable or immediately damaging — e.g., live API keys, private keys, missing origin checks |
| **HIGH** | High-impact issue requiring prompt remediation — e.g., DOM XSS sinks, CORS wildcard, hardcoded tokens |
| **MEDIUM** | Significant risk depending on context — e.g., sensitive endpoints, OAuth client IDs, localhost URLs |
| **LOW** | Low-risk or informational with minor security implications |
| **INFO** | Recon / inventory data — e.g., third-party SDKs loaded, external URLs, storage usage |

---

## Example: Bulk Recon Workflow

```bash
# 1. Collect JS bundle URLs from a target (using any recon tool)
cat js_urls.txt

# 2. Run JSSA across all of them and produce a combined JSON report
python jssa.py -l js_urls.txt -o recon_output.json --json

# 3. Filter only CRITICAL findings with jq
jq '[.targets[].findings[] | select(.severity == "CRITICAL")]' recon_output.json
```

---
This tool is made by Yahia Ramadan , you do not have a permision to take the code
