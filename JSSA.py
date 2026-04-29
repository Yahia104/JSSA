#!/usr/bin/env python3
"""
================================================================================
                JavaScript Security Analyzer (JSSA) v3.0
                   Advanced Static Analysis Tool
================================================================================
Author  : Yahia Ramadan
Version : 3.0
Usage   : python jssa.py <file.js>              # local file
          python jssa.py <url>                  # remote .js URL
          python jssa.py -l <urls.txt>          # list of URLs/files
          python jssa.py <file.js> -o out.json  # JSON output
          python jssa.py <file.js> --bb-report  # bug bounty report
"""

import re
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Set, Optional
from collections import defaultdict

# ─────────────────────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────────────────────

class C:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    DIM     = '\033[2m'
    END     = '\033[0m'

SEV_COLOR = {
    "CRITICAL": C.RED,
    "HIGH":     C.YELLOW,
    "MEDIUM":   C.CYAN,
    "LOW":      C.BLUE,
    "INFO":     C.WHITE,
}

# ─────────────────────────────────────────────────────────────────────────────
# FINDING
# ─────────────────────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, severity: str, category: str, title: str,
                 detail: str, evidence: str = "", line: int = 0,
                 context: str = "", cwe: str = ""):
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        self.evidence = evidence[:300]
        self.line = line
        self.context = context[:200]
        self.cwe = cwe
        self.ts = datetime.now().isoformat()

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "line": self.line,
            "context": self.context,
            "cwe": self.cwe,
        }

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_line(content: str, pos: int) -> Tuple[int, str]:
    """Return (line_number, line_text) for a character position."""
    lines = content[:pos].split('\n')
    line_no = len(lines)
    # grab the actual line from content
    all_lines = content.split('\n')
    line_text = all_lines[line_no - 1] if line_no <= len(all_lines) else ""
    return line_no, line_text.strip()[:150]

def is_in_comment(content: str, pos: int) -> bool:
    """Rough check: is this position inside a // or /* */ comment?"""
    # Check single-line comment
    line_start = content.rfind('\n', 0, pos) + 1
    line_so_far = content[line_start:pos]
    if '//' in line_so_far:
        comment_pos = line_so_far.index('//')
        if comment_pos < (pos - line_start):
            # Make sure // is not inside a string
            singles = line_so_far[:comment_pos].count("'") % 2
            doubles = line_so_far[:comment_pos].count('"') % 2
            if singles == 0 and doubles == 0:
                return True
    # Check block comment (simple heuristic)
    before = content[:pos]
    open_block = before.rfind('/*')
    close_block = before.rfind('*/')
    if open_block > close_block:
        return True
    return False

def strip_comments(content: str) -> str:
    """Remove // and /* */ comments to reduce false positives."""
    # Remove block comments
    content = re.sub(r'/\*[\s\S]*?\*/', ' ', content)
    # Remove line comments (careful not to destroy URLs)
    content = re.sub(r'(?<![:/])//[^\n]*', ' ', content)
    return content

def fetch_url(url: str, timeout: int = 15) -> Optional[str]:
    """Fetch a remote URL and return its text content."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; JSSA/3.0; security-research)',
        'Accept': 'application/javascript, text/javascript, */*',
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                return raw.decode('latin-1')
    except urllib.error.HTTPError as e:
        print(f"{C.RED}[!] HTTP {e.code} fetching: {url}{C.END}")
    except urllib.error.URLError as e:
        print(f"{C.RED}[!] URL error fetching {url}: {e.reason}{C.END}")
    except Exception as e:
        print(f"{C.RED}[!] Error fetching {url}: {e}{C.END}")
    return None

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

class JSSecurityAnalyzer:

    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    # Tokens/values that almost certainly are placeholders, not real secrets
    FALSE_POSITIVE_VALUES = {
        'undefined', 'null', 'true', 'false', 'function', 'object',
        'constructor', 'prototype', 'your-key-here', 'your_api_key',
        'xxx', 'yyy', 'zzz', 'example', 'sample', 'placeholder',
        'changeme', 'replace_me', 'insert_here', 'todo', 'fixme',
        'password', 'secret', 'token', 'apikey', 'api_key',
        '1234567890', 'abcdefghij', '**redacted**',
    }

    def __init__(self, source: str, verbose: bool = False, source_label: str = ""):
        self.source = source           # file path or URL
        self.source_label = source_label or source
        self.verbose = verbose
        self.content = ""
        self.clean = ""               # comment-stripped version
        self.lines: List[str] = []
        self.findings: List[Finding] = []
        self.file_size = 0

    # ── Loading ────────────────────────────────────────────────────────────────

    def load(self) -> bool:
        if self.source.startswith(('http://', 'https://')):
            return self._load_url()
        return self._load_file()

    def _load_file(self) -> bool:
        try:
            p = Path(self.source)
            if not p.exists():
                print(f"{C.RED}[!] File not found: {self.source}{C.END}")
                return False
            self.content = p.read_text(encoding='utf-8', errors='ignore')
            self._post_load()
            return True
        except Exception as e:
            print(f"{C.RED}[!] Error reading file: {e}{C.END}")
            return False

    def _load_url(self) -> bool:
        print(f"{C.CYAN}[*] Fetching: {self.source}{C.END}")
        text = fetch_url(self.source)
        if text is None:
            return False
        self.content = text
        self._post_load()
        return True

    def _post_load(self):
        self.file_size = len(self.content)
        self.lines = self.content.split('\n')
        self.clean = strip_comments(self.content)

    # ── Finding helpers ────────────────────────────────────────────────────────

    def _add(self, severity: str, category: str, title: str, detail: str,
             evidence: str = "", pos: int = -1, cwe: str = ""):
        line_no, ctx = (get_line(self.content, pos) if pos >= 0 else (0, ""))
        f = Finding(severity, category, title, detail, evidence, line_no, ctx, cwe)
        self.findings.append(f)
        if self.verbose:
            col = SEV_COLOR.get(severity, C.WHITE)
            ln = f" [L{line_no}]" if line_no else ""
            print(f"  {col}[{severity}]{C.END} {title}{ln}: {detail[:80]}")

    def _is_fp(self, value: str) -> bool:
        """Return True if value looks like a false positive."""
        v = value.strip().lower()
        if len(v) < 6:
            return True
        if v in self.FALSE_POSITIVE_VALUES:
            return True
        # All same character
        if len(set(v)) <= 2:
            return True
        # Looks like a variable name
        if re.match(r'^[a-z_][a-z0-9_]{0,20}$', v) and not any(c.isdigit() for c in v):
            return True
        return False

    def _findall_with_pos(self, pattern: str, text: str, flags=0) -> List[Tuple[str, int]]:
        """Return list of (match_string, start_pos)."""
        results = []
        for m in re.finditer(pattern, text, flags):
            results.append((m.group(), m.start()))
        return results

    # =========================================================================
    # SCAN: API KEYS & SECRETS
    # =========================================================================

    def scan_api_keys(self):
        patterns = [
            # Google
            (r'\bAIza[0-9A-Za-z_-]{35}\b',                        "Google API Key",            self.CRITICAL, "CWE-798"),
            (r'\bGOOGLE_API_KEY\s*[=:]\s*["\']([A-Za-z0-9_-]{20,})["\']', "Google API Key (var)", self.CRITICAL, "CWE-798"),
            # AWS
            (r'\bAKIA[0-9A-Z]{16}\b',                              "AWS Access Key ID",         self.CRITICAL, "CWE-798"),
            (r'\bA3T[A-Z0-9]|AGPA|AIDA|AROA|ASCA|ASIA[0-9A-Z]{16}\b', "AWS Role/Assumed Key", self.CRITICAL, "CWE-798"),
            (r'(?i)aws[_\-\.]?secret[_\-\.]?(?:access[_\-\.]?)?key\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "AWS Secret Key", self.CRITICAL, "CWE-798"),
            # Stripe
            (r'\bsk_live_[0-9a-zA-Z]{24,}\b',                     "Stripe Live Secret Key",    self.CRITICAL, "CWE-798"),
            (r'\bsk_test_[0-9a-zA-Z]{24,}\b',                     "Stripe Test Secret Key",    self.HIGH,     "CWE-798"),
            (r'\brk_live_[0-9a-zA-Z]{24,}\b',                     "Stripe Restricted Key",     self.CRITICAL, "CWE-798"),
            (r'\bpk_live_[0-9a-zA-Z]{24,}\b',                     "Stripe Live Public Key",    self.MEDIUM,   "CWE-312"),
            (r'\bpk_test_[0-9a-zA-Z]{24,}\b',                     "Stripe Test Public Key",    self.LOW,      "CWE-312"),
            # GitHub
            (r'\bghp_[A-Za-z0-9]{36,}\b',                         "GitHub Personal Token",     self.CRITICAL, "CWE-798"),
            (r'\bgho_[A-Za-z0-9]{36,}\b',                         "GitHub OAuth Token",        self.CRITICAL, "CWE-798"),
            (r'\bghs_[A-Za-z0-9]{36,}\b',                         "GitHub App Token",          self.CRITICAL, "CWE-798"),
            (r'\bghr_[A-Za-z0-9]{36,}\b',                         "GitHub Refresh Token",      self.CRITICAL, "CWE-798"),
            # Slack
            (r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b',               "Slack Token",               self.CRITICAL, "CWE-798"),
            (r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+', "Slack Webhook", self.HIGH, "CWE-798"),
            # Twilio
            (r'\bAC[a-f0-9]{32}\b',                               "Twilio Account SID",        self.HIGH,     "CWE-798"),
            (r'\bSK[a-f0-9]{32}\b',                               "Twilio Auth Token",         self.CRITICAL, "CWE-798"),
            # SendGrid
            (r'\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b', "SendGrid API Key",          self.CRITICAL, "CWE-798"),
            # Mailgun
            (r'\bkey-[0-9a-z]{32}\b',                             "Mailgun API Key",           self.CRITICAL, "CWE-798"),
            # Mailchimp
            (r'\b[0-9a-f]{32}-us[0-9]{1,2}\b',                   "Mailchimp API Key",         self.CRITICAL, "CWE-798"),
            # HubSpot
            (r'\bhubspot[_\-]?api[_\-]?key\s*[=:]\s*["\']([0-9a-f-]{36})["\']', "HubSpot API Key", self.CRITICAL, "CWE-798"),
            # Shopify
            (r'\bshpss_[0-9a-fA-F]{32}\b',                       "Shopify Session Token",     self.CRITICAL, "CWE-798"),
            (r'\bshpat_[0-9a-fA-F]{32}\b',                       "Shopify Access Token",      self.CRITICAL, "CWE-798"),
            # Square
            (r'\bEAAAE[a-zA-Z0-9_-]{60,}\b',                     "Square Access Token",       self.CRITICAL, "CWE-798"),
            # PayPal / Braintree
            (r'\baccess_token\$production\$[a-z0-9]{16}\$[0-9a-f]{32}\b', "PayPal/Braintree Token", self.CRITICAL, "CWE-798"),
            # Algolia
            (r'(?i)algolia[_\-\.]?app[_\-\.]?id\s*[=:]\s*["\']([A-Z0-9]{10})["\']', "Algolia App ID", self.MEDIUM, "CWE-312"),
            (r'(?i)algolia[_\-\.]?(?:admin|api)[_\-\.]?key\s*[=:]\s*["\']([a-f0-9]{32})["\']', "Algolia Admin Key", self.CRITICAL, "CWE-798"),
            # Mapbox
            (r'\bpk\.eyJ1[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b',    "Mapbox Token",              self.HIGH,     "CWE-798"),
            # Cloudinary
            (r'cloudinary://[0-9]+:[A-Za-z0-9_-]+@[a-z]+',      "Cloudinary URL",            self.HIGH,     "CWE-798"),
            # Pusher
            (r'(?i)pusher[_\-\.]?app[_\-\.]?(?:key|secret)\s*[=:]\s*["\']([A-Za-z0-9]{10,})["\']', "Pusher Credential", self.HIGH, "CWE-798"),
            # Datadog
            (r'(?i)dd[_\-\.]?api[_\-\.]?key\s*[=:]\s*["\']([a-f0-9]{32})["\']', "Datadog API Key", self.CRITICAL, "CWE-798"),
            # NPM
            (r'\bnpm_[A-Za-z0-9]{36,}\b',                        "NPM Token",                 self.CRITICAL, "CWE-798"),
            # OpenAI
            (r'\bsk-[A-Za-z0-9]{48}\b',                          "OpenAI API Key",            self.CRITICAL, "CWE-798"),
            # Anthropic
            (r'\bsk-ant-[A-Za-z0-9\-_]{40,}\b',                 "Anthropic API Key",         self.CRITICAL, "CWE-798"),
            # Supabase
            (r'\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]{43}\b', "Supabase/JWT Token", self.HIGH, "CWE-522"),
            # Generic high-entropy
            (r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{32,})["\']', "Generic API Key", self.HIGH, "CWE-798"),
            (r'(?i)(?:auth[_-]?token|authtoken)\s*[=:]\s*["\']([A-Za-z0-9_\-]{32,})["\']', "Auth Token", self.HIGH, "CWE-522"),
            (r'(?i)(?:bearer)\s+([A-Za-z0-9\-_]{32,})',         "Bearer Token",              self.HIGH,     "CWE-522"),
            # Sentry
            (r'[a-f0-9]{32}@o\d+\.ingest\.sentry\.io',          "Sentry Key",                self.HIGH,     "CWE-798"),
        ]
        seen = set()
        for pattern, name, severity, cwe in patterns:
            for m in re.finditer(pattern, self.content):
                val = m.group(1) if m.lastindex else m.group()
                key = (name, val[:40])
                if key in seen:
                    continue
                if self._is_fp(val):
                    continue
                seen.add(key)
                self._add(severity, "API Keys", name, val[:80], m.group(), m.start(), cwe)

    # =========================================================================
    # SCAN: FIREBASE
    # =========================================================================

    def scan_firebase(self):
        # Full config block
        for m in re.finditer(r'(?:firebaseConfig|initializeApp)\s*[\(=:]\s*\{([^}]{50,})\}',
                             self.content, re.DOTALL):
            block = m.group(1)
            if 'apiKey' in block:
                self._add(self.CRITICAL, "Firebase", "Firebase Config Block",
                          "Complete Firebase configuration exposed", block[:200], m.start(), "CWE-312")
                return  # no need for field-level after this

        # Individual fields
        fields = {
            'apiKey':           (self.CRITICAL, "Firebase API Key"),
            'databaseURL':      (self.HIGH,     "Firebase DB URL"),
            'storageBucket':    (self.MEDIUM,   "Firebase Storage Bucket"),
            'messagingSenderId':(self.MEDIUM,   "Firebase Sender ID"),
            'appId':            (self.MEDIUM,   "Firebase App ID"),
            'measurementId':    (self.LOW,      "Firebase Measurement ID"),
            'projectId':        (self.LOW,      "Firebase Project ID"),
        }
        for field, (sev, label) in fields.items():
            m = re.search(rf'{field}["\']?\s*:\s*["\']([^"\'{{}}]+)["\']', self.content)
            if m and not self._is_fp(m.group(1)):
                self._add(sev, "Firebase", label, m.group(1), m.group(), m.start(), "CWE-312")

    # =========================================================================
    # SCAN: PRIVATE KEYS / CERTIFICATES
    # =========================================================================

    def scan_private_keys(self):
        patterns = [
            (r'-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----',     "RSA Private Key"),
            (r'-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----',       "EC Private Key"),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----', "SSH Private Key"),
            (r'-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----',             "PKCS#8 Private Key"),
            (r'-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----', "PGP Private Key"),
        ]
        for pattern, name in patterns:
            for m in re.finditer(pattern, self.content):
                self._add(self.CRITICAL, "Private Keys", name,
                          f"Length: {len(m.group())} chars", m.group()[:60], m.start(), "CWE-321")

    # =========================================================================
    # SCAN: HARDCODED CREDENTIALS
    # =========================================================================

    def scan_hardcoded_credentials(self):
        patterns = [
            (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',  "Hardcoded Password", self.CRITICAL, "CWE-259"),
            (r'(?i)(?:db_pass|database_password)\s*[=:]\s*["\']([^"\']{6,})["\']', "DB Password", self.CRITICAL, "CWE-259"),
            (r'(?i)secret\s*[=:]\s*["\']([^"\']{16,})["\']',                  "Hardcoded Secret",  self.HIGH,     "CWE-321"),
            (r'(?i)private_key\s*[=:]\s*["\']([^"\']{16,})["\']',             "Hardcoded Priv Key",self.CRITICAL, "CWE-321"),
            (r'(?i)(?:username|user)\s*[=:]\s*["\']([^"\']{3,})["\']',        "Hardcoded Username",self.MEDIUM,   "CWE-798"),
        ]
        skip_vals = {'example', 'demo', 'test', 'admin', 'root', 'user', 'username',
                     'password', 'your_password', 'changeme'}
        for pattern, name, sev, cwe in patterns:
            for m in re.finditer(pattern, self.clean):
                val = m.group(1)
                if val.lower() in skip_vals or self._is_fp(val):
                    continue
                if is_in_comment(self.content, m.start()):
                    continue
                self._add(sev, "Credentials", name, val[:60], m.group(), m.start(), cwe)

    # =========================================================================
    # SCAN: DOM XSS (deep)
    # =========================================================================

    def scan_dom_xss(self):
        """
        Track user-controlled sources flowing into dangerous sinks.
        Sources: location.*, document.referrer, postMessage data, URL params, cookie, hash
        Sinks: innerHTML, outerHTML, document.write, eval, src, href, setTimeout(string)
        """
        sources = [
            r'location\.(?:href|hash|search|pathname|host|hostname)',
            r'document\.(?:referrer|URL|documentURI|baseURI|cookie)',
            r'window\.name',
            r'history\.(?:pushState|replaceState)',
            r'URLSearchParams',
            r'new\s+URL\s*\(',
            r'(?:params|query|qs|search)\[',
            r'getQueryParam|getParam|getUrlParam',
        ]

        sinks = [
            (r'\.innerHTML\s*[+]?=(?!=)',          "innerHTML assignment",       self.HIGH,     "CWE-79"),
            (r'\.outerHTML\s*[+]?=(?!=)',          "outerHTML assignment",       self.HIGH,     "CWE-79"),
            (r'\.insertAdjacentHTML\s*\(',         "insertAdjacentHTML",         self.HIGH,     "CWE-79"),
            (r'document\.write\s*\(',              "document.write",             self.HIGH,     "CWE-79"),
            (r'document\.writeln\s*\(',            "document.writeln",           self.HIGH,     "CWE-79"),
            (r'\beval\s*\(',                       "eval()",                     self.CRITICAL, "CWE-95"),
            (r'new\s+Function\s*\(',               "new Function()",             self.CRITICAL, "CWE-95"),
            (r'setTimeout\s*\(\s*(?:["\']|`)',     "setTimeout(string)",         self.HIGH,     "CWE-95"),
            (r'setInterval\s*\(\s*(?:["\']|`)',    "setInterval(string)",        self.HIGH,     "CWE-95"),
            (r'\.src\s*=',                         "src assignment",             self.MEDIUM,   "CWE-79"),
            (r'\.href\s*=',                        "href assignment",            self.MEDIUM,   "CWE-79"),
            (r'\.action\s*=',                      "form action assignment",     self.MEDIUM,   "CWE-601"),
            (r'location\.(?:href|replace|assign)\s*=', "location redirect",     self.MEDIUM,   "CWE-601"),
            (r'\$\s*\(\s*(?:location|document)',   "jQuery sink with DOM source",self.HIGH,     "CWE-79"),
            (r'\.html\s*\(\s*(?!(?:"|\')\s*<)',    "jQuery .html() with dynamic",self.HIGH,     "CWE-79"),
            (r'\.append\s*\([^)]*(?:html|content|data)', "jQuery append dynamic",self.MEDIUM,  "CWE-79"),
            (r'createContextualFragment\s*\(',     "createContextualFragment",   self.HIGH,     "CWE-79"),
            (r'Range\(\)\.createContextual',       "Range createContextual",     self.HIGH,     "CWE-79"),
        ]

        # Find all sinks in the file with surrounding context
        for pattern, name, sev, cwe in sinks:
            for m in re.finditer(pattern, self.clean):
                if is_in_comment(self.content, m.start()):
                    continue
                line_no, line_txt = get_line(self.content, m.start())
                # Check if a source variable appears nearby (±500 chars)
                snippet = self.content[max(0, m.start()-500): m.start()+200]
                source_nearby = any(re.search(src, snippet) for src in sources)
                # Determine severity: if source is nearby it's definite, else lower
                actual_sev = sev if source_nearby else (
                    self.MEDIUM if sev == self.HIGH else
                    self.LOW    if sev == self.MEDIUM else sev
                )
                confidence = "HIGH" if source_nearby else "MEDIUM"
                self._add(actual_sev, "DOM XSS",
                          f"DOM XSS Sink: {name}",
                          f"[Confidence:{confidence}] Line {line_no}: {line_txt[:100]}",
                          m.group(), m.start(), cwe)

    # =========================================================================
    # SCAN: POSTMESSAGE ATTACKS
    # =========================================================================

    def scan_postmessage(self):
        """Detect postMessage vulnerabilities: missing origin checks, data used in sinks."""

        # 1) addEventListener for message without origin validation
        listener_pattern = re.compile(
            r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(?:function\s*\((\w*)\)|(\w+))',
            re.DOTALL
        )
        for m in re.finditer(listener_pattern, self.content):
            handler_start = m.end()
            # Grab the handler body (next ~1500 chars as proxy for function body)
            snippet = self.content[handler_start: handler_start + 1500]
            has_origin_check = bool(re.search(
                r'(?:event|e|evt|msg|message)\.origin\s*(?:===|!==|==)',
                snippet
            ))
            has_source_check = bool(re.search(r'\.source\s*===', snippet))
            uses_data = bool(re.search(
                r'(?:event|e|evt|msg|message)\.data',
                snippet
            ))
            uses_dangerous_sink = bool(re.search(
                r'innerHTML|eval|document\.write|Function\(|\.src\s*=|\.href\s*=',
                snippet
            ))
            line_no, line_txt = get_line(self.content, m.start())

            if not has_origin_check:
                sev = self.CRITICAL if (uses_data and uses_dangerous_sink) else self.HIGH
                self._add(sev, "postMessage",
                          "postMessage handler missing origin check",
                          f"Line {line_no} — no event.origin validation found in handler",
                          m.group(), m.start(), "CWE-346")
            elif uses_dangerous_sink:
                self._add(self.MEDIUM, "postMessage",
                          "postMessage data flows into dangerous sink",
                          f"Line {line_no} — verify data sanitization before sink",
                          m.group(), m.start(), "CWE-79")

            if not has_source_check and uses_data:
                self._add(self.LOW, "postMessage",
                          "postMessage handler missing source check",
                          f"Line {line_no} — event.source not validated",
                          m.group(), m.start(), "CWE-346")

        # 2) postMessage calls with wildcard '*' origin
        for m in re.finditer(r'\.postMessage\s*\([^)]*,\s*["\']?\*["\']?\s*\)', self.content):
            line_no, line_txt = get_line(self.content, m.start())
            self._add(self.HIGH, "postMessage",
                      "postMessage sent with wildcard '*' origin",
                      f"Line {line_no}: {line_txt[:100]}",
                      m.group(), m.start(), "CWE-346")

        # 3) postMessage calls in general (for inventory)
        count = len(re.findall(r'\.postMessage\s*\(', self.content))
        if count > 0:
            self._add(self.INFO, "postMessage",
                      "postMessage usage detected",
                      f"{count} postMessage call(s) — review all handlers")

    # =========================================================================
    # SCAN: PROTOTYPE POLLUTION (deep)
    # =========================================================================

    def scan_prototype_pollution(self):
        patterns = [
            # Direct __proto__ assignment
            (r'\b__proto__\s*[\[\.]',              "Direct __proto__ access",         self.CRITICAL, "CWE-1321"),
            # Object.prototype assignment
            (r'Object\.prototype\s*\.\s*\w+\s*=', "Object.prototype modification",   self.CRITICAL, "CWE-1321"),
            # Bracket notation on prototype
            (r'prototype\s*\[\s*(?:key|prop|name|k|p)\s*\]', "Dynamic prototype key write", self.HIGH, "CWE-1321"),
            # Deep merge / extend without guard
            (r'(?:deepmerge|extend|merge|assign|defaults)\s*\([^)]*\)',
             "Deep merge/assign — may allow pollution if key not sanitised",          self.MEDIUM,   "CWE-1321"),
            # User-controlled key used in obj assignment
            (r'obj\s*\[\s*(?:key|k|prop|name)\s*\]\s*=',
             "Dynamic key assignment on object",                                       self.MEDIUM,   "CWE-1321"),
            # constructor.prototype
            (r'\.constructor\s*\.prototype',       "constructor.prototype access",    self.HIGH,     "CWE-1321"),
            # lodash _.set / _.merge patterns
            (r'_\.(?:set|merge|defaultsDeep)\s*\(', "Lodash deep set/merge",         self.MEDIUM,   "CWE-1321"),
            # JSON.parse without sanitisation feeding into object
            (r'JSON\.parse\s*\([^)]*\)\s*\.\s*\w+\s*=',
             "JSON.parse result directly assigned",                                    self.LOW,      "CWE-1321"),
            # hasOwnProperty bypass
            (r'(?:hasOwnProperty|propertyIsEnumerable)\s*\(',
             "hasOwnProperty usage — verify it guards all merge operations",           self.INFO,     "CWE-1321"),
        ]
        for pattern, name, sev, cwe in patterns:
            for m in re.finditer(pattern, self.clean):
                if is_in_comment(self.content, m.start()):
                    continue
                line_no, line_txt = get_line(self.content, m.start())
                self._add(sev, "Prototype Pollution",
                          name,
                          f"Line {line_no}: {line_txt[:120]}",
                          m.group(), m.start(), cwe)

    # =========================================================================
    # SCAN: THIRD-PARTY INTEGRATIONS
    # =========================================================================

    def scan_third_party(self):
        integrations = [
            # Analytics / tracking
            (r'\bGTM-[A-Z0-9]{4,}\b',                                 "Google Tag Manager ID",  self.INFO),
            (r'\bUA-\d{5,}-\d+\b',                                    "Google Analytics UA",    self.INFO),
            (r'\bG-[A-Z0-9]{8,}\b',                                   "Google Analytics 4",     self.INFO),
            (r'(?i)mixpanel\.init\s*\(\s*["\']([A-Za-z0-9]{32})["\']', "Mixpanel Token",        self.MEDIUM),
            (r'(?i)amplitude\.getInstance\(\)\.init\s*\(\s*["\']([A-Za-z0-9]{32})["\']', "Amplitude Key", self.MEDIUM),
            (r'(?i)Intercom\s*\(\s*["\']init["\'].*?app_id\s*:\s*["\']([^"\']+)["\']', "Intercom App ID", self.INFO),
            (r'(?i)heap\.load\s*\(\s*["\'](\d{8,})["\']',            "Heap.io App ID",          self.INFO),
            (r'(?i)segment\.load\s*\(\s*["\']([A-Za-z0-9]{20,})["\']', "Segment Write Key",     self.MEDIUM),
            (r'(?i)Hotjar\.init\s*\(\s*(\d{5,})',                    "Hotjar Site ID",           self.INFO),
            (r'(?i)FullStory\.init\s*\(\s*\{[^}]*org\s*:\s*["\']([^"\']+)["\']', "FullStory Org", self.INFO),
            (r'(?i)dataLayer\.push',                                  "GTM dataLayer push",       self.INFO),
            # Error tracking
            (r'(?i)Sentry\.init\s*\(',                                "Sentry Init",             self.INFO),
            (r'(?i)bugsnag\.start\s*\(',                              "Bugsnag Init",             self.INFO),
            (r'(?i)rollbar\.init\s*\(',                               "Rollbar Init",             self.INFO),
            (r'(?i)LogRocket\.init\s*\(\s*["\']([^"\']+)["\']',     "LogRocket App ID",         self.INFO),
            # Payments
            (r'(?i)stripe\.js|stripe\.com/v[0-9]',                   "Stripe.js loaded",         self.INFO),
            (r'(?i)paypal\.com/sdk/js',                              "PayPal SDK",               self.INFO),
            (r'(?i)braintree',                                        "Braintree SDK",            self.INFO),
            # CDNs / infra
            (r'(?i)cdn\.jsdelivr\.net',                              "jsDelivr CDN",             self.INFO),
            (r'(?i)unpkg\.com',                                       "unpkg CDN",               self.INFO),
            (r'(?i)cloudflare(?:insights|beacon)',                    "Cloudflare Analytics",    self.INFO),
            # Chat / support
            (r'(?i)drift\.com/drift\.js',                            "Drift Chat",               self.INFO),
            (r'(?i)widget\.freshworks\.com',                         "Freshworks Widget",        self.INFO),
            (r'(?i)zopim|zendesk',                                    "Zendesk/Zopim",           self.INFO),
            # Auth
            (r'(?i)auth0\.com',                                       "Auth0 integration",        self.INFO),
            (r'(?i)okta\.com',                                        "Okta integration",         self.INFO),
            (r'(?i)cognito',                                          "AWS Cognito",              self.INFO),
            # Maps
            (r'maps\.googleapis\.com/maps/api',                      "Google Maps API",          self.INFO),
            (r'api\.mapbox\.com',                                    "Mapbox API",               self.INFO),
        ]
        seen = set()
        for pattern, name, sev in integrations:
            for m in re.finditer(pattern, self.content, re.IGNORECASE):
                key = (name, m.group()[:30])
                if key not in seen:
                    seen.add(key)
                    val = m.group(1) if m.lastindex else m.group()[:80]
                    self._add(sev, "Third-Party", name, val, m.group(), m.start())

    # =========================================================================
    # SCAN: OAUTH / AUTH CONFIGS
    # =========================================================================

    def scan_oauth(self):
        patterns = [
            (r'(?i)client[_-]?id\s*[=:]\s*["\']([A-Za-z0-9\-_.]{10,})["\']',   "OAuth Client ID",     self.MEDIUM, "CWE-312"),
            (r'(?i)client[_-]?secret\s*[=:]\s*["\']([A-Za-z0-9\-_.]{10,})["\']', "OAuth Client Secret", self.CRITICAL,"CWE-798"),
            (r'(?i)tenant[_-]?id\s*[=:]\s*["\']([A-Za-z0-9\-]{10,})["\']',     "Tenant ID",           self.LOW,    "CWE-312"),
            (r'(?i)redirect[_-]?uri\s*[=:]\s*["\']([^"\']{10,})["\']',          "Redirect URI",        self.MEDIUM, "CWE-601"),
            (r'(?i)scope\s*[=:]\s*["\']([^"\']{5,})["\']',                       "OAuth Scope",         self.INFO,   ""),
        ]
        fp_extra = {'your-client-id', 'your_client_secret', 'client_id', 'client_secret'}
        for pattern, name, sev, cwe in patterns:
            for m in re.finditer(pattern, self.content):
                val = m.group(1) if m.lastindex else m.group()
                if self._is_fp(val) or val.lower() in fp_extra:
                    continue
                self._add(sev, "OAuth", name, val[:80], m.group(), m.start(), cwe)

    # =========================================================================
    # SCAN: CORS
    # =========================================================================

    def scan_cors(self):
        patterns = [
            (r'Access-Control-Allow-Origin["\']?\s*:\s*["\']?\*',    "CORS Wildcard (*)",        self.HIGH,   "CWE-942"),
            (r'Access-Control-Allow-Credentials["\']?\s*:\s*["\']?true', "CORS Allow-Credentials", self.MEDIUM, "CWE-942"),
            (r'(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*true',            "CORS origin: true",        self.HIGH,   "CWE-942"),
            (r'(?i)res\.(?:set|header)\s*\(\s*["\']Access-Control', "CORS header set in code",  self.INFO,   "CWE-942"),
        ]
        for pattern, name, sev, cwe in patterns:
            for m in re.finditer(pattern, self.content, re.IGNORECASE):
                line_no, ctx = get_line(self.content, m.start())
                self._add(sev, "CORS", name,
                          f"Line {line_no}: {ctx[:100]}",
                          m.group(), m.start(), cwe)

    # =========================================================================
    # SCAN: SENSITIVE ENDPOINTS
    # =========================================================================

    def scan_endpoints(self):
        # Sensitive path segments
        sensitive = {
            'admin':    self.HIGH,
            'internal': self.HIGH,
            'debug':    self.MEDIUM,
            'test':     self.LOW,
            'staging':  self.LOW,
            'backup':   self.HIGH,
            'config':   self.MEDIUM,
            'secret':   self.HIGH,
            'private':  self.HIGH,
            'token':    self.MEDIUM,
            'key':      self.MEDIUM,
            'password': self.HIGH,
            'export':   self.MEDIUM,
            'import':   self.MEDIUM,
            'upload':   self.MEDIUM,
            'download': self.LOW,
            'health':   self.INFO,
            'metrics':  self.INFO,
            'actuator': self.HIGH,
            'swagger':  self.MEDIUM,
            'graphql':  self.MEDIUM,
        }
        endpoint_re = re.compile(r'["\'](\/([\w\-./{}:]+))["\']')
        seen = set()
        for m in re.finditer(endpoint_re, self.content):
            ep = m.group(1)
            if ep in seen or len(ep) < 3:
                continue
            seen.add(ep)
            parts = ep.lower().split('/')
            for seg, sev in sensitive.items():
                if seg in parts:
                    self._add(sev, "Endpoints",
                              f"Sensitive endpoint ({seg})",
                              ep, m.group(), m.start())
                    break
            else:
                if '/api/' in ep.lower():
                    self._add(self.INFO, "Endpoints", "API endpoint", ep, m.group(), m.start())

    # =========================================================================
    # SCAN: URLS
    # =========================================================================

    def scan_urls(self):
        url_re = re.compile(
            r'https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)',
            re.IGNORECASE
        )
        skip_ext = {'.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                    '.woff', '.woff2', '.ttf', '.ico', '.webp', '.map'}
        seen = set()
        for m in re.finditer(url_re, self.content):
            url = m.group().rstrip('.,;:"\' ')
            if url in seen or len(url) < 16:
                continue
            if any(url.lower().endswith(e) for e in skip_ext):
                continue
            seen.add(url)
            lower = url.lower()
            if any(x in lower for x in ['localhost', '127.0.0.1', '0.0.0.0']):
                self._add(self.MEDIUM, "URLs", "Localhost/internal URL", url, url, m.start())
            elif any(x in lower for x in ['staging', 'dev.', 'uat.', 'test.']):
                self._add(self.LOW, "URLs", "Dev/staging URL", url, url, m.start())
            elif any(x in lower for x in ['api.', '/api/', 'auth.', '/oauth', '/token']):
                self._add(self.INFO, "URLs", "API/Auth URL", url, url, m.start())
            else:
                self._add(self.INFO, "URLs", "External URL", url, url, m.start())

    # =========================================================================
    # SCAN: STORAGE
    # =========================================================================

    def scan_storage(self):
        patterns = [
            (r'localStorage\.setItem\s*\(\s*["\']([^"\']+)["\']', "localStorage write",  self.INFO),
            (r'localStorage\.getItem\s*\(\s*["\']([^"\']+)["\']', "localStorage read",   self.INFO),
            (r'sessionStorage\.',                                   "sessionStorage usage", self.INFO),
            (r'document\.cookie\s*=',                              "Cookie write",         self.LOW),
            (r'document\.cookie(?!\s*=)',                          "Cookie read",          self.INFO),
            (r'indexedDB\.',                                        "IndexedDB usage",      self.INFO),
        ]
        # Flag if sensitive values stored
        sensitive_keys = re.compile(
            r'localStorage\.setItem\s*\(\s*["\']([^"\']*(?:token|key|secret|password|auth)[^"\']*)["\']',
            re.IGNORECASE
        )
        for m in re.finditer(sensitive_keys, self.content):
            self._add(self.HIGH, "Storage",
                      "Sensitive data in localStorage",
                      f"Key: {m.group(1)}", m.group(), m.start(), "CWE-312")

        for pattern, name, sev in patterns:
            count = len(re.findall(pattern, self.content))
            if count:
                self._add(sev, "Storage", name, f"{count} occurrence(s)")

    # =========================================================================
    # SCAN: DANGEROUS FUNCTIONS (expanded)
    # =========================================================================

    def scan_dangerous_functions(self):
        patterns = [
            (r'\beval\s*\(',                              "eval()",                     self.CRITICAL, "CWE-95"),
            (r'new\s+Function\s*\(',                     "new Function()",             self.CRITICAL, "CWE-95"),
            (r'execScript\s*\(',                         "execScript()",               self.CRITICAL, "CWE-95"),
            (r'setTimeout\s*\(\s*(?:["\']|`)',           "setTimeout(string)",         self.HIGH,     "CWE-95"),
            (r'setInterval\s*\(\s*(?:["\']|`)',          "setInterval(string)",        self.HIGH,     "CWE-95"),
            (r'\.innerHTML\s*[+]?=',                     "innerHTML write",            self.HIGH,     "CWE-79"),
            (r'\.outerHTML\s*[+]?=',                     "outerHTML write",            self.HIGH,     "CWE-79"),
            (r'\.insertAdjacentHTML\s*\(',               "insertAdjacentHTML",         self.HIGH,     "CWE-79"),
            (r'document\.write\s*\(',                    "document.write",             self.HIGH,     "CWE-79"),
            (r'document\.writeln\s*\(',                  "document.writeln",           self.HIGH,     "CWE-79"),
            (r'createContextualFragment\s*\(',           "createContextualFragment",   self.HIGH,     "CWE-79"),
            (r'\.srcdoc\s*=',                            "iframe srcdoc write",        self.HIGH,     "CWE-79"),
            (r'(?i)dangerouslySetInnerHTML',             "React dangerouslySetInnerHTML", self.HIGH,  "CWE-79"),
            (r'bypassSecurityTrust',                     "Angular bypassSecurityTrust", self.HIGH,    "CWE-79"),
            (r'v-html\s*=',                              "Vue v-html directive",       self.HIGH,     "CWE-79"),
            (r'\.html\s*\(',                             "jQuery .html()",             self.MEDIUM,   "CWE-79"),
            (r'XMLHttpRequest|\.xhr\b',                  "XHR usage",                  self.INFO,     ""),
            (r'fetch\s*\(',                              "fetch() API",                self.INFO,     ""),
            (r'WebSocket\s*\(',                          "WebSocket usage",            self.INFO,     ""),
        ]
        seen_types = set()
        for pattern, name, sev, cwe in patterns:
            for m in re.finditer(pattern, self.clean):
                if is_in_comment(self.content, m.start()):
                    continue
                line_no, ctx = get_line(self.content, m.start())
                key = (name, line_no)
                if key in seen_types:
                    continue
                seen_types.add(key)
                self._add(sev, "Dangerous Functions",
                          name,
                          f"Line {line_no}: {ctx[:100]}",
                          m.group(), m.start(), cwe)

    # =========================================================================
    # SCAN: SENTRY DSN
    # =========================================================================

    def scan_sentry(self):
        for m in re.finditer(
            r'https://[a-f0-9]{32}@(?:o\d+\.ingest\.sentry\.io|sentry\.io)/\d+',
            self.content
        ):
            self._add(self.HIGH, "API Keys", "Sentry DSN exposed", m.group(), m.group(), m.start(), "CWE-312")

    # =========================================================================
    # SCAN: JWT
    # =========================================================================

    def scan_jwt(self):
        jwt_re = re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}')
        seen = set()
        for m in re.finditer(jwt_re, self.content):
            t = m.group()
            if t not in seen:
                seen.add(t)
                self._add(self.HIGH, "Secrets", "Hardcoded JWT token", t[:100], t, m.start(), "CWE-522")

    # =========================================================================
    # SCAN: ACCESS / REFRESH / SESSION TOKENS
    # =========================================================================

    def scan_tokens(self):
        """
        Detect hardcoded access tokens, refresh tokens, session tokens, and
        bearer tokens in all their common JS forms:
          - var accessToken = "..."
          - this.accessToken = "..."
          - accessToken: "..."
          - localStorage.setItem('accessToken', "...")
          - response.access_token
          - Authorization: Bearer <token>
          - token stored in object/config literals
        """

        # ── Token keyword variants ────────────────────────────────────────────
        # Covers camelCase, snake_case, UPPER_CASE, and kebab-case names
        # NOTE: used inside re.compile(..., re.IGNORECASE | re.VERBOSE) — no inline flags here
        TOKEN_NAMES = r"""
            access[_\-]?token   |
            refresh[_\-]?token  |
            id[_\-]?token       |
            session[_\-]?token  |
            csrf[_\-]?token     |
            xsrf[_\-]?token     |
            x[_\-]?csrf[_\-]?token |
            auth[_\-]?token     |
            user[_\-]?token     |
            device[_\-]?token   |
            push[_\-]?token     |
            fcm[_\-]?token      |
            registration[_\-]?token |
            verification[_\-]?token |
            reset[_\-]?token    |
            invite[_\-]?token   |
            confirm[_\-]?token  |
            activation[_\-]?token |
            otp[_\-]?token      |
            login[_\-]?token    |
            app[_\-]?token      |
            api[_\-]?token      |
            service[_\-]?token  |
            bearer[_\-]?token   |
            oauth[_\-]?token    |
            oauth2[_\-]?token   |
            jwt[_\-]?token      |
            session[_\-]?id     |
            access[_\-]?key     |
            secret[_\-]?key     |
            private[_\-]?key    |
            encryption[_\-]?key |
            signing[_\-]?key
        """

        # ── Pattern 1: assignment with = ─────────────────────────────────────
        # var/let/const/this/self/window.accessToken = "VALUE"
        # response.accessToken = "VALUE"
        # data.access_token = "VALUE"
        pat_assign = re.compile(
            rf'(?:{TOKEN_NAMES})\s*=\s*["\`]([A-Za-z0-9\-_./+=]{{16,}})["\`]',
            re.IGNORECASE | re.VERBOSE
        )

        # ── Pattern 2: object literal / JSON key ─────────────────────────────
        # { accessToken: "VALUE" }
        # "access_token": "VALUE"
        pat_obj = re.compile(
            rf'["\']?(?:{TOKEN_NAMES})["\']?\s*:\s*["\`]([A-Za-z0-9\-_./+=]{{16,}})["\`]',
            re.IGNORECASE | re.VERBOSE
        )

        # ── Pattern 3: function call argument ────────────────────────────────
        # setToken("VALUE") / storeAccessToken("VALUE")
        # localStorage.setItem("accessToken", "VALUE")
        pat_call = re.compile(
            rf'(?:set|store|save|cache|put|write)?(?:{TOKEN_NAMES})\s*\(\s*["\`]([A-Za-z0-9\-_./+=]{{16,}})["\`]',
            re.IGNORECASE | re.VERBOSE
        )

        # ── Pattern 4: localStorage / sessionStorage with token key ──────────
        # localStorage.setItem("accessToken", someVar)  → flag the key name
        # localStorage.setItem("access_token", "VALUE") → flag value too
        pat_storage = re.compile(
            rf'(?:localStorage|sessionStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*["\'](?:{TOKEN_NAMES})["\']',
            re.IGNORECASE | re.VERBOSE
        )

        # ── Pattern 5: Authorization header with hardcoded token ─────────────
        # headers: { Authorization: "Bearer eyJ..." }
        # "Authorization": "Bearer abc123"
        pat_auth_header = re.compile(
            r'["\']?[Aa]uthorization["\']?\s*[=:]\s*["\`]\s*(?:Bearer|Token|Basic)\s+([A-Za-z0-9\-_./+=]{16,})["\`]',
            re.IGNORECASE
        )

        # ── Pattern 6: response / API data extraction (informational) ─────────
        # response.data.access_token / data.access_token / result.accessToken
        pat_response = re.compile(
            rf'(?:response|res|data|result|body|payload|json|resp)\s*(?:\.|(?:\[["\']))(?:{TOKEN_NAMES})(?:["\'])?\]?',
            re.IGNORECASE | re.VERBOSE
        )

        # ── Severity mapping by token name ────────────────────────────────────
        def _severity_for(name: str) -> str:
            name = name.lower()
            if any(x in name for x in ('access_token', 'accesstoken', 'refresh_token',
                                        'refreshtoken', 'id_token', 'idtoken',
                                        'auth_token', 'authtoken', 'signing', 'private',
                                        'encryption', 'secret_key', 'secretkey')):
                return self.CRITICAL
            if any(x in name for x in ('session', 'csrf', 'xsrf', 'bearer', 'oauth',
                                        'jwt', 'api_token', 'apitoken', 'service')):
                return self.HIGH
            return self.MEDIUM

        seen = set()

        def _record(pattern, label, sev_override=None):
            for m in re.finditer(pattern, self.clean):
                if is_in_comment(self.content, m.start()):
                    continue
                val = m.group(1) if m.lastindex else ""
                if val and self._is_fp(val):
                    continue
                # Extract the token keyword from the match for severity
                match_str = m.group()
                token_keyword = re.search(TOKEN_NAMES, match_str, re.IGNORECASE | re.VERBOSE)
                kw = token_keyword.group() if token_keyword else "token"
                sev = sev_override or _severity_for(kw)
                dedup_key = (label, val[:30] if val else match_str[:30])
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                line_no, ctx = get_line(self.content, m.start())
                detail = f"Line {line_no}: {ctx[:120]}"
                evidence = f"{kw} = {val[:80]}" if val else match_str[:80]
                self._add(sev, "Tokens", label, detail, evidence, m.start(), "CWE-522")

        _record(pat_assign,      "Hardcoded token (assignment)")
        _record(pat_obj,         "Hardcoded token (object literal)")
        _record(pat_call,        "Hardcoded token (function argument)")
        _record(pat_auth_header, "Hardcoded Authorization header", self.CRITICAL)

        # Storage — flag even when value is a variable (not hardcoded string)
        for m in re.finditer(pat_storage, self.clean):
            if is_in_comment(self.content, m.start()):
                continue
            token_keyword = re.search(TOKEN_NAMES, m.group(), re.IGNORECASE | re.VERBOSE)
            kw = token_keyword.group() if token_keyword else "token"
            key = ("storage", kw.lower(), m.start())
            if key in seen:
                continue
            seen.add(key)
            line_no, ctx = get_line(self.content, m.start())
            sev = _severity_for(kw)
            self._add(sev, "Tokens",
                      f"Token stored in browser storage ({kw})",
                      f"Line {line_no}: {ctx[:120]}",
                      m.group(), m.start(), "CWE-922")

        # Response extraction — informational, just for recon
        resp_seen = set()
        for m in re.finditer(pat_response, self.clean):
            if is_in_comment(self.content, m.start()):
                continue
            token_keyword = re.search(TOKEN_NAMES, m.group(), re.IGNORECASE | re.VERBOSE)
            kw = token_keyword.group() if token_keyword else "token"
            if kw.lower() in resp_seen:
                continue
            resp_seen.add(kw.lower())
            line_no, ctx = get_line(self.content, m.start())
            self._add(self.INFO, "Tokens",
                      f"Token extracted from response ({kw})",
                      f"Line {line_no}: {ctx[:120]}",
                      m.group(), m.start(), "CWE-522")

    # =========================================================================
    # RUN ALL
    # =========================================================================

    def run(self):
        print(f"\n{C.BOLD}{C.CYAN}{'='*70}{C.END}")
        print(f"{C.BOLD}  JSSA v3.0 — JavaScript Security Analyzer{C.END}")
        print(f"{C.BOLD}{C.CYAN}{'='*70}{C.END}")
        print(f"{C.DIM}  Source : {self.source_label}{C.END}")
        print(f"{C.DIM}  Size   : {self.file_size:,} bytes  |  Lines: {len(self.lines):,}{C.END}")
        print(f"{C.DIM}  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.END}\n")

        scans = [
            ("API Keys & Tokens",        self.scan_api_keys),
            ("Access/Refresh Tokens",    self.scan_tokens),
            ("Firebase",                 self.scan_firebase),
            ("Private Keys",             self.scan_private_keys),
            ("Hardcoded Credentials",    self.scan_hardcoded_credentials),
            ("JWT Tokens",               self.scan_jwt),
            ("Sentry DSN",               self.scan_sentry),
            ("DOM XSS",                  self.scan_dom_xss),
            ("postMessage Attacks",      self.scan_postmessage),
            ("Prototype Pollution",      self.scan_prototype_pollution),
            ("Dangerous Functions",      self.scan_dangerous_functions),
            ("CORS Misconfig",           self.scan_cors),
            ("OAuth / Auth Configs",     self.scan_oauth),
            ("Third-Party Integrations", self.scan_third_party),
            ("Sensitive Endpoints",      self.scan_endpoints),
            ("URLs",                     self.scan_urls),
            ("Storage Usage",            self.scan_storage),
        ]

        for name, fn in scans:
            if self.verbose:
                print(f"{C.DIM}  [*] {name}...{C.END}")
            try:
                fn()
            except Exception as e:
                print(f"{C.RED}  [!] Error in {name}: {e}{C.END}")

        print(f"\n{C.GREEN}  [+] Scan complete.{C.END}\n")

    # ─────────────────────────────────────────────────────────────────────────
    # REPORTS
    # ─────────────────────────────────────────────────────────────────────────

    def print_report(self):
        by_sev = defaultdict(list)
        for f in self.findings:
            by_sev[f.severity].append(f)

        label_map = [
            ("CRITICAL", "🔴"),
            ("HIGH",     "🟠"),
            ("MEDIUM",   "🟡"),
            ("LOW",      "🟢"),
            ("INFO",     "🔵"),
        ]

        print(f"\n{C.BOLD}{'='*70}")
        print("  SECURITY ANALYSIS REPORT")
        print(f"{'='*70}{C.END}")

        for sev, emoji in label_map:
            items = by_sev.get(sev, [])
            if not items:
                continue
            col = SEV_COLOR[sev]
            print(f"\n{col}{C.BOLD}{emoji} {sev} ({len(items)}){C.END}")
            for f in items:
                ln = f" L{f.line}" if f.line else ""
                cwe = f" [{f.cwe}]" if f.cwe else ""
                print(f"  {col}▸ [{f.category}] {f.title}{cwe}{C.END}{ln}")
                if f.detail:
                    print(f"    {C.DIM}{f.detail[:120]}{C.END}")

        print(f"\n{C.BOLD}  Total findings: {len(self.findings)}{C.END}")
        # Dedup count
        cats = defaultdict(int)
        for f in self.findings:
            cats[f.category] += 1
        print(f"  By category: " + " | ".join(f"{k}:{v}" for k, v in sorted(cats.items())))
        print(f"{C.BOLD}{'='*70}{C.END}\n")

    def to_json(self, output: str = None) -> dict:
        report = {
            "meta": {
                "source": self.source_label,
                "size_bytes": self.file_size,
                "lines": len(self.lines),
                "scan_time": datetime.now().isoformat(),
                "total": len(self.findings),
                "by_severity": {
                    s: len([f for f in self.findings if f.severity == s])
                    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                }
            },
            "findings": [f.to_dict() for f in self.findings]
        }
        if output:
            Path(output).write_text(json.dumps(report, indent=2))
            print(f"{C.GREEN}[+] JSON report → {output}{C.END}")
        return report

    def to_bb_report(self, output: str = None) -> str:
        by_sev = defaultdict(list)
        for f in self.findings:
            by_sev[f.severity].append(f)

        lines = [
            "=" * 80,
            "           SECURITY VULNERABILITY REPORT — Bug Bounty Submission",
            "=" * 80,
            f"Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Target     : {self.source_label}",
            f"File size  : {self.file_size:,} bytes | {len(self.lines)} lines",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 80,
            f"Total Findings : {len(self.findings)}",
            "",
        ]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            c = len(by_sev[sev])
            if c:
                lines.append(f"  {sev:10}: {c}")

        lines += ["", "=" * 80, "DETAILED FINDINGS", "=" * 80, ""]
        idx = 1
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = by_sev[sev]
            if not items:
                continue
            lines += [f"\n{'─'*40}", f"  {sev} SEVERITY", f"{'─'*40}"]
            for f in items:
                lines += [
                    f"\nFinding #{idx}",
                    f"  Severity : {f.severity}",
                    f"  Category : {f.category}",
                    f"  Title    : {f.title}",
                    f"  CWE      : {f.cwe or 'N/A'}",
                    f"  Line     : {f.line or 'N/A'}",
                    f"  Detail   : {f.detail}",
                    f"  Evidence : {f.evidence[:120]}",
                ]
                idx += 1

        lines += ["", "=" * 80, "END OF REPORT", "=" * 80]
        text = "\n".join(lines)
        if output:
            Path(output).write_text(text)
            print(f"{C.GREEN}[+] BB report → {output}{C.END}")
        return text


# ─────────────────────────────────────────────────────────────────────────────
# MULTI-TARGET RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_targets(targets: List[str], args) -> List[JSSecurityAnalyzer]:
    results = []
    for i, target in enumerate(targets, 1):
        if len(targets) > 1:
            print(f"\n{C.MAGENTA}[{i}/{len(targets)}] Target: {target}{C.END}")
        az = JSSecurityAnalyzer(target, verbose=args.verbose, source_label=target)
        if not az.load():
            continue
        az.run()
        az.print_report()
        results.append(az)
        time.sleep(0.5)  # polite delay between URLs

    # ── Single combined output file ──────────────────────────────────────────
    if args.output and results:
        if args.json or args.output.endswith('.json'):
            _write_combined_json(results, args.output)
        elif args.bb_report:
            _write_combined_bb(results, args.output)
        else:
            _write_combined_bb(results, args.output)

    return results


def _write_combined_json(results: List[JSSecurityAnalyzer], output: str):
    """Write all targets into one JSON file, each URL has its own key."""
    combined = {
        "scan_info": {
            "generated_at": datetime.now().isoformat(),
            "total_targets": len(results),
            "total_findings": sum(len(r.findings) for r in results),
        },
        "targets": []
    }

    for az in results:
        by_sev = defaultdict(int)
        for f in az.findings:
            by_sev[f.severity] += 1

        combined["targets"].append({
            "target": az.source_label,
            "size_bytes": az.file_size,
            "lines": len(az.lines),
            "total_findings": len(az.findings),
            "by_severity": {
                s: by_sev[s]
                for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
            "findings": [f.to_dict() for f in az.findings]
        })

    Path(output).write_text(json.dumps(combined, indent=2))
    print(f"\n{C.GREEN}[+] Combined JSON report → {output}{C.END}")
    print(f"{C.GREEN}    {len(results)} target(s) | "
          f"{sum(len(r.findings) for r in results)} total findings{C.END}")


def _write_combined_bb(results: List[JSSecurityAnalyzer], output: str):
    """Write all targets into one text file."""
    lines = [
        "=" * 80,
        "      SECURITY VULNERABILITY REPORT — Bug Bounty Submission",
        "=" * 80,
        f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Targets   : {len(results)}",
        f"Total     : {sum(len(r.findings) for r in results)} findings",
        "",
    ]
    for az in results:
        lines.append(az.to_bb_report())
        lines.append("\n")
    Path(output).write_text("\n".join(lines))
    print(f"\n{C.GREEN}[+] Combined BB report → {output}{C.END}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="JSSA v3.0 — JavaScript Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jssa.py app.js                          # local file
  python jssa.py https://example.com/bundle.js  # remote URL
  python jssa.py -l urls.txt                    # list of URLs/files
  python jssa.py app.js -v -o report.json --json
  python jssa.py app.js -o report.txt --bb-report
        """
    )
    parser.add_argument("target", nargs="?", help="JS file path or URL to analyze")
    parser.add_argument("-l", "--list", metavar="FILE",
                        help="Text file containing one JS URL or path per line")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print findings in real-time during scan")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Output file for report")
    parser.add_argument("--json", action="store_true",
                        help="Output report as JSON")
    parser.add_argument("--bb-report", action="store_true",
                        help="Output as bug bounty formatted text report")

    args = parser.parse_args()

    targets: List[str] = []

    if args.list:
        p = Path(args.list)
        if not p.exists():
            print(f"{C.RED}[!] List file not found: {args.list}{C.END}")
            sys.exit(1)
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                targets.append(line)
        print(f"{C.CYAN}[*] Loaded {len(targets)} target(s) from {args.list}{C.END}")
    elif args.target:
        targets.append(args.target)
    else:
        parser.print_help()
        sys.exit(0)

    if not targets:
        print(f"{C.RED}[!] No targets found.{C.END}")
        sys.exit(1)

    run_targets(targets, args)


if __name__ == "__main__":
    main()
