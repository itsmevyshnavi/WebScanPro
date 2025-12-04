#!/usr/bin/env python3
"""
AccessControl.py - Week 6: Access Control & IDOR Testing (DVWA)

- Target app: DVWA (e.g. http://localhost:8080/)
- Uses CSRF token login (default creds: admin / password)
- Horizontal checks: ID tampering on known endpoints (IDOR-style)
- Vertical checks: compare anonymous vs logged-in access on “sensitive” URLs
- Output CSV: week6_access_control_idor_results.csv

Run:
    python AccessControl.py --target http://localhost:8080 --username admin --password password
"""

import argparse
import csv
import os
import time
import hashlib
import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "WebScanPro-AccessControl/2.0"}
DEFAULT_OUT = "week6_access_control_idor_results.csv"
REQUEST_DELAY = 0.3
ID_RANGE = 3  # how far around the original ID to probe

# DVWA endpoints that usually contain ID-like parameters
KNOWN_ID_TARGETS = [
    "vulnerabilities/sqli/?id=1&Submit=Submit",
    "vulnerabilities/sqli_blind/?id=1&Submit=Submit",
    "vulnerabilities/weak_id/",
]

# Endpoints that should normally require authentication or higher privileges
ADMIN_ENDPOINTS = [
    "security.php",
    "vulnerabilities/fi/?page=file1.php",
    "vulnerabilities/exec/?ip=8.8.8.8&Submit=Submit",
    "vulnerabilities/sqli/?id=1&Submit=Submit",
]

REPORT_COLUMNS = [
    "test_type", "tested_url", "method",
    "param_or_path", "original_value", "tested_value",
    "status_code", "evidence", "notes",
]


# ---------------- HTTP helpers ----------------

def safe_get(session, url):
    """Wrapper around session.get() so a single failure doesn’t crash the whole script."""
    try:
        return session.get(url, headers=HEADERS, timeout=10)
    except Exception as e:
        print(f"[ERROR] GET {url} failed: {e}")
        return None


def safe_post(session, url, data):
    """Wrapper around session.post() for safer handling of connection errors."""
    try:
        return session.post(url, data=data, headers=HEADERS, timeout=10)
    except Exception as e:
        print(f"[ERROR] POST {url} failed: {e}")
        return None


def fingerprint(resp):
    """
    Take a quick “fingerprint” of a response:
    - status code
    - SHA-256 hash of the first part of the body
    This helps us see if content changed when we tweaked an ID.
    """
    if not resp or not getattr(resp, "text", ""):
        return "none", "none"
    snippet = resp.text[:600]
    return resp.status_code, hashlib.sha256(
        snippet.encode("utf-8", errors="ignore")
    ).hexdigest()


# ---------------- DVWA login helpers ----------------

def extract_token(html):
    """Grab the DVWA CSRF token from the login form."""
    soup = BeautifulSoup(html, "html.parser")
    tok = soup.find("input", {"name": "user_token"})
    return tok.get("value") if tok else None


def dvwa_login(session, base_url, username="admin", password="password"):
    """
    Perform DVWA login with CSRF token and verify that we’re actually logged in
    by checking index.php for typical logged-in markers (Logout, DVWA Security, etc.).
    """
    login_url = urljoin(base_url, "login.php")
    index_url = urljoin(base_url, "index.php")

    print(f"[i] Opening login page: {login_url}")
    r1 = safe_get(session, login_url)
    if not r1:
        print("[ERROR] Cannot fetch login.php")
        return False

    token = extract_token(r1.text)
    if not token:
        print("[ERROR] Could not find user_token on login page.")
        return False

    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }

    print("[i] Submitting login form with CSRF token...")
    r2 = safe_post(session, login_url, payload)
    if not r2:
        print("[ERROR] Login POST failed (no response).")
        return False

    body_lower = r2.text.lower()

    # If DVWA explicitly tells us login failed, no need to continue
    if "login failed" in body_lower or "incorrect login" in body_lower:
        print("[ERROR] DVWA indicates login failure (check credentials / security level).")
        return False

    # Some DVWA setups may redirect or just reload; check index.php explicitly
    r3 = safe_get(session, index_url)
    if r3 and r3.status_code == 200:
        text = r3.text.lower()
        if "logout" in text or "dvwa security" in text or "welcome to damn vulnerable web app" in text:
            print("[+] Login successful (verified via index.php).")
            return True

    print("[ERROR] Login failed (could not confirm logged-in state).")
    return False


# ---------------- Build ID targets ----------------

def build_id_targets(base):
    """
    Build a list of (full_url, original_id or None) from KNOWN_ID_TARGETS.
    If the “id” query param is present, we keep its starting value.
    """
    targets = []
    for path in KNOWN_ID_TARGETS:
        full = urljoin(base, path)
        parsed = urlparse(full)
        qs = parse_qs(parsed.query)

        if "id" in qs:
            try:
                orig_id = int(qs["id"][0])
            except Exception:
                orig_id = 1
            targets.append((full, orig_id))
        else:
            targets.append((full, None))
    return targets


# ---------------- Horizontal IDOR tests ----------------

def horizontal_tests(session_auth, writer, base):
    """
    Horizontal / IDOR-style checks:
    - Use an authenticated session.
    - For each endpoint, try nearby IDs.
    - Log only:
        * Any ID that clearly changes content (possible IDOR), OR
        * A single summary row saying "no IDOR detected" for that endpoint.
    """
    print("[*] Running horizontal access / IDOR tests...")

    targets = build_id_targets(base)
    for url, orig_id in targets:
        print(f"  [*] Base URL: {url} (start_id={orig_id})")

        base_resp = safe_get(session_auth, url)
        fp_base = fingerprint(base_resp)

        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        base_path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        idor_found = False  # track if any interesting change happens

        if orig_id is not None and "id" in qs:
            for offset in range(-ID_RANGE, ID_RANGE + 1):
                if offset == 0:
                    continue
                new_id = orig_id + offset
                if new_id <= 0:
                    continue

                new_qs = qs.copy()
                new_qs["id"] = [str(new_id)]
                new_url = base_path + "?" + urlencode(new_qs, doseq=True)

                resp = safe_get(session_auth, new_url)
                fp_new = fingerprint(resp)

                if resp:
                    status = resp.status_code
                    if fp_new != fp_base and status == 200:
                        # 🚨 More interesting: possible IDOR
                        idor_found = True
                        writer.writerow({
                            "test_type": "horizontal_idor",
                            "tested_url": new_url,
                            "method": "GET",
                            "param_or_path": "id",
                            "original_value": orig_id,
                            "tested_value": new_id,
                            "status_code": status,
                            "evidence": "content_changed",
                            "notes": "Different content observed for a tampered ID (potential IDOR).",
                        })
                    # else → we don't log boring "no_change_or_denied" per ID anymore
                else:
                    # network issue, ignore for report
                    pass

                time.sleep(REQUEST_DELAY)

            # after checking all IDs, if no change found → one summary row
            if not idor_found:
                writer.writerow({
                    "test_type": "horizontal_summary",
                    "tested_url": url,
                    "method": "GET",
                    "param_or_path": "id",
                    "original_value": orig_id,
                    "tested_value": "",
                    "status_code": base_resp.status_code if base_resp else None,
                    "evidence": "no_idor_detected",
                    "notes": "Tried nearby ID values; responses looked similar (no obvious IDOR).",
                })

        else:
            # e.g. weak_id without explicit id param in the URL
            if base_resp:
                writer.writerow({
                    "test_type": "horizontal_summary",
                    "tested_url": url,
                    "method": "GET",
                    "param_or_path": "(none)",
                    "original_value": "",
                    "tested_value": "",
                    "status_code": base_resp.status_code,
                    "evidence": "no_explicit_id_param",
                    "notes": "Endpoint reached but no explicit 'id' parameter in query.",
                })
            time.sleep(REQUEST_DELAY)

# ---------------- Vertical access control tests ----------------

def vertical_tests(session_anon, session_auth, writer, base):
    """
    Vertical access control checks:
    - Compare what an authenticated user sees vs an anonymous user
      for a set of “admin-ish” endpoints.
    - If anonymous can access content that looks real and not just the login page,
      we mark it as a vertical privilege issue.
    """
    print("[*] Running vertical access control tests (anonymous vs authenticated)...")

    for ep in ADMIN_ENDPOINTS:
        url = urljoin(base, ep)
        print(f"  [*] Checking vertical access on: {url}")

        r_auth = safe_get(session_auth, url)
        r_anon = safe_get(session_anon, url)

        if not r_auth or r_auth.status_code != 200:
            # If even the authenticated user can’t see it, skip
            time.sleep(REQUEST_DELAY)
            continue

        anon_ok = r_anon and r_anon.status_code == 200
        if anon_ok:
            body = r_anon.text.lower()
            # Very rough heuristic: if it doesn’t obviously look like a login page,
            # treat this as a vertical access problem.
            if "login" not in body and "username" not in body:
                writer.writerow({
                    "test_type": "vertical",
                    "tested_url": url,
                    "method": "GET",
                    "param_or_path": ep,
                    "original_value": "",
                    "tested_value": "",
                    "status_code": r_anon.status_code,
                    "evidence": "anonymous_access_to_priv_resource",
                    "notes": "Anonymous user accessed a page that should be restricted.",
                })

        time.sleep(REQUEST_DELAY)


# ---------------- Main entry point ----------------

def main():
    parser = argparse.ArgumentParser(
        description="Week 6: Access Control & IDOR Testing against DVWA"
    )
    parser.add_argument("--target", required=True, help="Base URL (e.g., http://localhost:8080)")
    parser.add_argument("--username", default="admin", help="DVWA username (default: admin)")
    parser.add_argument("--password", default="password", help="DVWA password (default: password)")
    parser.add_argument("--out", default=DEFAULT_OUT, help="Output CSV file name")
    args = parser.parse_args()

    base = args.target.rstrip("/") + "/"

    # Make sure the directory for the output file exists
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_COLUMNS)
        writer.writeheader()

        # Logged-in session
        session_auth = requests.Session()
        if not dvwa_login(session_auth, base, args.username, args.password):
            print("[ERROR] Authenticated login failed. Stopping Week 6 tests.")
            return

        # Anonymous session
        session_anon = requests.Session()

        # Run tests
        horizontal_tests(session_auth, writer, base)
        vertical_tests(session_anon, session_auth, writer, base)

    print(f"\n[DONE] Week 6 access control & IDOR results saved to: {args.out}")


if __name__ == "__main__":
    main()
