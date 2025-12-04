# scanner_requests.py
"""
WebScanPro - Target Scanner using requests + BeautifulSoup
Usage:
    pip install requests beautifulsoup4 lxml tqdm
    python scanner_requests.py --target http://127.0.0.1/dvwa/ --max-depth 2
Outputs:
    - scan_results_requests.json
    - scan_results_requests.csv
"""

import requests, time, json, csv, argparse, sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urldefrag
from tqdm import tqdm

DEFAULT_USER_AGENT = "WebScanPro/1.0 (+https://example.local)"
REQUEST_TIMEOUT = 6
SLEEP_BETWEEN_REQUESTS = 0.25

def normalize_link(base, link):
    joined = urljoin(base, link)
    cleaned, _ = urldefrag(joined)
    return cleaned

def same_domain(a, b):
    return urlparse(a).netloc == urlparse(b).netloc

def fetch_html_requests(url, headers=None):
    headers = headers or {"User-Agent": DEFAULT_USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return r.status_code, r.text
    except Exception as e:
        return None, f"__error__:{str(e)}"

def extract_links_and_forms(base_url, html_text):
    soup = BeautifulSoup(html_text, "lxml")
    links = set()
    forms = []

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href:
            full = normalize_link(base_url, href)
            links.add(full)

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            typ = inp.get("type") if inp.name == "input" else inp.name
            value = inp.get("value")
            if not name:
                fallback = inp.get("id") or inp.get("placeholder")
                name = fallback if fallback else None
            inputs.append({"name": name, "type": typ, "value": value})
        forms.append({"action": normalize_link(base_url, action) if action else base_url,
                      "method": method, "inputs": inputs})
    return list(links), forms

def crawl_requests(start_url, max_depth=2, max_pages=500):
    domain = urlparse(start_url).netloc
    visited = set()
    queue = [(start_url, 0)]
    results = []
    pbar = tqdm(total=max_pages, desc="Pages processed", unit="page")
    try:
        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)
            status, html = fetch_html_requests(url)
            if isinstance(html, str) and html.startswith("__error__"):
                results.append({"page": url, "status": status, "error": html.replace("__error__:", ""), "forms": [], "links": []})
                pbar.update(1)
                time.sleep(SLEEP_BETWEEN_REQUESTS)
                continue
            links, forms = extract_links_and_forms(url, html)
            same_domain_links = []
            for link in links:
                try:
                    if same_domain(start_url, link):
                        same_domain_links.append(link)
                        if link not in visited and (depth + 1) <= max_depth:
                            queue.append((link, depth + 1))
                except Exception:
                    continue
            results.append({"page": url, "status": status, "forms": forms, "links": same_domain_links})
            pbar.update(1)
            time.sleep(SLEEP_BETWEEN_REQUESTS)
        pbar.close()
    except KeyboardInterrupt:
        pbar.close()
    return results

def save_json(filename, data):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved JSON -> {filename}")

def save_csv(filename, data):
    rows = []
    for entry in data:
        page = entry.get("page")
        links = entry.get("links", [])
        forms = entry.get("forms", [])
        if forms:
            for form in forms:
                action = form.get("action")
                method = form.get("method")
                inputs = form.get("inputs", [])
                if inputs:
                    for inp in inputs:
                        rows.append({"page": page, "action": action, "method": method,
                                     "input_name": inp.get("name"), "input_type": inp.get("type"),
                                     "input_value": inp.get("value"), "link_count": len(links)})
                else:
                    rows.append({"page": page, "action": action, "method": method,
                                 "input_name": None, "input_type": None, "input_value": None, "link_count": len(links)})
        else:
            rows.append({"page": page, "action": None, "method": None, "input_name": None,
                         "input_type": None, "input_value": None, "link_count": len(links)})
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["page", "action", "method", "input_name", "input_type", "input_value", "link_count"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"[+] Saved CSV -> {filename}")

def main():
    parser = argparse.ArgumentParser(description="WebScanPro - requests crawler")
    parser.add_argument("--target", "-t", required=True, help="Base target URL (e.g., http://127.0.0.1/dvwa/)")
    parser.add_argument("--max-depth", "-d", type=int, default=2)
    parser.add_argument("--max-pages", type=int, default=500)
    parser.add_argument("--out-json", default="scan_results_requests.json")
    parser.add_argument("--out-csv", default="scan_results_requests.csv")
    args = parser.parse_args()
    target = args.target
    if not target.startswith("http://") and not target.startswith("https://"):
        print("[!] Target must start with http:// or https://")
        sys.exit(1)
    print(f"[i] Starting requests-based crawl for {target} (depth={args.max_depth})")
    results = crawl_requests(start_url=target, max_depth=args.max_depth, max_pages=args.max_pages)
    save_json(args.out_json, results)
    save_csv(args.out_csv, results)
    print("[i] Done.")

if __name__ == "__main__":
    main()
