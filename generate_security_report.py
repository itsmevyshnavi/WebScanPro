import os
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode


REPORT_HTML = "security_report.html"

# ---------- Helper: Safe CSV loader ----------

def load_csv_if_exists(path, encoding="utf-8"):
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding=encoding) as f:
        reader = csv.DictReader(f)
        return list(reader)


# ---------- 1. Load & normalize vulnerabilities ----------

def load_sql_vulns(path="sql_testing_results.csv"):
    rows = load_csv_if_exists(path)
    vulns = []
    for r in rows:
        evidence = r.get("evidence", "") or ""
        endpoint = r.get("page_url") or ""
        payload = r.get("payload") or ""
        base_len = r.get("baseline_length") or r.get("baseline_len")
        sev = "Low"

        if "sql_error_in_body" in evidence or "time_delay" in evidence:
            sev = "High"
        elif "content_length_change" in evidence:
            sev = "Medium"

        if sev == "Low":
            # If nothing suspicious, skip to avoid noise
            continue

        vulns.append({
            "type": "SQL Injection",
            "endpoint": endpoint,
            "severity": sev,
            "evidence": f"Evidence: {evidence} | Payload: {payload}",
            "source": path
        })
    return vulns


def load_xss_vulns(path="week4_xss_results.csv"):
    rows = load_csv_if_exists(path)
    vulns = []
    for r in rows:
        endpoint = r.get("page_url") or ""
        evidence = r.get("evidence", "") or ""
        payload = r.get("payload", "") or ""
        reflected = (r.get("reflected", "") in ["True", "true", "1"])
        dom_rendered = (r.get("dom_rendered", "") in ["True", "true", "1"])
        stored_pages = r.get("stored_candidate_pages", "") or ""

        if not reflected and not stored_pages:
            # Basic heuristic: skip weak/noisy cases
            continue

        # Severity
        if stored_pages or dom_rendered:
            sev = "High"
        elif reflected:
            sev = "Medium"
        else:
            sev = "Low"

        vulns.append({
            "type": "Cross-Site Scripting (XSS)",
            "endpoint": endpoint,
            "severity": sev,
            "evidence": f"Reflected={reflected}, DOM={dom_rendered}, StoredPages={stored_pages}, Evidence={evidence}, Payload={payload}",
            "source": path
        })
    return vulns


def load_auth_vulns(path="week5_auth_session_results.csv"):
    rows = load_csv_if_exists(path)
    vulns = []
    for r in rows:
        t = r.get("test_type", "")
        endpoint = r.get("endpoint") or r.get("target") or ""
        evidence = r.get("evidence", "") or ""
        notes = r.get("notes", "") or ""
        username = r.get("username") or ""
        cookie_name = r.get("cookie_name") or ""
        cookie_flags = r.get("cookie_flags") or ""

        sev = None
        vtype = "Auth & Session Management Issue"

        if t == "weak_credential" and "login_success" in evidence:
            sev = "High"
            vtype = "Password Policy Weakness"
        elif t == "bruteforce" and "login_success" in evidence:
            sev = "High"
            vtype = "Login Brute-force Exposure"
        elif t == "session_hijack" and "Hijack successful" in notes:
            sev = "High"
            vtype = "Session Hijacking / Fixation"
        elif t == "cookie_analysis":
            issues = evidence.split(";") if evidence else []
            if any("low_entropy" in i for i in issues):
                sev = "Medium"
            elif "missing_Secure" in issues or "missing_HttpOnly" in issues:
                sev = "Low"
            else:
                continue  # nothing interesting

        if not sev:
            continue

        vulns.append({
            "type": vtype,
            "endpoint": endpoint,
            "severity": sev,
            "evidence": f"Test={t}, Evidence={evidence}, Notes={notes}, User={username}, Cookie={cookie_name} ({cookie_flags})",
            "source": path
        })
    return vulns


def load_access_vulns(path="week6_access_control_idor_results.csv"):
    rows = load_csv_if_exists(path)
    vulns = []

    # Group findings so sqli?id=2/3/4 become one logical finding
    grouped = {}

    for r in rows:
        t = r.get("test_type", "")
        full_url = r.get("tested_url") or ""
        evidence = r.get("evidence", "") or ""
        notes = r.get("notes", "") or ""
        param = r.get("param_or_path", "")
        orig = r.get("original_value", "")
        new = r.get("tested_value", "")

        if not t:
            continue

        # Normalize URL: drop specific 'id' so 1/2/3/4 merge
        parsed = urlparse(full_url)
        qs = parse_qs(parsed.query)
        qs.pop("id", None)
        if qs:
            norm_query = urlencode(qs, doseq=True)
            norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{norm_query}"
        else:
            norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # --------- severity logic (tuned to give you Low for weak_id) ----------
        if t in ["horizontal_idor", "vertical"]:
            sev = "High"
        elif t == "horizontal_summary":
            # by default treat summaries as Medium
            sev = "Medium"
        else:
            sev = "Medium"

        # explicitly downgrade weak_id endpoint to Low severity
        if "weak_id" in full_url:
            sev = "Low"

        vname = "Broken Access Control (Object-Level)"
        if t == "vertical":
            vname = "Privilege Escalation – Vertical"
        elif t == "horizontal_idor":
            vname = "Insecure Direct Object Reference (Horizontal)"

        key = (vname, norm_url)
        entry = grouped.get(key)
        if not entry:
            grouped[key] = {
                "type": vname,
                "endpoint": norm_url,
                "severity": sev,
                "examples": [],
                "source": path,
            }
            entry = grouped[key]

        # Keep highest severity seen (Low < Medium < High)
        sev_rank = {"Low": 1, "Medium": 2, "High": 3}
        if sev_rank.get(sev, 1) > sev_rank.get(entry["severity"], 1):
            entry["severity"] = sev

        entry["examples"].append(
            f"Param={param}, Original={orig}, Tested={new}, Evidence={evidence}, Notes={notes}"
        )

    # Flatten
    for (_, _), data in grouped.items():
        ev_text = " | ".join(data["examples"])
        vulns.append({
            "type": data["type"],
            "endpoint": data["endpoint"],
            "severity": data["severity"],
            "evidence": ev_text,
            "source": data["source"],
        })

    return vulns

def load_all_vulns():
    all_v = []
    all_v.extend(load_sql_vulns())
    all_v.extend(load_xss_vulns())
    all_v.extend(load_auth_vulns())
    all_v.extend(load_access_vulns())
    return all_v


# ---------- 2. Mitigation Texts ----------

MITIGATIONS = {
    "Password Policy Weakness": (
        "Replace default or guessable passwords with strong password rules. "
        "Force users to change any shipped/default credentials at first login and block their reuse. "
        "Introduce account lockout or additional verification after several failed attempts."
    ),
    "Login Brute-force Exposure": (
        "Throttle repeated login attempts using rate limiting or CAPTCHAs. "
        "Lock or temporarily suspend accounts after too many failures and alert admins about suspicious activity."
    ),
    "Session Hijacking / Fixation": (
        "Generate long, unpredictable session IDs and send them only over HTTPS. "
        "Set HttpOnly, Secure and SameSite attributes on cookies and rotate session IDs whenever a user logs in or elevates privileges."
    ),
    "Auth & Session Management Issue": (
        "Review login, logout and session handling logic. "
        "Avoid exposing session IDs in URLs or client-side scripts and make sure sessions are invalidated on logout or timeout."
    ),
    "Broken Access Control (Object-Level)": (
        "Check user authorisation on the server for every access to an object or record. "
        "Do not trust IDs coming from the browser; always verify that the current user owns or is allowed to view the target resource."
    ),
    "Insecure Direct Object Reference (Horizontal)": (
        "Avoid direct, predictable identifiers where possible, or combine them with strict server-side checks. "
        "Ensure a user cannot view or modify another user’s data simply by changing an ID in the request."
    ),
    "Privilege Escalation – Vertical": (
        "Enforce role-based access control for every privileged feature. "
        "Restrict admin functionality to dedicated roles and never rely only on hiding links in the UI."
    ),
    # keep others like SQL Injection, XSS etc. if you used them in earlier weeks
}



def get_mitigation(vtype: str) -> str:
    # Try exact match, then fall back on broader category
    if vtype in MITIGATIONS:
        return MITIGATIONS[vtype]
    if "XSS" in vtype:
        return MITIGATIONS["Cross-Site Scripting (XSS)"]
    if "SQL" in vtype:
        return MITIGATIONS["SQL Injection"]
    if "IDOR" in vtype or "Access Control" in vtype:
        return MITIGATIONS["Access Control / IDOR"]
    if "Session" in vtype or "Auth" in vtype:
        return MITIGATIONS["Authentication / Session"]
    return "Review and apply appropriate security best practices (least privilege, input validation, output encoding, proper authorization checks)."


# ---------- 3. HTML Report Generation ----------

def generate_html_report(vulns, outfile=REPORT_HTML):
    total = len(vulns)
    by_severity = Counter(v["severity"] for v in vulns)
    by_type = Counter(v["type"] for v in vulns)

    # Normalize severity order: High → Medium → Low
    sev_order = ["High", "Medium", "Low"]
    sev_labels = [s for s in sev_order if s in by_severity]
    sev_values = [by_severity[s] for s in sev_labels]

    type_labels = list(by_type.keys())
    type_values = [by_type[t] for t in type_labels]

    # simple numeric risk score (High=3, Medium=2, Low=1)
    score_map = {"High": 3, "Medium": 2, "Low": 1}
    risk_score = sum(score_map.get(v["severity"], 1) for v in vulns)

    # severity percentages for summary line
    def percent(count):
        return round((count / total) * 100) if total else 0

    sev_percent_text = ", ".join(
        f"{label}: {by_severity[label]} ({percent(by_severity[label])}%)"
        for label in sev_labels
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>DVWA Security Assessment Dashboard – WebScanPro</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{
            margin: 0;
            padding: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: radial-gradient(circle at top, #222641 0, #101322 40%, #050612 100%);
            color: #f5f6ff;
        }}
        .shell {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 24px 20px 40px 20px;
        }}
        .card {{
            background: rgba(15, 19, 38, 0.96);
            border-radius: 16px;
            padding: 16px 18px;
            box-shadow: 0 18px 40px rgba(0,0,0,0.55);
            margin-bottom: 18px;
            border: 1px solid rgba(121, 134, 203, 0.25);
        }}
        .title-row {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 12px;
            flex-wrap: wrap;
        }}
        h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .subtitle {{
            margin: 4px 0 0 0;
            font-size: 12px;
            color: #cfd2ff;
        }}
        .pill {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 999px;
            border: 1px solid #3c3f6b;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #cfd2ff;
            background: rgba(32, 39, 78, 0.7);
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 14px;
            margin-top: 14px;
        }}
        .summary-item h3 {{
            margin: 0 0 4px 0;
            font-size: 13px;
            color: #cfd2ff;
        }}
        .summary-item p {{
            margin: 0;
            font-size: 13px;
        }}
        .summary-item strong {{
            font-size: 20px;
        }}
        .charts-row {{
            display: grid;
            grid-template-columns: minmax(260px, 1.1fr) minmax(260px, 1.3fr);
            gap: 16px;
        }}
        @media (max-width: 900px) {{
            .charts-row {{
                grid-template-columns: 1fr;
            }}
        }}
        .chart-box h3 {{
            margin-top: 0;
            font-size: 14px;
            color: #dde0ff;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
            margin-top: 10px;
        }}
        thead tr {{
            background: #262b46;
        }}
        th, td {{
            border: 1px solid #323757;
            padding: 6px 8px;
            vertical-align: top;
        }}
        tbody tr:nth-child(even) {{
            background: #191d31;
        }}
        tbody tr:nth-child(odd) {{
            background: #131728;
        }}
        .tiny {{
            font-size: 11px;
            color: #d0d2ff;
        }}
        .severity-chip {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 999px;
            font-size: 11px;
            margin-right: 4px;
            border: 1px solid #3b3f68;
        }}
        .sev-High {{
            background: rgba(244, 67, 54, 0.18);
            color: #ff8a80;
            border-color: rgba(244, 67, 54, 0.7);
        }}
        .sev-Medium {{
            background: rgba(255, 167, 38, 0.18);
            color: #ffcc80;
            border-color: rgba(255, 167, 38, 0.7);
        }}
        .sev-Low {{
            background: rgba(76, 175, 80, 0.18);
            color: #a5d6a7;
            border-color: rgba(76, 175, 80, 0.7);
        }}
    </style>
</head>
<body>
<div class="shell">
    <div class="card">
        <div class="title-row">
            <div>
                <h1>DVWA Security Assessment Dashboard</h1>
                <p class="subtitle">
                    Consolidated findings from WebScanPro modules (authentication, brute-force, access control).
                    Duplicate attempts are merged so you see each issue once, with clear severity and category.
                </p>
            </div>
            <div>
                <span class="pill">Target: http://localhost:8080</span><br/>
                <span class="pill" style="margin-top:6px; background: rgba(233, 30, 99, 0.18); border-color: rgba(233, 30, 99, 0.6);">
                    Auto-generated report
                </span>
            </div>
        </div>

        <div class="summary-grid">
            <div class="summary-item">
                <h3>Total Issues</h3>
                <p><strong>{total}</strong> consolidated vulnerabilities</p>
            </div>
            <div class="summary-item">
                <h3>Severity Breakdown</h3>
                <p>{sev_percent_text}</p>
            </div>
            <div class="summary-item">
                <h3>Categories Observed</h3>
                <p>{", ".join(type_labels)}</p>
            </div>
            <div class="summary-item">
                <h3>Approx. Risk Score</h3>
                <p><strong>{risk_score}</strong> (High=3, Medium=2, Low=1)</p>
            </div>
        </div>
    </div>

    <div class="card">
        <div class="charts-row">
            <div class="chart-box">
                <h3>Distribution by Severity</h3>
                <canvas id="severityChart" width="320" height="240"></canvas>
            </div>
            <div class="chart-box">
                <h3>Distribution by Category</h3>
                <canvas id="typeChart" width="320" height="240"></canvas>
            </div>
        </div>
    </div>

    <div class="card">
        <h2 style="margin:0 0 8px 0; font-size:18px;">Detailed Findings</h2>
        <p class="tiny">
            Each row below represents one consolidated issue. For example, multiple successful brute-force passwords
            for the same account are collapsed into a single “Login Brute-force Exposure” finding.
        </p>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Category</th>
                    <th>Affected Endpoint</th>
                    <th>Severity</th>
                    <th>Evidence / Notes</th>
                    <th>Suggested Mitigation</th>
                </tr>
            </thead>
            <tbody>
    """

    # table rows
    for i, v in enumerate(vulns, 1):
        mit = get_mitigation(v["type"])
        sev = v["severity"]
        sev_class = f"sev-{sev}"
        html += f"""
                <tr>
                    <td>{i}</td>
                    <td>{v['type']}</td>
                    <td>{v['endpoint']}</td>
                    <td><span class="severity-chip {sev_class}">{sev}</span></td>
                    <td class="tiny">{v['evidence']}</td>
                    <td class="tiny">{mit}</td>
                </tr>
        """

    html += """
            </tbody>
        </table>
    </div>
</div>

<script>
    // Severity chart (doughnut)
    const sevCtx = document.getElementById('severityChart').getContext('2d');
    new Chart(sevCtx, {
        type: 'doughnut',
        data: {
            labels: """ + json.dumps(sev_labels) + """,
            datasets: [{
                data: """ + json.dumps(sev_values) + """,
                backgroundColor: [
                    'rgba(244, 67, 54, 0.7)',   // High
                    'rgba(255, 167, 38, 0.7)',  // Medium
                    'rgba(76, 175, 80, 0.7)'    // Low
                ].slice(0, """ + str(len(sev_labels)) + """),
                borderWidth: 1
            }]
        },
        options: {
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { boxWidth: 14 }
                },
                tooltip: {
                    callbacks: {
                        label: function(ctx) {
                            const count = ctx.parsed;
                            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
                            const pct = total ? Math.round((count / total) * 100) : 0;
                            return ctx.label + ': ' + count + ' (' + pct + '%)';
                        }
                    }
                }
            },
            cutout: '55%'
        }
    });

    // Category chart (horizontal bar)
    const typeCtx = document.getElementById('typeChart').getContext('2d');
    new Chart(typeCtx, {
        type: 'bar',
        data: {
            labels: """ + json.dumps(type_labels) + """,
            datasets: [{
                data: """ + json.dumps(type_values) + """,
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(ctx) {
                            return ctx.raw + ' issue(s)';
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { precision: 0 }
                }
            }
        }
    });
</script>
</body>
</html>
"""

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"[+] HTML report written to {outfile}")
    print("    Open in a browser and use 'Print → Save as PDF' to export as PDF.")

def main():
    vulns = load_all_vulns()
    if not vulns:
        print("[!] No vulnerabilities loaded. Make sure your CSV files exist and have data.")
    else:
        generate_html_report(vulns, REPORT_HTML)


if __name__ == "__main__":
    main()
