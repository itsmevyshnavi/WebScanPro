#  WebScanPro – Automated Web Security Testing Tool

WebScanPro is a simple and beginner-friendly automated security testing tool that helps identify common web application vulnerabilities.  
It was built by analyzing intentionally vulnerable apps like **DVWA**, **OWASP Juice Shop**, and **bWAPP**, and performing modules such as SQL Injection testing, XSS detection, authentication testing, and access-control checks.

This tool was created as part of a hands-on security learning project and generates clean, visual HTML reports to help understand vulnerabilities easily.

---

##  What This Project Does

WebScanPro performs automated checks on a target website and detects issues such as:

🔸 SQL Injection  
🔸 Cross-Site Scripting (XSS)  
🔸 Weak Password Policies  
🔸 Broken Authentication  
🔸 Brute-force Login Vulnerabilities  
🔸 Access Control & IDOR issues  

It then generates a **Security Assessment Dashboard** HTML summarizing:
- Total issues  
- Severity (High, Medium, Low)  
- Categories found  
- Risk score  
- Detailed vulnerability explanations & suggested fixes  

---

##  Project Structure

The repository contains:

- `scanner_requests.py` – Scans HTTP requests  
- `sql_tester_from_scan.py` – Tests for SQL Injection  
- `xss_tester_from_scan.py` – Detects reflected/stored XSS attempts  
- `AccessControl.py` – Tests for IDOR & broken access control  
- `Session_Auth.py` – Weak password & authentication testing  
- `summarize_scan.py` – Consolidates test results  
- `generate_security_report.py` – Builds the final security dashboard  
- `DVWA/…` – Example input/output files generated while testing  
- `docker-compose.yml` – Option to run DVWA setup via Docker  

The generated PDF/Web dashboard includes charts and vulnerability tables from the analysis, such as the severity breakdown and category charts visible in the project screenshot PDFs. :contentReference[oaicite:3]{index=3}

---

##  Technologies Used
- Python  
- BeautifulSoup  
- Selenium (optional for crawling)  
- Requests  
- Chart.js (for dashboard visualization)

---

##  Project Workflow (Week-Wise)

### **Week 1 – Setup**
- Installed DVWA locally  
- Understood application behavior and security flaws  

### **Week 2 – Crawler & Target Scanning**
- Built a small crawler using BeautifulSoup/Selenium  
- Extracted pages, links, input fields, and forms  

### **Week 3 – SQL Injection Module**
- Injected test payloads  
- Checked responses for SQL errors or anomalies  

### **Week 4 – XSS Testing**
- Injected harmless markers and looked for reflection in HTML/DOM  
- Detected reflected/stored XSS  

### **Week 5 – Authentication Testing**
- Tested default credentials  
- Checked cookies (Secure, HttpOnly, SameSite)  
- Simulated brute-force attempts  

### **Week 6 – Access Control Testing**
- Tried accessing unauthorized data  
- Detected broken access control & IDOR issues  

### **Week 7 – Report Generation**
- Merged results  
- Visualized data using Chart.js  
- Generated the interactive dashboard  

### **Week 8 – Documentation & Presentation**
- Prepared final explanatory documentation and results  

---

Thank you for exploring **WebScanPro**!  
This project represents a complete end-to-end learning journey in web application security combining automation, vulnerability analysis, and clear report generation.

Feel free to explore the code, enhance existing modules, or add new vulnerability testing features.  
Contributions, suggestions, and improvements are always welcome!

![License](https://img.shields.io/badge/License-MIT-green)
