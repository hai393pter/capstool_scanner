import time
import signal
import sys
import logging
import requests
import json
import os
from playwright.sync_api import sync_playwright, Playwright
from playwright._impl._errors import TimeoutError
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import jinja2

# Thiết lập logging
logging.basicConfig(filename='security_misconfig_scan.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
results = []

# Xử lý tín hiệu dừng (Ctrl+C)
def signal_handler(sig, frame):
    print("\n[!] Stopping scan...")
    if results:
        generate_html_report()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Cấu hình
class Config:
    DEFAULT_CREDS = [
        ("admin", "admin"), ("admin", "admin123"), ("root", "root"), ("test", "test"),
        ("user", "123456"), ("admin", "password"), ("admin", "1234")
    ]
    ENDPOINTS = ["/login", "/admin", "/system-info", "/config", "/debug", "/.env", "/robots.txt"]
    HEADERS_TO_CHECK = ["Server", "X-Powered-By", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]

# Kiểm tra Security Misconfiguration
def check_security_misconfig(playwright: Playwright, base_url, proxy=None, max_retries=3):
    global results
    browser = None
    try:
        print(f"[*] Launching Chromium to scan {base_url} with proxy {proxy}...")
        browser = playwright.chromium.launch(headless=False)
        context = browser.new_context(ignore_https_errors=True, proxy=proxy)
        page = context.new_page()

        # Xử lý dialog
        def handle_dialog(dialog):
            print(f"[*] Dialog triggered: {dialog.message}")
            dialog.accept()

        page.on("dialog", handle_dialog)

        for endpoint in Config.ENDPOINTS:
            url = urljoin(base_url, endpoint)
            try:
                print(f"[*] Checking {url}...")
                page.goto(url, timeout=30000)

                # Kiểm tra phản hồi HTTP
                response = requests.get(url, timeout=10, proxies={"http": proxy, "https": proxy} if proxy else {})
                headers = response.headers
                content = response.text
                soup = BeautifulSoup(content, 'html.parser')

                misconfig_findings = []
                severity = "Low"

                # Kiểm tra header nhạy cảm
                missing_security_headers = [h for h in Config.HEADERS_TO_CHECK if h not in headers or not headers[h]]
                if missing_security_headers or "Server" in headers or "X-Powered-By" in headers:
                    misconfig_findings.append({
                        "type": "Sensitive Header Exposure",
                        "details": f"Headers: {headers}, Missing: {missing_security_headers}",
                        "severity": "Medium" if missing_security_headers else "Low"
                    })
                    logging.warning(f"Sensitive headers or missing security headers at {url}: {headers}")

                # Kiểm tra file tĩnh nhạy cảm
                if endpoint in ["/.env", "/robots.txt"]:
                    if response.status_code == 200 and any(keyword in content.lower() for keyword in ["db_password", "api_key", "secret"]):
                        misconfig_findings.append({
                            "type": "Sensitive File Exposure",
                            "details": f"Found sensitive data in {endpoint}",
                            "severity": "High"
                        })
                        logging.critical(f"Sensitive data exposed at {url}")

                # Kiểm tra directory listing
                if "Index of" in content or "Directory listing" in content:
                    misconfig_findings.append({
                        "type": "Directory Listing Enabled",
                        "details": "Server allows directory browsing",
                        "severity": "High"
                    })
                    logging.critical(f"Directory listing enabled at {url}")

                # Kiểm tra form đăng nhập với tài khoản mặc định
                if page.query_selector("input[name='username']") and page.query_selector("input[name='password']"):
                    print(f"[*] Found login form at {url}, testing default credentials...")
                    for username, password in Config.DEFAULT_CREDS:
                        page.fill("input[name='username']", username)
                        page.fill("input[name='password']", password)
                        page.click("input[type='submit']")
                        time.sleep(1)
                        if "successful" in page.content().lower() or "welcome" in page.content().lower():
                            misconfig_findings.append({
                                "type": "Default Credentials",
                                "details": f"Login successful with {username}:{password}",
                                "severity": "High"
                            })
                            logging.critical(f"Default credentials found at {url}: {username}:{password}")
                            break

                # Kiểm tra version disclosure
                if any(version in content.lower() for version in ["php", "apache", "nginx", "flask", "django"]):
                    misconfig_findings.append({
                        "type": "Version Disclosure",
                        "details": f"Version info found: {content}",
                        "severity": "Medium"
                    })
                    logging.warning(f"Version disclosure at {url}")

                # Kiểm tra lỗi stack trace
                try:
                    page.evaluate("throw new Error('Test Error');")
                    page.wait_for_timeout(2000)
                    if "stack trace" in page.content().lower() or "error" in page.content().lower():
                        misconfig_findings.append({
                            "type": "Debug Mode Enabled",
                            "details": "Stack trace or error details exposed",
                            "severity": "High"
                        })
                        logging.critical(f"Debug mode enabled at {url}, exposing stack trace")
                except Exception:
                    pass

                # Ghi kết quả
                if misconfig_findings:
                    result = {
                        "url": url,
                        "misconfigurations": misconfig_findings,
                        "timestamp": time.ctime()
                    }
                    results.append(result)
                    max_severity = max(f["severity"] for f in misconfig_findings)
                    print(f"[!!!] Security Misconfiguration found at {url} (Severity: {max_severity}): {misconfig_findings}")
                else:
                    print(f"[*] No misconfiguration found at {url}")

            except TimeoutError:
                print(f"[!] Timeout while checking {url}, skipping...")
                logging.error(f"Timeout error at {url}")
            except Exception as e:
                print(f"[!] Error checking {url}: {e}")
                logging.error(f"Error at {url}: {e}")

        # Kiểm tra endpoint không được bảo vệ
        for endpoint in ["/admin", "/manager", "/config", "/backup"]:
            url = urljoin(base_url, endpoint)
            try:
                response = requests.get(url, timeout=10, proxies={"http": proxy, "https": proxy} if proxy else {})
                if response.status_code == 200:
                    misconfig_findings = [{
                        "type": "Unprotected Endpoint",
                        "details": f"Endpoint {url} accessible without authentication",
                        "severity": "High"
                    }]
                    result = {
                        "url": url,
                        "misconfigurations": misconfig_findings,
                        "timestamp": time.ctime()
                    }
                    results.append(result)
                    print(f"[!!!] Unprotected endpoint found at {url} (Severity: High)")
                    logging.critical(f"Unprotected endpoint at {url}")
            except:
                continue

    except Exception as e:
        print(f"[!] Critical error: {e}")
        logging.error(f"Critical error: {e}")
    finally:
        if browser:
            print("[*] Closing Chrome browser...")
            browser.close()

# Tạo báo cáo HTML
def generate_html_report():
    global results
    template = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="./")).from_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Security Misconfiguration Report</title>
        <style>
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .high { background-color: #ffcccc; }
            .medium { background-color: #fff3cd; }
            .low { background-color: #d4edda; }
        </style>
    </head>
    <body>
        <h1>Security Misconfiguration Scan Report</h1>
        <table>
            <tr>
                <th>URL</th>
                <th>Misconfiguration Type</th>
                <th>Details</th>
                <th>Severity</th>
                <th>Timestamp</th>
            </tr>
            {% for result in results %}
                {% for finding in result.misconfigurations %}
                    <tr class="{{ finding.severity|lower }}">
                        <td>{{ result.url }}</td>
                        <td>{{ finding.type }}</td>
                        <td>{{ finding.details }}</td>
                        <td>{{ finding.severity }}</td>
                        <td>{{ result.timestamp }}</td>
                    </tr>
                {% endfor %}
            {% endfor %}
        </table>
    </body>
    </html>
    """)
    with open("security_misconfig_report.html", "w") as f:
        f.write(template.render(results=results))
    print("[*] HTML report generated: security_misconfig_report.html")

# Hàm quét Security Misconfiguration
def scan_security_misconfig(target_url):
    global results
    proxy = input("Enter proxy (e.g., http://localhost:8080) or press Enter to skip: ").strip() or None
    with sync_playwright() as playwright:
        check_security_misconfig(playwright, target_url, proxy)
    
    if results:
        with open("security_misconfig_results.json", "w") as f:
            json.dump(results, f, indent=4)
        generate_html_report()
        print("[*] Scan results saved to security_misconfig_results.json and security_misconfig_report.html")

# Hàm chính và menu
def main():
    print("=== Advanced Security Misconfiguration Scanner ===")
    while True:
        target_url = input("Enter target URL to scan (e.g., http://localhost:5000/): ")
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        scan_security_misconfig(target_url)

        print("\nScan completed!")
        print("Would you like to scan another URL or exit?")
        print("1. Scan another URL")
        print("2. Exit")
        choice = input("Enter your choice (1 or 2): ")

        if choice == "2":
            print("[*] Exiting program...")
            if results:
                generate_html_report()
            sys.exit(0)
        elif choice != "1":
            print("[!] Invalid choice. Exiting program...")
            sys.exit(0)

if __name__ == "__main__":
    # Cài đặt BeautifulSoup và Jinja2 nếu chưa có
    try:
        import bs4
        import jinja2
    except ImportError:
        print("[!] Installing required packages (beautifulsoup4, jinja2)...")
        os.system("pip install beautifulsoup4 jinja2")
    main()