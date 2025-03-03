import socket
import requests
import threading
from bs4 import BeautifulSoup

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"
}

SQLI_ERRORS = [
    "You have an error in your SQL syntax", "Warning: mysql_", "SQL syntax error",
    "Unclosed quotation mark", "SQLSTATE["
]

COMMON_PORTS = {80, 443, 8080, 8443}

PAYLOADS = {
    "SQL Injection": ["' OR '1'='1", "admin' --", "' UNION SELECT null, version() --"],
    "XSS": ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
}

def scan_ports(target, port_range=range(1, 1025)):
    open_ports = []
    lock = threading.Lock()

    def scan(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((target, port)) == 0:
                    with lock:
                        open_ports.append(port)
        except Exception:
            pass

    threads = []
    for port in port_range:
        t = threading.Thread(target=scan, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return open_ports

def safe_request(url, method="GET", params=None, data=None):
    try:
        response = requests.request(method, url, headers=HEADERS, params=params, data=data, timeout=3)
        return response
    except requests.exceptions.RequestException:
        return None

def check_sqli(url, forms):
    for payload in PAYLOADS["SQL Injection"]:
        response = safe_request(url, params={"test": payload})
        if response and any(error in response.text for error in SQLI_ERRORS):
            print(f"[!] Phát hiện SQL Injection tại {url} với payload: {payload}")
            return True
        
        for form in forms:
            action = form.get("action")
            inputs = form.find_all("input")
            form_url = url if not action else f"{url}/{action}"
            data = {input.get("name"): payload for input in inputs if input.get("name")}
            response = safe_request(form_url, method="POST", data=data)
            if response and any(error in response.text for error in SQLI_ERRORS):
                print(f"[!] Phát hiện SQL Injection tại {form_url} với payload: {payload}")
                return True
    return False

def check_xss(url, forms):
    for payload in PAYLOADS["XSS"]:
        response = safe_request(url, params={"test": payload})
        if response and payload in response.text:
            print(f"[!] Phát hiện XSS tại {url} với payload: {payload}")
            return True
        
        for form in forms:
            action = form.get("action")
            inputs = form.find_all("input")
            form_url = url if not action else f"{url}/{action}"
            data = {input.get("name"): payload for input in inputs if input.get("name")}
            response = safe_request(form_url, method="POST", data=data)
            if response and payload in response.text:
                print(f"[!] Phát hiện XSS tại {form_url} với payload: {payload}")
                return True
    return False

def extract_forms(url):
    response = safe_request(url)
    if response:
        soup = BeautifulSoup(response.text, "html.parser")
        return soup.find_all("form")
    return []

def detect_protocol(target):
    if not target.startswith(("http://", "https://")):
        test_http = f"http://{target}"
        test_https = f"https://{target}"
        if safe_request(test_http):
            return test_http
        elif safe_request(test_https):
            return test_https
        else:
            print(f"[X] Không thể kết nối đến {target}")
            return None
    return target

def run_web_scan(target):
    target = detect_protocol(target)
    if not target:
        return
    print(f"[+] Đang quét web tại: {target}")
    forms = extract_forms(target)
    check_sqli(target, forms)
    check_xss(target, forms)
    print(f"[+] Tìm thấy {len(forms)} form nhập liệu trên trang.")

def scan_target():
    target = input("Nhập IP hoặc domain để quét: ").strip()
    open_ports = scan_ports(target)
    print(f"[+] Các port mở trên {target}: {open_ports}" if open_ports else "[-] Không có port nào mở.")
    is_web_found = any(port in COMMON_PORTS for port in open_ports)
    if is_web_found:
        run_web_scan(target)
    else:
        choice = input("Không phát hiện cổng web. Bạn có muốn ép quét web? (y/n): ").strip().lower()
        if choice == "y":
            target = input("Nhập URL trang web (bao gồm http/https): ").strip()
            run_web_scan(target)

if __name__ == "__main__":
    scan_target()
