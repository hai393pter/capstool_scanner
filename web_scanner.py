import requests
from urllib.parse import urljoin, urlencode

# Danh sách payloads OWASP để kiểm tra lỗ hổng
PAYLOADS = {
    "SQL Injection": [
        "' OR '1'='1", "' UNION SELECT null, version() --", "' OR sleep(5) --"
    ],
    "XSS": [
        "<script>alert('XSS')</script>", "\"><img src=x onerror=alert(1)>"
    ],
    "LFI": [
        "../../../../etc/passwd", "../windows/win.ini"
    ],
    "SSRF": [
        "http://169.254.169.254/latest/meta-data/", "http://localhost/admin"
    ],
    "SSTI": [
        "{{7*7}}", "#{7*7}", "<%= 7 * 7 %>"
    ]
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

COMMON_FILES = ["robots.txt", "config.php", ".env", "debug"]

ADMIN_PATHS = ["/admin", "/login", "/dashboard"]


# Kiểm tra security headers
def check_security_headers(url):
    response = requests.get(url)
    headers = response.headers
    missing_headers = [h for h in SECURITY_HEADERS if h not in headers]
    
    if missing_headers:
        print(f"⚠️ Thiếu security headers: {', '.join(missing_headers)}")
    else:
        print("✅ Security headers đầy đủ!")

# Kiểm tra các lỗ hổng phổ biến
def test_vulnerability(url, params):
    print(f"\n🔍 Đang quét lỗ hổng trên {url}...")
    
    for vuln_type, payloads in PAYLOADS.items():
        print(f"🔹 Đang kiểm tra {vuln_type}...")
        for payload in payloads:
            test_params = {key: payload for key in params.keys()}
            test_url = f"{url}?{urlencode(test_params)}"
            
            try:
                response = requests.get(test_url, timeout=5)
                if is_vulnerable(response.text, vuln_type):
                    print(f"⚠️ Phát hiện {vuln_type}: {test_url}")
            except requests.exceptions.RequestException:
                pass

# Xác định trang web có lỗ hổng hay không
def is_vulnerable(response_text, vuln_type):
    if vuln_type == "SQL Injection":
        return "sql" in response_text.lower() or "syntax" in response_text.lower()
    elif vuln_type == "XSS":
        return "<script>alert('XSS')</script>" in response_text
    elif vuln_type == "LFI":
        return "root:x:" in response_text or "[extensions]" in response_text
    elif vuln_type == "SSRF":
        return "EC2" in response_text or "meta-data" in response_text
    elif vuln_type == "SSTI":
        return "49" in response_text
    return False

# Kiểm tra file nhạy cảm
def check_sensitive_files(url):
    for file in COMMON_FILES:
        full_url = urljoin(url, file)
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"⚠️ Tệp nhạy cảm có thể truy cập: {full_url}")

# Kiểm tra các trang quản trị
def check_admin_access(url):
    for path in ADMIN_PATHS:
        full_url = urljoin(url, path)
        response = requests.get(full_url)
        if response.status_code == 200:
            print(f"⚠️ Trang quản trị có thể truy cập: {full_url}")

# Kiểm tra bảo mật của Azure Storage
def check_azure_storage():
    azure_storage_urls = [
        "https://example.blob.core.windows.net/container/",
        "https://example.file.core.windows.net/share/"
    ]
    for url in azure_storage_urls:
        response = requests.get(url)
        if response.status_code == 200:
            print(f"⚠️ Azure Storage {url} có thể public!")

if __name__ == "__main__":
    target_url = input("Nhập URL web cần quét (VD: http://example.com): ")
    check_security_headers(target_url)
def run_web_scan(target_url):
    print("\n=== Quét bảo mật Web ===")
    check_security_headers(target_url)
    test_vulnerability(target_url, {"id": "test"})
    check_sensitive_files(target_url)
    check_admin_access(target_url)
    check_azure_storage()
    print("\n✅ Quét hoàn thành!")
    
    
    