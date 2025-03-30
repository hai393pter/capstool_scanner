import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

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
            print(f"[!] Request failed: {e}")
            return None, None, None

    def is_access_denied(self, status, content):
        deny_keywords = ["Access Denied", "403 Forbidden", "Permission Denied", "Login Required"]
        return status in [403, 401, 302] or (content and any(keyword in content for keyword in deny_keywords))

    def upload_file(self, upload_endpoint, filename="test.php.png"):
        """Simulate uploading a .php.png file."""
        print(f"[*] Attempting to upload file: {filename}")
        parsed_url = urlparse(self.url)
        upload_url = f"{parsed_url.scheme}://{parsed_url.netloc}/{upload_endpoint.lstrip('/')}"

        php_content = b"<?php echo 'Hello from PHP'; ?>"
        files = {"file": (filename, php_content, "image/png")}  # Spoof MIME type as image
        data = {"submit": "Upload"}  # Assumed field name

        status, content, headers = self.send_request(upload_url, method="POST", files=files, data=data)
        if status:
            print(f"[+] Upload response status: {status}")
            print(f"Response Snippet: {content[:200]}...")
            if "uploads" in content:
                import re
                match = re.search(r"/uploads/[^\"']+", content)
                return match.group(0) if match else None
            return None
        else:
            print(f"[!] Upload failed")
            return None

    def test_file_upload_access(self, filename="test.php.png", attempts=10, etag_prefix="67cb1", etag_suffix_len=8, upload_endpoint=None):
        print(f"[*] Testing file upload access for: {filename}")
        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        uploaded_file_path = None
        if upload_endpoint:
            uploaded_file_path = self.upload_file(upload_endpoint, filename)
            if uploaded_file_path:
                print(f"[!] Uploaded file path: {uploaded_file_path}")
                target_url = f"{base_url}{uploaded_file_path}"
                status, content, _ = self.send_request(target_url)
                if status == 200 and not self.is_access_denied(status, content):
                    print(f"[!] File accessible at: {target_url}")
                    print(f"Response Snippet: {content[:200]}...")
                return

        # If upload fails or no endpoint, try guessing ETag
        uploads_base = f"{base_url}/uploads/"
        import random
        import string
        for _ in range(attempts):
            random_suffix = ''.join(random.choices(string.hexdigits.lower(), k=etag_suffix_len))
            etag = f"{etag_prefix}{random_suffix}"
            target_url = f"{uploads_base}{etag}_{filename}"
            print(f"[*] Attempting URL: {target_url}")
            status, content, _ = self.send_request(target_url)
            if status:
                print(f"[+] Status: {status}")
                if status == 200 and not self.is_access_denied(status, content):
                    print(f"[!] Potential file found! URL: {target_url}")
                    print(f"Response Snippet: {content[:200]}...")
                else:
                    print(f"[-] Access denied or not found: {target_url}")
            else:
                print(f"[-] No response from: {target_url}")

    def test_forced_browsing(self, endpoints=None, max_workers=5):
        if not endpoints:
            endpoints = ["/admin", "/login.php", "/guestbook.php", "/search.php", "/uploads/"]

        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        def check_endpoint(endpoint):
            target_url = f"{base_url}/{endpoint.lstrip('/')}"
            print(f"[*] Attempting URL: {target_url}")
            status, content, _ = self.send_request(target_url)
            if status:
                print(f"[+] Status: {status}")
                if status == 200 and not self.is_access_denied(status, content):
                    print(f"[!] Potential sensitive endpoint found: {endpoint}")
                    print(f"Response Snippet: {content[:200]}...")
                else:
                    print(f"[-] Access denied or not found: {endpoint}")
            else:
                print(f"[-] No response from: {endpoint}")

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

def main(target_url=None):
    print("[*] Broken Access Control Tester")
    
    if target_url is None:
        target_url = input("[?] Enter target URL: ").strip()
    try:
        target_url = validate_url(target_url)
    except ValueError as e:
        print(f"[!] {e}. Exiting...")
        return

    cookie = input("[?] Enter session cookie (e.g., PHPSESSID=abc123, press Enter to skip): ").strip() or None
    tester = BrokenAccessTester(target_url, cookie)

    # Simplified for demo: only running file access test by default
    run_file_test = input("Run file access test? (y/n): ").lower() == 'y'
    if run_file_test:
        tester.test_file_upload_access(upload_endpoint="/upload.php")  # Default endpoint for testing

    run_forced_browsing = input("Run forced browsing test? (y/n): ").lower() == 'y'
    if run_forced_browsing:
        tester.test_forced_browsing()

if __name__ == "__main__":
    main()