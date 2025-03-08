import requests
import argparse
from urllib.parse import urlparse, urlencode
from colorama import init, Fore
import os
import random
import string

# Initialize colorama for colored output
init(autoreset=True)

class BrokenAccessTester:
    def __init__(self, url, cookie=None):
        self.url = url
        self.cookie = cookie
        self.session = requests.Session()
        if cookie:
            self.session.cookies.update({"Cookie": cookie})

    def send_request(self, target_url, method="GET", custom_headers=None, data=None):
        """Send an HTTP request with specified method, headers, and optional data."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        if custom_headers:
            headers.update(custom_headers)
        try:
            if method == "POST":
                response = self.session.post(target_url, headers=headers, data=data, verify=False)
            else:
                response = self.session.get(target_url, headers=headers, verify=False)
            return response.status_code, response.text, response.headers
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Request failed: {e}")
            return None, None, None

    def test_file_upload_access(self, filename, attempts=5):
        """Test access to uploaded files with random ETag guesses."""
        print(f"{Fore.YELLOW}[*] Testing file upload access for: {filename}")
        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/uploads/"

        # Known ETag prefix
        etag_prefix = "67cb1"

        for i in range(attempts):
            # Generate a random ETag suffix (8 characters)
            random_suffix = ''.join(random.choices(string.hexdigits.lower(), k=8))
            etag = f"{etag_prefix}{random_suffix}"
            target_url = f"{base_url}{etag}_{filename}"
            print(f"{Fore.CYAN}[*] Attempting URL: {target_url}")

            # Test with different methods and headers
            methods = ["GET", "POST"]
            headers_list = [
                None,  # Default headers
                {"User-Agent": "Googlebot/2.1"},  # Bot impersonation
                {"X-Requested-With": "XMLHttpRequest"},  # AJAX simulation
                {"Referer": base_url}  # Fake referer
            ]

            for method in methods:
                for headers in headers_list:
                    print(f"{Fore.CYAN}[*] Method: {method}, Headers: {headers}")
                    status, content, resp_headers = self.send_request(target_url, method=method, custom_headers=headers)
                    if status:
                        print(f"{Fore.GREEN}[+] Status: {status}")
                        print(f"{Fore.CYAN}[*] Response Headers: {resp_headers}")
                        if status == 200 and "Access Denied" not in content and "403 Forbidden" not in content:
                            print(f"{Fore.GREEN}[!] Potential file found! URL: {target_url}")
                            print(f"Response Snippet: {content[:200]}...")
                        else:
                            print(f"{Fore.RED}[-] Access denied or not found: {target_url}")
                    print("-" * 50)

    def test_forced_browsing(self, endpoints):
        """Test forced browsing by accessing sensitive endpoints."""
        print(f"{Fore.YELLOW}[*] Testing forced browsing on: {self.url}")
        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        for endpoint in endpoints:
            target_url = f"{base_url}/{endpoint.lstrip('/')}"
            print(f"{Fore.CYAN}[*] Attempting URL: {target_url}")

            # Test with different methods and headers
            methods = ["GET", "POST"]
            headers_list = [
                None,  # Default headers
                {"User-Agent": "Googlebot/2.1"},  # Bot impersonation
                {"X-Requested-With": "XMLHttpRequest"},  # AJAX simulation
                {"Referer": base_url}  # Fake referer
            ]

            for method in methods:
                for headers in headers_list:
                    print(f"{Fore.CYAN}[*] Method: {method}, Headers: {headers}")
                    status, content, resp_headers = self.send_request(target_url, method=method, custom_headers=headers)
                    if status:
                        print(f"{Fore.GREEN}[+] Status: {status}")
                        print(f"{Fore.CYAN}[*] Response Headers: {resp_headers}")
                        if status == 200 and "Access Denied" not in content and "403 Forbidden" not in content:
                            print(f"{Fore.GREEN}[!] Potential sensitive endpoint found! Endpoint: {endpoint}")
                            print(f"Response Snippet: {content[:200]}...")
                        else:
                            print(f"{Fore.RED}[-] Access denied or not found: {endpoint}")
                    print("-" * 50)

def main():
    print(f"{Fore.BLUE}[*] Broken Access Control Tester ")
    
    # Prompt for target URL
    url = input(f"{Fore.YELLOW}[?] Enter target URL: ").strip()
    if not url:
        print(f"{Fore.RED}[!] URL is required. Exiting...")
        return

    # Prompt for cookie (optional)
    cookie = input(f"{Fore.YELLOW}[?] Enter session cookie (e.g., PHPSESSID=abc123, press Enter to skip): ").strip() or None

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Broken Access Control Testing Tool")
    parser.add_argument("--file-access", action="store_true", help="Test access to uploaded files")
    parser.add_argument("--filename", default="test.php.png", help="Filename to test (default: test.php.png)")
    parser.add_argument("--forced-browsing", action="store_true", help="Test forced browsing")
    args = parser.parse_args()

    # Determine test type if no arguments provided
    run_file_access = args.file_access
    run_forced_browsing = args.forced_browsing

    if not (run_file_access or run_forced_browsing):
        print(f"{Fore.YELLOW}[?] No test type specified.")
        print("Available tests:")
        print("  1. File Upload Access")
        print("  2. Forced Browsing")
        print("  3. Both")
        print("  4. Exit")
        choice = input(f"{Fore.YELLOW}[?] Select a test to run (1/2/3/4): ").strip()

        if choice == '1':
            run_file_access = True
        elif choice == '2':
            run_forced_browsing = True
        elif choice == '3':
            run_file_access = True
            run_forced_browsing = True
        elif choice == '4':
            print(f"{Fore.YELLOW}[*] Exiting...")
            return
        else:
            print(f"{Fore.RED}[!] Invalid choice. Exiting...")
            return

    tester = BrokenAccessTester(url, cookie)

    if run_file_access:
        tester.test_file_upload_access(args.filename)

    if run_forced_browsing:
        sensitive_endpoints = [
            "/admin.php", "/admin_panel.php", "/uploads/", "/view.php",
            "/manage.php", "/dashboard.php", "/config.php", "/login.php", "/view_messages.php"
        ]
        tester.test_forced_browsing(sensitive_endpoints)

if __name__ == "__main__":
    main()