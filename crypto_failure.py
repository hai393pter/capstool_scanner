import requests
import argparse
from urllib.parse import urlparse
from colorama import init, Fore
import hashlib
import ssl
import socket
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
init(autoreset=True)

class CryptoFailureTester:
    def __init__(self, url, cookie=None):
        self.url = url
        self.cookie = cookie
        self.session = requests.Session()
        if cookie:
            self.session.cookies.update({"Cookie": cookie})

    def send_request(self, target_url, method="GET", data=None):
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        try:
            if method == "POST":
                response = self.session.post(target_url, headers=headers, data=data, verify=False)
            else:
                response = self.session.get(target_url, headers=headers, verify=False)
            return response.status_code, response.text, response.headers, response.url
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Request failed: {e}")
            return None, None, None, None

    def check_protocol(self):
        print(f"{Fore.YELLOW}[*] Checking protocol enforcement for: {self.url}")
        http_url = self.url.replace("https://", "http://")
        status, _, _, final_url = self.send_request(http_url)
        if status and "https://" in final_url:
            print(f"{Fore.GREEN}[+] HTTP redirected to HTTPS: {final_url}")
        elif status:
            print(f"{Fore.RED}[!] Site allows HTTP access: {final_url} - Data could be intercepted!")
        parsed_url = urlparse(self.url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    print(f"{Fore.GREEN}[+] TLS Cipher: {cipher[0]}, Version: {cipher[1]}, Strength: {cipher[2]} bits")
                    if cipher[2] < 128:
                        print(f"{Fore.RED}[!] Weak cipher strength (< 128 bits) detected!")
        except Exception as e:
            print(f"{Fore.RED}[!] SSL/TLS check failed: {e}")

    def test_login_encryption(self, username="admin", password="password"):
        print(f"{Fore.YELLOW}[*] Testing login encryption on: {self.url}/login.php")
        target_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}/login.php"
        
        data = {"username": username, "password": password}
        status, content, headers, _ = self.send_request(target_url, method="POST", data=data)
        if status:
            print(f"{Fore.GREEN}[+] Status: {status}")
            print(f"{Fore.CYAN}[*] Headers: {headers}")
            print(f"Response Snippet: {content[:200]}...")
            
            # Improved leak detection
            md5_hash = hashlib.md5(password.encode()).hexdigest()
            sha1_hash = hashlib.sha1(password.encode()).hexdigest()
            if md5_hash in content:
                print(f"{Fore.RED}[!] MD5 hash leak detected: {md5_hash}")
            elif sha1_hash in content:
                print(f"{Fore.RED}[!] SHA-1 hash leak detected: {sha1_hash}")
            elif password in content and "password" not in content.lower().split(password)[0]:  # Avoid false positives from form
                print(f"{Fore.RED}[!] Plain-text password leak detected: {password}")
            # Check login success
            if "form" not in content.lower() or "welcome" in content.lower():
                print(f"{Fore.GREEN}[!] Possible login success with {username}:{password}")

    def crack_hash(self, hash_value):
        print(f"{Fore.YELLOW}[*] Attempting to crack hash: {hash_value}")
        rainbow_table = {
            "5f4dcc3b5aa765d61d8327deb882cf99": "password",
            "d41d8cd98f00b204e9800998ecf8427e": "",
            "a94a8fe5ccb19ba61c4c0873d391e987": "123456"
        }
        if hash_value in rainbow_table:
            print(f"{Fore.GREEN}[!] Hash cracked! Plain-text: {rainbow_table[hash_value]}")
        else:
            print(f"{Fore.RED}[-] Hash not found in rainbow table. Try Hashcat or online tools.")

def main():
    print(f"{Fore.BLUE}[*] Cryptographic Failures Tester by Grok 3 (xAI) - A02:2021]")
    url = input(f"{Fore.YELLOW}[?] Enter target URL (e.g., https://capstoneprjfuhcm.id.vn): ").strip()
    if not url:
        print(f"{Fore.RED}[!] URL is required. Exiting...")
        return
    cookie = input(f"{Fore.YELLOW}[?] Enter session cookie (e.g., PHPSESSID=abc123, press Enter to skip): ").strip() or None

    parser = argparse.ArgumentParser(description="Cryptographic Failures Testing Tool")
    parser.add_argument("--protocol", action="store_true", help="Check protocol enforcement and cipher strength")
    parser.add_argument("--login", action="store_true", help="Test login endpoint for encryption issues")
    parser.add_argument("--hash", type=str, help="Crack a specific hash (e.g., MD5)")
    args = parser.parse_args()

    tester = CryptoFailureTester(url, cookie)
    if args.protocol:
        tester.check_protocol()
    if args.login:
        tester.test_login_encryption()
    if args.hash:
        tester.crack_hash(args.hash)

if __name__ == "__main__":
    main()