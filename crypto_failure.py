import requests
from urllib.parse import urlparse
import hashlib

# Suppress SSL warnings for simplicity in Pyodide
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
            print(f"[!] Request failed: {e}")
            return None, None, None, None

    def check_protocol(self):
        print(f"[*] Checking protocol enforcement for: {self.url}")
        http_url = self.url.replace("https://", "http://")
        status, _, _, final_url = self.send_request(http_url)
        if status and "https://" in final_url:
            print(f"[+] HTTP redirected to HTTPS: {final_url}")
        elif status:
            print(f"[!] Site allows HTTP access: {final_url} - Data could be intercepted!")
        else:
            print(f"[!] Unable to verify protocol enforcement.")

        # Note: Direct SSL/TLS cipher check removed due to Pyodide limitations
        print("[*] TLS cipher check skipped (not supported in this environment).")

    def test_login_encryption(self, username="admin", password="password"):
        print(f"[*] Testing login encryption on: {self.url}/login.php")
        target_url = f"{urlparse(self.url).scheme}://{urlparse(self.url).netloc}/login.php"
        
        data = {"username": username, "password": password}
        status, content, headers, _ = self.send_request(target_url, method="POST", data=data)
        if status:
            print(f"[+] Status: {status}")
            print(f"[*] Headers: {headers}")
            print(f"Response Snippet: {content[:200]}...")
            
            # Check for credential leaks
            md5_hash = hashlib.md5(password.encode()).hexdigest()
            sha1_hash = hashlib.sha1(password.encode()).hexdigest()
            if md5_hash in content:
                print(f"[!] MD5 hash leak detected: {md5_hash}")
            elif sha1_hash in content:
                print(f"[!] SHA-1 hash leak detected: {sha1_hash}")
            elif password in content and "password" not in content.lower().split(password)[0]:
                print(f"[!] Plain-text password leak detected: {password}")
            # Check login success
            if "form" not in content.lower() or "welcome" in content.lower():
                print(f"[!] Possible login success with {username}:{password}")
        else:
            print(f"[!] Login test failed.")

    def crack_hash(self, hash_value):
        print(f"[*] Attempting to crack hash: {hash_value}")
        rainbow_table = {
            "5f4dcc3b5aa765d61d8327deb882cf99": "password",
            "d41d8cd98f00b204e9800998ecf8427e": "",
            "a94a8fe5ccb19ba61c4c0873d391e987": "123456"
        }
        if hash_value in rainbow_table:
            print(f"[!] Hash cracked! Plain-text: {rainbow_table[hash_value]}")
        else:
            print(f"[-] Hash not found in rainbow table.")

def main(target_url=None):
    print("[*] Cryptographic Failures Tester")
    
    if target_url is None:
        target_url = input("[?] Enter target URL: ").strip()
    if not target_url:
        print("[!] URL is required. Exiting...")
        return
    
    # Validate URL
    parsed = urlparse(target_url)
    if not parsed.scheme:
        target_url = "http://" + target_url
    if not parsed.netloc:
        print("[!] Invalid URL: No domain specified. Exiting...")
        return

    cookie = input("[?] Enter session cookie (press Enter to skip): ").strip() or None
    tester = CryptoFailureTester(target_url, cookie)

    # Interactive test selection
    if input("Check protocol enforcement? (y/n): ").lower() == 'y':
        tester.check_protocol()
    if input("Test login encryption? (y/n): ").lower() == 'y':
        tester.test_login_encryption()
    hash_value = input("[?] Enter hash to crack (or press Enter to skip): ").strip()
    if hash_value:
        tester.crack_hash(hash_value)

if __name__ == "__main__":
    main()