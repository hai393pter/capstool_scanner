import requests
import ssl
import sys
import os
from urllib.parse import urljoin
from datetime import datetime
import argparse
from typing import List, Optional, Dict
import base64
import jwt  # Thư viện để decode JWT, cần cài: pip install pyjwt
import socket

# Tạo file log để ghi kết quả
def log_result(message: str, log_file: str = "pentest_crypto_log.txt"):
    """Ghi kết quả vào file log với timestamp."""
    with open(log_file, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

def load_wordlist(wordlist_path: str) -> list:
    """Tải danh sách các đường dẫn từ file wordlist."""
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Wordlist file {wordlist_path} not found.")
        sys.exit(1)

def check_ssl_configuration(base_url: str) -> dict:
    """Kiểm tra cấu hình SSL/TLS của server, xử lý lỗi NoneType và TLS 1.3."""
    try:
        # Test kết nối HTTPS
        response = requests.get(base_url, verify=True, timeout=10)
        if response.status_code == 200:
            print(f"SSL/TLS connection successful for {base_url}")
            log_result(f"SSL/TLS connection successful for {base_url}")
        
        # Kiểm tra chi tiết SSL/TLS bằng ssl module
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=base_url.replace("https://", "")) as s:
            s.connect((base_url.replace("https://", ""), 443))
            cert = s.getpeercert()
        
        # Kiểm tra cipher suite và protocol, xử lý NoneType
        cipher_info = s.cipher()
        cipher_suite = cipher_info[0] if cipher_info and isinstance(cipher_info, tuple) and len(cipher_info) > 0 else "Unknown cipher suite"
        protocol_version = cipher_info[1] if cipher_info and isinstance(cipher_info, tuple) and len(cipher_info) > 1 else "Unknown protocol"
        
        # Lấy thông tin protocol từ socket, ưu tiên TLS 1.3
        try:
            protocol = s.version()
            if protocol is None:
                protocol = "Unknown protocol"
            elif "TLSv1.3" in protocol or "TLS" in protocol:
                protocol = "TLS 1.3"
            elif "TLSv" in protocol:
                protocol = protocol.replace("TLSv", "TLS ").strip()
            else:
                protocol = "Unknown protocol"
        except AttributeError:
            protocol = "Unknown protocol"
        
        result = {
            "tls_version": context.options if hasattr(context, "options") else "Unknown TLS context",
            "cipher_suite": cipher_suite,
            "protocol_version": protocol,
            "valid": True
        }
        print(f"SSL/TLS Configuration: TLS Version={result['tls_version']}, Cipher={result['cipher_suite']}, Protocol={result['protocol_version']}")
        log_result(f"SSL/TLS Configuration: TLS Version={result['tls_version']}, Cipher={result['cipher_suite']}, Protocol={result['protocol_version']}")
        
        return result
    except ssl.SSLError as e:
        print(f"SSL/TLS Error: {e}")
        log_result(f"SSL/TLS Error for {base_url}: {e}")
        return {"valid": False, "error": str(e)}
    except requests.RequestException as e:
        print(f"Error checking SSL: {e}")
        log_result(f"Error checking SSL for {base_url}: {e}")
        return {"valid": False, "error": str(e)}
    except Exception as e:
        print(f"Unexpected SSL error: {e}")
        log_result(f"Unexpected SSL error for {base_url}: {e}")
        return {"valid": False, "error": str(e)}

def check_http_vulnerability(base_url: str) -> bool:
    """Kiểm tra xem server có chấp nhận HTTP không (dẫn đến truyền dữ liệu không mã hóa)."""
    http_url = base_url.replace("https://", "http://")
    try:
        response = requests.get(http_url, verify=True, timeout=10, allow_redirects=True)
        if response.status_code == 200:
            print(f"CRITICAL: Server accepts HTTP at {http_url} - Data may be transmitted unencrypted!")
            log_result(f"CRITICAL: Server accepts HTTP at {http_url} - Data may be transmitted unencrypted!")
            return True
        return False
    except requests.RequestException:
        return False

def analyze_cookies_and_headers(base_url: str, endpoint: str, headers: Dict, cookies: Dict) -> None:
    """Phân tích cookie và header để tìm dữ liệu không mã hóa."""
    try:
        url = urljoin(base_url, endpoint)
        response = requests.get(url, headers=headers, cookies=cookies, verify=True, timeout=10, allow_redirects=True)
        
        if response.status_code == 200:
            # Kiểm tra cookie
            if cookies:
                print(f"Cookies sent: {cookies}")
                log_result(f"Cookies sent for {url}: {cookies}")
                for cookie_name, cookie_value in cookies.items():
                    try:
                        # Thử decode Base64 hoặc JWT
                        try:
                            decoded = base64.b64decode(cookie_value).decode('utf-8', errors='ignore')
                            print(f"WARNING: Cookie {cookie_name} may be Base64 encoded and unencrypted: {decoded}")
                            log_result(f"WARNING: Cookie {cookie_name} may be Base64 encoded and unencrypted: {decoded}")
                        except (base64.binascii.Error, UnicodeDecodeError):
                            pass
                        try:
                            decoded_jwt = jwt.decode(cookie_value, options={"verify_signature": False})
                            print(f"WARNING: Cookie {cookie_name} is a JWT and may contain unencrypted data: {decoded_jwt}")
                            log_result(f"WARNING: Cookie {cookie_name} is a JWT and may contain unencrypted data: {decoded_jwt}")
                        except jwt.InvalidTokenError:
                            pass
                    except Exception as e:
                        print(f"Error decoding cookie {cookie_name}: {e}")
                        log_result(f"Error decoding cookie {cookie_name} for {url}: {e}")

            # Kiểm tra header response
            for header_name, header_value in response.headers.items():
                if "token" in header_name.lower() or "session" in header_name.lower():
                    print(f"Header {header_name}: {header_value}")
                    log_result(f"Header {header_name} for {url}: {header_value}")
                    try:
                        decoded = base64.b64decode(header_value).decode('utf-8', errors='ignore')
                        print(f"WARNING: Header {header_name} may be Base64 encoded and unencrypted: {decoded}")
                        log_result(f"WARNING: Header {header_name} may be Base64 encoded and unencrypted: {decoded}")
                    except (base64.binascii.Error, UnicodeDecodeError):
                        pass
        else:
            print(f"Cannot analyze cookies/headers for {url}, status code: {response.status_code}")
            log_result(f"Cannot analyze cookies/headers for {url}, status code: {response.status_code}")
    except requests.RequestException as e:
        print(f"Error analyzing cookies/headers: {e}")
        log_result(f"Error analyzing cookies/headers for {url}: {e}")

def test_cryptographic_failures(base_url: str, endpoints: List[str] = ["/", "/uploads/", "/admin/"], wordlist_path: Optional[str] = None):
    """
    Test Cryptographic Failures including SSL/TLS, HTTP vulnerability, and cookie/header analysis.
    
    Parameters:
    - base_url: Base URL of the target (e.g., "https://capstoneprjfuhcm.id.vn")
    - endpoints: List of endpoints to test for cookies/headers (default: ["/", "/uploads/", "/admin/"])
    - wordlist_path: Path to wordlist file for additional endpoints (optional)
    """
    # Load wordlist if provided
    additional_endpoints = load_wordlist(wordlist_path) if wordlist_path else []
    all_endpoints = endpoints + additional_endpoints

    # Configure headers and cookies for testing (public access)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
    cookies = {}

    print(f"\nStarting Cryptographic Failures test on {base_url}...")
    log_result(f"Starting Cryptographic Failures test on {base_url}")

    # Check SSL/TLS configuration
    ssl_result = check_ssl_configuration(base_url)
    if not ssl_result["valid"]:
        print(f"CRITICAL: SSL/TLS configuration failed for {base_url}")
        log_result(f"CRITICAL: SSL/TLS configuration failed for {base_url}")

    # Check HTTP vulnerability
    if check_http_vulnerability(base_url):
        print(f"CRITICAL: Server vulnerable to HTTP transmission - Data may be transmitted unencrypted!")
        log_result(f"CRITICAL: Server vulnerable to HTTP transmission - Data may be transmitted unencrypted!")

    # Analyze cookies and headers for each endpoint
    for endpoint in all_endpoints:
        analyze_cookies_and_headers(base_url, endpoint, headers, cookies)

    print(f"\nCryptographic Failures test completed for {base_url}.")
    log_result(f"Cryptographic Failures test completed for {base_url}")

def main():
    # Argument parser for user input
    parser = argparse.ArgumentParser(description="Pentest Tool for Cryptographic Failures")
    parser.add_argument("--url", required=True, help="Base URL of the target (e.g., https://example.com)")
    parser.add_argument("--endpoints", nargs="+", default=["/", "/uploads/", "/admin/"], help="Endpoints to test (space-separated)")
    parser.add_argument("--wordlist", default=None, help="Path to wordlist file for additional endpoints")
    
    args = parser.parse_args()

    # Run the test
    test_cryptographic_failures(args.url, args.endpoints, args.wordlist)

if __name__ == "__main__":
    main()