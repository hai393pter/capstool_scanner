import port_scanner
import web_scanner
import pyfiglet

def show_banner():
    banner = pyfiglet.figlet_format("CAPSTOOL PROJECT")
    print(banner)

def scan_target():
    print("\n🔍 WEB VULNERABILITIES SCANNER")
    target = input("Enter IP or Domain to scan: ").strip()
    
    # Quét port
    open_ports = port_scanner.scan_ports(target, range(1, 1025))  # Quét từ port 1 đến 1024
    
    if open_ports:
        print(f"\n✅ Open ports on {target}: {open_ports}")
    else:
        print(f"\n❌ Cannot find open ports on {target}.")
    
    # Kiểm tra cổng web
    WEB_PORTS = {80, 443, 8080, 8443}
    if any(port in WEB_PORTS for port in open_ports):
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        
        print("\n=== Scanning Web ===")
        web_scanner.run_web_scan(target)
    else:
        print("\n🚫 Cannot find any web server. Exiting.")

def main():
    show_banner()
    while True:
        scan_target()
        
        print("\n🔹 Menu:")
        print("1. Continue")
        print("2. Exit")
        
        choice = input("Choose your option: ").strip()
        if choice == "2":
            print(" Bye")
            break

if __name__ == "__main__":
    main()
