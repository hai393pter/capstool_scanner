import port_scanner
import web_scanner
import pyfiglet

def show_banner():
    banner = pyfiglet.figlet_format("CAPSTOOL PROJECT")
    print(banner)

def scan_target():
    print("\n🔍 Tool Quét Tổng Hợp: Port Scan & Web Scan")
    target = input("Nhập IP hoặc domain để quét: ").strip()
    
    # Quét port
    open_ports = port_scanner.scan_ports(target, range(1, 1025))  # Quét từ port 1 đến 1024
    
    if open_ports:
        print(f"\n✅ Các port mở trên {target}: {open_ports}")
    else:
        print(f"\n❌ Không tìm thấy port nào mở trên {target}.")
    
    # Kiểm tra cổng web
    WEB_PORTS = {80, 443, 8080, 8443}
    if any(port in WEB_PORTS for port in open_ports):
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        
        print("\n=== Bắt đầu quét web ===")
        web_scanner.run_web_scan(target)
    else:
        print("\n🚫 Không phát hiện cổng web server nào. Bỏ qua quét web.")

def main():
    show_banner()
    while True:
        scan_target()
        
        print("\n🔹 Lựa chọn:")
        print("1. Tiếp tục quét")
        print("2. Thoát")
        
        choice = input("Nhập lựa chọn của bạn: ").strip()
        if choice == "2":
            print(" Bye")
            break

if __name__ == "__main__":
    main()
