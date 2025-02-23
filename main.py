import port_scanner
import web_scanner

def main():
    print("🔍 Tool Quét Tổng Hợp: Port Scan & Web Scan")
    target = input("Nhập IP hoặc domain để quét: ").strip()

    # Quét port trước
    open_ports = port_scanner.scan_ports(target, range(1, 1025))  # Quét từ port 1 đến 1024


    if open_ports:
        print(f"\n✅ Các port mở trên {target}: {open_ports}")
    else:
        print(f"\n❌ Không tìm thấy port nào mở trên {target}.")

    # Kiểm tra xem có cổng nào liên quan đến Web Server không
    WEB_PORTS = {80, 443, 8080, 8443}  # Các port phổ biến của web server
    if any(port in WEB_PORTS for port in open_ports):
        # Thêm http:// nếu cần
        if not target.startswith(("http://", "https://")):
            target = "http://" + target

        print("\n=== Bắt đầu quét web ===")
        web_scanner.run_web_scan(target)
    else:
        print("\n🚫 Không phát hiện cổng web server nào. Bỏ qua quét web.")

if __name__ == "__main__":
    main()
