import socket
import concurrent.futures

# Danh sách các dịch vụ phổ biến dựa trên cổng
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    902: "VMware Server",
    912: "VMware Authentication",
    3306: "MySQL",
    3389: "RDP"
}

def scan_port(target, port):
    """Kiểm tra port có mở không và lấy thông tin dịch vụ"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            
            if result == 0:  # Port open
                service = COMMON_PORTS.get(port, "Unknown Service")
                return (port, "open", service)
            else:
                return (port, "closed", "N/A")

    except Exception as e:
        return (port, "error", str(e))

def scan_ports(target, ports):
    """Quét danh sách các port"""
    print(f" Đang quét các ports trên {target}...\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(lambda p: scan_port(target, p), ports))

    # Hiển thị kết quả quét
    print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<20}")
    print("=" * 40)
    for port, state, service in results:
        if state == "open":
            print(f"{port:<8}{state:<10}{service:<20}")

    open_ports = [port for port, state, _ in results if state == "open"]
    
    if not open_ports:
        print(" Không tìm thấy port nào mở.")
    else:
        print("\n Quét hoàn thành!")

    return open_ports

if __name__ == "__main__":
    target_host = input("Nhập IP hoặc domain để quét: ")
    port_range = range(1, 1025)  # Quét từ 1 đến 1024

    scan_ports(target_host, port_range)
