import socket
import concurrent.futures
import re

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

def clean_target(target):
    """Remove http:// or https:// from the target and return the hostname."""
    # Remove http:// or https:// and trailing slashes
    target = re.sub(r'^https?://', '', target)
    target = target.rstrip('/')
    return target

def scan_port(target, port):
    """Scanning"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)  # Increased timeout to 2 seconds
            result = s.connect_ex((target, port))
            
            if result == 0:  # Port open
                service = COMMON_PORTS.get(port, "Unknown Service")
                return (port, "open", service)
            else:
                return (port, "closed", "N/A")

    except socket.gaierror as e:
        return (port, "error", f"Failed to resolve hostname: {e}")
    except Exception as e:
        return (port, "error", str(e))

def scan_ports(target, ports):
    """Ports scanning"""
    print(f"Scanning ports on {target}...\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(lambda p: scan_port(target, p), ports))

    # Hiển thị kết quả quét
    print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<20}")
    print("=" * 40)
    for port, state, service in results:
        if state == "open":
            print(f"{port:<8}{state:<10}{service:<20}")
        elif state == "error":
            print(f"{port:<8}{state:<10}{service:<20}")

    open_ports = [port for port, state, _ in results if state == "open"]
    
    if not open_ports:
        print("No open ports detected.")
    else:
        print("\nScanning completed!")

    return open_ports

def main(target):
    """
    Main function to execute port scanning.
    Args:
        target (str): The IP or URL to scan.
    Returns:
        list: List of open ports.
    """
    try:
        target = clean_target(target)  # Clean the target input
        port_range = range(1, 1025)  # Quét từ 1 đến 1024
        open_ports = scan_ports(target, port_range)
        return open_ports
    except Exception as e:
        print(f"Error in port_scanner: {e}")
        return []

if __name__ == "__main__":
    target = input("Enter IP or URL to scan: ")
    main(target)