import pyfiglet
import port_scanner
import secu_misconfig
import XSS_auto
import SQLi_auto
import brute_force_login
import broken_access
import crypto_failure
import sys

def show_banner():
    banner = pyfiglet.figlet_format("CAPSTOOL PROJECT")
    print(banner)

def show_menu():
    print("\n=== CAPSTOOL PROJECT Menu ===")
    print("1. Port Scanner")
    print("2. Security Misconfiguration Scanner")
    print("3. XSS Scanner")
    print("4. SQL Injection Scanner")
    print("5. Brute Force Login Scanner")
    print("6. Broken Access Control Scanner")
    print("7. Cryptographic Failure Scanner")
    print("8. Exit")
    print("===========================")

def post_scan_menu():
    print("\nScan completed!")
    print("1. Continue scanning (return to menu)")
    print("2. Exit")
    choice = input("Choice (1 or 2): ").strip()
    return choice

def main():
    show_banner()
    
    # Prompt for the URL once
    target_url = input("Enter target URL to scan (e.g., http://example.com): ")
    
    while True:
        show_menu()
        choice = input("Select an option (1-8): ").strip()
        
        try:
            if choice == "1":
                print(f"\n>>> port_scanner.main('{target_url}')")
                port_scanner.main(target_url)
            elif choice == "2":
                print(f"\n>>> secu_misconfig.main('{target_url}')")
                secu_misconfig.main(target_url)
            elif choice == "3":
                print(f"\n>>> XSS_auto.main('{target_url}')")
                XSS_auto.main(target_url)
            elif choice == "4":
                print(f"\n>>> SQLi_auto.main('{target_url}')")
                SQLi_auto.main(target_url)
            elif choice == "5":
                print(f"\n>>> brute_force_login.main('{target_url}')")
                brute_force_login.main(target_url)
            elif choice == "6":
                print(f"\n>>> broken_access.main('{target_url}')")
                broken_access.main(target_url)
            elif choice == "7":
                print(f"\n>>> crypto_failure.main('{target_url}')")
                crypto_failure.main(target_url)
            elif choice == "8":
                print("[*] Exiting...")
                sys.exit(0)
            else:
                print("[!] Invalid choice. Please select a number between 1 and 8.")
                continue

            # After a script finishes, show the post-scan menu
            post_choice = post_scan_menu()
            if post_choice == "2":
                print("[*] Exiting...")
                sys.exit(0)
            # If choice is "1" or anything else, loop back to the menu

        except Exception as e:
            print(f"[!] Error running scan: {e}")
            post_choice = post_scan_menu()
            if post_choice == "2":
                print("[*] Exiting...")
                sys.exit(0)

if __name__ == "__main__":
    main()