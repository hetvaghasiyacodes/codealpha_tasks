import requests
import urllib.parse
import argparse
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# ---------------------------
# Banner, Developer & Warning
# ---------------------------
banner = r"""
   ____          _      _    _ _       _       
  / ___|___   __| | ___| | _(_) |_ ___| |__    
 | |   / _ \ / _` |/ _ \ |/ / | __/ __| '_ \   
 | |__| (_) | (_| |  __/   <| | || (__| | | |  
  \____\___/ \__,_|\___|_|\_\_|\__\___|_| |_|  

        _   _      _   _                              
       | | | | ___| |_| |__   ___  _ __   ___ _ __    
       | |_| |/ _ \ __| '_ \ / _ \| '_ \ / _ \ '__|   
       |  _  |  __/ |_| | | | (_) | | | |  __/ |      
       |_| |_|\___|\__|_| |_|\___/|_| |_|\___|_|      
"""
print(Fore.CYAN + banner)
print(Fore.GREEN + "Developed by @hackwithhet\n")
print(Fore.RED + "⚠️ WARNING: Only use this tool on targets you own or have explicit permission to test. Unauthorized use is illegal!\n" + Style.RESET_ALL)


# ---------------------------
# XSS Scan
# ---------------------------
def scan_xss(url, payloads):
    print(f"{Fore.CYAN}[XSS] Scanning {url} with {len(payloads)} payloads...{Style.RESET_ALL}")
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    for param in query_params:
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = payload
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(test_url, timeout=5)
                if payload in r.text:
                    print(f"{Fore.GREEN}[VULNERABLE] XSS found with payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}[URL] {test_url}{Style.RESET_ALL}")
                    return
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}[INFO] No XSS vulnerabilities found.{Style.RESET_ALL}")


# ---------------------------
# SQLi Scan
# ---------------------------
def scan_sqli(url, payloads):
    print(f"{Fore.CYAN}[SQLi] Scanning {url} with {len(payloads)} payloads...{Style.RESET_ALL}")
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)

    for param in query_params:
        for payload in payloads:
            test_params = query_params.copy()
            test_params[param] = payload
            new_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            try:
                r = requests.get(test_url, timeout=5)
                if "mysql" in r.text.lower() or "syntax" in r.text.lower() or "error" in r.text.lower():
                    print(f"{Fore.GREEN}[VULNERABLE] SQL Injection found with payload: {payload}{Style.RESET_ALL}")
                    print(f"{Fore.MAGENTA}[URL] {test_url}{Style.RESET_ALL}")
                    return
            except Exception as e:
                print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}[INFO] No SQLi vulnerabilities found.{Style.RESET_ALL}")


# ---------------------------
# Main Function
# ---------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameters")
    parser.add_argument("--scan", required=True, choices=["xss", "sqli", "all"], help="Type of scan to perform")
    args = parser.parse_args()

    # Load payloads from files
    with open("xss_payloads.txt", "r") as f:
        xss_payloads = [line.strip() for line in f if line.strip()]

    with open("sqli_payloads.txt", "r") as f:
        sqli_payloads = [line.strip() for line in f if line.strip()]

    if args.scan in ["xss", "all"]:
        scan_xss(args.url, xss_payloads)
    if args.scan in ["sqli", "all"]:
        scan_sqli(args.url, sqli_payloads)
