import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse
from rich.console import Console
import argparse


def is_valid_url(url):
    """Validate the entered URL."""
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def display_banner():
    """Display the ASCII art banner."""
    banner = r"""
     __  ______ ____ _____ _____ ____ _____ _____ ____    
     \ \/ / ___/ ___|_   _| ____/ ___|_   _| ____|  _ \   
      \  /\___ \___ \ | | |  _| \___ \ | | |  _| | |_) |  
      /  \ ___) |__) || | | |___ ___) || | | |___|  _ <   
     /_/\_\____/____/ |_| |_____|____/ |_| |_____|_| \_\  
         ______________                                                                
              _  _____ ____  _   _         _  _____ ____  
       ___   / \|_   _/ ___|| \ | | ___   / \|_   _/ ___| 
      / __| / _ \ | | \___ \|  \| |/ __| / _ \ | | \___ \ 
     | (__ / ___ \| |  ___) | |\  | (__ / ___ \| |  ___) |
      \___/_/   \_\_| |____/|_| \_|\___/_/   \_\_| |____/ 
    """
    console.print(banner, style="bold green")


def get_all_forms(url):
    """Extract all forms from the given URL."""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """Extract details of a form."""
    details = {
        "action": form.attrs.get("action", "").lower(),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": [],
    }
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        details["inputs"].append({"type": input_type, "name": input_name})
    return details


def submit_form(form_details, url, value):
    """Submit a form with a payload."""
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] in ["text", "search"]:
            input["value"] = value
        if input["name"]:
            data[input["name"]] = input.get("value", "")
    console.print(f"[+] Submitting malicious payload to {target_url}", style="bold cyan")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    return requests.get(target_url, params=data)


def scan_xss(url):
    """Scan the target URL for XSS vulnerabilities."""
    try:
        forms = get_all_forms(url)
        console.print(f"[+] Detected {len(forms)} forms on {url}.", style="bold yellow")
        js_script = "<Script>alert('hi')</scripT>"
        is_vulnerable = False
        for form in forms:
            form_details = get_form_details(form)
            content = submit_form(form_details, url, js_script).content.decode()
            if js_script in content:
                console.print(f"[+] XSS Detected on {url}", style="bold red")
                pprint(form_details)
                is_vulnerable = True
        return is_vulnerable
    except requests.exceptions.RequestException as e:
        console.print(f"[!] An error occurred: {e}", style="bold red")
        return False


if __name__ == "__main__":
    console = Console()
    
    # Add argparse for help (-h)
    parser = argparse.ArgumentParser(
        description="A tool for scanning websites for XSS vulnerabilities."
    )
    parser.add_argument(
        "url",
        type=str,
        nargs="?",
        help="The URL to scan for XSS vulnerabilities.",
    )
    args = parser.parse_args()

    display_banner()
    console.print("Welcome to the XSS Scanning Tool", style="bold blue")

    # If no URL is provided, prompt the user interactively
    if not args.url:
        while True:
            console.print("Example: https://xss-game.appspot.com/level1/frame", style="bold red")
            target_url = input("Enter URL to scan for XSS: ")
            if is_valid_url(target_url):
                break
            console.print("[!] Invalid URL format. Please try again.", style="bold red")
    else:
        target_url = args.url

    if is_valid_url(target_url):
        scan_xss(target_url)
    else:
        console.print("[!] Invalid URL format. Please provide a valid URL.", style="bold red")