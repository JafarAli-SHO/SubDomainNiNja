import requests
import tldextract
import subprocess
import argparse
from queue import Queue
import pyfiglet
import random
from termcolor import colored

def list_fonts():
    return pyfiglet.FigletFont.getFonts()

def display_banner():
    fonts = list_fonts()
    selected_font = random.choice(fonts)
    
    # Create the pyfiglet text with the randomly selected font
    figlet_text = pyfiglet.figlet_format("SubDomainNiNja", font=selected_font)
    
    # Colorize the text
    colored_text = colored(figlet_text, color="magenta")
    
    # Print the banner
    print(colored_text)
    print(f"Font used: {selected_font}")

class Colors:
    LYELLOW = '\033[33m'
    RESTORE = '\033[0m'
    MAGENTA = '\033[35m'
    LBLUE = '\033[34m'
    LGREEN = '\033[32m'
    RED = '\033[31m'

# Function to fetch subdomains from VirusTotal
def fetch_vt_subdomains(domain, vt_api_key):
    url = tldextract.extract(domain).registered_domain
    response = requests.get(f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={vt_api_key}&domain={url}")

    if response.status_code != 200:
        print(f"{Colors.RED}Error: Failed to fetch data from VirusTotal. Status code: {response.status_code}{Colors.RESTORE}")
        return []

    try:
        response_json = response.json()
    except ValueError:
        print(f"{Colors.RED}Error: Failed to parse JSON response from VirusTotal.{Colors.RESTORE}")
        print(response.text)
        return []

    return response_json.get('subdomains', [])

# Function to fetch subdomains from DNSDumpster
def fetch_subdomains_from_dnsdumpster(domain):
    url = "https://api.hackertarget.com/hostsearch/?q=" + domain
    response = requests.get(url)
    
    if response.status_code == 200:
        subdomains = {line.split(',')[0] for line in response.text.splitlines()}
        return subdomains
    else:
        print(f"Error fetching from DNSDumpster: {response.status_code} {response.text}")
        return set()

# Function to fetch subdomains from SecurityTrails
def fetch_subdomains_from_securitytrails(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "APIKEY": api_key
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        subdomains = {f"{sub}.{domain}" for sub in data['subdomains']}
        return subdomains
    else:
        print(f"Error fetching from SecurityTrails: {response.status_code} {response.text}")
        return set()

# Function for recursive subdomain discovery
def recursive_subdomain_discovery(domain, api_keys, depth=2):
    discovered_subdomains = {
        'virustotal': set(),
        'dnsdumpster': set(),
        'securitytrails': set()
    }
    queue = Queue()
    queue.put(domain)
    seen = set()
    
    while not queue.empty() and depth > 0:
        current_domain = queue.get()
        if current_domain in seen:
            continue
        seen.add(current_domain)
        
        # VirusTotal
        vt_subdomains = set(fetch_vt_subdomains(current_domain, api_keys.get('virustotal')))
        discovered_subdomains['virustotal'].update(vt_subdomains)
        
        # DNSDumpster
        dnsdumpster_subdomains = fetch_subdomains_from_dnsdumpster(current_domain)
        discovered_subdomains['dnsdumpster'].update(dnsdumpster_subdomains)
        
        # SecurityTrails
        securitytrails_subdomains = fetch_subdomains_from_securitytrails(current_domain, api_keys.get('securitytrails'))
        discovered_subdomains['securitytrails'].update(securitytrails_subdomains)
        
        # Add new subdomains to the queue for further discovery
        all_subdomains = vt_subdomains.union(dnsdumpster_subdomains).union(securitytrails_subdomains)
        for subdomain in all_subdomains:
            queue.put(subdomain)
        
        depth -= 1

    return discovered_subdomains

# Main function for SubDomainNiNja scan
def SubDomainNiNja(domain, vt_api_key, st_api_key, depth):
    display_banner()
    print(f"{Colors.LYELLOW}======== SubDomainNiNja Scanning: {domain} ========{Colors.RESTORE}")

    api_keys = {
        "virustotal": vt_api_key,
        "securitytrails": st_api_key
    }

    discovered_subdomains = recursive_subdomain_discovery(domain, api_keys, depth)

    for source, subdomains in discovered_subdomains.items():
        print(f"{Colors.LBLUE}[*]Source: {source}{Colors.RESTORE}")
        for subdomain in subdomains:
            cname_result = subprocess.getoutput(f"dig CNAME {subdomain}")
            cnames = cname_result.split("\n")[-1].split(" ")[-1] if cname_result else "N/A"

            arecord_result = subprocess.getoutput(f"dig A {subdomain}")
            arecords = [line.split(" ")[-1] for line in arecord_result.split("\n") if "IN A" in line]

            print(f"{Colors.LGREEN}[-] {subdomain}{Colors.RESTORE}")
            print(f"{Colors.MAGENTA}A Records: {', '.join(arecords)}{Colors.RESTORE}")
            print("="*50)
           
def main():
    # Define API keys
    VTOTAL_API_KEY = "Place_your_api_key_Here"  # Replace with your VirusTotal API key
    STRAILS_API_KEY = "Place_your_api_key_Here"  # Replace with your SecurityTrails API key

    parser = argparse.ArgumentParser(description="SubDomainNiNja tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-r", "--depth", type=int, default=2, help="Recursive depth for subdomain enumeration")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    SubDomainNiNja(args.domain, VTOTAL_API_KEY, STRAILS_API_KEY, args.depth)

    # Pick-up line
    print(f"{Colors.MAGENTA}\nHey SubDomainNiNja, are you a subdomain? Because when I run this tool, you're the only one I see in my results!\n{Colors.RESTORE}")

if __name__ == "__main__":
    main()
