#!/usr/bin/env python3
import re
import sys
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Global HTTP Configuration to mirror standard testing platforms
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}

def scan_endpoint_access(base_url, endpoint):
    """
    ACTIVE SCANNING LAYER: Probes the extracted endpoint to audit
    authorization boundaries and missing access controls.
    """
    full_url = urljoin(base_url, endpoint)
    print(f"    [!] Actively probing access boundary: {full_url}")
    
    try:
        # Send a baseline unauthorized request
        response = requests.get(full_url, headers=HEADERS, timeout=5)
        status = response.status_code
        
        if status == 200:
            print(f"        🚨 [CRITICAL] 200 OK - Potential Missing Access Control / Bypassed Auth!")
        elif status in [401, 403]:
            print(f"        🔒 [SECURE] {status} - Endpoint correctly enforces authentication barriers.")
        elif status == 404:
            print(f"        ❓ [404 NOT FOUND] Route exists in front-end JS but returned a dead backend sink.")
        else:
            print(f"        ℹ️ [INFO] Received status code: {status}")
            
    except requests.exceptions.RequestException as e:
        print(f"        [-] Network timeout or connection drop during probe: {e}")

def extract_intelligence(target_url):
    print(f"\n[*] Initializing Master Recon Stream Against: {target_url}\n" + "="*60)
    
    try:
        response = requests.get(target_url, headers=HEADERS, timeout=10)
        if response.status_code != 200:
            print(f"[-] Root application unreachable. Status: {response.status_code}")
            return
    except Exception as e:
        print(f"[-] Connection layout failure: {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    script_srcs = [script.get('src') for script in soup.find_all('script') if script.get('src')]
    
    print(f"[+] Discovered {len(script_srcs)} client-side JavaScript streams to deconstruct.\n")
    
    # 1. Complex Regex Engines
    endpoint_regex = re.compile(
        r'(?:["\'])(/api/v[0-9]/[a-zA-Z0-9_\-\/]+|/[a-zA-Z0-9_\-\/]+/v[0-9]/[a-zA-Z0-9_\-\/]+)(?:["\'])'
    )
    # Target common variable definitions for keys, secrets, tokens, and credentials
    secrets_regex = re.compile(
        r'(?:secret|api_key|token|auth|password|dev_key|private_key)(?:\s*=\s*|\s*:\s*)(?:["\'])([a-zA-Z0-9_\-\+\/=!@#$%^&*]{5,})(?:["\'])',
        re.IGNORECASE
    )

    # 2. Stream Analysis Core Loop
    for src in script_srcs:
        js_url = urljoin(target_url, src)
        print(f"[*] Auditing Target Source: {js_url}")
        print("-" * 50)
        
        try:
            js_res = requests.get(js_url, headers=HEADERS, timeout=10)
            js_content = js_res.text

            # --- PASSIVE SECRETS HUNTING ---
            found_secrets = secrets_regex.findall(js_content)
            if found_secrets:
                for secret in set(found_secrets):
                    print(f"    🔑 [FOUND HARDCODED SECRET]: {secret}")
            else:
                print("    [-] No immediate high-value credential strings isolated.")

            # --- ROUTE EXTRACTION & ACTIVE FUZZING ---
            found_endpoints = endpoint_regex.findall(js_content)
            if found_endpoints:
                for endpoint in set(found_endpoints):
                    print(f"    🔗 [FOUND ENDPOINT PATH]: {endpoint}")
                    # Push directly into the active probing engine
                    scan_endpoint_access(target_url, endpoint)
            else:
                print("    [-] No microservice API endpoints mapped in this file.")
                
            print("-" * 50 + "\n")

        except Exception as e:
            print(f"    [-] Read error or processing drop on script resource: {src} ({e})\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[-] Error: Missing arguments.")
        print("[-] Usage: python3 recon_harness.py <target_url>")
        sys.exit(1)
        
    extract_intelligence(sys.argv[1])
