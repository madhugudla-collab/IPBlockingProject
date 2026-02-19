#!/usr/bin/env python3
import sys
import re
import requests
import time



# Configuration for the IPLocate API (Example URL, replace with actual service if needed)
IP_LOCATE_API = "https://api.iplocate.io/api/lookup"

# High-risk regions and types to block automatically
BLOCKED_COUNTRIES = ["China", "Russia", "North Korea"]
BLOCK_TOR = True

def get_ip_info(ip):
    """
    Enriches IP data using the IPLocate using API.
    Returns a tuple of (country, is_tor, is_abuser).
    """

    try:
        response = requests.get(f"{IP_LOCATE_API}/{ip}", timeout=5)
        print(f"API Status Code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            country = data.get("country", "Unknown")
            privacy = data.get("privacy", {})
            is_tor = privacy.get("is_tor", False)
            is_abuser = privacy.get("is_abuser", False)
            return country, is_tor, is_abuser
        else:
            print(f"API Response: {response.text}")
    except Exception as e:
        print(f"API Error for {ip}: {e}")
    return "Unknown", False, False

def process_logs(log_files):
    """
    Scans logs, extracts IPs, and simulates blocking based on security logic.
    """
    # Use a set to track processed IPs and ensure no duplicate reports
    processed_ips = set()
    blocked_ips = set()
    blocked_json = [] 
    print(f"{processed_ips}")
    # Regex to extract IP addresses (IPv4 pattern)
    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for log_file in log_files:
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    match = ip_pattern.search(line)
                    if match:
                        ip = match.group(1)
                        
                        # Skip if we already handled this IP
                        if ip in processed_ips:
                            continue
                        
                        processed_ips.add(ip)

                        # Enrich IP data via API
                        country, is_tor, is_abuser = get_ip_info(ip)
                        time.sleep(0.5)  # Rate limit: 500ms delay between requests
                        print(f"IP: {ip}, Country: {country}, TOR: {is_tor}, Abuser: {is_abuser}")

                        # Blocking Logic
                        should_block = False
                        reason = ""

                        if is_tor:
                            should_block = True
                            reason = f"{country}, Tor Exit Node"
                        elif country in BLOCKED_COUNTRIES:
                            should_block = True
                            reason = country
                        elif is_abuser:
                            should_block = True
                            reason = "known abuser"

                        if should_block:
                            blocked_ips.add(ip)
                            blocked_json.append({"ip": ip, "country": country, "is_tor": is_tor, "is_abuser": is_abuser, "reason": reason})
                            print(f"[BLOCKED] IP {ip} ({reason}) has been blocked.")

        except FileNotFoundError:
            print(f"Error: File {log_file} not found.", file=sys.stderr)

    return blocked_ips,blocked_json

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python LogfileReview.py <log_file1> <log_file2> ...")
        sys.exit(1)

    # Accept one or more log files from command-line arguments
    blocked_ips, blocked_json = process_logs(sys.argv[1:])
    print(f"\nBlocked IPs: {blocked_ips}")
    print(f"\nBlocked Details: {blocked_json}")

    # AI Threat Analysis
    if blocked_ips:
        import os
        import openai
        import json
        from phoenix.otel import register
        from openinference.instrumentation.openai import OpenAIInstrumentor
        from dotenv import load_dotenv
        
        tracer_provider = register(project_name="malware-detection-app", auto_instrument=True)
        OpenAIInstrumentor().instrument(tracer_provider=tracer_provider)
        
        load_dotenv()
        client = openai.OpenAI()
        
        def check_ip_malware(ip_address):
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are a security analyst. Analyze IP addresses for malware, phishing, or C2 activity. Return response in JSON format with risk_score, malicious_type, threat_sources, and analysis."},
                    {"role": "user", "content": f"Analyze this IP: {ip_address}. Provide JSON output."}
                ],
                response_format={"type": "json_object"}
            )
            return response.choices[0].message.content
        
        print("\n=== AI Threat Analysis ===")
        for ip in blocked_ips:
            print(f"\n{'='*60}")
            print(f"IP: {ip}")
            print('='*60)
            analysis = check_ip_malware(ip)
            
            data = json.loads(analysis)
            print(f"Risk Score: {data.get('risk_score', 'N/A')}")
            print(f"Malicious Type: {data.get('malicious_type', 'None')}")
            print(f"\nAnalysis:\n{data.get('analysis', 'N/A')}")
            if data.get('threat_sources'):
                sources = data.get('threat_sources', [])
                if isinstance(sources, list):
                    print(f"\nThreat Sources: {', '.join(sources)}")
    else:
        print("\nNo blocked IPs to analyze.")
