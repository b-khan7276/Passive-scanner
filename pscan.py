import argparse
import os
import subprocess
import requests
import whois
import dns.resolver
from theHarvester.harvester import HarvesterAPI

def main(target):
    # Gather DNS information
    try:
        dns_records = []
        answers = dns.resolver.resolve(target, 'ANY')
        for rdata in answers:
            dns_records.append(rdata.to_text())
        print("[*] DNS Records:")
        for record in dns_records:
            print("    "+record)
        print("\n")
    except Exception as e:
        print("[*] Error: Could not gather DNS information")
    
    # Gather WHOIS information
    try:
        whois_data = whois.whois(target)
        print("[*] WHOIS Information:")
        print("    Domain Name: {}".format(whois_data.domain_name))
        print("    Registrar: {}".format(whois_data.registrar))
        print("    Expiration Date: {}".format(whois_data.expiration_date))
        print("    Creation Date: {}".format(whois_data.creation_date))
        print("    Updated Date: {}".format(whois_data.updated_date))
        print("    Registrant Name: {}".format(whois_data.name))
        print("    Registrant Organization: {}".format(whois_data.org))
        print("    Registrant Email: {}".format(whois_data.email))
        print("\n")
    except Exception as e:
        print("[*] Error: Could not gather WHOIS information")
    
    # Gather email addresses and other information using theHarvester
    try:
        harvester = HarvesterAPI(target)
        emails = harvester.search()
        print("[*] Email Addresses:")
        for email in emails:
            print("    "+email)
        print("\n")
    except Exception as e:
        print("[*] Error: Could not gather email addresses using theHarvester")
    
    # Use search engines to gather additional information
    try:
        url = "https://www.google.com/search?q={}&num=100".format(target)
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36'}
        response = requests.get(url, headers=headers)
        links = response.content.decode('utf-8').split('href="')
        print("[*] Google Search Results:")
        for link in links:
            if "http" in link:
                link = link.split('"')[0]
                print("    "+link)
        print("\n")
    except Exception as e:
        print("[*] Error: Could not gather Google search results")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Passive Reconnaissance Tool")
    parser.add_argument("target", help="The target to gather information about")
    args = parser.parse_args()
    target = args.target

    main(target)
