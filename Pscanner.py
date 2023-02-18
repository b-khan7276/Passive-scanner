import whois
import dns.resolver
import requests
import nmap
import shodan
from theHarvester import Harvester
import argparse

def whois_lookup(domain):
    w = whois.whois(domain)
    print("WHOIS Information:\n")
    print(w)

def dns_lookup(domain):
    answers = dns.resolver.query(domain, 'A')
    print("\nDNS Information:\n")
    for rdata in answers:
        print(rdata)

def http_request(domain):
    print("\nHTTP/HTTPS Information:\n")
    try:
        r = requests.get(f'http://{domain}')
        print(f"Server Type: {r.headers['server']}")
        print("Cookies:")
        for cookie in r.cookies:
            print(cookie)
    except requests.exceptions.RequestException as e:
        print(e)

def scan_ports(domain):
    print("\nScanning for open ports using Nmap:\n")
    nm = nmap.PortScanner()
    nm.scan(domain, arguments='-sS -T4 -n -Pn -p 1-65535')
    for host in nm.all_hosts():
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            for port in lport:
                print('Port : %s\tState : %s' % (port, nm[host][proto][port]['state']))

def shodan_search(api_key, domain):
    print("\nSearching for devices and gathering information using Shodan:\n")
    api = shodan.Shodan(api_key)
    try:
        # Search Shodan
        results = api.search(domain)
        # Show the results
        for result in results['matches']:
            print('IP: %s' % result['ip_str'])
            print(result['data'])
            print('')
    except shodan.APIError as e:
        print('Error: %s' % e)

def email_harvest(domain):
    print("\nPerforming email enumeration using theHarvester:\n")
    h = Harvester()
    emails = h.harvest(domain)
    print(emails)

# Define command-line arguments
parser = argparse.ArgumentParser(description='Passive Reconnaissance Tool')
parser.add_argument('-d', '--domain', type=str, required=True, help='Target domain')
parser.add_argument('-k', '--apikey', type=str, required=False, help='Shodan API key')

# Parse command-line arguments
args = parser.parse_args()

# Perform reconnaissance tasks based on command-line arguments
domain = args.domain

whois_lookup(domain)
dns_lookup(domain)
http_request(domain)
scan_ports(domain)

if args.apikey:
    shodan_search(args.apikey, domain)
else:
    print("\nShodan search skipped. No API key provided.\n")

email_harvest(domain)
