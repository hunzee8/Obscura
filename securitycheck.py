#!/usr/bin/env python3
import requests
from argparse import ArgumentParser

class SecurityCheck:
    @staticmethod
    def check_tor():
        try:
            resp = requests.get("https://check.torproject.org/api/ip", timeout=10)
            data = resp.json()
            return data.get('IsTor', False), data.get('IP', 'Unknown')
        except:
            return False, "Error"

    @staticmethod
    def check_dns_leak():
        try:
            resp = requests.get("https://www.dnsleaktest.com/api/v1/ip", timeout=10)
            return 'tor' in resp.text.lower()
        except:
            return False

    @staticmethod
    def check_webrtc_leak():
        try:
            resp = requests.get("https://ipleak.net/json/", timeout=10)
            return not any(k in resp.json() for k in ['webrtc', 'rtc'])
        except:
            return False

    @staticmethod
    def check_ipv6_leak():
        try:
            resp = requests.get("https://ipv6-test.com/api/myip.php", timeout=5)
            return resp.text.strip() == ''
        except:
            return False

def print_results(results):
    print("\n\033[94m[ Security Report ]\033[0m")
    
    tor_status, tor_ip = results['Tor Connection']
    print(f"Tor:       {'\033[92mConnected\033[0m' if tor_status else '\033[91mDisconnected\033[0m'}")
    print(f"IP:        {tor_ip}")
    
    for test, passed in list(results.items())[1:]:
        status = "\033[92mPASS\033[0m" if passed else "\033[91mFAIL\033[0m"
        print(f"{test:12}: {status}")

def main():
    parser = ArgumentParser(description='SecurityCheck - Privacy Verification Tool')
    parser.add_argument('-a', '--all', action='store_true', help='Run all checks')
    parser.add_argument('-t', '--tor', action='store_true', help='Check Tor connection')
    parser.add_argument('-d', '--dns', action='store_true', help='Check DNS leaks')
    parser.add_argument('-w', '--webrtc', action='store_true', help='Check WebRTC leaks')
    parser.add_argument('-6', '--ipv6', action='store_true', help='Check IPv6 leaks')
    
    args = parser.parse_args()
    checker = SecurityCheck()
    
    if args.all:
        results = {
            'Tor Connection': checker.check_tor(),
            'DNS Leak': checker.check_dns_leak(),
            'WebRTC Leak': not checker.check_webrtc_leak(),
            'IPv6 Leak': checker.check_ipv6_leak()
        }
        print_results(results)
    else:
        results = {}
        if args.tor:
            results['Tor Connection'] = checker.check_tor()
        if args.dns:
            results['DNS Leak'] = checker.check_dns_leak()
        if args.webrtc:
            results['WebRTC Leak'] = not checker.check_webrtc_leak()
        if args.ipv6:
            results['IPv6 Leak'] = checker.check_ipv6_leak()
        
        if results:
            print_results(results)
        else:
            parser.print_help()

if __name__ == '__main__':
    main()