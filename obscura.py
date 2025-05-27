#!/usr/bin/env python3
import os
import sys
import json
import random
import time
import subprocess
import psutil
import logging
from subprocess import call, check_call, CalledProcessError
from os.path import isfile, basename, expanduser, join, exists, dirname
from os import devnull, makedirs, geteuid
from sys import exit
from atexit import register
from argparse import ArgumentParser
from urllib.request import urlopen
from urllib.error import URLError
from time import sleep
from logging.handlers import RotatingFileHandler

class PrivacyNet:
    def __init__(self):
        if geteuid() != 0:
            exit("\033[91m[!] Error: PrivacyNet must be run as root\033[0m")

        # Network Configuration
        self.local_dnsport = "53"
        self.virtual_net = "10.0.0.0/10"
        self.local_loopback = "127.0.0.1"
        self.non_tor_net = ["192.168.0.0/16", "172.16.0.0/12"]
        self.non_tor = ["127.0.0.0/9", "127.128.0.0/10", "127.0.0.0/8"]
        self.tor_uid = self._get_tor_uid()
        self.trans_port = "9040"
        self.tor_config_file = '/etc/tor/torrc'
        
        # WebRTC Configuration
        self.browser_configs = {
            'firefox': {
                'prefs': {
                    'media.peerconnection.enabled': False,
                    'media.navigator.enabled': False,
                    'privacy.resistFingerprinting': True,
                    'privacy.firstparty.isolate': True
                },
                'paths': [
                    '~/.mozilla/firefox',
                    '~/.var/app/org.mozilla.firefox/.mozilla/firefox'
                ]
            },
            'chrome': {
                'prefs': {
                    'webrtc.ip_handling_policy': 'disable_non_proxied_udp',
                    'webrtc.multiple_routes_enabled': False,
                    'webrtc.nonproxied_udp_enabled': False
                },
                'paths': [
                    '~/.config/google-chrome',
                    '~/.config/chromium',
                    '~/.var/app/com.google.Chrome/config/google-chrome',
                    '~/.var/app/org.chromium.Chromium/config/chromium'
                ]
            },
            'brave': {
                'prefs': {
                    'webrtc.ip_handling_policy': 'disable_non_proxied_udp',
                    'webrtc.multiple_routes_enabled': False
                },
                'paths': [
                    '~/.config/BraveSoftware/Brave-Browser'
                ]
            }
        }

        # Initialize logging
        self._setup_logging()

    def _get_tor_uid(self):
        """Get Tor user UID with fallback"""
        try:
            return subprocess.getoutput("id -ur debian-tor")
        except:
            try:
                call(["useradd", "-r", "-s", "/bin/false", "debian-tor"])
                return subprocess.getoutput("id -ur debian-tor")
            except:
                exit("\033[91m[!] Failed to create Tor user\033[0m")

    def _setup_logging(self):
        """Configure advanced logging"""
        log_file = "/var/log/privacynet.log"
        os.makedirs(dirname(log_file), exist_ok=True)
        
        self.logger = logging.getLogger('PrivacyNet')
        self.logger.setLevel(logging.INFO)
        
        handler = RotatingFileHandler(
            log_file,
            maxBytes=1_000_000,
            backupCount=3,
            encoding='utf-8'
        )
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
        # Also log to console when running interactively
        if sys.stdout.isatty():
            console = logging.StreamHandler()
            console.setFormatter(formatter)
            self.logger.addHandler(console)

    def _exec_cmd(self, cmd, silent=False):
        """Execute shell command with error handling"""
        try:
            if silent:
                with open(devnull, 'w') as null:
                    return subprocess.check_call(cmd, stdout=null, stderr=null)
            return subprocess.check_call(cmd)
        except CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(e.cmd)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            return False

    def flush_iptables(self):
        """Reset all iptables rules"""
        self._exec_cmd(["iptables", "-F"])
        self._exec_cmd(["iptables", "-t", "nat", "-F"])
        self._exec_cmd(["ip6tables", "-F"])
        self._exec_cmd(["ip6tables", "-t", "nat", "-F"])
        self.logger.info("Flushed all iptables rules")

    def configure_tor(self):
        """Ensure Tor is properly configured"""
        if not isfile(self.tor_config_file):
            self.logger.error("Tor config file not found")
            return False

        with open(self.tor_config_file, 'a+') as f:
            f.seek(0)
            content = f.read()
            if 'VirtualAddrNetwork' not in content:
                f.write(f"\n# PrivacyNet Configuration\n"
                       f"VirtualAddrNetwork {self.virtual_net}\n"
                       f"AutomapHostsOnResolve 1\n"
                       f"TransPort {self.trans_port}\n"
                       f"DNSPort {self.local_dnsport}\n")
                self.logger.info("Added Tor configuration")
        return True

    def configure_iptables(self):
        """Set up iptables rules for Tor transparency"""
        self.flush_iptables()
        
        # IPv4 Rules
        self._exec_cmd(["iptables", "-I", "OUTPUT", "!", "-o", "lo", "!", "-d", self.local_loopback, 
                       "!", "-s", self.local_loopback, "-p", "tcp", "-m", "tcp", "--tcp-flags", 
                       "ACK,FIN", "ACK,FIN", "-j", "DROP"])
        
        self._exec_cmd(["iptables", "-t", "nat", "-A", "OUTPUT", "-m", "owner", "--uid-owner", 
                       self.tor_uid, "-j", "RETURN"])
        
        for net in self.non_tor + self.non_tor_net:
            self._exec_cmd(["iptables", "-t", "nat", "-A", "OUTPUT", "-d", net, "-j", "RETURN"])

        self._exec_cmd(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", 
                       "-j", "REDIRECT", "--to-ports", self.local_dnsport])
        
        self._exec_cmd(["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn", 
                       "-j", "REDIRECT", "--to-ports", self.trans_port])
        
        # IPv6 Blocking
        self._exec_cmd(["ip6tables", "-A", "OUTPUT", "-j", "REJECT"])
        
        self.logger.info("Configured iptables rules")
        return True

    def prevent_dns_leaks(self):
        """Additional DNS leak protection"""
        self._exec_cmd(["iptables", "-A", "OUTPUT", "-p", "udp", "!", "--dport", self.local_dnsport, "-j", "DROP"])
        self._exec_cmd(["iptables", "-A", "OUTPUT", "-p", "tcp", "!", "--dport", self.trans_port, "-j", "DROP"])
        self.logger.info("Enabled DNS leak protection")

    def configure_webrtc(self):
        """Configure all browsers to prevent WebRTC leaks"""
        results = {}
        for browser, config in self.browser_configs.items():
            results[browser] = False
            for path_template in config['paths']:
                path = expanduser(path_template)
                if exists(path):
                    if browser == 'firefox':
                        results[browser] = self._configure_firefox(path, config['prefs'])
                    else:
                        results[browser] = self._configure_chromium(path, config['prefs'])
                    if results[browser]:
                        break
        return results

    def _configure_firefox(self, path, prefs):
        """Configure Firefox preferences"""
        try:
            for profile in os.listdir(path):
                if profile.endswith(('.default', '.default-release')):
                    prefs_file = join(path, profile, 'user.js')
                    with open(prefs_file, 'a') as f:
                        for key, value in prefs.items():
                            f.write(f'user_pref("{key}", {json.dumps(value)});\n')
            self.logger.info("Configured Firefox WebRTC protection")
            return True
        except Exception as e:
            self.logger.error(f"Firefox config failed: {str(e)}")
            return False

    def _configure_chromium(self, path, prefs):
        """Configure Chrome/Chromium/Brave preferences"""
        try:
            prefs_file = join(path, 'Default', 'Preferences')
            if exists(prefs_file):
                with open(prefs_file, 'r+') as f:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = {}
                    
                    # Deep merge preferences
                    def deep_update(target, src):
                        for key, value in src.items():
                            if isinstance(value, dict):
                                target[key] = deep_update(target.get(key, {}), value)
                            else:
                                target[key] = value
                        return target
                    
                    deep_update(data, {'profile': {'content_settings': {'exceptions': {
                        'webrtc': {'*': {'setting': 2}}}}})

                    # Set additional preferences
                    for key, value in prefs.items():
                        keys = key.split('.')
                        current = data
                        for k in keys[:-1]:
                            current = current.setdefault(k, {})
                        current[keys[-1]] = value
                    
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()
                
                self.logger.info(f"Configured {basename(path)} WebRTC protection")
                return True
        except Exception as e:
            self.logger.error(f"Chromium config failed: {str(e)}")
            return False

    def kill_browsers(self):
        """Terminate all browsers to apply changes"""
        browsers = ['firefox', 'chrome', 'chromium', 'brave', 'opera', 'vivaldi']
        killed = []
        for proc in psutil.process_iter(['name', 'pid']):
            try:
                if proc.info['name'].lower() in browsers:
                    proc.kill()
                    killed.append(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return killed

    def get_ip_info(self):
        """Get current public IP"""
        try:
            return subprocess.getoutput('curl -s ifconfig.me')
        except:
            return "Unknown"

    def change_ip(self):
        """Request new Tor circuit"""
        self._exec_cmd(['killall', '-HUP', 'tor'])
        self.logger.info("Requested new Tor circuit")
        return self.get_ip_info()

def main():
    parser = ArgumentParser(description='PrivacyNet - Network Anonymization Tool')
    parser.add_argument('-l', '--load', action='store_true', help='Enable full protection')
    parser.add_argument('-f', '--flush', action='store_true', help='Reset iptables rules')
    parser.add_argument('-r', '--refresh', action='store_true', help='Change Tor circuit')
    parser.add_argument('-i', '--info', action='store_true', help='Show current IP')
    parser.add_argument('-w', '--webrtc', action='store_true', help='Configure WebRTC protection')
    parser.add_argument('-k', '--kill-browsers', action='store_true', help='Kill browsers after config')
    parser.add_argument('-a', '--auto', action='store_true', help='Auto IP rotation')
    parser.add_argument('-t', '--interval', type=int, default=3600, help='Rotation interval (seconds)')
    
    args = parser.parse_args()

    try:
        pn = PrivacyNet()
        
        if args.flush:
            pn.flush_iptables()
            print("\033[92m[+] iptables rules reset\033[0m")
        
        if args.load:
            if pn.configure_tor() and pn.configure_iptables():
                pn.prevent_dns_leaks()
                print("\033[92m[+] Full protection enabled\033[0m")
        
        if args.webrtc:
            print("\n\033[94m[ Configuring WebRTC Protection ]\033[0m")
            results = pn.configure_webrtc()
            for browser, success in results.items():
                status = "\033[92mSUCCESS\033[0m" if success else "\033[91mFAILED\033[0m"
                print(f"{browser.capitalize():15}: {status}")
            
            if args.kill_browsers:
                killed = pn.kill_browsers()
                if killed:
                    print("\n\033[93m[ Killed browsers ]\033[0m")
                    for browser in killed:
                        print(f"- {browser}")
                else:
                    print("\nNo browsers were running")
        
        if args.info:
            ip = pn.get_ip_info()
            print(f"\nCurrent IP: {ip}")
        
        if args.refresh:
            ip = pn.change_ip()
            print(f"\033[92m[+] New IP: {ip}\033[0m")
        
        if args.auto:
            print("\033[92m[+] Starting automatic IP rotation...\033[0m")
            try:
                while True:
                    pn.change_ip()
                    sleep(args.interval)
            except KeyboardInterrupt:
                print("\n\033[93m[!] Stopped IP rotation\033[0m")
        
        if not any(vars(args).values()):
            parser.print_help()

    except KeyboardInterrupt:
        print("\n\033[93m[!] Operation cancelled by user\033[0m")
    except Exception as e:
        print(f"\033[91m[!] Error: {str(e)}\033[0m")

if __name__ == '__main__':
    main()