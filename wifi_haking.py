#!/usr/bin/env python3
"""
WiFi Password Dumper - Offline, No External Dependencies
Compatible with Python 3.6+ on Windows/Linux/macOS
Requires admin/root privileges for full access.
"""

import subprocess
import sys
import re
import platform
import json
from pathlib import Path

def run_cmd(cmd):
    """Execute shell command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return ""

def get_windows_wifi_passwords():
    """Extract WiFi passwords from Windows (netsh)."""
    profiles = {}
    
    # Get all WiFi profiles
    profiles_output = run_cmd('netsh wlan show profiles')
    profile_names = re.findall(r'All User Profile\s*:\s*(.+)', profiles_output)
    
    for profile in profile_names:
        profile = profile.strip()
        # Get profile details including password
        profile_info = run_cmd(f'netsh wlan show profile name="{profile}" key=clear')
        
        # Extract SSID and password
        ssid_match = re.search(rf'All User Profile\s*:\s*{re.escape(profile)}', profile_info)
        key_match = re.search(r'Key Content\s*:\s*(.+)', profile_info)
        
        profiles[profile] = {
            'password': key_match.group(1).strip() if key_match else 'N/A (No password saved)'
        }
    
    return profiles

def get_linux_wifi_passwords():
    """Extract WiFi passwords from Linux (NetworkManager)."""
    profiles = {}
    
    # Common NetworkManager connection dirs
    nm_dirs = [
        Path('/etc/NetworkManager/system-connections/'),
        Path.home() / '.config/NetworkManager/system-connections/'
    ]
    
    for nm_dir in nm_dirs:
        if nm_dir.exists():
            for conn_file in nm_dir.glob('*.nmconnection'):
                try:
                    content = conn_file.read_text()
                    ssid_match = re.search(r'id=(.+)', content)
                    psk_match = re.search(r'psk=(.+)', content)
                    
                    if ssid_match:
                        ssid = ssid_match.group(1).strip('"')
                        password = psk_match.group(1).strip('"') if psk_match else 'N/A'
                        profiles[ssid] = {'password': password}
                except:
                    continue
    
    # Fallback: wpa_supplicant conf
    wpa_conf = Path.home() / '.wpa_supplicant.conf'
    if wpa_conf.exists():
        content = wpa_conf.read_text()
        networks = re.findall(r'network=\{([^}]+)\}', content, re.DOTALL)
        for net in networks:
            ssid_match = re.search(r'ssid="([^"]+)"', net)
            psk_match = re.search(r'psk="([^"]+)"', net)
            if ssid_match:
                ssid = ssid_match.group(1)
                password = psk_match.group(1) if psk_match else 'N/A'
                profiles[ssid] = {'password': password}
    
    return profiles

def get_macos_wifi_passwords():
    """Extract WiFi passwords from macOS (security command)."""
    profiles = {}
    
    # Get saved networks
    prefs_path = Path.home() / 'Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist'
    if prefs_path.exists():
        # KnownNetworks section contains saved networks
        cmd = f'security find-generic-password -ga "*" | grep "airport"'
        output = run_cmd(cmd)
        
        # Parse security output (requires sudo for passwords)
        networks = run_cmd('defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist KnownNetworks')
        if networks:
            # Extract network names
            net_names = re.findall(r'"([^"]+)"', networks)
            for net in net_names:
                try:
                    password = run_cmd(f'security find-generic-password -w -a "{net}" -s "AirPort" 2>/dev/null')
                    profiles[net] = {'password': password.strip() if password else 'N/A'}
                except:
                    profiles[net] = {'password': 'N/A'}
    return profiles

def main():
    system = platform.system().lower()
    print(f"[+] WiFi Password Extractor for {platform.system()}")
    print(f"[+] Running on: {platform.release()}\n")
    
    profiles = {}
    
    if system == 'windows':
        print("[+] Extracting Windows WiFi profiles (netsh)...")
        profiles = get_windows_wifi_passwords()
    
    elif system == 'linux':
        print("[+] Extracting Linux WiFi profiles (NetworkManager/wpa_supplicant)...")
        profiles = get_linux_wifi_passwords()
    
    elif system == 'darwin':
        print("[+] Extracting macOS WiFi profiles (airport preferences)...")
        profiles = get_macos_wifi_passwords()
    
    else:
        print("[-] Unsupported OS. Supported: Windows/Linux/macOS")
        sys.exit(1)
    
    if not profiles:
        print("[-] No WiFi profiles found or insufficient permissions.")
        print("[!] Run as Administrator/root for full access.")
        sys.exit(1)
    
    print(f"\n[+] Found {len(profiles)} WiFi profile(s):\n")
    print("-" * 60)
    
    # Pretty JSON output
    output = {
        "system": platform.system(),
        "profiles": profiles,
        "timestamp": "2026-01-04"
    }
    
    print(json.dumps(output, indent=2))
    
    # Save to file
    with open('wifi_passwords.json', 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n[+] Results saved to: wifi_passwords.json")
    print("-" * 60)

if __name__ == "__main__":
    if platform.system().lower() == 'windows':
        # Check for admin privileges
        try:
            run_cmd('net session >nul 2>&1')
        except:
            print("[-] Administrator privileges required!")
            sys.exit(1)
    
    main()