#!/usr/bin/env python3
"""
Network Scanner Module for Wi-Fi Device Tracker
Handles scanning the local network for devices using ARP or Nmap
"""
import os
import json
import time
import socket
import ipaddress
import subprocess
import platform
import re
from datetime import datetime
import netifaces
import nmap

class NetworkScanner:
    """Class to handle network scanning operations"""
    
    def __init__(self, config_path=None):
        """Initialize the scanner with configuration"""
        self.scan_method = "nmap"  # Default scan method
        self.trusted_devices = []
        self.seen_devices = []
        self.load_trusted_devices()
        self.load_seen_devices()
        
    def load_trusted_devices(self, devices_file="app/devices.json"):
        """Load trusted devices from JSON file"""
        try:
            if os.path.exists(devices_file):
                with open(devices_file, 'r') as f:
                    data = json.load(f)
                    self.trusted_devices = data.get('trusted_devices', [])
            else:
                # Create default file if it doesn't exist
                self.trusted_devices = []
                self.save_trusted_devices(devices_file)
        except Exception as e:
            print(f"Error loading trusted devices: {e}")
            self.trusted_devices = []
    
    def save_trusted_devices(self, devices_file="app/devices.json"):
        """Save trusted devices to JSON file"""
        try:
            data = {'trusted_devices': self.trusted_devices}
            os.makedirs(os.path.dirname(devices_file), exist_ok=True)
            with open(devices_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Error saving trusted devices: {e}")
            
    def load_seen_devices(self, devices_file="app/seen_devices.json"):
        """Load previously seen devices from JSON file"""
        try:
            if os.path.exists(devices_file):
                with open(devices_file, 'r') as f:
                    data = json.load(f)
                    self.seen_devices = data.get('seen_devices', [])
            else:
                # Create default file if it doesn't exist
                self.seen_devices = []
                self.save_seen_devices(devices_file)
        except Exception as e:
            print(f"Error loading seen devices: {e}")
            self.seen_devices = []
    
    def save_seen_devices(self, devices_file="app/seen_devices.json"):
        """Save seen devices to JSON file"""
        try:
            data = {'seen_devices': self.seen_devices}
            os.makedirs(os.path.dirname(devices_file), exist_ok=True)
            with open(devices_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Error saving seen devices: {e}")
    
    def is_device_seen_before(self, mac):
        """Check if a device has been seen before"""
        normalized_mac = self._normalize_mac(mac)
        return any(d.get('mac') == normalized_mac for d in self.seen_devices)
    
    def add_seen_device(self, mac, ip, hostname=""):
        """Add a device to the seen devices list"""
        normalized_mac = self._normalize_mac(mac)
        
        # Don't add if already in the list
        if self.is_device_seen_before(normalized_mac):
            return
        
        # Add to seen devices with timestamp
        self.seen_devices.append({
            'mac': normalized_mac,
            'ip': ip,
            'hostname': hostname,
            'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
        # Save the updated list
        self.save_seen_devices()
    
    def get_trusted_devices(self):
        """Return the list of trusted devices"""
        return self.trusted_devices
    
    def add_trusted_device(self, mac, name, devices_file="app/devices.json"):
        """Add a device to trusted devices list"""
        # Normalize MAC address format
        mac = self._normalize_mac(mac)
        
        # Check if device already exists
        for device in self.trusted_devices:
            if device.get('mac') == mac:
                device['name'] = name
                self.save_trusted_devices(devices_file)
                return True
        
        # Add new device
        self.trusted_devices.append({
            'mac': mac,
            'name': name,
            'added_on': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        self.save_trusted_devices(devices_file)
        return True
    
    def remove_trusted_device(self, mac, devices_file="app/devices.json"):
        """Remove a device from trusted devices list"""
        mac = self._normalize_mac(mac)
        initial_count = len(self.trusted_devices)
        self.trusted_devices = [d for d in self.trusted_devices if d.get('mac') != mac]
        
        if len(self.trusted_devices) < initial_count:
            self.save_trusted_devices(devices_file)
            return True
        return False
    
    def _normalize_mac(self, mac):
        """Normalize MAC address format to XX:XX:XX:XX:XX:XX"""
        if not mac:
            return ""
            
        # Remove any separators and convert to uppercase
        mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
        
        # Format with colons
        return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])
    
    def get_local_ip_and_subnet(self):
        """Get the local IP address and subnet"""
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                interface = gateways['default'][netifaces.AF_INET][1]
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    ip_info = addrs[netifaces.AF_INET][0]
                    ip = ip_info['addr']
                    netmask = ip_info.get('netmask', '255.255.255.0')
                    
                    # Calculate CIDR notation
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    return ip, str(network)
            
            # Fallback method if the above fails
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip, f"{ip.rsplit('.', 1)[0]}.0/24"
            
        except Exception as e:
            print(f"Error getting local IP: {e}")
            return "127.0.0.1", "127.0.0.1/24"
    
    def scan_network(self, timeout=20):
        """Scan the network for devices with timeout"""
        local_ip, subnet = self.get_local_ip_and_subnet()
        print(f"Starting network scan of {subnet} (local IP: {local_ip})")
        
        # Try multiple scan methods to ensure we find all devices
        devices = []
        
        # First try nmap scan which is more comprehensive
        if self.scan_method == "nmap":
            print("Using nmap scan method")
            devices = self._scan_with_nmap(subnet, timeout)
        
        # If nmap didn't find many devices or isn't available, try ping scan
        if len(devices) <= 2:  # If only found router and local machine
            print("Nmap scan found few devices, trying ping scan")
            ping_devices = self._scan_with_ping(subnet, timeout)
            
            # Merge the results, avoiding duplicates
            existing_ips = [d.get('ip') for d in devices]
            for device in ping_devices:
                if device.get('ip') not in existing_ips:
                    devices.append(device)
        
        # Try ARP scan as a final method to find devices
        print("Performing ARP table scan to find additional devices")
        arp_devices = self._scan_arp_table()
        
        # Merge ARP results
        existing_ips = [d.get('ip') for d in devices]
        for device in arp_devices:
            if device.get('ip') not in existing_ips:
                devices.append(device)
        
        print(f"Total devices found across all scan methods: {len(devices)}")
        return devices
    
    def _scan_with_nmap(self, subnet, timeout=20):
        """Scan network using python-nmap with timeout"""
        try:
            nm = nmap.PortScanner()
            # Add timeout to nmap scan and use more aggressive scanning
            nm.scan(hosts=subnet, arguments=f'-sn -PE -PA21,22,23,80,443,3389 --host-timeout {timeout}s')
            
            devices = []
            for host in nm.all_hosts():
                # Debug output to help diagnose issues
                print(f"Found host: {host} with addresses: {nm[host].get('addresses', {})}")
                
                if 'mac' in nm[host].get('addresses', {}):
                    mac = nm[host]['addresses']['mac']
                    ip = nm[host]['addresses']['ipv4']
                    hostname = nm[host].get('hostnames', [{'name': ''}])[0]['name']
                    
                    # Check if device is trusted
                    is_trusted = any(d.get('mac') == self._normalize_mac(mac) for d in self.trusted_devices)
                    
                    # Get device name from trusted devices if available
                    device_name = hostname or "Unknown Device"
                    for d in self.trusted_devices:
                        if d.get('mac') == self._normalize_mac(mac):
                            device_name = d.get('name', hostname or "Unknown Device")
                            break
                    
                    # Try to determine device type based on MAC prefix
                    vendor = self._get_vendor_from_mac(mac)
                    if vendor and (not device_name or device_name == "Unknown Device"):
                        device_name = f"{vendor} Device"
                    
                    devices.append({
                        'ip': ip,
                        'mac': self._normalize_mac(mac),
                        'hostname': hostname or "Unknown",
                        'name': device_name,
                        'trusted': is_trusted
                    })
                elif 'ipv4' in nm[host].get('addresses', {}):
                    # Device without MAC (could be a virtual interface)
                    ip = nm[host]['addresses']['ipv4']
                    hostname = nm[host].get('hostnames', [{'name': ''}])[0]['name']
                    
                    # Try to get MAC from ARP table as a fallback
                    mac = self._get_mac_from_arp(ip)
                    is_trusted = False
                    if mac:
                        is_trusted = any(d.get('mac') == self._normalize_mac(mac) for d in self.trusted_devices)
                    
                    devices.append({
                        'ip': ip,
                        'mac': self._normalize_mac(mac) if mac else 'Unknown',
                        'hostname': hostname,
                        'name': hostname,
                        'trusted': is_trusted
                    })
            
            # If no devices found with nmap, try a fallback method
            if not devices:
                print("No devices found with nmap, trying ping scan fallback")
                return self._scan_with_ping(subnet, timeout)
                
            return devices
        except Exception as e:
            print(f"Error scanning with nmap: {e}")
            # Fallback to ping scan
            return self._scan_with_ping(subnet, timeout)
    
    def _scan_with_ping(self, subnet, timeout=20):
        """Fallback method using ping sweep with timeout"""
        devices = []
        network = ipaddress.IPv4Network(subnet)
        
        # Calculate how many IPs to scan and set a time limit per IP
        total_ips = sum(1 for _ in network.hosts())
        time_per_ip = min(1.0, timeout / max(total_ips, 1))  # Increased to 1.0 second per IP max
        
        start_time = time.time()
        print(f"Starting ping scan of {subnet} with {total_ips} hosts")
        
        # First scan the local IP and gateway to ensure we get at least those devices
        local_ip, _ = self.get_local_ip_and_subnet()
        gateway = self._get_default_gateway()
        priority_ips = [local_ip, gateway]
        
        # Always add the local machine to devices list regardless of ping result
        print(f"Adding local machine {local_ip} to devices list")
        hostname = socket.gethostname()
        mac = self._get_mac_from_arp(local_ip) or "Local-Machine"
        
        # Check if device is trusted
        is_trusted = False
        if mac:
            is_trusted = any(d.get('mac') == self._normalize_mac(mac) for d in self.trusted_devices)
        
        devices.append({
            'ip': local_ip,
            'mac': self._normalize_mac(mac) if mac and mac != "Local-Machine" else mac,
            'hostname': hostname,
            'name': f"This Computer ({hostname})",
            'trusted': True  # Always trust the local machine
        })
        
        # Scan gateway if available
        if gateway and gateway != "Unknown" and gateway != local_ip:
            try:
                print(f"Scanning gateway: {gateway}")
                # Ping with longer timeout for gateway
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '2', '-w', '2', gateway]
                response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2.0)
                
                if response.returncode == 0:
                    # Try to get MAC address from ARP table
                    mac = self._get_mac_from_arp(gateway)
                    hostname = self._get_hostname(gateway) or "Gateway"
                    
                    devices.append({
                        'ip': gateway,
                        'mac': self._normalize_mac(mac) if mac else 'Gateway-Router',
                        'hostname': hostname,
                        'name': f"Router ({hostname})",
                        'trusted': True  # Always trust the gateway
                    })
                    print(f"Found gateway: {gateway} with MAC: {mac if mac else 'Gateway-Router'}")
            except Exception as e:
                print(f"Error pinging gateway {gateway}: {e}")
                # Add gateway anyway even if ping fails
                devices.append({
                    'ip': gateway,
                    'mac': 'Gateway-Router',
                    'hostname': 'Gateway',
                    'name': 'Network Router',
                    'trusted': True
                })
        
        # Only scan a limited number of other IPs to avoid excessive timeouts
        # Focus on the most likely IPs in the subnet
        scan_limit = min(20, total_ips)  # Limit to 20 IPs max
        ips_scanned = 0
        
        # Then scan the rest of the network
        for ip in network.hosts():
            # Check if we've exceeded our timeout or scan limit
            if time.time() - start_time > timeout or ips_scanned >= scan_limit:
                print(f"Ping scan limit reached after {ips_scanned} IPs or {timeout} seconds")
                break
                
            ip_str = str(ip)
            
            # Skip broadcast, network addresses, and already scanned priority IPs
            if ip_str.endswith('.0') or ip_str.endswith('.255') or ip_str in [local_ip, gateway]:
                continue
                
            try:
                # Only increment counter for IPs we actually try to scan
                ips_scanned += 1
                
                # Ping the IP with a short timeout
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '1', '-w', '2', ip_str]  # Increased timeout to 2 seconds
                response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=time_per_ip)
                
                if response.returncode == 0:
                    # Try to get MAC address from ARP table
                    mac = self._get_mac_from_arp(ip_str)
                    hostname = self._get_hostname(ip_str)
                    
                    # Check if device is trusted
                    is_trusted = False
                    if mac:
                        is_trusted = any(d.get('mac') == self._normalize_mac(mac) for d in self.trusted_devices)
                    
                    # Get device name from trusted devices if available
                    device_name = hostname or ip_str
                    if mac:
                        for d in self.trusted_devices:
                            if d.get('mac') == self._normalize_mac(mac):
                                device_name = d.get('name', hostname or ip_str)
                                break
                    
                    devices.append({
                        'ip': ip_str,
                        'mac': self._normalize_mac(mac) if mac else 'Unknown',
                        'hostname': hostname,
                        'name': device_name,
                        'trusted': is_trusted
                    })
                    print(f"Found device: {ip_str} with MAC: {mac if mac else 'Unknown'}")
            except Exception as e:
                # Just log the error and continue
                pass
        
        print(f"Ping scan completed. Found {len(devices)} devices.")
        return devices
        
    def _scan_arp_table(self):
        """Scan the ARP table for all devices"""
        devices = []
        try:
            # Get ARP table
            if platform.system().lower() == 'windows':
                # Windows ARP command
                output = subprocess.check_output(['arp', '-a'], universal_newlines=True)
            else:
                # Linux/Mac ARP command
                output = subprocess.check_output(['arp', '-n'], universal_newlines=True)
            
            print("ARP table scan results:")
            print(output)
            
            # Parse the output to extract IP and MAC addresses
            # Windows format: "192.168.1.1           00-11-22-33-44-55     dynamic"
            # Linux format: "192.168.1.1                 ether   00:11:22:33:44:55   C                     eth0"
            lines = output.split('\n')
            for line in lines:
                # Skip header lines and empty lines
                if not line.strip() or 'Interface' in line or 'Address' in line:
                    continue
                    
                # Extract IP and MAC
                parts = line.split()
                if len(parts) >= 2:
                    ip = None
                    mac = None
                    
                    # Try to identify IP and MAC in the line
                    for part in parts:
                        if self._is_valid_ip(part):
                            ip = part
                        elif self._is_valid_mac(part):
                            mac = part
                    
                    if ip and mac and mac.lower() != "ff:ff:ff:ff:ff:ff" and not mac.startswith("00:00:00"):
                        hostname = self._get_hostname(ip)
                        
                        # Check if device is trusted
                        is_trusted = False
                        if mac:
                            is_trusted = any(d.get('mac') == self._normalize_mac(mac) for d in self.trusted_devices)
                        
                        # Get device name from trusted devices if available
                        device_name = hostname or ip
                        if mac:
                            for d in self.trusted_devices:
                                if d.get('mac') == self._normalize_mac(mac):
                                    device_name = d.get('name', hostname or ip)
                                    break
                        
                        devices.append({
                            'ip': ip,
                            'mac': self._normalize_mac(mac),
                            'hostname': hostname or "Unknown",
                            'name': device_name,
                            'trusted': is_trusted
                        })
                        print(f"ARP table found device: {ip} with MAC: {mac}")
            
        except Exception as e:
            print(f"Error scanning ARP table: {e}")
        
        return devices
    
    def _is_valid_ip(self, ip_str):
        """Check if a string is a valid IP address"""
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except:
            return False
    
    def _is_valid_mac(self, mac_str):
        """Check if a string looks like a MAC address"""
        # Check for common MAC formats (with : or - separators)
        if re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac_str):
            return True
        # Check for Windows format without separators
        if re.match(r'^[0-9A-Fa-f]{12}$', mac_str):
            return True
        return False
        
    def _get_default_gateway(self):
        """Get the default gateway IP address"""
        try:
            gateways = netifaces.gateways()
            if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                return gateways['default'][netifaces.AF_INET][0]
            return "Unknown"
        except Exception as e:
            print(f"Error getting default gateway: {e}")
            return "Unknown"
    
    def _get_mac_from_arp(self, ip):
        """Get MAC address from ARP table"""
        try:
            if platform.system().lower() == 'windows':
                output = subprocess.check_output(f'arp -a {ip}', shell=True).decode('utf-8')
                for line in output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1].replace('-', ':')
            else:
                output = subprocess.check_output(f'arp -n {ip}', shell=True).decode('utf-8')
                for line in output.splitlines():
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except Exception as e:
            print(f"Error getting MAC from ARP: {e}")
        
        return None
    
    def _get_hostname(self, ip):
        """Try to resolve hostname from IP"""
        try:
            hostname = socket.getfqdn(ip)
            if hostname != ip:
                return hostname
        except Exception:
            pass
        
        return ""
    
    def log_scan_results(self, devices, logs_file="app/logs.json"):
        """Log scan results to JSON file"""
        try:
            logs = []
            if os.path.exists(logs_file):
                with open(logs_file, 'r') as f:
                    try:
                        data = json.load(f)
                        logs = data.get('logs', [])
                    except json.JSONDecodeError:
                        logs = []
            
            log_entry = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'device_count': len(devices),
                'untrusted_count': sum(1 for d in devices if not d.get('trusted', False)),
                'devices': devices
            }
            
            logs.append(log_entry)
            
            if len(logs) > 100:
                logs = logs[-100:]
                
            data = {'logs': logs}
            os.makedirs(os.path.dirname(logs_file), exist_ok=True)
            with open(logs_file, 'w') as f:
                json.dump(data, f, indent=4)
                
            return log_entry
        except Exception as e:
            print(f"Error logging scan results: {e}")
            return None

if __name__ == "__main__":
    scanner = NetworkScanner()
    print("Scanning network...")
    devices = scanner.scan_network()
    print(f"Found {len(devices)} devices:")
    for device in devices:
        status = "TRUSTED" if device['trusted'] else "UNTRUSTED"
        print(f"{device['ip']} - {device['mac']} - {device['name']} - {status}")
    
    scanner.log_scan_results(devices)
    print("Scan results logged.")
