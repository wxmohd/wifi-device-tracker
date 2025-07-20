#!/usr/bin/env python3
"""
Auto-Trust Network Scanner Module for Wi-Fi Device Tracker
Extends the NetworkScanner to automatically trust devices after they've been seen once
"""
import os
import json
from datetime import datetime
from app.scanner import NetworkScanner

class AutoTrustScanner(NetworkScanner):
    """
    Extended NetworkScanner that automatically trusts devices after they've been seen once
    """
    
    def __init__(self, config_path=None):
        """Initialize the scanner with configuration"""
        super().__init__(config_path)
        self.seen_devices = []
        self.load_seen_devices()
    
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
    
    def _scan_with_nmap(self, subnet, timeout=20):
        """Override scan method to implement auto-trust"""
        print(f"AutoTrustScanner: Starting nmap scan of {subnet} with timeout {timeout}s")
        devices = super()._scan_with_nmap(subnet, timeout)
        print(f"AutoTrustScanner: Nmap scan found {len(devices)} devices")
        
        # Process devices to implement auto-trust
        for device in devices:
            mac = device.get('mac')
            if mac and mac != 'Unknown':
                # If device has been seen before, mark it as trusted
                if self.is_device_seen_before(mac):
                    device['trusted'] = True
                else:
                    # Add new device to seen devices list
                    self.add_seen_device(mac, device.get('ip', ''), device.get('hostname', ''))
        
        return devices
    
    def _scan_with_ping(self, subnet, timeout=20):
        """Override ping scan method to implement auto-trust"""
        print(f"AutoTrustScanner: Starting ping scan of {subnet} with timeout {timeout}s")
        devices = super()._scan_with_ping(subnet, timeout)
        print(f"AutoTrustScanner: Ping scan found {len(devices)} devices")
        
        # Process devices to implement auto-trust
        for device in devices:
            mac = device.get('mac')
            if mac and mac != 'Unknown':
                # If device has been seen before, mark it as trusted
                if self.is_device_seen_before(mac):
                    device['trusted'] = True
                else:
                    # Add new device to seen devices list
                    self.add_seen_device(mac, device.get('ip', ''), device.get('hostname', ''))
        
        return devices

# For testing the module directly
if __name__ == "__main__":
    scanner = AutoTrustScanner()
    print("Scanning network with auto-trust...")
    devices = scanner.scan_network()
    print(f"Found {len(devices)} devices:")
    for device in devices:
        status = "TRUSTED" if device['trusted'] else "UNTRUSTED"
        print(f"{device['ip']} - {device['mac']} - {device['name']} - {status}")
    
    scanner.log_scan_results(devices)
    print("Scan results logged.")
