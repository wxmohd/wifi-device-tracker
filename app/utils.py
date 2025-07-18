#!/usr/bin/env python3
"""
Utility functions for Wi-Fi Device Tracker
"""
import os
import json
import re
from datetime import datetime

def load_json_file(file_path, default=None):
    """Load data from a JSON file with error handling"""
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        return default if default is not None else {}
    except Exception as e:
        print(f"Error loading JSON file {file_path}: {e}")
        return default if default is not None else {}

def save_json_file(file_path, data):
    """Save data to a JSON file with error handling"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"Error saving JSON file {file_path}: {e}")
        return False

def normalize_mac(mac):
    """Normalize MAC address format to XX:XX:XX:XX:XX:XX"""
    if not mac:
        return ""
        
    # Remove any separators and convert to uppercase
    mac = mac.replace(':', '').replace('-', '').replace('.', '').upper()
    
    # Format with colons
    return ':'.join([mac[i:i+2] for i in range(0, len(mac), 2)])

def is_valid_mac(mac):
    """Check if a string is a valid MAC address"""
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac))

def get_recent_logs(logs_file="app/logs.json", count=10):
    """Get the most recent scan logs"""
    logs_data = load_json_file(logs_file, {"logs": []})
    logs = logs_data.get("logs", [])
    
    # Sort logs by timestamp (newest first)
    logs.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    
    return logs[:count]

def get_alert_count(logs_file="app/logs.json", hours=None, days=None):
    """Count alerts (untrusted devices) in the last X hours or days"""
    logs_data = load_json_file(logs_file, {"logs": []})
    logs = logs_data.get("logs", [])
    
    # Convert days to hours if days is provided
    if days is not None and hours is None:
        hours = days * 24
    
    # Default to all logs if neither hours nor days is specified
    if hours is None:
        hours = float('inf')
    
    alert_count = 0
    current_time = datetime.now()
    
    for log in logs:
        try:
            log_time = datetime.strptime(log.get("timestamp", ""), '%Y-%m-%d %H:%M:%S')
            time_diff_hours = (current_time - log_time).total_seconds() / 3600
            
            if time_diff_hours <= hours:
                alert_count += log.get("untrusted_count", 0)
        except Exception:
            continue
            
    return alert_count

def format_timestamp(timestamp, format_str="%Y-%m-%d %H:%M:%S"):
    """Format timestamp for display"""
    try:
        dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        return dt.strftime(format_str)
    except Exception:
        return timestamp
