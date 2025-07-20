#!/usr/bin/env python3
"""
Wi-Fi Device Tracker / Rogue Device Detector
Main Flask application entry point
"""
import os
import sys
import threading
import time
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_wtf.csrf import CSRFProtect

from app.auto_trust_scanner import AutoTrustScanner
from app.utils import get_recent_logs, get_alert_count

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_change_in_production')
csrf = CSRFProtect(app)

# Initialize network scanner with auto-trust capability
scanner = AutoTrustScanner()

# Global variables for scan status and results
scan_status = {
    'is_scanning': False,
    'progress': 0,
    'status_message': '',
    'devices_found': 0,
    'last_scan_devices': []  # Store the most recent scan results
}

@app.route('/')
def index():
    """Main dashboard route"""
    global scan_status
    
    # Get local IP and subnet
    local_ip, subnet = scanner.get_local_ip_and_subnet()
    
    # Get trusted devices
    trusted_devices = scanner.get_trusted_devices()
    
    # Get recent scan results
    recent_logs = get_recent_logs()
    
    # Get last scan time and devices
    last_scan_time = "Never"
    devices = []
    
    # If we have devices from a recent scan in memory, use those first
    if scan_status.get('last_scan_devices') and len(scan_status['last_scan_devices']) > 0:
        devices = scan_status['last_scan_devices']
        last_scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    # Otherwise fall back to the logs
    elif recent_logs:
        last_scan = recent_logs[0]
        last_scan_time = last_scan.get('timestamp', "Unknown")
        devices = last_scan.get('devices', [])
    
    # Count untrusted devices
    untrusted_count = sum(1 for device in devices if not device.get('trusted', False))
    
    # Get alert counts
    total_alerts = get_alert_count()
    alerts_24h = get_alert_count(hours=24)
    alerts_7d = get_alert_count(hours=168)  # 7 days
    
    # Get total scan count
    total_scans = len(recent_logs)
    
    return render_template(
        'dashboard.html',
        local_ip=local_ip,
        subnet=subnet,
        last_scan_time=last_scan_time,
        devices=devices,
        trusted_devices=trusted_devices,
        untrusted_count=untrusted_count,
        total_alerts=total_alerts,
        alerts_24h=alerts_24h,
        alerts_7d=alerts_7d,
        total_scans=total_scans,
        recent_logs=recent_logs,
        scan_status=scan_status  # Pass scan status to the template
    )

def scan_network_with_progress():
    """Background thread function to scan network with progress updates"""
    global scan_status
    
    print("\n==== Scan Thread Started ====\n")
    print(f"Thread ID: {threading.current_thread().ident}")
    sys.stdout.flush()
    
    try:
        # Initialize scanner
        print("Initializing scanner...")
        sys.stdout.flush()
        scan_status['status_message'] = 'Initializing scanner...'
        scan_status['progress'] = 10
        
        try:
            scanner = AutoTrustScanner()
            print("Scanner object created successfully")
            sys.stdout.flush()
            
            scanner.load_trusted_devices()
            print("Trusted devices loaded successfully")
            sys.stdout.flush()
        except Exception as e:
            print(f"ERROR initializing scanner: {str(e)}")
            sys.stdout.flush()
            raise
        scan_status['status_message'] = 'Initializing scan...'
        scan_status['devices_found'] = 0
        
        # Get local IP and subnet
        scan_status['status_message'] = 'Detecting network information...'
        scan_status['progress'] = 10
        local_ip, subnet = scanner.get_local_ip_and_subnet()
        print(f"Scanning network: {subnet} (local IP: {local_ip})")
        time.sleep(0.5)  # Small delay to show progress
        
        # Start scanning with timeout protection
        scan_status['status_message'] = 'Scanning network for devices...'
        scan_status['progress'] = 30
        
        # Set a maximum scan time (45 seconds)
        start_time = time.time()
        max_scan_time = 45  # seconds - increased for more thorough scanning
        
        # Create a progress update thread
        def update_progress_thread(scan_status):
            """Thread to update progress incrementally while scanning"""
            start = 31
            end = 89
            step = 2
            delay = 1.0
            
            print("Progress update thread started")
            
            while scan_status['is_scanning'] and scan_status['progress'] < end:
                time.sleep(delay)
                if scan_status['progress'] < start:
                    scan_status['progress'] = start
                else:
                    # Slow down progress updates as we get closer to the end
                    scan_status['progress'] += step
                    if scan_status['progress'] > end:
                        scan_status['progress'] = end
                    print(f"Progress updated to {scan_status['progress']}%")
            
            print("Progress update thread finished")
            # Force progress to 90% when thread exits if still scanning
            if scan_status['is_scanning'] and scan_status['progress'] < 90:
                scan_status['progress'] = 90
                print("Progress forced to 90% as thread exits")
        
        # Start progress update thread
        progress_thread = threading.Thread(target=update_progress_thread, args=(scan_status,))
        progress_thread.daemon = True
        progress_thread.start()
        
        try:
            # Run scan with timeout protection
            print("Starting network scan...")
            print("This may take some time, please be patient...")
            sys.stdout.flush()  # Force output to be displayed immediately
            
            # Add a timestamp to track scan duration
            scan_start = time.time()
            devices = scanner.scan_network(timeout=max_scan_time)
            scan_duration = time.time() - scan_start
            
            print(f"Scan completed in {scan_duration:.1f} seconds, found {len(devices)} devices")
            sys.stdout.flush()  # Force output to be displayed immediately
            
            # Add at least the local device if no devices were found
            if not devices:
                print("No devices found, adding local machine")
                devices = [{
                    'ip': local_ip,
                    'mac': 'Local Machine',
                    'hostname': 'localhost',
                    'name': 'This Computer',
                    'trusted': True
                }]
                
        except Exception as e:
            print(f"Error during network scan: {e}")
            devices = [{
                'ip': local_ip,
                'mac': 'Local Machine',
                'hostname': 'localhost',
                'name': 'This Computer (Error during scan)',
                'trusted': True
            }]
            
        # Check if scan took too long
        if time.time() - start_time > max_scan_time:
            scan_status['status_message'] = 'Scan took too long, showing partial results'
        
        # Process results
        scan_status['status_message'] = 'Processing scan results...'
        scan_status['progress'] = 92
        scan_status['devices_found'] = len(devices)
        
        # Print devices for debugging
        print(f"Devices found ({len(devices)}):")  
        for device in devices:
            print(f"  - {device.get('ip')} | {device.get('mac')} | {device.get('name')}")
        
        # Store the devices in the scan_status for immediate display
        scan_status['last_scan_devices'] = devices
        
        time.sleep(0.5)  # Small delay to show progress
        
        # Log results
        scan_status['status_message'] = 'Logging scan results...'
        scan_status['progress'] = 95
        print("Logging scan results, progress at 95%")
        scanner.log_scan_results(devices)
        
        # Complete - ensure is_scanning is set to False BEFORE setting progress to 100%
        scan_status['status_message'] = 'Scan complete!'
        scan_status['is_scanning'] = False  # Set is_scanning to False FIRST
        scan_status['progress'] = 100       # Then set progress to 100%
        print("Scan complete, progress at 100%, is_scanning set to False")
        
        # Wait a moment before resetting status
        time.sleep(2)
        
    except Exception as e:
        print(f"Exception in scan thread: {e}")
        scan_status['status_message'] = f'Error during scan: {str(e)}'
        scan_status['progress'] = 100
    finally:
        # Always ensure scan status is properly reset
        # Set is_scanning to False FIRST, then set progress to 100%
        scan_status['is_scanning'] = False
        scan_status['progress'] = 100
        print("Scan thread finalized, is_scanning=False, progress=100%")
        
        # Force a small delay to ensure UI updates
        time.sleep(0.5)

@app.route('/scan', methods=['POST'])
def scan():
    """Perform a new network scan"""
    global scan_status
    
    # Don't start a new scan if one is already in progress
    if scan_status['is_scanning']:
        # Return appropriate response based on request type
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'status': 'in_progress', 'message': 'A scan is already in progress!'}), 409
        else:
            flash('A scan is already in progress!', 'info')
            return redirect(url_for('index'))
    
    # Reset scan status
    scan_status['is_scanning'] = True
    scan_status['progress'] = 0
    scan_status['status_message'] = 'Initializing scan...'
    scan_status['devices_found'] = 0
    
    print("\n==== Starting Scan Thread ====\n")
    sys.stdout.flush()
    
    # Start scan in a background thread
    scan_thread = threading.Thread(target=scan_network_with_progress)
    scan_thread.daemon = True
    scan_thread.start()
    
    print(f"Scan thread started: {scan_thread.name}, is_alive: {scan_thread.is_alive()}")
    sys.stdout.flush()
    
    # Return JSON if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'status': 'started'})
    
    # For non-AJAX requests, just redirect without a flash message
    # since we're now handling the progress display with JavaScript
    return redirect(url_for('index'))

@app.route('/scan_status')
def get_scan_status():
    """Return the current scan status as JSON"""
    global scan_status
    
    # Create a copy of scan_status without the potentially large devices list
    # to keep the response size small for status updates
    status_copy = scan_status.copy()
    if 'last_scan_devices' in status_copy:
        del status_copy['last_scan_devices']
        
    return jsonify(status_copy)

@app.route('/trust', methods=['POST'])
def trust_device():
    """Add a device to the trusted list"""
    mac = request.form.get('mac')
    name = request.form.get('name')
    
    if not mac or not name:
        flash('MAC address and name are required!', 'danger')
        return redirect(url_for('index'))
    
    success = scanner.add_trusted_device(mac, name)
    
    if success:
        flash(f'Device {name} ({mac}) added to trusted devices!', 'success')
    else:
        flash(f'Failed to add device {mac} to trusted devices!', 'danger')
    
    return redirect(url_for('index'))

@app.route('/untrust', methods=['POST'])
def untrust_device():
    """Remove a device from the trusted list"""
    mac = request.form.get('mac')
    
    if not mac:
        flash('MAC address is required!', 'danger')
        return redirect(url_for('index'))
    
    success = scanner.remove_trusted_device(mac)
    
    if success:
        flash(f'Device {mac} removed from trusted devices!', 'success')
    else:
        flash(f'Failed to remove device {mac} from trusted devices!', 'danger')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Add disclaimer
    print("=" * 80)
    print("Wi-Fi Device Tracker / Rogue Device Detector")
    print("=" * 80)
    print("DISCLAIMER: This tool is for ethical use only.")
    print("Do not scan networks you don't own or have permission to scan.")
    print("=" * 80)
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
