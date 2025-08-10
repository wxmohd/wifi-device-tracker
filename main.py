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

# Global variables
scan_status = {
    'is_scanning': False,
    'progress': 0,
    'status_message': '',
    'devices_found': 0,
    'last_scan_devices': []  # Store the most recent scan results
}

# Global event to signal scan thread to stop
scan_stop_event = threading.Event()

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
    """Run network scan in a background thread and update progress"""
    global scan_status, scan_stop_event
    
    print("\n==== Scan Thread Started ====\n")
    print(f"Thread ID: {threading.current_thread().ident}")
    sys.stdout.flush()
    
    # Reset stop event
    scan_stop_event.clear()
    
    # Create an event to signal when scanning is complete
    scan_complete_event = threading.Event()
    
    # Define the progress update thread function
    def update_progress_thread():
        """Thread to update progress incrementally while scanning"""
        try:
            # Define scan phases with faster progression
            phases = [
                {"start": 10, "end": 30, "step": 5, "delay": 0.3, "message": "Initializing scanner"},
                {"start": 30, "end": 60, "step": 5, "delay": 0.2, "message": "Detecting devices"},
                {"start": 60, "end": 90, "step": 5, "delay": 0.2, "message": "Analyzing connections"}
            ]
            
            print("Progress update thread started - faster version")
            sys.stdout.flush()
            
            # Loop through each phase
            for phase in phases:
                # Skip if scan is already complete
                if scan_complete_event.is_set() or not scan_status['is_scanning'] or scan_stop_event.is_set():
                    break
                    
                # Update progress through this phase
                for progress in range(phase['start'], phase['end'], phase['step']):
                    scan_status['progress'] = progress
                    scan_status['status_message'] = f"{phase['message']}"
                    print(f"Progress updated to {progress}% - {phase['message']}")
                    sys.stdout.flush()
                    
                    # Small delay between updates
                    time.sleep(phase['delay'])
                    
                    # Break the loop if scan is complete
                    if scan_complete_event.is_set() or not scan_status['is_scanning'] or scan_stop_event.is_set():
                        break
            
            print("Progress update thread finished")
            sys.stdout.flush()
        except Exception as e:
            print(f"Error in progress update thread: {e}")
            sys.stdout.flush()
    
    try:
        # Initialize scanner
        scanner = AutoTrustScanner()
        scan_status['progress'] = 10
        scan_status['status_message'] = 'Scanner initialized'
        print("Scanner initialized, progress set to 10%")
        sys.stdout.flush()
        
        # Start progress update thread
        progress_thread = threading.Thread(target=update_progress_thread)
        progress_thread.daemon = True
        progress_thread.start()
        
        # Start the scan
        scan_status['status_message'] = 'Scanning network...'
        scan_status['progress'] = 30
        print("Starting network scan, progress set to 30%")
        sys.stdout.flush()
        
        # Run the scan with a timeout
        start_time = time.time()
        max_scan_time = 60  # Maximum scan time in seconds
        
        # Run the scan
        devices = scanner.scan_network()
        
        # Check if scan took too long
        if time.time() - start_time > max_scan_time:
            print("Scan took too long, showing partial results")
            scan_status['status_message'] = 'Scan took too long, showing partial results'
        
        # Signal that the scan is complete to stop the progress thread
        scan_complete_event.set()
        
        # Process results
        scan_status['status_message'] = 'Processing scan results...'
        scan_status['progress'] = 85
        print("Main thread setting progress to 85%")
        sys.stdout.flush()
        
        scan_status['devices_found'] = len(devices)
        
        # Print devices for debugging
        print(f"Devices found ({len(devices)}):")  
        for device in devices:
            print(f"  - {device.get('ip')} | {device.get('mac')} | {device.get('name')}")
        sys.stdout.flush()
        
        # Store the devices in the scan_status for immediate display
        try:
            scan_status['last_scan_devices'] = devices
            print("Successfully stored devices in scan_status")
            sys.stdout.flush()
            
            # Update progress to 90%
            scan_status['progress'] = 90
            print("Progress updated to 90%")
            sys.stdout.flush()
        except Exception as e:
            print(f"Error storing devices in scan_status: {e}")
            sys.stdout.flush()
        
        # Log results
        try:
            scan_status['status_message'] = 'Logging scan results...'
            scan_status['progress'] = 95
            print("Logging scan results, progress at 95%")
            sys.stdout.flush()
            scanner.log_scan_results(devices)
            print("Successfully logged scan results")
            sys.stdout.flush()
        except Exception as e:
            print(f"Error logging scan results: {e}")
            sys.stdout.flush()
        
        # Complete - ensure is_scanning is set to False BEFORE setting progress to 100%
        try:
            scan_status['status_message'] = 'Scan complete!'
            sys.stdout.flush()
            
            # Set is_scanning to False first
            scan_status['is_scanning'] = False
            print("Set is_scanning to False")
            sys.stdout.flush()
            
            # Set stop event to prevent any further scanning
            scan_stop_event.set()
            print("Set scan_stop_event to prevent auto-restart")
            sys.stdout.flush()
            
            # Small delay to ensure status update is processed
            time.sleep(0.2)
            
            # Then set progress to 100%
            scan_status['progress'] = 100
            print("Set progress to 100%")
            sys.stdout.flush()
            
            print("Scan complete, progress at 100%, is_scanning set to False")
            sys.stdout.flush()
        except Exception as e:
            print(f"Error updating final scan status: {e}")
            sys.stdout.flush()
            # Even if there's an error, make sure to set these values
            scan_status['is_scanning'] = False
        
    except Exception as e:
        print(f"Exception in scan thread: {e}")
        sys.stdout.flush()
        scan_status['status_message'] = f'Error during scan: {str(e)}'
        scan_status['is_scanning'] = False
        scan_status['progress'] = 100
        print("Scan error handled, is_scanning=False, progress=100%")
        sys.stdout.flush()
    finally:
        # Always ensure scan status is properly reset
        if scan_status['is_scanning'] or scan_status['progress'] < 100:
            print("Forcing scan completion in finally block")
            sys.stdout.flush()
            scan_status['is_scanning'] = False
            scan_status['progress'] = 100
            print("Scan thread finalized, is_scanning=False, progress=100%")
            sys.stdout.flush()

@app.route('/scan', methods=['POST'])
def scan():
    """Perform a new network scan"""
    global scan_status, scan_stop_event
    
    # Stop any existing scan that might be running
    scan_stop_event.set()
    time.sleep(0.5)  # Give any running scan thread time to stop
    
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
    scan_status['scan_start_time'] = time.time()  # Track when the scan started
    
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
    
    # Check if scan has been running too long (more than 30 seconds)
    if scan_status['is_scanning'] and 'scan_start_time' in scan_status:
        elapsed_time = time.time() - scan_status['scan_start_time']
        if elapsed_time > 30:  # Force completion after 30 seconds
            print(f"Scan has been running for {elapsed_time:.1f} seconds, forcing completion")
            scan_status['is_scanning'] = False
            scan_status['progress'] = 100
            scan_status['status_message'] = 'Scan completed (timeout)'
            scan_stop_event.set()  # Signal any running scan threads to stop
    
    return jsonify(scan_status)

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
