# 📡 Wi-Fi Device Tracker & Rogue Device Detector

A Python-based cybersecurity tool to scan your local Wi-Fi network, display all connected devices, and alert you if any unknown or unauthorized devices appear on your network.

---

## ⚙️ Features

- Real-time scanning of devices on your local subnet using ARP or Nmap
- Alerts for unknown MAC addresses (rogue devices)
- Allowlist of trusted devices (editable via UI)
- Simple web dashboard (Flask) with responsive design
- Logs all scans and detection events with timestamps
- Cross-platform support (Windows, macOS, Linux)

---

## 🔧 Installation

1. **Clone the repo**
```bash
git clone https://github.com/wxmohd/wifi-device-tracker.git
cd wifi-device-tracker
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python main.py
```

4. **Access the dashboard**
Open your browser and navigate to: http://localhost:5000

---

## 📋 Usage

1. **Dashboard Overview**
   - View all connected devices on your network
   - See which devices are trusted vs. unknown
   - Check recent scan logs and alerts

2. **Managing Trusted Devices**
   - Add devices to your trusted list by clicking "Trust" next to a detected device
   - Manually add trusted devices by MAC address
   - Remove devices from trusted list as needed

3. **Scanning**
   - Click "Scan Now" to perform an immediate network scan
   - The dashboard auto-refreshes every 5 minutes

---

## 🧱 Project Structure

```
wifi-device-tracker/
├── app/
│   ├── scanner.py      # Network scanning functionality
│   ├── devices.json    # Trusted MAC allowlist
│   ├── logs.json       # Logs of all scans and alerts
│   ├── utils.py        # Helper functions
│   └── templates/
│       └── dashboard.html  # Flask UI template
├── static/
│   └── style.css       # Custom styling for UI
├── main.py             # Flask app entry point
├── requirements.txt    # Dependencies
├── README.md           # Project documentation
└── LICENSE             # MIT license
```

---

## ⚠️ Disclaimer

This tool is for **ethical use only**. Do not scan networks you don't own or have permission to scan. The authors are not responsible for any misuse of this software.

---

## 🔍 Advanced Features

- **Network Scanning Methods**: Uses Nmap for comprehensive scanning with fallback to simple ping/ARP scanning
- **Responsive UI**: Mobile-friendly dashboard that works on any device
- **Alert System**: Visual indicators for unknown devices
- **Logging**: Comprehensive logging of all scan activities

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

