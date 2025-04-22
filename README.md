# 🔍 QuickScan

**QuickScan** is a lightweight, Python-based tool developed by **Klatu** for scanning all devices on your local network and detecting open ports (1–1024) on each. It’s a fast and portable alternative to heavier scanners, perfect for quick diagnostics, auditing, or recon.

## 🚀 Features

- 🔎 Scans an entire local subnet (e.g., 192.168.1.0/24)
- 🛠️ Checks **ports 1–1024** (well-known/common ports) for every host
- ⚡ High-speed scanning using multithreading
- 💻 Lightweight and can be compiled into a standalone `.exe` or binary

## 🧰 Requirements

- Python 3.x
- No external libraries needed (`socket`, `concurrent.futures` are built-in)

## 🛠️ How to Use

### Option 1: Run from Python
1. Clone the repository:
   - git clone https://github.com/yourusername/quickscan-by-klatu.git
   - cd quickscan-by-klatu
   
2. Run the script
   - python quickscan.py


### Option 2: Create a Standalone Executable
1. pip install pyinstaller
2. pyinstaller --onefile quickscan.py

- Just double-click it (Windows)


## 🔐 Legal Disclaimer
- This tool is intended for educational and authorized auditing purposes only. Unauthorized scanning may be illegal. Use responsibly.


## 📄 License
MIT License — feel free to use, modify, and share!

