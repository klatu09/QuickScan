import tkinter as tk
from tkinter import scrolledtext, filedialog
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from datetime import datetime
import threading
import winsound

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"
}

PORT_VULNERABILITIES = {
    21: "Plaintext credentials, brute-force attacks",
    22: "Brute-force, outdated encryption",
    23: "Unencrypted text, easy sniffing",
    25: "Open relay for spam",
    53: "DNS cache poisoning",
    80: "Man-in-the-middle, XSS, directory traversal",
    110: "Plaintext login, MITM",
    139: "NetBIOS info leaks",
    143: "Plaintext login",
    443: "SSL vulnerabilities if misconfigured",
    445: "WannaCry, EternalBlue",
    3306: "Unauthorized access, SQL injection",
    3389: "Brute-force, BlueKeep"
}

scanning = False
executor = None

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            result = s.connect_ex((ip, port))
            if result == 0:
                name = COMMON_PORTS.get(port, "Unknown")
                vuln = PORT_VULNERABILITIES.get(port, "General vulnerability")
                return (port, name, vuln)
    except:
        return None
    return None

def play_sound():
    winsound.Beep(800, 200)

def log_message(message, tag=None):
    log_output.insert(tk.END, message + "\n", tag)
    log_output.see(tk.END)

def start_scan(ip, mode):
    global scanning, executor
    if scanning:
        return
    scanning = True
    status_label.config(text="🔍 Scanning...")
    log_output.delete('1.0', tk.END)
    scan_button.config(state="disabled")
    cancel_button.config(state="normal")
    save_button.config(state="disabled")
    progress_bar["value"] = 0

    if mode == "full":
        ports = range(1, 65536)
    elif mode == "common":
        ports = COMMON_PORTS.keys()
    else:
        ports = range(1, 1025)

    total_ports = len(ports)
    progress_step = 100 / total_ports

    def run():
        nonlocal ports
        open_ports = []
        executor = ThreadPoolExecutor(max_workers=200)
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        completed = 0
        for future in as_completed(futures):
            if not scanning:
                break
            result = future.result()
            if result:
                port, name, vuln = result
                open_ports.append(result)
                log_message(f"[+] Open port: {port} ({name}) - Vulnerability: {vuln}", "success")
            completed += 1
            progress_bar["value"] = progress_step * completed

        if not open_ports and scanning:
            log_message("[!] No open ports found.", "warning")
            status_label.config(text="⚠️ No open ports found.")
        elif scanning:
            status_label.config(text="✅ Scan complete!")

        scan_button.config(state="normal")
        cancel_button.config(state="disabled")
        save_button.config(state="normal")
        play_sound()
        scanning = False

    threading.Thread(target=run).start()

def stop_scan():
    global scanning
    scanning = False
    status_label.config(text="❌ Scan canceled.")
    scan_button.config(state="normal")
    cancel_button.config(state="disabled")
    save_button.config(state="normal")
    log_message("[X] Scan canceled by user.", "warning")

def save_report():
    desktop = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    filename = f"QuickScan_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(desktop, filename)
    with open(filepath, 'w') as f:
        f.write(log_output.get('1.0', tk.END))
    log_message(f"[✔] Report saved to Desktop as {filename}", "info")
    play_sound()

# GUI setup
app = tk.Tk()
app.title("QuickScan by Klatu")
app.geometry("850x650")
app.configure(bg="#1e1e1e")

# Terminal-style background animation
bg_text = tk.Label(app, text="QUICKSCAN BY KLATU", font=("Consolas", 26, "bold"),
                   fg="#00ffcc", bg="#1e1e1e")
bg_text.pack(pady=10)

entry_label = tk.Label(app, text="Target IP Address:", font=("Consolas", 12), bg="#1e1e1e", fg="white")
entry_label.pack()
ip_entry = tk.Entry(app, font=("Consolas", 14), width=30, bg="#111", fg="white", insertbackground='white')
ip_entry.pack(pady=5)

# Mode toggle
mode_var = tk.StringVar(value="common")
tk.Radiobutton(app, text="Common Ports", variable=mode_var, value="common", bg="#1e1e1e", fg="white", selectcolor="#111").pack()
tk.Radiobutton(app, text="Top 1024", variable=mode_var, value="top", bg="#1e1e1e", fg="white", selectcolor="#111").pack()
tk.Radiobutton(app, text="Full Range (1-65535)", variable=mode_var, value="full", bg="#1e1e1e", fg="white", selectcolor="#111").pack()

# Status label
status_label = tk.Label(app, text="", font=("Consolas", 12), fg="#00b7ff", bg="#1e1e1e")
status_label.pack(pady=5)

# Log output area
log_output = scrolledtext.ScrolledText(app, font=("Consolas", 11), width=100, height=18, bg="#111", fg="#ffffff", insertbackground='white')
log_output.tag_config("success", foreground="#00ff00")
log_output.tag_config("warning", foreground="#ffaa00")
log_output.tag_config("info", foreground="#00b7ff")
log_output.pack(padx=10, pady=10)

# Progress bar
progress_bar = tk.ttk.Progressbar(app, length=600, mode="determinate")
progress_bar.pack(pady=10)

# Buttons
button_frame = tk.Frame(app, bg="#1e1e1e")
button_frame.pack()

scan_button = tk.Button(button_frame, text="Start Scan", command=lambda: start_scan(ip_entry.get(), mode_var.get(), ), font=("Consolas", 12), bg="#00b7ff", fg="white", width=15)
scan_button.grid(row=0, column=0, padx=10)

cancel_button = tk.Button(button_frame, text="Cancel", command=stop_scan, font=("Consolas", 12), bg="#ff5555", fg="white", width=15, state="disabled")
cancel_button.grid(row=0, column=1, padx=10)

save_button = tk.Button(button_frame, text="Save Report", command=save_report, font=("Consolas", 12), bg="#66cc66", fg="white", width=15, state="disabled")
save_button.grid(row=0, column=2, padx=10)

app.mainloop()
