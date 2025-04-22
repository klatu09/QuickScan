import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, StringVar, ttk, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import platform

# Common ports, their names, and associated vulnerabilities
PORT_VULNERABILITIES = {
    21: ("FTP", "Vulnerable to unauthorized access and man-in-the-middle attacks."),
    22: ("SSH", "Can be vulnerable to brute force attacks if weak passwords are used."),
    23: ("Telnet", "Vulnerable to eavesdropping and man-in-the-middle attacks. Should be replaced with SSH."),
    25: ("SMTP", "Vulnerable to spamming and email spoofing."),
    53: ("DNS", "Vulnerable to DNS spoofing and amplification attacks."),
    80: ("HTTP", "Vulnerable to Cross-Site Scripting (XSS) and SQL Injection."),
    110: ("POP3", "Can be vulnerable to brute force attacks and unauthorized access."),
    139: ("NetBIOS", "Can be used for network discovery and exploitation via SMB."),
    143: ("IMAP", "Can be vulnerable to brute force attacks and unauthorized access."),
    443: ("HTTPS", "Vulnerable to SSL/TLS vulnerabilities (e.g., Heartbleed)."),
    445: ("SMB", "Vulnerable to ransomware attacks and exploits like EternalBlue."),
    3306: ("MySQL", "Vulnerable to unauthorized access and SQL injection."),
    3389: ("RDP", "Vulnerable to brute force attacks and unauthorized access."),
    8080: ("HTTP-Proxy", "Vulnerable to Proxy Hijacking and Cross-Site Scripting (XSS).")
}

# For playing a sound on scan completion
def play_sound():
    try:
        if platform.system() == "Windows":
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        else:
            os.system('printf "\\a"')  # Simple beep for macOS/Linux
    except:
        pass

COMMON_PORTS = list(PORT_VULNERABILITIES.keys())

log_data = []

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                port_name, vulnerability = PORT_VULNERABILITIES.get(port, ("Unknown", "No known vulnerabilities"))
                return port, port_name, vulnerability
    except:
        pass
    return None

def start_scan(ip, mode, log_callback):
    if mode == "full":
        ports = range(1, 65536)
    elif mode == "common":
        ports = COMMON_PORTS
    else:
        ports = range(1, 1025)

    log_callback(f"\n[~] Scanning {ip} — Mode: {mode.capitalize()}", tag="info")

    open_ports = []
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result:
                port, port_name, vulnerability = result
                open_ports.append((port, port_name, vulnerability))
                log_callback(f"[+] Open port: {port} ({port_name}) - Vulnerability: {vulnerability}", tag="success")

    if not open_ports:
        log_callback(f"[!] No open ports found on {ip}.", tag="warning")

    scan_button.config(state="normal")
    save_button.config(state="normal")
    play_sound()

def run_scan():
    ip = ip_entry.get().strip()
    mode = scan_mode.get()

    if not ip:
        log_output.insert(tk.END, "[!] Please enter a valid IP address.\n", "warning")
        return

    scan_button.config(state="disabled")
    save_button.config(state="disabled")
    log_output.delete(1.0, tk.END)
    log_data.clear()

    def log_callback(msg, tag=None):
        log_data.append(msg)
        log_output.insert(tk.END, msg + "\n", tag)
        log_output.see(tk.END)

    threading.Thread(target=start_scan, args=(ip, mode, log_callback)).start()

def save_report():
    try:
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        file_path = os.path.join(desktop_path, "QuickScan_Report.txt")
        with open(file_path, "w") as file:
            file.write("\n".join(log_data))
        log_output.insert(tk.END, f"\n[✔] Report saved to Desktop: QuickScan_Report.txt\n", "info")
    except Exception as e:
        log_output.insert(tk.END, f"\n[!] Failed to save report: {e}\n", "warning")

# GUI Setup
app = tk.Tk()
app.title("QuickScan by Klatu")
app.geometry("780x530")
app.configure(bg="#1e1e1e")

style = ttk.Style()
style.configure("TButton", font=("Consolas", 12), padding=6)

title = tk.Label(app, text="QuickScan by Klatu", font=("Consolas", 22, "bold"), fg="#00ffe1", bg="#1e1e1e")
title.pack(pady=15)

input_frame = tk.Frame(app, bg="#1e1e1e")
input_frame.pack()

tk.Label(input_frame, text="Target IP:", font=("Consolas", 14), fg="#ffffff", bg="#1e1e1e").grid(row=0, column=0, padx=8)
ip_entry = tk.Entry(input_frame, width=25, font=("Consolas", 14))
ip_entry.grid(row=0, column=1)

scan_mode = StringVar(value="default")
modes = [("Default", "default"), ("Common", "common"), ("Full", "full")]
for i, (text, val) in enumerate(modes):
    tk.Radiobutton(
        input_frame, text=text, variable=scan_mode, value=val,
        font=("Consolas", 12), bg="#1e1e1e", fg="white", selectcolor="#333"
    ).grid(row=1, column=i, padx=10, pady=5)

scan_button = ttk.Button(app, text="Start Scan", command=run_scan)
scan_button.pack(pady=10)

save_button = ttk.Button(app, text="Save Report to Desktop", command=save_report, state="disabled")
save_button.pack(pady=5)

log_output = scrolledtext.ScrolledText(app, font=("Consolas", 11), width=90, height=18, bg="#111", fg="#ffffff", insertbackground='white')
log_output.pack(padx=10, pady=10)

# Log styles
log_output.tag_config("success", foreground="#00ff88")
log_output.tag_config("warning", foreground="#ffcc00")
log_output.tag_config("info", foreground="#00b7ff")

app.mainloop()
