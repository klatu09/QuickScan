import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, StringVar, ttk
import os
import platform
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

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

COMMON_PORTS = list(PORT_VULNERABILITIES.keys())

log_data = []
scanning = False
scan_thread = None
cancel_event = threading.Event()  # Event to signal scan cancellation

def play_sound():
    try:
        if platform.system() == "Windows":
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        else:
            os.system('printf "\a"')  # Simple beep for macOS/Linux
    except:
        pass

def scan_port(ip, port, cancel_event):
    if cancel_event.is_set():
        return None  # Immediately return None if the cancel event is set

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

def cancel_scan():
    global scanning
    if scanning:
        cancel_event.set()  # Signal the scan thread to stop
        scanning = False  # Set scanning flag to False so the scan thread can terminate gracefully

        # Update the UI immediately to reflect the cancellation
        cancel_button.config(state="disabled")  # Disable the cancel button during cancellation
        save_button.config(state="normal")  # Enable the save button once the scan is canceled
        log_callback("\n[!] Scan canceled.", "warning")  # Log the cancellation
        progress_bar["value"] = 0  # Reset the progress bar to 0

        # Allow the GUI to remain responsive
        app.update_idletasks()
    else:
        # Reset UI for a new scan if no scan is active
        ip_entry.delete(0, tk.END)  # Clear the IP entry field
        scan_button.config(state="normal")  # Enable the start scan button
        cancel_button.config(state="disabled")  # Disable the cancel button
        save_button.config(state="disabled")  # Disable the save button
        clear_button.config(state="normal")  # Enable the clear log button
        log_output.delete(1.0, tk.END)  # Clear the log output
        log_data.clear()  # Clear the log data
        progress_bar["value"] = 0  # Reset the progress bar to 0

def start_scan(ip, mode, log_callback, progress_callback, time_callback):
    global scanning
    try:
        start_time = time.time()

        if mode == "full":
            ports = range(1, 65536)
        elif mode == "common":
            ports = COMMON_PORTS
        else:
            ports = range(1, 1025)

        log_callback(f"\n[~] Scanning {ip} — Mode: {mode.capitalize()}", tag="info")

        open_ports = []
        total_ports = len(ports)

        with ThreadPoolExecutor(max_workers=200) as executor:
            futures = [executor.submit(scan_port, ip, port, cancel_event) for port in ports]
            for i, future in enumerate(as_completed(futures)):
                if cancel_event.is_set():
                    log_callback(f"[!] Scan canceled.\n", tag="warning")
                    return

                result = future.result()
                if result:
                    port, port_name, vulnerability = result
                    open_ports.append((port, port_name, vulnerability))
                    log_callback(f"[+] Open port: {port} ({port_name}) - Vulnerability: {vulnerability}", tag="success")
                progress_callback((i + 1) / total_ports * 100)

        elapsed_time = time.time() - start_time
        minutes, seconds = divmod(int(elapsed_time), 60)
        time_callback(f"Scan completed in {minutes}m {seconds}s")

        if not open_ports:
            log_callback(f"[!] No open ports found on {ip}.", tag="warning")

    finally:
        # Ensure scanning is reset even if an exception occurs
        scanning = False
        scan_button.config(state="normal")
        cancel_button.config(state="disabled")
        save_button.config(state="normal")
        play_sound()

def run_scan():
    global scanning, scan_thread
    if scanning:
        log_callback("[!] A scan is already running.", "warning")
        return

    ip = ip_entry.get().strip()
    mode = scan_mode.get()

    try:
        ip_type = "IPv6" if ":" in ipaddress.ip_address(ip).compressed else "IPv4"
        log_callback(f"[✔] Valid {ip_type} address detected.", "info")
    except ValueError:
        log_callback("[!] Invalid IP address.", "warning")
        return

    scan_button.config(state="disabled")
    cancel_button.config(state="normal")
    save_button.config(state="disabled")
    progress_bar["value"] = 0
    log_output.delete(1.0, tk.END)
    log_data.clear()

    def progress_callback(percent):
        progress_bar["value"] = percent
        progress_bar.update_idletasks()

    def time_callback(duration):
        log_callback(f"[✔] {duration}", "info")

    cancel_event.clear()  # Clear the cancel event before starting the scan
    scanning = True  # Set scanning flag to True
    scan_thread = threading.Thread(target=start_scan, args=(ip, mode, log_callback, progress_callback, time_callback))
    scan_thread.start()

def save_report():
    try:
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        file_path = os.path.join(desktop_path, "QuickScan_Report.txt")
        with open(file_path, "w") as file:
            file.write("\n".join(log_data))
        log_callback(f"\n[✔] Report saved to Desktop: QuickScan_Report.txt", "info")
    except Exception as e:
        log_callback(f"\n[!] Failed to save report: {e}", "warning")

def clear_log():
    log_output.delete(1.0, tk.END)
    log_data.clear()

# Function to log messages to the log_output widget
def log_callback(message, tag="info"):
    log_output.insert(tk.END, message + "\n", tag)
    log_output.see(tk.END)
    log_data.append(message)

# GUI Setup
app = tk.Tk()
app.title("QuickScan by Klatu")
app.geometry("840x600")
app.configure(bg="#1e1e1e")

# Title - Subtle and placed in the upper left
title = tk.Label(app, text="QuickScan by Klatu", font=("Roboto", 12), fg="#888888", bg="#1e1e1e")
title.place(x=10, y=10)

bg_canvas = tk.Canvas(app, width=840, height=600, bg="#1e1e1e", highlightthickness=0)
bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)

input_frame = tk.Frame(app, bg="#1e1e1e")
input_frame.place(relx=0.5, rely=0.15, anchor="center")

tk.Label(input_frame, text="Target IP:", font=("Roboto", 14), fg="#ffffff", bg="#1e1e1e").grid(row=0, column=0, padx=8)
ip_entry = tk.Entry(input_frame, width=25, font=("Roboto", 14), relief="flat")
ip_entry.grid(row=0, column=1)

# Modes with port numbers displayed
scan_mode = StringVar(value="default")
modes = [
    ("Default (1-1024)", "default"),
    ("Common (21,22,23,80,443, etc.)", "common"),
    ("Full (1-65535)", "full")
]
for i, (text, val) in enumerate(modes):
    tk.Radiobutton(
        input_frame, text=text, variable=scan_mode, value=val,
        font=("Roboto", 12), bg="#1e1e1e", fg="white", selectcolor="#333"
    ).grid(row=1, column=i, padx=10, pady=5)

# Log output
log_output = scrolledtext.ScrolledText(app, width=90, height=15, font=("Courier New", 12, "bold"), wrap=tk.WORD, bg="#2e2e2e", fg="white")
log_output.place(relx=0.5, rely=0.5, anchor="center")

# Configure tags for colored logs
log_output.tag_config("info", foreground="lightblue")  # Info messages in light blue
log_output.tag_config("success", foreground="green")  # Success messages in green
log_output.tag_config("warning", foreground="orange")  # Warning messages in orange
log_output.tag_config("error", foreground="red")  # Error messages in red

# Buttons Frame (Horizontal alignment)
button_frame = tk.Frame(app, bg="#1e1e1e")
button_frame.place(relx=0.5, rely=0.75, anchor="center")

# Start Scan button
scan_button = tk.Button(button_frame, text="Start Scan", font=("Roboto", 12), command=run_scan, width=15)
scan_button.grid(row=0, column=0, padx=10)

# Cancel Scan button
cancel_button = tk.Button(button_frame, text="Cancel Scan", font=("Roboto", 12), command=cancel_scan, width=15, state="disabled")
cancel_button.grid(row=0, column=1, padx=10)

# Save Report button
save_button = tk.Button(button_frame, text="Save Report in txt", font=("Roboto", 12), command=save_report, width=15, state="disabled")
save_button.grid(row=0, column=2, padx=10)

# Clear Log button
clear_button = tk.Button(button_frame, text="Clear Log", font=("Roboto", 12), command=clear_log, width=15)
clear_button.grid(row=0, column=3, padx=10)

# Progress bar
progress_bar = ttk.Progressbar(app, mode="determinate", length=400, style="TProgressbar")
progress_bar.place(relx=0.5, rely=0.25, anchor="center")

# Start the application
app.mainloop()