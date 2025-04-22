import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, StringVar, ttk
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143,
    443, 445, 3306, 3389, 8080
]

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except:
        pass
    return None

def scan_host(ip, port_range, log_callback):
    open_ports = []
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in port_range]
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)
    if open_ports:
        log_callback(f"[+] {ip} Open ports: {', '.join(map(str, open_ports))}")

def start_scan(subnet, mode, log_callback):
    if mode == "full":
        port_range = range(1, 65536)
    elif mode == "common":
        port_range = COMMON_PORTS
    else:
        port_range = range(1, 1025)

    log_callback(f"\n[~] Scanning {subnet}.0/24 — Mode: {mode.capitalize()}\n")

    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        scan_host(ip, port_range, log_callback)

def run_scan():
    subnet = subnet_entry.get()
    mode = scan_mode.get()
    scan_button.config(state="disabled")
    log_output.delete(1.0, tk.END)

    def log_callback(msg):
        log_output.insert(tk.END, msg + "\n")
        log_output.see(tk.END)

    threading.Thread(target=start_scan, args=(subnet, mode, log_callback)).start()
    scan_button.config(state="normal")

# GUI setup
app = tk.Tk()
app.title("QuickScan by Klatu")
app.geometry("700x500")
app.resizable(False, False)

title = tk.Label(app, text="QuickScan by Klatu", font=("Consolas", 20, "bold"))
title.pack(pady=10)

frame = tk.Frame(app)
frame.pack()

tk.Label(frame, text="Target Subnet (e.g. 192.168.1):", font=("Consolas", 12)).grid(row=0, column=0, padx=10)
subnet_entry = tk.Entry(frame, width=25, font=("Consolas", 12))
subnet_entry.grid(row=0, column=1)

scan_mode = StringVar(value="default")
modes = [("Default", "default"), ("Common", "common"), ("Full", "full")]
for idx, (text, val) in enumerate(modes):
    tk.Radiobutton(frame, text=text, variable=scan_mode, value=val, font=("Consolas", 11)).grid(row=1, column=idx, padx=10)

scan_button = ttk.Button(app, text="Start Scan", command=run_scan)
scan_button.pack(pady=10)

log_output = scrolledtext.ScrolledText(app, font=("Courier", 10), width=85, height=20)
log_output.pack(padx=10, pady=10)

app.mainloop()
