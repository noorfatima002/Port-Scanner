import tkinter as tk
from tkinter import messagebox
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime


def scan_port(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            return port, "OPEN"
        return port, "CLOSED"

    except socket.timeout:
        return port, "TIMEOUT"

    except Exception as error:
        return port, f"ERROR: {error}"


def run_scan():
    target = target_entry.get().strip()

    try:
        start_port = int(start_entry.get())
        end_port = int(end_entry.get())
    except ValueError:
        window.after(
            0,
            lambda: messagebox.showerror(
                "Invalid Input",
                "Please enter valid port numbers."
            )
        )
        return

    if not target:
        window.after(
            0,
            lambda: messagebox.showerror(
                "Invalid Target",
                "Please enter a target host."
            )
        )
        return

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        window.after(
            0,
            lambda: messagebox.showerror(
                "Invalid Range",
                "Enter a valid range from 1 to 65535."
            )
        )
        return

    results_box.delete("1.0", tk.END)
    results_box.insert(tk.END, f"Target: {target}\n")
    results_box.insert(tk.END, "Starting TCP scan...\n")
    results_box.insert(tk.END, "-" * 50 + "\n")

    scan_button.config(state=tk.DISABLED)
    status_label.config(text="Scanning...")

    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(
            executor.map(
                lambda port: scan_port(target, port),
                ports
            )
        )

    log_lines = []

    for port, status in results:
        line = f"Port {port}: {status}"
        log_lines.append(line)

        window.after(
            0,
            lambda text=line: results_box.insert(
                tk.END, text + "\n"
            )
        )

    with open("scan_results.txt", "a") as file:
        file.write("\n")
        file.write("=" * 50 + "\n")
        file.write(f"Scan Time: {datetime.now()}\n")
        file.write(f"Target: {target}\n")
        file.write("-" * 50 + "\n")

        for line in log_lines:
            file.write(line + "\n")

        file.write("Scan completed.\n")

    window.after(
        0,
        lambda: results_box.insert(
            tk.END,
            "-" * 50 +
            "\nScan completed!\n"
            "Results saved in scan_results.txt\n"
        )
    )

    window.after(
        0,
        lambda: scan_button.config(state=tk.NORMAL)
    )

    window.after(
        0,
        lambda: status_label.config(text="Scan completed")
    )


def start_scan():
    threading.Thread(
        target=run_scan,
        daemon=True
    ).start()


def clear_results():
    results_box.delete("1.0", tk.END)
    status_label.config(text="Ready")


# ---------------- MAIN WINDOW ----------------

window = tk.Tk()
window.title("TCP Port Scanner")
window.geometry("700x650")
window.resizable(False, False)

# Title
title = tk.Label(
    window,
    text="TCP PORT SCANNER",
    font=("Arial", 24, "bold")
)
title.pack(pady=20)

subtitle = tk.Label(
    window,
    text="Network Security & Port Analysis Tool",
    font=("Arial", 11)
)
subtitle.pack(pady=2)


# Target
tk.Label(
    window,
    text="Target Host",
    font=("Arial", 11, "bold")
).pack(pady=(20, 3))

target_entry = tk.Entry(
    window,
    width=45,
    font=("Arial", 11)
)
target_entry.pack()
target_entry.insert(0, "127.0.0.1")


# Start Port
tk.Label(
    window,
    text="Start Port",
    font=("Arial", 11, "bold")
).pack(pady=(15, 3))

start_entry = tk.Entry(
    window,
    width=20,
    font=("Arial", 11)
)
start_entry.pack()
start_entry.insert(0, "80")


# End Port
tk.Label(
    window,
    text="End Port",
    font=("Arial", 11, "bold")
).pack(pady=(15, 3))

end_entry = tk.Entry(
    window,
    width=20,
    font=("Arial", 11)
)
end_entry.pack()
end_entry.insert(0, "85")


# Buttons
button_frame = tk.Frame(window)
button_frame.pack(pady=20)

scan_button = tk.Button(
    button_frame,
    text="START SCAN",
    command=start_scan,
    font=("Arial", 11, "bold"),
    width=15
)
scan_button.grid(row=0, column=0, padx=8)

clear_button = tk.Button(
    button_frame,
    text="CLEAR RESULTS",
    command=clear_results,
    font=("Arial", 11, "bold"),
    width=15
)
clear_button.grid(row=0, column=1, padx=8)


# Status
status_label = tk.Label(
    window,
    text="Ready",
    font=("Arial", 11, "bold")
)
status_label.pack(pady=5)


# Results
tk.Label(
    window,
    text="Scan Results",
    font=("Arial", 12, "bold")
).pack(pady=(10, 5))

results_box = tk.Text(
    window,
    width=75,
    height=17,
    font=("Consolas", 10)
)
results_box.pack(padx=15, pady=5)


window.mainloop()