import customtkinter as ctk
import requests
import threading
import time
import json
import concurrent.futures
from tkinter import ttk
import tkinter as tk
from tkinter import filedialog, messagebox
import re
import ipaddress
import subprocess

# --- Configuration & Theme ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class GravityDNSHunter(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Who's This DNS!")
        self.geometry("900x700")

        self.target_list = []
        self.results = []
        self.is_scanning = False
        self.scan_thread = None
        self.stop_event = threading.Event()

        self._init_ui()

    def _init_ui(self):
        # --- Theme Colors ---
        self.col_bg = "#212121"      # Darker Background
        self.col_panel = "#2b2b2b"   # Panel Gray
        self.col_accent = "#6c5ce7"  # Purple
        self.col_accent_hover = "#5f27cd"
        self.col_text = "#dfe6e9"
        
        # Main Layout
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.configure(fg_color=self.col_bg)

        # --- Header ---
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, sticky="ew", padx=30, pady=(20, 10))
        
        title = ctk.CTkLabel(self.header_frame, text="GRAVITY SCANNER", 
                             font=("Roboto Medium", 24), text_color=self.col_text)
        title.pack(side="left")
        
        subtitle = ctk.CTkLabel(self.header_frame, text="  |  Latency & Speed Probe", 
                                font=("Roboto", 14), text_color="gray")
        subtitle.pack(side="left", pady=(8,0))

        # --- Controls Bar ---
        self.controls_frame = ctk.CTkFrame(self, fg_color=self.col_panel, corner_radius=10)
        self.controls_frame.grid(row=1, column=0, sticky="ew", padx=30, pady=10)
        self.controls_frame.grid_columnconfigure(1, weight=0) # Spacer
        self.controls_frame.grid_columnconfigure(3, weight=1) # Entry expands
        
        # Source Selection
        self.source_var = ctk.StringVar(value="web")
        self.source_var.trace_add("write", self.on_source_change)
        
        # Modern Radio Buttons
        self.radio_web = ctk.CTkRadioButton(self.controls_frame, text="Web Public List", 
                                            variable=self.source_var, value="web",
                                            fg_color=self.col_accent, hover_color=self.col_accent_hover)
        self.radio_web.grid(row=0, column=0, padx=20, pady=15)
        
        self.radio_file = ctk.CTkRadioButton(self.controls_frame, text="Local File (.txt)", 
                                             variable=self.source_var, value="file",
                                             fg_color=self.col_accent, hover_color=self.col_accent_hover)
        self.radio_file.grid(row=0, column=1, padx=20, pady=15)

        # File Entry (Dynamic)
        self.file_path_entry = ctk.CTkEntry(self.controls_frame, placeholder_text="Path to file...", 
                                            fg_color="#1e1e1e", border_color="#444", text_color="white")
        self.browse_btn = ctk.CTkButton(self.controls_frame, text="Browse", width=80, 
                                        fg_color="#444", hover_color="#555", command=self.browse_file)
        
        # Start Button
        self.action_btn = ctk.CTkButton(self.controls_frame, text="START SCAN", 
                                        font=("Roboto", 14, "bold"),
                                        fg_color=self.col_accent, hover_color=self.col_accent_hover,
                                        height=36, command=self.on_start_stop)
        self.action_btn.grid(row=0, column=5, padx=20, pady=15)

        # Status below controls? Or integrated?
        # Let's put status in the footer to keep it clean, or a small text below title.
        
        # --- Progress Bar (Slim) ---
        self.progress_bar = ctk.CTkProgressBar(self, height=4, progress_color=self.col_accent)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=2, column=0, sticky="ew", padx=0, pady=0)
        # Hidden initially or just empty?
        self.progress_bar.grid_forget()

        # --- Results Table ---
        self.tree_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.tree_frame.grid(row=3, column=0, sticky="nsew", padx=30, pady=(10, 20))
        self.tree_frame.grid_columnconfigure(0, weight=1)
        self.tree_frame.grid_rowconfigure(0, weight=1)

        # Custom TTK Style for Treeview
        style = ttk.Style()
        style.theme_use("clam")
        
        bg_color = self.col_panel
        header_bg = "#4834d4" # Brighter Deep Purple
        header_fg = "white"
        select_bg = "#0984e3" # Blue
        
        style.configure("Treeview", 
                        background=bg_color, 
                        foreground="white", 
                        fieldbackground=bg_color,
                        borderwidth=0,
                        rowheight=30,
                        font=("Roboto", 11))
                        
        style.configure("Treeview.Heading", 
                        background=header_bg, 
                        foreground=header_fg, 
                        borderwidth=0,
                        font=("Roboto", 12, "bold"))
        
        style.map("Treeview", 
                  background=[("selected", select_bg)], 
                  foreground=[("selected", "white")])
        style.map("Treeview.Heading", background=[("active", "#686de0")])

        columns = ("ip", "latency", "down", "up")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings", selectmode="browse")
        
        self.tree.heading("ip", text="  Target IP", anchor="w")
        self.tree.heading("latency", text="Latency", anchor="center")
        self.tree.heading("down", text="Download", anchor="center")
        self.tree.heading("up", text="Upload", anchor="center")
        
        self.tree.column("ip", width=250, anchor="w")
        self.tree.column("latency", width=120, anchor="center")
        self.tree.column("down", width=150, anchor="center")
        self.tree.column("up", width=150, anchor="center")

        # Tags
        self.tree.tag_configure("error", foreground="#636e72")
        self.tree.tag_configure("good", foreground="#00d2d3") # Cyan
        self.tree.tag_configure("fast", foreground="#a29bfe") # Light Purple

        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.current_row = 1

        # --- Footer ---
        self.footer_frame = ctk.CTkFrame(self, height=40, fg_color=self.col_panel, corner_radius=0)
        self.footer_frame.grid(row=4, column=0, sticky="ew")
        
        self.status_label = ctk.CTkLabel(self.footer_frame, text="Ready to Scan", text_color="gray", font=("Roboto", 12))
        self.status_label.pack(side="left", padx=30, pady=8)
        
        self.count_label = ctk.CTkLabel(self.footer_frame, text="Scanned: 0  |  Success: 0", font=("Roboto", 12, "bold"))
        self.count_label.pack(side="left", padx=20)
        
        self.export_btn = ctk.CTkButton(self.footer_frame, text="Export Best IPs", 
                                        width=120, height=28,
                                        fg_color="#0984e3", hover_color="#00cec9",
                                        command=self.export_json)
        self.export_btn.pack(side="right", padx=30, pady=8)
        
        # Initial UI state (Run once)
        self.on_source_change()

    def on_source_change(self, *args):
        mode = self.source_var.get()
        # Clean up old data status
        self.target_list = []
        self.results = []
        self.status_label.configure(text=f"Mode: {mode.upper()} selected.")
        
        if mode == "file":
            self.file_path_entry.grid(row=0, column=2, padx=10, sticky="ew")
            self.browse_btn.grid(row=0, column=3, padx=10)
        else:
            self.file_path_entry.grid_forget()
            self.browse_btn.grid_forget()

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filename:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, filename)
            self.source_var.set("file")
            self.load_file(filename)

    def toggle_source(self):
        # Deprecated by on_source_change
        pass

    def load_file(self, path):
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
            
            self.target_list = []
            for line in lines:
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', line)
                if match:
                    found_str = match.group(1)
                    if '/' in found_str:
                        try:
                            net = ipaddress.ip_network(found_str, strict=False)
                            for ip in net.hosts():
                                self.target_list.append(str(ip))
                        except ValueError:
                            pass
                    else:
                        self.target_list.append(found_str)
            
            self.status_label.configure(text=f"Loaded {len(self.target_list)} unique targets.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def fetch_web_list(self):
        try:
            self.status_label.configure(text="Downloading target list...")
            self.update_idletasks()
            
            url = "https://public-dns.info/nameservers.txt" 
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            
            lines = resp.text.splitlines()
            self.target_list = []
            for line in lines:
                parts = line.split() 
                if parts:
                    ip = parts[0]
                    if ip.count('.') == 3: 
                        self.target_list.append(ip)
            
            # Limit
            if len(self.target_list) > 2000:
                self.target_list = self.target_list[:2000]
                
            self.status_label.configure(text=f"Fetched {len(self.target_list)} targets from web.")
        except Exception as e:
            messagebox.showerror("Error", f"Fetch failed: {e}")
            self.target_list = []

    def on_start_stop(self):
        if self.is_scanning:
            self.stop_event.set()
            self.status_label.configure(text="Stopping scan...")
            self.action_btn.configure(text="Stopping...", state="disabled")
        else:
            if self.source_var.get() == "web" and not self.target_list:
                 self.fetch_web_list()
            
            if not self.target_list:
                messagebox.showwarning("Empty", "No targets to scan.")
                return

            self.is_scanning = True
            self.stop_event.clear()
            self.action_btn.configure(text="STOP", fg_color="#d63031", hover_color="#c0392b") # Red
            self.progress_bar.grid(row=2, column=0, sticky="ew") # Show progress bar
            
            self.results = []
            for item in self.tree.get_children():
                self.tree.delete(item)
            self.count_label.configure(text="Scanned: 0  |  Success: 0")

            self.scan_thread = threading.Thread(target=self.run_scan_loop, daemon=True)
            self.scan_thread.start()

    def run_scan_loop(self):
        total = len(self.target_list)
        max_workers = 50 
        
        self.completed_count = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(self.check_host, ip) for ip in self.target_list]
            
            for future in concurrent.futures.as_completed(futures):
                if self.stop_event.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                try:
                    res = future.result()
                    self.after(0, self.update_progress, res, total)
                except Exception:
                    pass

        self.after(0, self.finish_scan)

    def check_host(self, ip):
        # 1. Latency & Download
        result = {
            "ip": ip,
            "latency": 9999,
            "down_speed": 0.0,
            "up_speed": 0.0,
            "status": "error"
        }
        
        # --- 1. ICMP Ping (Raw Latency) ---
        try:
            # Hide console window
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            # Windows ping: -n 1 (count), -w 1000 (timeout ms)
            proc = subprocess.Popen(
                ['ping', '-n', '1', '-w', '1000', ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                startupinfo=startupinfo,
                text=True
            )
            stdout, _ = proc.communicate()
            
            if proc.returncode == 0:
                # Parse "time=14ms" or "time<1ms"
                match = re.search(r"time[=<](\d+)", stdout, re.IGNORECASE)
                if match:
                    result["latency"] = int(match.group(1))
                else:
                    # Sometimes it says "time<1ms", regex catches digit '1'
                    result["latency"] = 1
        except Exception:
            pass # Keep 9999 if failed
            
        # --- 2. Speed Test (HTTP) ---
        # Even if Ping blocked, HTTP might open
        url = f"http://{ip}"
        try:
             # Connect & Download
            try:
                # If ping failed (9999), we can calculate HTTP connect latency as fallback
                start_time = time.time()
                
                resp = requests.get(url, stream=True, timeout=2)
                
                # Use HTTP latency if ICMP failed
                if result["latency"] == 9999:
                    http_lat = (time.time() - start_time) * 1000
                    result["latency"] = int(http_lat)
                
                # Download (1MB max or 1.5s)
                downloaded_bytes = 0
                dl_start = time.time()
                for chunk in resp.iter_content(chunk_size=4096):
                    downloaded_bytes += len(chunk)
                    if downloaded_bytes > 1024 * 1024: break
                    if time.time() - dl_start > 1.5: break
                
                dl_time = time.time() - dl_start
                if dl_time > 0 and downloaded_bytes > 0:
                    mb = downloaded_bytes / (1024 * 1024)
                    result["down_speed"] = round(mb / dl_time, 2)

                # Upload (512KB)
                try:
                    data = b"0" * (512 * 1024) 
                    ul_start = time.time()
                    requests.post(url, data=data, timeout=2)
                    ul_time = time.time() - ul_start
                    if ul_time > 0:
                         mb = len(data) / (1024 * 1024)
                         result["up_speed"] = round(mb / ul_time, 2)
                except:
                    pass 
                
                # Status determination
                if result["down_speed"] > 0 or result["up_speed"] > 0:
                     result["status"] = "good"
                     if result["down_speed"] > 1.0: result["status"] = "fast"
                
                # If we got a response but speed is 0 (e.g. valid empty page), mark good if latency is good
                if result["status"] == "error" and result["latency"] < 9999:
                    # It's up, just no speed
                    # But user wanted "ping AND up/down speed" for export
                    # We'll leave it as error/gray visually unless it has properties
                    # Actually, if ping is UP, let's at least mark it good so it's cyan
                    result["status"] = "good"

            except Exception:
                pass # HTTP Connect fail
            
        except Exception:
            pass
            
        return result

    def update_progress(self, result, total):
        self.completed_count += 1
        prog = self.completed_count / total
        self.progress_bar.set(prog)
        
        # Don't show numeric progress on status label to avoid jitter, progress bar is enough
        # self.status_label.configure(text=f"Scanning... {int(prog*100)}%")
        
        if result:
            self.results.append(result)
            found_success = len([r for r in self.results if r['status'] in ('good', 'fast')])
            self.count_label.configure(text=f"Scanned: {self.completed_count}/{total}  |  Success: {found_success}")
            
            # Add valid/semi-valid rows? Or all rows?
            # Creating row items is slightly expensive. Let's add all for feedback.
            self._add_row(result)

    def finish_scan(self):
        self.is_scanning = False
        self.action_btn.configure(text="START SCAN", fg_color=self.col_accent, state="normal")
        self.progress_bar.grid_forget() # Hide progress bar
        self.status_label.configure(text="Scan Completed.")

    def refresh_table(self):
        # Clear existing rows
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.current_row = 1
        for res in self.results:
            self._add_row(res)

    def _add_row(self, result):
        tag = result["status"]
        
        lat_text = f"{result['latency']} ms" if result["latency"] != 9999 else "---"
        dl_text = f"{result['down_speed']} MB/s" if result["down_speed"] > 0 else "---"
        ul_text = f"{result['up_speed']} MB/s" if result["up_speed"] > 0 else "---"
        
        self.tree.insert("", "end", values=(
            result["ip"],
            lat_text,
            dl_text,
            ul_text
        ), tags=(tag,))

    def export_json(self):
        # 1. Filter: Up > 0 AND Down > 0 (User Requirement: "ping and up/down speed")
        #    Actually user said "choose the ips that give ping and up/down speed"
        #    Safe to assume they mean valid working ones.
        valid_results = [
            r for r in self.results 
            if r['down_speed'] > 0 and r['up_speed'] > 0
        ]
        
        if not valid_results:
             messagebox.showinfo("Export Info", "No results with both Up and Down speed > 0 found.")
             return

        # 2. Sort: Best to Worst
        #    Sort criteria: Higher Down is better, Higher Up is better, Lower Latency is better.
        valid_results.sort(key=lambda x: (-x['down_speed'], -x['up_speed'], x['latency']))
            
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(valid_results, f, indent=4)
                messagebox.showinfo("Export Success", f"Exported {len(valid_results)} optimized records.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = GravityDNSHunter()
    app.mainloop()
