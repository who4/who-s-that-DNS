import customtkinter as ctk
import dns.resolver
import requests
import threading
import time
import json
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
        # Grid Layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # --- Header ---
        self.header_frame = ctk.CTkFrame(self, corner_radius=0)
        self.header_frame.grid(row=0, column=0, sticky="ew")
        
        self.title_label = ctk.CTkLabel(self.header_frame, text="Who's This DNS!", font=("Roboto Medium", 24))
        self.title_label.pack(pady=10, padx=20, side="left")

        # --- Controls / Settings ---
        self.controls_frame = ctk.CTkFrame(self)
        self.controls_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=10)

        # Source Selection
        self.source_var = ctk.StringVar(value="web")
        self.source_var.trace_add("write", self.on_source_change)
        
        # Remove command= from radio buttons, rely on variable trace
        self.radio_web = ctk.CTkRadioButton(self.controls_frame, text="Fetch from Web", variable=self.source_var, value="web")
        self.radio_web.grid(row=0, column=0, padx=20, pady=10)
        
        self.radio_file = ctk.CTkRadioButton(self.controls_frame, text="Load from .txt", variable=self.source_var, value="file")
        self.radio_file.grid(row=0, column=1, padx=20, pady=10)

        # File Picker (Hidden by default or shown based on selection)
        self.file_path_entry = ctk.CTkEntry(self.controls_frame, placeholder_text="Select file...", width=200)
        self.browse_btn = ctk.CTkButton(self.controls_frame, text="Browse", width=80, command=self.browse_file)
        
        # Start/Stop Button
        self.action_btn = ctk.CTkButton(self.controls_frame, text="START SCAN", command=self.on_start_stop, fg_color="green", hover_color="darkgreen")
        self.action_btn.grid(row=0, column=4, padx=20, pady=10, sticky="e")
        self.controls_frame.grid_columnconfigure(4, weight=1)

        # Status Label
        self.status_label = ctk.CTkLabel(self.controls_frame, text="Ready", text_color="gray")
        self.status_label.grid(row=1, column=0, columnspan=5, sticky="w", padx=20)
        
        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self.controls_frame)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=2, column=0, columnspan=5, sticky="ew", padx=20, pady=(0, 10))

        # --- Results Table ---
        # Using a scrollable frame for results
        self.table_frame = ctk.CTkScrollableFrame(self, label_text="Scan Results")
        self.table_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=10)
        
        # Table Headers
        headers = ["IP Address", "Ping", "DNS", "Latency (ms)"]
        for i, h in enumerate(headers):
             lbl = ctk.CTkLabel(self.table_frame, text=h, font=("Roboto", 14, "bold"))
             lbl.grid(row=0, column=i, sticky="w", padx=10, pady=5)
        
        self.table_frame.grid_columnconfigure(0, weight=1) 
        self.table_frame.grid_columnconfigure(1, weight=0)
        self.table_frame.grid_columnconfigure(2, weight=0)
        self.table_frame.grid_columnconfigure(3, weight=0)

        self.current_row = 1

        # --- Footer ---
        self.footer_frame = ctk.CTkFrame(self, height=50)
        self.footer_frame.grid(row=3, column=0, sticky="ew")

        self.export_btn = ctk.CTkButton(self.footer_frame, text="Export JSON", command=self.export_json)
        self.export_btn.pack(side="right", padx=20, pady=10)
        
        self.count_label = ctk.CTkLabel(self.footer_frame, text="Alive: 0 | DNS: 0")
        self.count_label.pack(side="left", padx=20, pady=10)
        
        # Initial UI state
        self.on_source_change()

    def on_source_change(self, *args):
        mode = self.source_var.get()
        print(f"Source changed to: {mode}")
        
        # Clear previous data to avoid mixing sources
        self.target_list = []
        self.results = []
        self.status_label.configure(text=f"Switched to {mode.upper()}. List cleared.")
        
        if mode == "file":
            self.file_path_entry.grid(row=0, column=2, padx=10)
            self.browse_btn.grid(row=0, column=3, padx=10)
        else:
            self.file_path_entry.grid_forget()
            self.browse_btn.grid_forget()
            self.status_label.configure(text="Web Mode. Click START to fetch & scan.")

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filename:
            self.file_path_entry.delete(0, tk.END)
            self.file_path_entry.insert(0, filename)
            # Force source mode to file (triggers trace)
            self.source_var.set("file")
            # If already file, trace might not fire if value didn't change?
            # Let's explicitly check:
            if self.source_var.get() == "file":
                 # If we are already in file mode, we just want to load the file, 
                 # BUT we need to clear previous list first properly.
                 # Actually load_file overwrites target_list, so it's fine.
                 pass
            
            self.load_file(filename)

    def toggle_source(self):
        # Deprecated by on_source_change
        pass

    def load_file(self, path):
        try:
            print(f"Loading file: {path}")
            with open(path, 'r') as f:
                lines = f.readlines()
            
            self.target_list = []
            for line in lines:
                # Look for IP pattern x.x.x.x or CIDR x.x.x.x/xx
                match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', line)
                if match:
                    found_str = match.group(1)
                    if '/' in found_str:
                        try:
                            # Expand CIDR
                            net = ipaddress.ip_network(found_str, strict=False)
                            # Add all usable hosts
                            for ip in net.hosts():
                                self.target_list.append(str(ip))
                        except ValueError:
                            pass
                    else:
                        self.target_list.append(found_str)
            
            print(f"Parsed {len(self.target_list)} IPs")
            self.status_label.configure(text=f"Loaded {len(self.target_list)} IPs. CLICK 'START SCAN'!")
        except Exception as e:
            print(f"Error loading file: {e}")
            messagebox.showerror("Error", str(e))

    def fetch_web_list(self):
        try:
            print("Fetching public DNS list...")
            self.status_label.configure(text="Fetching public DNS list...")
            self.update_idletasks()
            
            url = "https://public-dns.info/nameservers.txt" 
            print(f"GET {url}")
            resp = requests.get(url, timeout=10)
            print(f"Status Code: {resp.status_code}")
            resp.raise_for_status()
            
            lines = resp.text.splitlines()
            print(f"Downloaded {len(lines)} lines")
            
            self.target_list = []
            for line in lines:
                parts = line.split() 
                if parts:
                    ip = parts[0]
                    if ip.count('.') == 3: 
                        self.target_list.append(ip)
            
            # Limit for demo/performance if huge
            if len(self.target_list) > 2000:
                print(f"Truncating list from {len(self.target_list)} to 2000")
                self.target_list = self.target_list[:2000]
                
            print(f"Successfully fetched {len(self.target_list)} IPs")
            self.status_label.configure(text=f"Fetched {len(self.target_list)} IPs from web")
        except Exception as e:
            print(f"FETCH ERROR: {e}")
            messagebox.showerror("Error Fetching", f"Could not fetch list: {e}")
            self.target_list = []

    def on_start_stop(self):
        print("Start/Stop clicked")
        if self.is_scanning:
            # Stop
            self.stop_event.set()
            self.status_label.configure(text="Stopping...")
            self.action_btn.configure(text="Stopping...", state="disabled")
        else:
            # Start
            print(f"Starting scan. Source: {self.source_var.get()}")
            if self.source_var.get() == "web" and not self.target_list:
                 self.fetch_web_list()
            
            if not self.target_list:
                print("No targets")
                messagebox.showwarning("No Targets", "No IP addresses to scan.")
                return

            self.is_scanning = True
            self.stop_event.clear()
            self.action_btn.configure(text="STOP SCAN", fg_color="red", hover_color="darkred")
            self.results = []
            self.current_row = 1
            
            # Clear table
            for widget in self.table_frame.winfo_children():
                if int(widget.grid_info()["row"]) > 0: # keep headers
                    widget.destroy()

            self.scan_thread = threading.Thread(target=self.run_scan_loop, daemon=True)
            self.scan_thread.start()

    def run_scan_loop(self):
        total = len(self.target_list)
        # Using a semaphore to limit concurrency
        max_threads = 50
        sem = threading.Semaphore(max_threads)
        threads = []

        self.completed_count = 0
        
        def worker(ip):
            with sem:
                if self.stop_event.is_set(): return
                res = self.check_host(ip)
                
                # Update progress safely
                if not self.stop_event.is_set():
                     self.after(0, self.update_progress, res, total)

        for ip in self.target_list:
            if self.stop_event.is_set(): break
            t = threading.Thread(target=worker, args=(ip,))
            t.start()
            threads.append(t)
        
        # Wait for all
        for t in threads:
            t.join()

        self.after(0, self.finish_scan)

    def check_dns(self, ip):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout = 1
        resolver.lifetime = 1
        
        start = time.time()
        try:
            # Try resolving google.com
            # Using type 'A' 
            answer = resolver.resolve("google.com", "A")
            latency = (time.time() - start) * 1000
            return {"ip": ip, "status": "OK", "latency": int(latency)}
        except Exception:
            return {"ip": ip, "status": "Timeout", "latency": 9999}
            latency = (time.time() - start) * 1000
            return {"ip": ip, "status": "OK", "latency": int(latency)}
        except Exception:
            # Return failure result instead of None
            return {"ip": ip, "status": "Timeout", "latency": 9999}

    def check_host(self, ip):
        # 1. System Ping (Check IP)
        is_up = False
        ping_lat = 0
        try:
            # -n 1 (count), -w 500 (timeout ms) 
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            t_start = time.time()
            ret = subprocess.call(['ping', '-n', '1', '-w', '500', ip], 
                                  stdout=subprocess.DEVNULL, 
                                  stderr=subprocess.DEVNULL,
                                  startupinfo=startupinfo)
            ping_lat = (time.time() - t_start) * 1000
            is_up = (ret == 0)
        except:
            pass

        ping_status = "UP" if is_up else "DOWN"
        
        # 2. DNS Check (if UP, or we can try anyway, but usually fails if down)
        dns_status = "Fail"
        dns_lat = 0
        
        # Even if ping fails (blocked ICMP), DNS might work (open UDP/53)
        # So we try DNS regardless, but quickly.
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout = 1
        resolver.lifetime = 1
        
        try:
            d_start = time.time()
            resolver.resolve("google.com", "A")
            dns_lat = (time.time() - d_start) * 1000
            dns_status = "OK"
        except:
            pass
            
        # Determine sorting latency: DNS latency if OK, else Ping latency if UP, else 9999
        sort_lat = 9999
        if dns_status == "OK":
            sort_lat = int(dns_lat)
        elif is_up:
            sort_lat = int(ping_lat)
            
        return {
            "ip": ip, 
            "ping": ping_status, 
            "dns": dns_status, 
            "latency": sort_lat,
            "display_lat": int(dns_lat if dns_status=="OK" else ping_lat)
        }

    def update_progress(self, result, total):
        self.completed_count += 1
        prog = self.completed_count / total
        self.progress_bar.set(prog)
        
        self.status_label.configure(text=f"Scanning... {self.completed_count}/{total}")
        
        if result:
            self.results.append(result)
            found_dns = len([r for r in self.results if r['dns']=='OK'])
            found_ip = len([r for r in self.results if r['ping']=='UP'])
            self.count_label.configure(text=f"Alive: {found_ip} | DNS: {found_dns}")
            
            # Add to table (Limit to prevent lag if huge headers)
            # Only add if we haven't flooded the UI, say 500 rows?
            # Or just add all for this small range.
            self._add_row(result)

    def finish_scan(self):
        self.is_scanning = False
        self.action_btn.configure(text="START SCAN", fg_color="green", hover_color="darkgreen", state="normal")
        
        # Sort results by latency (lowest first)
        self.results.sort(key=lambda x: x['latency'])
        self.refresh_table()
        
        self.status_label.configure(text=f"Scan Finished. Sorted {len(self.results)} results.")
        if self.stop_event.is_set():
             self.status_label.configure(text="Scan Stopped")

    def refresh_table(self):
        # Clear existing rows (skip headers if they were children of table_frame)
        # Note: In _init_ui, headers are in row 0.
        for widget in self.table_frame.winfo_children():
            if int(widget.grid_info()["row"]) > 0:
                widget.destroy()
        
        self.current_row = 1
        for res in self.results:
            self._add_row(res)

    def _add_row(self, result):
        r = self.current_row
        
        # IP
        l_ip = ctk.CTkLabel(self.table_frame, text=result["ip"])
        l_ip.grid(row=r, column=0, sticky="w", padx=10)
        
        # Ping
        p_color = "green" if result["ping"] == "UP" else "red"
        l_ping = ctk.CTkLabel(self.table_frame, text=result["ping"], text_color=p_color)
        l_ping.grid(row=r, column=1, sticky="w", padx=10)
        
        # DNS
        d_color = "green" if result["dns"] == "OK" else "gray"
        l_dns = ctk.CTkLabel(self.table_frame, text=result["dns"], text_color=d_color)
        l_dns.grid(row=r, column=2, sticky="w", padx=10)
        
        # Latency
        lat_text = f"{result['display_lat']} ms" if result["latency"] != 9999 else "---"
        l_lat = ctk.CTkLabel(self.table_frame, text=lat_text)
        l_lat.grid(row=r, column=3, sticky="w", padx=10)
        
        self.current_row += 1

    def export_json(self):
        if not self.results:
            messagebox.showinfo("Info", "No results to export.")
            return
        
        # Ensure it's sorted before export just in case
        self.results.sort(key=lambda x: x['latency'])
            
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=4)
                messagebox.showinfo("Success", f"Saved {len(self.results)} records.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = GravityDNSHunter()
    app.mainloop()
