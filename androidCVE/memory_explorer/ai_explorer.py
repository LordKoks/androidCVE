import os
import sys
import time
import struct

class MemoryExplorerAI:
    def __init__(self):
        self.found_items = []
        self.system_apps = {
            "com.android.settings": "Settings / Developer Mode",
            "com.android.systemui": "System UI / Status Bar",
            "com.android.clock": "Clock App",
            "com.android.calculator": "Calculator",
            "com.android.contacts": "Contacts / Phonebook",
            "com.android.gallery3d": "Gallery / Camera",
            "system_server": "Kernel System Server (Core)",
        }
        self.kernel_structures = {
            b"KETO0422": "task_struct (Process Marker)",
            b"selinux_enforcing": "SELinux Enforcing Bit",
            b"init_cred": "Root Credentials Structure",
        }

    def classify_page(self, page_data, va):
        """
        AI-lite heuristic classification of a 4KB memory page
        """
        classification = {
            "type": "Unknown",
            "description": "Raw Data",
            "va": hex(va),
            "confidence": 0.0
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
        # Looking for 4 consecutive occurrences of 1000 (ruid, gid, suid, fsuid)
        uid_pattern = struct.pack("<IIII", 1000, 1000, 1000, 1000)
        if uid_pattern in page_data:
            classification["type"] = "System Service"
            classification["description"] = "Process running with System privileges (UID 1000)"
            classification["confidence"] = 0.8
            return classification

        return classification

    def render_tui(self):
        """
        Terminal-in-terminal File Manager style UI
        """
        os.system('clear')
        print("="*60)
        print(" KGSL MEMORY EXPLORER & AI CLASSIFIER (BETA V1) ")
        print("="*60)
        print(f"{'TYPE':<15} | {'DESCRIPTION':<30} | {'VA ADDRESS':<12}")
        print("-"*60)
        
        for item in self.found_items:
            print(f"{item['type']:<15} | {item['description']:<30} | {item['va']:<12}")
        
        print("\n" + "="*60)
        print("[S] Start Scanning   [Q] Quit   [Enter] View Details")

    def show_detail(self, item_idx):
        if item_idx >= len(self.found_items):
            return
        
        item = self.found_items[item_idx]
        os.system('clear')
        print(f"--- DETAIL VIEW: {item['description']} ---")
        print(f"Virtual Address: {item['va']}")
        print(f"Confidence: {item['confidence']*100}%")
        print("-" * 40)
        
        # Binary Representation (BIOS style)
        print("BINARY DATA (Bits 0-31):")
        # Mock data for demonstration
        mock_data = [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x000003E8]
        for val in mock_data:
            print(f"0x{val:08X}: {bin(val)[2:].zfill(32)}")
        
        print("\nHEX DUMP:")
        for i, val in enumerate(mock_data):
            print(f"{i*4:04X}: {val:08X}  ", end="")
            if (i+1) % 2 == 0: print()
        
        print("\nAI TRANSLATION (Human Readable):")
        if "Settings" in item['description']:
            print(">> [Analysis]: This region corresponds to the 'com.android.settings' package memory.")
            print(">> [Security]: Potentially contains developer mode flags and display configuration.")
        elif "UID 1000" in item['description']:
            print(">> [Analysis]: Detected a 'cred' structure belonging to a system-level service.")
            print(">> [Security]: Modifying this region could elevate current process to system privileges.")
        
        input("\nPress Enter to return...")

    def run(self):
        # Simulated scan for demonstration
        self.render_tui()
        while True:
            cmd = input("> ").lower()
            if cmd == 'q':
                break
            elif cmd == 's':
                print("[*] GPU Spraying slowly... analyzing patterns...")
                time.sleep(1)
                # Mock found data 1
                mock_page = b"com.android.settings" + b"\x00" * 4000
                res = self.classify_page(mock_page, 0x7001ff000)
                self.found_items.append(res)
                # Mock found data 2
                mock_page2 = struct.pack("<IIII", 1000, 1000, 1000, 1000) + b"\x00" * 4000
                res2 = self.classify_page(mock_page2, 0x7002ef000)
                self.found_items.append(res2)
                self.render_tui()
            elif cmd.isdigit():
                self.show_detail(int(cmd))
                self.render_tui()

if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.run()
