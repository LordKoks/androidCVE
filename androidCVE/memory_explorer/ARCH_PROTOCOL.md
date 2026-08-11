# KGSL Memory Explorer & AI Classifier Architecture

## 1. Overview
This project implements a kernel memory forensic tool disguised as a "File Manager" TUI. It leverages the KGSL UAF vulnerability to map physical pages into user-space and uses heuristic-based pattern recognition (AI-lite) to classify memory regions.

## 2. Component Architecture

### A. GPU Spray Engine (The "Physical Eye")
- **Mechanism**: Slow, targeted PTE manipulation via KGSL.
- **Role**: Maps physical pages into a 64MB-128MB "View Window" in User Virtual Address (UVA) space.
- **Optimization**: Minimal CPU load during mapping; most work is done by the GPU command processor.

### B. CPU Intelligence Layer (Pattern Recognition / ML)
- **Algorithm**: Signature-based classification with weighted probability.
- **Classification Categories**:
    - **Kernel Core**: `task_struct`, `cred`, `selinux_state`, `swapper` stack.
    - **System Services**: `system_server`, `surfaceflinger`, `adbd`.
    - **System Apps**: Clock, Calculator, Settings (identified via `comm` strings and UID 1000 range).
    - **User Apps**: Chrome, Games, etc. (identified via high UID ranges and package-specific strings).
- **Deep Analysis**: 
    - Disassembles binary blobs into AArch64 instructions.
    - Matches pointers against known `KERNEL_BASE` offsets to identify global variables.

### C. TUI Interface (Memory Manager)
- **Visuals**: A nested menu structure.
    - `[Root]` -> `[Kernel]` / `[System]` / `[User Space]`
- **Detail View**: 
    - **Hex**: Traditional BIOS-style hexdump.
    - **Binary**: Bit-level visualization.
    - **Logic**: Translated human-readable descriptions (e.g., "This region contains a credential structure with UID 10237 and full capabilities").

## 3. Communication Protocols

### Protocol V1: Discovery
1. GPU maps a 4KB page.
2. CPU scans for "Markers" (e.g., `comm` names, magic numbers).
3. If a marker is found, the page is flagged and classified.
4. If no marker is found, GPU proceeds to the next physical address step.

### Protocol V2: Classification Weights
- **Weight 1.0**: Found string "com.android.settings".
- **Weight 0.8**: Found pointer to `KERNEL_BASE` + `SELINUX_OFFSET`.
- **Weight 0.5**: Found UID sequence `10237, 10237, 10237`.

## 4. Hardware Resource Management
- **GPU**: Handles the heavy lifting of physical-to-virtual translation.
- **CPU**: Runs the TUI loop and the classification algorithms.
- **RAM**: Managed via a sliding window to prevent Termux OOM crashes.
