# KGSL Memory Explorer: AI-Driven Forensic Protocol

## 1. Architecture Overview
The system is divided into three functional layers to ensure stability on high-performance devices like the ASUS ROG 5S while maintaining deep analytical capabilities.

### Layer 1: Hardware Interaction (GPU)
- **Role**: Memory Mapping and Spraying.
- **Implementation**: `kgsl_engine.c`.
- **Strategy**: "Slow Spray" - mapping physical pages into user-space via CVE-2023-33107 in iterative batches.
- **Constraints**: GPU operations are throttled to prevent thermal spikes and kernel panics.

### Layer 2: Heuristic Analysis (CPU - AI Core)
- **Role**: Content Classification and Pattern Recognition.
- **Algorithm**: Multi-weighted Heuristic Scanner.
- **Detection Vectors**:
    - **Strings**: Searching for package names (`com.android.*`) and kernel symbols.
    - **Binary Signatures**: Identifying AArch64 function prologues and `ADRP` instructions.
    - **UID Patterns**: Detecting consecutive UID/GID fields in `cred` structures.
    - **Pointers**: Identifying pointers within the `KERNEL_BASE` range.

### Layer 3: Interactive Explorer (TUI)
- **Role**: User Interface and Logic Translation.
- **Style**: "Terminal-in-Terminal" File Manager.
- **Logic Translation**: Converts raw bytes into human-readable descriptions of kernel intent.

## 2. AI Classification Weights
The classifier assigns confidence scores based on the following:
- **Weight 1.0**: Exact match of known Android package names in process memory.
- **Weight 0.9**: Match of unique kernel markers (e.g., `KETO0422` or `init_cred`).
- **Weight 0.8**: Found pointer to `KERNEL_BASE` + `SELINUX_OFFSET`.
- **Weight 0.6**: Consecutive AArch64 stack frame setups.

## 3. Data Flow Protocol
1. **Trigger**: GPU creates a "Memory Window" into the kernel.
2. **Scan**: Engine reports "Interesting" VAs (non-zero or signature matches).
3. **Analyze**: Python AI Core reads the page, runs heuristics, and populates the Explorer.
4. **Interact**: User selects a "Memory File" to view BIOS-style HEX/Binary and AI Logic.
