# KGSL Memory Explorer & AI Classifier: Architecture Protocol

## 1. Overview
This project implements an intelligent memory forensic tool designed for the ASUS ROG 5S. It transforms a low-level KGSL UAF vulnerability into a user-friendly "Memory File Manager" with AI-driven content classification.

## 2. Layered Architecture

### Layer 1: Hardware Interaction (GPU)
- **Primary Task**: "Slow Spray" & Page Mapping.
- **Mechanism**: Iteratively maps physical pages into the user-space process using the KGSL UAF vulnerability.
- **Throttling**: The GPU spray is deliberately slowed to prevent system freezes and keep RAM usage under control.
- **Output**: Raw binary pages available for reading.

### Layer 2: Intelligence & Classification (CPU)
- **Primary Task**: AI Content Recognition.
- **Classification Engine**:
    - **Kernel Core**: Detection of `cred`, `selinux_enforcing`, `task_struct`, and Kernel Base pointers.
    - **System Context**: Identification of system-critical apps (Settings, UI, Camera, Gallery, etc.) using UID patterns and package string signatures.
    - **User Context**: Identification of third-party apps (Google Play, RuStore) based on heap patterns.
- **Logic Translation**: Converts binary blobs into human-readable descriptions of the data's purpose.

### Layer 3: Interactive Interface (TUI)
- **Style**: "Terminal-in-Terminal" File Manager.
- **Navigation**: Allows browsing memory offsets as if they were files in a directory.
- **Detail View**: 
    - **Binary View**: Bit-level representation.
    - **HEX View**: BIOS-style low-level hexadecimal dump.
    - **AI Summary**: Plain English explanation of what the code/data does.

## 3. AI Classification Weights
The "Machine Learning" aspect uses a weighted heuristic model:
1. **Signature Match (1.0)**: Exact match for kernel magic numbers or app package names.
2. **UID Proximity (0.8)**: Grouping of data around known system UIDs (e.g., 1000).
3. **Instruction Analysis (0.6)**: Detecting AArch64 function prologues or `ADRP/ADD` pairs.
4. **Data Entropy (0.4)**: Distinguishing between code segments, heap data, and empty buffers.

## 4. Operational Protocol
1. **Initialization**: Load the GPU engine and establish the UAF window.
2. **Exploration**: User triggers a "Slow Spray".
3. **Discovery**: AI-scanner identifies interesting offsets and populates the "File Manager".
4. **Analysis**: User selects an ID to perform deep BIOS-style inspection and logic translation.
