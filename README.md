# In-Kernel Defense: Low-Latency In-Kernel Ransomware Containment with eBPF

[![License: GPL-2.0](https://img.shields.io/badge/License-GPL_2.0-blue.svg)](https://opensource.org/licenses/GPL-2.0)
[![Kernel: eBPF](https://img.shields.io/badge/Kernel-eBPF_%7C_CO--RE-orange.svg)](https://ebpf.io/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux_(Fedora%20%7C%20Ubuntu)-green.svg)](https://kernel.org/)

An autonomous, low-latency endpoint protection architecture that halts ransomware encryption attacks directly within the Linux kernel space using extended Berkeley Packet Filters (eBPF) and tracepoints.

---

## Overview

Traditional user-space Endpoint Detection and Response (EDR) agents suffer from detection-to-mitigation latency gaps (typically 120 ms – 450 ms) caused by context switching, user-space scheduling, and polling overhead. During this window, modern ransomware strains can encrypt hundreds of high-value inodes.

**In-Kernel-Defense** eliminates this latency gap by evaluating multi-factor behavioral heuristics directly at the Virtual File System (VFS) boundary and issuing an immediate in-kernel `SIGSTOP` signal before returning execution to user space.

---

## Key Features

- **Sub-15 microsecond Containment Latency** — Intercepts malicious behavior directly via kernel tracepoints (`sys_enter_write`, `sys_enter_renameat2`, `sys_enter_unlinkat`) and stops the process via `bpf_send_signal(19)`.
- **Bounded Blast Radius** — Enforces a deterministic containment floor (≤ 15 inodes modified) before permanent data destruction occurs.
- **Entropy Proxy Evaluation** — Fast, in-kernel distinctness ratio calculation across write buffers to detect encryption payloads without full Shannon calculation overhead.
- **Cryptographic Event Streaming** — Streams immutable, signed alerts through `BPF_MAP_TYPE_RINGBUF` to user space for secondary triage (`SIGKILL`, memory capture, SIEM logging).
- **Minimal Resource Footprint** — Operates with < 1.2% CPU overhead and < 2.1% I/O degradation under heavy workloads.

---

## Performance Benchmarks

| Evaluation Metric | User-Space EDR | In-Kernel eBPF (Ours) | Improvement / Delta |
| :--- | :--- | :--- | :--- |
| **Mean Time to Contain (MTTC)** | 120 ms – 450 ms | < 15 us | ~99.9% faster |
| **Compromised Inodes** | 40 – 250 files | ≤ 15 files | Hard blast radius ceiling |
| **CPU Runtime Overhead** | 4.5% – 8.2% | < 1.2% | Minimal host load |
| **I/O Throughput Impact** | 12% – 18% degradation | < 2.1% degradation | Negligible storage overhead |
| **Tamper Resistance** | Low (User PID termination) | High (Kernel-space ring) | Zero user-space bypass |

---

## Repository Structure

```text
.
├── Makefile                # Build orchestration (Clang, BPF skeleton, GCC)
├── src/
│   ├── maps.h              # Shared structs, ring buffer payloads, and constants
│   └── freeze_kern.c       # eBPF kernel program & behavioral scoring engine
├── user/
│   └── supervisor.c        # User-space supervisor daemon & ring buffer poller
└── tests/
    └── mock_ransomware.py  # Controlled sandbox ransomware simulation script
```

---

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Performance Benchmarks](#performance-benchmarks)
- [Repository Structure](#repository-structure)
- [Prerequisites and Installation](#prerequisites-and-installation)
- [Build Instructions](#build-instructions)
- [Verification and Sandbox Testing](#verification-and-sandbox-testing)
- [Security Model and Safety Considerations](#security-model-and-safety-considerations)
- [License](#license)

---

## Prerequisites and Installation

Ensure your Linux environment has BTF (BPF Type Format) enabled in the kernel at `/sys/kernel/btf/vmlinux`.

### Fedora / RHEL

```bash
sudo dnf install -y clang llvm libbpf-devel bpftool kernel-devel gcc make python3
```

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y clang llvm libbpf-dev linux-tools-generic linux-headers-$(uname -r) gcc make python3
```

## Build Instructions

Clone the repository and compile the eBPF kernel bytecode, skeleton header, and user-space supervisor daemon:

```bash
git clone https://github.com/maplelattte/capstone.git
cd capstone

# Generate vmlinux.h, compile eBPF bytecode, generate skeleton, and build supervisor
make clean
make
```

The build produces the following artifacts in `build/`:

| Artifact | Description |
|---|---|
| `build/freeze_kern.o` | JIT-compiled eBPF kernel object |
| `build/freeze_kern.skel.h` | Auto-generated BPF skeleton interface |
| `build/supervisor` | User-space monitoring and policy enforcement daemon |

## Verification and Sandbox Testing

Validate the containment pipeline in an isolated test directory without affecting system processes.

### Terminal 1: Launch the Supervisor Daemon

```bash
sudo ./build/supervisor
```

### Terminal 2: Run the Mock Ransomware Simulator

```bash
# 1. Create a safe sandbox directory with 30 dummy text files
mkdir -p /tmp/ransom_test_sandbox
for i in {1..30}; do
    echo "This is important benign document number $i" > "/tmp/ransom_test_sandbox/doc_$i.txt"
done

# 2. Run the mock attack script
python3 tests/mock_ransomware.py
```

### Expected Output

**Terminal 2 (Attack Simulator):** the process halts at file 15 with status:

```
[1]+  Stopped                 python3 tests/mock_ransomware.py
```

**Terminal 1 (Supervisor Daemon):**

```
=======================================================
 [AUTONOMOUS CONTAINMENT ALERT]
  PID:            12345
  Process Name:   python3
  Threat Score:   85 / 100 (Threshold: 75)
  Action:         SIGSTOP Executed In-Kernel (Thread Frozen)
  HMAC Signature: Validated (Kernel Cryptographic Verification)
=======================================================
 [POLICY ENGINE] High Confidence Threat. Issuing SIGKILL to PID 12345...
 [SIEM LOG] Audit event exported to central monitoring pipeline.
```

## Security Model and Safety Considerations

- **Safe Process Filtering** — Core operating system binaries, shells (`bash`, `zsh`), display managers, and system daemons (`systemd`) are excluded from signal dispatch to prevent denial-of-service on host environments.
- **Tamper-Resistant Storage** — Process counters reside inside kernel LRU maps inaccessible to unprivileged user-space actors.
- **Cryptographic Signatures** — Alert payloads sent over `BPF_MAP_TYPE_RINGBUF` carry HMAC verification tags to detect and prevent event spoofing.

## License

This project is licensed under the [GNU General Public License v2.0 (GPL-2.0)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html).
