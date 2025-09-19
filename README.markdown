# CrashMac: macOS Slowdown Exploit Tool 🚀

## Overview 📖

**CrashMac** is a Python-based security testing tool designed to stress macOS systems by targeting network, CPU, and memory resources. It supports multiple attack vectors, including **SYN flood**, **ICMP flood**, **HTTP flood**, and **Slowloris-style SSH DoS**. The tool offers three operational modes:

- **LOIC**: High-frequency flood for rapid resource exhaustion.
- **HOIC**: Sustained multi-vector attack targeting multiple services.
- **SMART**: Dynamically switches between LOIC and HOIC based on target responsiveness.

CrashMac includes **resource monitoring**, **logging with rotation**, and **real-time status reporting** to ensure controlled and efficient operation. Developed by **ChillHack Jake**, an ethical hacker from Hong Kong.

> **⚠️ Ethical Use Warning**: This tool is for **authorized security testing only**. Unauthorized use is illegal and unethical. Always obtain explicit permission from the target system's owner before use.

---

## Features ✨

| Feature | Description |
| --- | --- |
| **Multiple Attack Vectors** | Includes SYN, ICMP, HTTP floods, and SSH DoS to stress target resources. |
| **Operational Modes** | LOIC (high-frequency), HOIC (multi-vector), and SMART (dynamic) modes. |
| **Resource Monitoring** | Pauses attacks if local CPU/memory usage exceeds 90%. |
| **Real-Time Status** | Displays target status, network delay, and attack statistics every 10 seconds. |
| **Logging** | Rotates logs (`crashmac_log.txt`, 5MB max, 3 backups) for analysis. |
| **Graceful Shutdown** | Handles `Ctrl+C` for safe termination. |
| **Port Scanning** | Detects open HTTP/HTTPS ports for targeted attacks. |

---

## Requirements 🛠️

- **Python**: 3.6 or higher
- **Dependencies**:
  - `psutil`: For resource monitoring
  - Install via:

    ```bash
    pip install psutil
    ```
- **Operating System**: Linux or macOS (root privileges required for raw sockets)
- **Network**: Access to the target IP
- **Permissions**: Run with `sudo` for SYN/ICMP floods

---

## Installation 📦

1. Clone the repository:

   ```bash
   git clone https://github.com/ChillHackJake/crashmac.git
   cd crashmac
   ```

2. Install dependencies:

   ```bash
   pip install psutil
   ```

3. Ensure root privileges for raw socket operations.

---

## Usage 🎮

Run CrashMac with the following command-line arguments:

```bash
sudo python3 crashmac.py --target-ip <IP> --target-port <PORT> [-L | -H | -S]
```

### Arguments

| Argument | Description | Required |
| --- | --- | --- |
| `--target-ip <IP>` | Target IP address (e.g., `192.168.0.227`) | Yes |
| `--target-port <PORT>` | Target port (e.g., `22` for SSH, `80` for HTTP) | Yes |
| `-L, --loic` | LOIC-style high-frequency flood | No |
| `-H, --hoic` | HOIC-style sustained multi-vector attack | No |
| `-S, --smart` | SMART mode for dynamic attack selection (default) | No |

**Note**: Only one mode (`-L`, `-H`, or `-S`) can be selected.

### Example Commands

1. **LOIC Mode** (High-Frequency Flood):

   ```bash
   sudo python3 crashmac.py --target-ip 192.168.0.227 --target-port 22 -L
   ```

2. **HOIC Mode** (Multi-Vector Attack):

   ```bash
   sudo python3 crashmac.py --target-ip 192.168.0.227 --target-port 80 -H
   ```

3. **SMART Mode** (Dynamic Attack):

   ```bash
   sudo python3 crashmac.py --target-ip 192.168.0.227 --target-port 22 -S
   ```

### Execution Steps

1. **Prepare**: Install dependencies and run with `sudo`.
2. **Run**: Specify target IP, port, and mode.
3. **Monitor**: View real-time status with:
   - Target status, runtime, network delay
   - CPU/RAM usage, active threads
   - Attack statistics (SYN, SSH, HTTP)
4. **Stop**: Press `Ctrl+C` to terminate gracefully.

---

## Configuration ⚙️

Edit the script to customize:

| Parameter | Description | Default |
| --- | --- | --- |
| `TARGET_PORTS_HTTP` | Ports to scan for HTTP | `[80, 443]` |
| `NUM_THREADS_SYN` | SYN flood threads | 50 |
| `NUM_THREADS_SSH` | SSH DoS threads | 10 |
| `NUM_THREADS_HTTP` | HTTP flood threads | 10 |
| `TIMEOUT` | Socket timeout (seconds) | 30 |
| `EXPLOIT_DURATION` | Attack duration (seconds) | 28,800 (8 hours) |
| `ATTEMPTS_PER_THREAD` | Attempts per thread | 2,000 |
| `RETRY_DELAY_MIN/MAX` | Delay range (seconds) | 1.0–5.0 |
| `MAX_LOG_SIZE` | Log file size | 5MB |
| `LOG_BACKUP_COUNT` | Backup logs | 3 |

---

## Attack Modes 🔍

### LOIC Mode

- **Description**: High-frequency SYN/ICMP floods.
- **Use Case**: Rapid resource exhaustion on single-port services.
- **Behavior**: Short delays (0.01–0.05s).

### HOIC Mode

- **Description**: Sustained multi-vector attack (SYN, ICMP, HTTP, SSH).
- **Use Case**: Prolonged attacks on multiple services.
- **Behavior**: Larger payloads, varied requests, longer delays (0.5–2.0s).

### SMART Mode

- **Description**: Switches between LOIC/HOIC every 60 seconds based on:
  - Ping delay (&gt;100ms → HOIC)
  - Port status (closed → HOIC)
  - HTTP response time (&gt;500ms → HOIC)
- **Use Case**: Adaptive attacks for unknown target responsiveness.

---

## Logging 📜

- **File**: `crashmac_log.txt` (5MB max, 3 backups)
- **Format**: `%(asctime)s [Thread-%(thread)d] %(levelname)s: %(message)s`
- **Content**: Attack events, errors, resource warnings, mode switches

---

## Safety Features 🛡️

- **Resource Monitoring**: Pauses if CPU/memory &gt;90%.
- **File Descriptor Limit**: Raises to 65,535 for connections.
- **Graceful Shutdown**: Closes sockets on `Ctrl+C`.
- **Timeout**: Prevents hanging connections.

---

## Limitations ⚠️

- Requires root privileges for raw sockets.
- Effectiveness depends on network conditions and target defenses.
- Optimized for macOS; results may vary on other systems.
- Must be used with explicit permission.

---

## Ethical Use 🚨

CrashMac is for **authorized security testing only**. Unauthorized use is illegal and may cause harm. Obtain explicit permission from the target system's owner before use. The developer is not responsible for misuse or damage.

---

## Contact 📬

- **Developer**: ChillHack Jake, Ethical Hacker from Hong Kong
- **Email**: info@chillhack.net
- **Website**: https://chillhack.net

---

## License 📄

This project is licensed under the MIT License. See the LICENSE file for details.