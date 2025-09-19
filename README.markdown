CrashMac: macOS Slowdown Exploit Tool

GitHub Description

CrashMac is a Python-based stress testing tool designed to gradually slow down macOS systems by exhausting network, CPU, and memory resources. It supports SYN, ICMP, HTTP floods, and SSH DoS attacks in LOIC, HOIC, and SMART modes. Developed by ChillHack Jake, an ethical hacker from Hong Kong. For authorized security testing only. Contact: info@chillhack.net | Website: https://chillhack.net

Overview

CrashMac is a Python-based tool designed for authorized security testing to stress macOS systems by targeting network, CPU, and memory resources. It employs multiple attack vectors, including SYN flood, ICMP flood, HTTP flood, and a Slowloris-style SSH DoS attack. The tool offers three modes: LOIC (high-frequency flood), HOIC (sustained multi-vector attack), and SMART (dynamic mode selection based on target responsiveness). It includes resource monitoring, logging with rotation, and real-time status reporting for controlled operation.

**Developed by**: ChillHack Jake, Developer and Ethical Hacker from Hong Kong\
**Contact**: info@chillhack.net\
**Website**: https://chillhack.net

**⚠️ Disclaimer**: This tool is for **educational and authorized security testing only**. Unauthorized use against systems without explicit permission is illegal and unethical. Always comply with applicable laws and regulations.

Features

**Multiple Attack Vectors**: SYN flood, ICMP flood, HTTP flood, and SSH DoS to stress target resources.

- **Operational Modes**:

**LOIC Mode**: High-frequency SYN and ICMP floods for rapid resource exhaustion.

**HOIC Mode**: Sustained multi-vector attack targeting HTTP and SSH services.

**SMART Mode**: Dynamically switches between LOIC and HOIC based on ping delay, port status, and HTTP response time.

**Resource Monitoring**: Pauses attacks if local CPU or memory usage exceeds 90%.

**Real-Time Status**: Displays runtime, target status, network delay, and attack statistics.

**Logging**: Rotates logs (`crashmac_log.txt`, 5MB max, 3 backups) for post-analysis.

**Graceful Shutdown**: Handles `Ctrl+C` for safe termination.

**Port Scanning**: Detects open HTTP/HTTPS ports for targeted attacks.

Requirements

**Python**: 3.6 or higher.

- **Dependencies**:

`psutil`: For resource monitoring.

Install via: `pip install psutil`

**Operating System**: Linux or macOS (root privileges required for raw socket operations).

**Network**: Access to the target IP.

**Permissions**: Run with `sudo` for SYN and ICMP floods.

Installation

1. Clone the repository:

git clone https://github.com/ChillHackJake/crashmac.git cd crashmac

1. Install dependencies:

pip install psutil

Ensure root privileges for raw socket operations.

Usage

Run CrashMac with the following command-line arguments:

`--target-ip <IP>`: Target IP address (e.g., `192.168.0.227`).

`--target-port <PORT>`: Target port (e.g., `22` for SSH, `80` for HTTP).

`-L, --loic`: LOIC-style high-frequency flood attack.

`-H, --hoic`: HOIC-style sustained multi-vector attack.

`-S, --smart`: SMART mode for dynamic attack selection (default).

**Note**: Only one mode (`-L`, `-H`, or `-S`) can be selected.

Example Commands

1. **LOIC Mode**:

sudo python3 crashmac.py --target-ip 192.168.0.227 --target-port 22 -L

High-frequency SYN and ICMP flood on port 22.

1. **HOIC Mode**:

sudo python3 crashmac.py --target-ip 192.168.0.227 --target-port 80 -H

Multi-vector attack with SYN, ICMP, HTTP floods, and SSH DoS.

1. **SMART Mode**:

sudo python3 crashmac.py --target-ip 192.168.0.227 --target-port 22 -S

Dynamically switches between LOIC and HOIC modes.

Execution Steps

**Prepare**: Install dependencies and run with `sudo`.

**Run**: Specify target IP, port, and mode.

1. **Monitor**: View real-time status (updates every 10 seconds) with:

Target status, runtime, and network delay.

CPU/RAM usage and active threads.

Attack statistics (SYN, SSH, HTTP attempts/successes).

**Stop**: Press `Ctrl+C` to gracefully terminate.

Configuration

Edit the script to modify:

`TARGET_PORTS_HTTP`: Ports to scan for HTTP (default: `[80, 443]`).

`NUM_THREADS_SYN/SSH/HTTP`: Thread counts (default: 50/10/10).

`TIMEOUT`: Socket timeout (default: 30 seconds).

`EXPLOIT_DURATION`: Attack duration (default: 8 hours).

`ATTEMPTS_PER_THREAD`: Attempts per thread (default: 2,000).

`RETRY_DELAY_MIN/MAX`: Delay range (default: 1.0–5.0 seconds).

`MAX_LOG_SIZE`: Log file size (default: 5MB).

`LOG_BACKUP_COUNT`: Backup logs (default: 3).

Attack Modes

**LOIC Mode**: Rapid SYN/ICMP floods with short delays (0.01–0.05s).

**HOIC Mode**: Sustained attack with larger payloads and varied HTTP/SSH requests.

- **SMART Mode**: Switches modes every 60 seconds based on:

Ping delay (&gt;100ms → HOIC).

Port status (closed → HOIC).

HTTP response time (&gt;500ms → HOIC).

Logging

**File**: `crashmac_log.txt` (5MB max, 3 backups).

**Format**: `%(asctime)s [Thread-%(thread)d] %(levelname)s: %(message)s`.

**Content**: Attack events, errors, resource warnings, and mode switches.

Safety Features

**Resource Monitoring**: Pauses if CPU/memory usage &gt;90%.

**File Descriptor Limit**: Raises to 65,535 for multiple connections.

**Graceful Shutdown**: Closes sockets on `Ctrl+C`.

**Timeout**: Prevents hanging connections.

Limitations

Requires root privileges for raw sockets.

Effectiveness depends on network conditions and target defenses.

Optimized for macOS; results may vary on other systems.

Must be used with explicit permission.

Ethical Use

CrashMac is for **authorized security testing only**. Unauthorized use is illegal and may cause harm. Obtain explicit permission from the target system's owner before use. The developer is not responsible for misuse or damage.

Contact

**Developer**: ChillHack Jake

**Email**: info@chillhack.net

**Website**: https://chillhack.net

License

This project is licensed under the MIT License. See the `LICENSE` file for details.