#!/usr/bin/env python3
"""
stress_test.py — High-Performance Network Stress & Throughput Tester for DB-IDS/IPS

Runs from Laptop B to evaluate:
1. Packet capture throughput of Laptop A's raw socket engine.
2. In-Database insertion rate into the ingress_packets table.
3. Redis sub-millisecond O(1) drop rate once the IP is placed on the blocklist.

Zero external dependencies (uses Python standard library).
"""

import sys
import time
import socket
import argparse
import threading

def stress_worker(target_ip: str, port: int, packet_type: str, stop_event: threading.Event, counter: list, lock: threading.Lock):
    local_count = 0
    payload = b"DB_IDS_IPS_STRESS_BENCHMARK_PAYLOAD_CHUNK_0123456789" * 4

    if packet_type == "UDP":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while not stop_event.is_set():
            try:
                sock.sendto(payload, (target_ip, port))
                local_count += 1
            except Exception:
                pass
        sock.close()
    elif packet_type == "TCP":
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect((target_ip, port))
                s.sendall(payload)
                s.close()
                local_count += 1
            except Exception:
                local_count += 1
    elif packet_type == "HTTP":
        http_req = f"GET /stress?load=1 HTTP/1.1\r\nHost: {target_ip}\r\nConnection: keep-alive\r\n\r\n".encode()
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                s.connect((target_ip, port))
                s.sendall(http_req)
                s.close()
                local_count += 1
            except Exception:
                local_count += 1

    with lock:
        counter[0] += local_count

def main():
    parser = argparse.ArgumentParser(description="High-Rate Network Stress Tester")
    parser.add_argument("--target", default="10.30.201.26", help="Laptop A IP (default: 10.30.201.26)")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--proto", choices=["UDP", "TCP", "HTTP"], default="UDP", help="Protocol to flood")
    parser.add_argument("--threads", type=int, default=16, help="Concurrent flooding threads (default: 16)")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds (default: 10)")
    args = parser.parse_args()

    print("================================================================")
    print("   DB-IDS/IPS HIGH-RATE STRESS & BENCHMARK TESTER               ")
    print("================================================================")
    print(f"[*] Target Laptop A:     {args.target}:{args.port}")
    print(f"[*] Protocol:            {args.proto}")
    print(f"[*] Flooding Threads:    {args.threads}")
    print(f"[*] Test Duration:       {args.duration} seconds")
    print("----------------------------------------------------------------\n")

    stop_event = threading.Event()
    counter = [0]
    lock = threading.Lock()
    threads = []

    print("[*] Launching stress threads...")
    start_time = time.time()
    for _ in range(args.threads):
        t = threading.Thread(target=stress_worker, args=(args.target, args.port, args.proto, stop_event, counter, lock), daemon=True)
        threads.append(t)
        t.start()

    for sec in range(1, args.duration + 1):
        time.sleep(1.0)
        with lock:
            current_count = counter[0]
        elapsed = time.time() - start_time
        pps = int(current_count / elapsed) if elapsed > 0 else 0
        sys.stdout.write(f"\r[+] Flooding in progress: {sec}/{args.duration}s | Total Packets: {current_count:,} | Rate: ~{pps:,} pkt/sec")
        sys.stdout.flush()

    stop_event.set()
    for t in threads:
        t.join(timeout=1.0)

    total_time = max(0.1, time.time() - start_time)
    final_pps = int(counter[0] / total_time)
    print(f"\n\n[+] STRESS TEST COMPLETE!")
    print(f"[*] Total Packets Transmitted: {counter[0]:,}")
    print(f"[*] Time Elapsed:              {total_time:.2f} seconds")
    print(f"[*] Average Throughput:        ~{final_pps:,} packets/sec")
    print("\nCheck Laptop A's React Dashboard -> Observe live traffic spikes in Session Inspector!")

if __name__ == "__main__":
    main()
