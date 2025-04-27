#!/usr/bin/env python3

import socket
import sys
import threading
import queue
import time
import argparse
from typing import List, Tuple
import ipaddress

class NetworkScanner:
    def __init__(self, target: str, ports: List[int], threads: int = 100):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.results = queue.Queue()
        self.active_threads = 0
        self.lock = threading.Lock()

    def scan_port(self, port: int) -> Tuple[int, bool, str]:
        """Scan a single port and return the results."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        try:
            result = sock.connect_ex((self.target, port))
            if result == 0:
                # Try to get service banner
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    banner = "No banner available"
                return port, True, banner
            return port, False, ""
        except socket.error:
            return port, False, ""
        finally:
            sock.close()

    def worker(self):
        """Worker function for thread pool."""
        while True:
            try:
                port = self.port_queue.get_nowait()
                result = self.scan_port(port)
                if result[1]:  # If port is open
                    self.results.put(result)
            except queue.Empty:
                break
            finally:
                self.port_queue.task_done()
                with self.lock:
                    self.active_threads -= 1

    def scan(self) -> List[Tuple[int, bool, str]]:
        """Perform the network scan."""
        print(f"\nStarting scan of {self.target}")
        print("=" * 50)
        
        self.port_queue = queue.Queue()
        for port in self.ports:
            self.port_queue.put(port)

        # Start worker threads
        threads = []
        for _ in range(min(self.threads, len(self.ports))):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
            with self.lock:
                self.active_threads += 1

        # Wait for all threads to complete
        self.port_queue.join()
        for t in threads:
            t.join()

        # Collect results
        results = []
        while not self.results.empty():
            results.append(self.results.get())
        
        return sorted(results, key=lambda x: x[0])

def validate_ip(ip: str) -> bool:
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_common_ports() -> List[int]:
    """Return a list of common ports to scan."""
    return [
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080
    ]

def main():
    parser = argparse.ArgumentParser(description='Network Security Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', help='Comma-separated list of ports to scan (default: common ports)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    args = parser.parse_args()

    # Validate target
    if not validate_ip(args.target):
        try:
            args.target = socket.gethostbyname(args.target)
        except socket.gaierror:
            print(f"Error: Could not resolve hostname {args.target}")
            sys.exit(1)

    # Parse ports
    if args.ports:
        try:
            ports = [int(p) for p in args.ports.split(',')]
        except ValueError:
            print("Error: Invalid port format. Use comma-separated numbers.")
            sys.exit(1)
    else:
        ports = get_common_ports()

    # Create scanner and perform scan
    scanner = NetworkScanner(args.target, ports, args.threads)
    start_time = time.time()
    results = scanner.scan()
    end_time = time.time()

    # Print results
    print("\nScan Results:")
    print("=" * 50)
    if results:
        print(f"Found {len(results)} open ports:")
        for port, is_open, banner in results:
            print(f"\nPort {port}:")
            print(f"  Status: {'Open' if is_open else 'Closed'}")
            if banner:
                print(f"  Banner: {banner}")
    else:
        print("No open ports found.")

    print(f"\nScan completed in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(0) 