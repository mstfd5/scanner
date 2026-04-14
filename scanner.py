#!/usr/bin/env python3
"""
Active Network Mapper & Topology Discovery Tool
Custom Nmap-like port scanner with service detection
"""

import socket
import ipaddress
import threading
import queue
import sys
import json
import csv
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama for Windows
init(autoreset=True)

# Common ports and their typical services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB"
}

# Vulnerable ports that trigger special warnings
VULNERABLE_PORTS = {
    21: "FTP - Anonymous access or weak password risk",
    23: "Telnet - Cleartext communication",
    445: "SMB - EternalBlue vulnerability possible",
    3389: "RDP - BlueKeep vulnerability possible"
}

class NetworkScanner:
    def __init__(self, target_network, port_range=(1, 1024), threads=100, timeout=1.0):
        """
        target_network: "192.168.1.0/24" or "192.168.1.1"
        port_range: (start, end)
        threads: Number of concurrent threads for scanning
        timeout: Connection timeout in seconds
        """
        self.target_network = target_network
        self.port_start, self.port_end = port_range
        self.threads = threads
        self.timeout = timeout
        self.alive_hosts = []
        self.scan_results = {}  # {ip: {port: service}}
        self.queue = queue.Queue()
        self.lock = threading.Lock()
        
    def get_hosts_from_network(self):
        """Extract all host IPs from the given network or single IP"""
        hosts = []
        try:
            # Check if CIDR format (e.g., 192.168.1.0/24)
            if '/' in self.target_network:
                network = ipaddress.ip_network(self.target_network, strict=False)
                for ip in network.hosts():
                    hosts.append(str(ip))
            else:
                # Single IP
                hosts.append(self.target_network)
        except Exception as e:
            print(f"[!] Invalid network format: {e}")
            sys.exit(1)
        return hosts
    
    def ping_host(self, ip):
        """Check if host is alive by trying common ports"""
        try:
            # Try common ports to see if host responds
            for test_port in [80, 443, 22]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, test_port))
                sock.close()
                if result == 0:
                    return True
            return False
        except:
            return False
    
    def scan_port(self, ip, port):
        """Scan a single port, detect service if open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                # Simple banner grabbing
                banner = ""
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    s.connect((ip, port))
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(256).decode(errors='ignore').strip()
                    s.close()
                except:
                    pass
                
                with self.lock:
                    if ip not in self.scan_results:
                        self.scan_results[ip] = {}
                    self.scan_results[ip][port] = {"service": service, "banner": banner}
                    
                # Colorized output
                if port in VULNERABLE_PORTS:
                    print(f"{Fore.RED} {ip}:{port} OPEN - {service} - VULNERABLE! {VULNERABLE_PORTS[port]}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN} {ip}:{port} OPEN - {service}{Style.RESET_ALL}")
                return True
        except:
            pass
        return False
    
    def worker(self, ip):
        """Thread worker: processes ports from queue"""
        while True:
            try:
                port = self.queue.get_nowait()
            except queue.Empty:
                break
            self.scan_port(ip, port)
            self.queue.task_done()
    
    def scan_host(self, ip):
        """Scan all ports for a single host using thread pool"""
        # Fill queue with ports
        for port in range(self.port_start, self.port_end + 1):
            self.queue.put(port)
        
        # Create thread pool
        threads = []
        for _ in range(min(self.threads, self.port_end - self.port_start + 1)):
            t = threading.Thread(target=self.worker, args=(ip,))
            t.start()
            threads.append(t)
        
        # Wait for queue to empty
        self.queue.join()
        
        # Stop threads
        for t in threads:
            t.join()
    
    def scan_network(self):
        """Scan the entire network"""
        hosts = self.get_hosts_from_network()
        print(f"{Fore.CYAN} Target network: {self.target_network}")
        print(f"Hosts to scan: {len(hosts)}")
        print(f"Port range: {self.port_start}-{self.port_end}")
        print(f"Thread count: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        print("-" * 50)
        
        # First, find alive hosts with ping
        print(f"{Fore.YELLOW} Discovering alive hosts...{Style.RESET_ALL}")
        for ip in hosts:
            if self.ping_host(ip):
                self.alive_hosts.append(ip)
                print(f"{Fore.GREEN} Alive: {ip}{Style.RESET_ALL}")
        
        if not self.alive_hosts:
            print(f"{Fore.RED} No alive hosts found!{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN} Found {len(self.alive_hosts)} alive host(s). Starting port scan...{Style.RESET_ALL}")
        
        # Scan each alive host in parallel
        scan_threads = []
        for ip in self.alive_hosts:
            t = threading.Thread(target=self.scan_host, args=(ip,))
            t.start()
            scan_threads.append(t)
        
        for t in scan_threads:
            t.join()
    
    def export_json(self, filename="scan_report.json"):
        """Export results to JSON file"""
        report = {
            "scan_time": datetime.now().isoformat(),
            "target": self.target_network,
            "alive_hosts": self.alive_hosts,
            "open_ports": self.scan_results
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
        print(f"{Fore.GREEN} JSON report saved: {filename}{Style.RESET_ALL}")
    
    def export_csv(self, filename="scan_report.csv"):
        """Export results to CSV file"""
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Port", "Service", "Banner"])
            for ip, ports in self.scan_results.items():
                for port, info in ports.items():
                    writer.writerow([ip, port, info["service"], info["banner"]])
        print(f"{Fore.GREEN} CSV report saved: {filename}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Display summary table"""
        print("\n" + "="*60)
        print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print("="*60)
        total_open = sum(len(ports) for ports in self.scan_results.values())
        print(f"Alive hosts: {len(self.alive_hosts)}")
        print(f"Total open ports: {total_open}")
        print(f"\nVulnerable ports found:")
        vuln_found = False
        for ip, ports in self.scan_results.items():
            for port, info in ports.items():
                if port in VULNERABLE_PORTS:
                    print(f"  {Fore.RED}{ip}:{port} - {info['service']} - {VULNERABLE_PORTS[port]}{Style.RESET_ALL}")
                    vuln_found = True
        if not vuln_found:
            print("  (No vulnerable ports found)")

def main():
    print("""
    ╔══════════════════════════════════════╗
    ║   Network Scanner - Mini Nmap        ║
    ║   Active Network Mapping Tool        ║
    ╚══════════════════════════════════════╝
    """)
    
    # Get target from command line or user input
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Target network or IP (e.g., 192.168.1.0/24 or 192.168.1.1): ")
    
    # Port range (optional)
    port_range = (1, 1024)  # Default: most common ports
    if len(sys.argv) > 2:
        try:
            start, end = map(int, sys.argv[2].split('-'))
            port_range = (start, end)
        except:
            pass
    
    # Thread count
    threads = 100
    if len(sys.argv) > 3:
        threads = int(sys.argv[3])
    
    scanner = NetworkScanner(target, port_range, threads, timeout=1.5)
    scanner.scan_network()
    
    if scanner.scan_results:
        scanner.print_summary()
        scanner.export_json()
        scanner.export_csv()
        print(f"\n{Fore.CYAN} Reports saved. Happy scanning!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED} No open ports found. Check your network settings.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()