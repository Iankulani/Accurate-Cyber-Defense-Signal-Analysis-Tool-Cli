#!/usr/bin/env python3
"""
Author:Ian Carter Kulani

"""

import os
import sys
import time
import socket
import threading
import subprocess
import platform
import json
import datetime
import logging
import requests
import sqlite3
from collections import deque, defaultdict
import select
import scapy.all as scapy
from scapy.all import IP, ICMP, TCP, UDP, ARP, Ether
import nmap
import psutil
import netifaces
from typing import Dict, List, Set, Optional, Tuple
import argparse
import readline
import signal
import configparser
from pathlib import Path
import hashlib
import base64
import zipfile
import tempfile

# Constants
VERSION = "2.0.0"
AUTHOR = "Cyber Security War Tool Team"
DEFAULT_CONFIG_FILE = "config.ini"
DATABASE_FILE = "threats.db"
HISTORY_FILE = "command_history.txt"
MAX_HISTORY = 1000
TELEGRAM_API_URL = "https://api.telegram.org/bot"

class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class CyberSecurityTool:
    """Main Cyber Security War Tool Class"""
    
    def __init__(self):
        self.running = True
        self.monitored_ips = set()
        self.threats_detected = []
        self.command_history = deque(maxlen=MAX_HISTORY)
        self.telegram_token = None
        self.telegram_chat_id = None
        self.telegram_last_update_id = 0
        self.monitoring_threads = {}
        self.analysis_results = {}
        self.system_status = "OPERATIONAL"
        self.db_conn = None
        self.nm = None
        self.setup_logging()
        self.setup_database()
        self.load_config()
        self.init_nmap()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cyber_tool.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_database(self):
        """Initialize SQLite database for threat storage"""
        try:
            self.db_conn = sqlite3.connect(DATABASE_FILE, check_same_thread=False)
            cursor = self.db_conn.cursor()
            
            # Create threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    port INTEGER,
                    protocol TEXT
                )
            ''')
            
            # Create monitoring table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS monitoring (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    added_date TEXT NOT NULL,
                    status TEXT NOT NULL
                )
            ''')
            
            # Create command history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    command TEXT NOT NULL
                )
            ''')
            
            self.db_conn.commit()
            self.logger.info("Database initialized successfully")
            
        except sqlite3.Error as e:
            self.logger.error(f"Database initialization error: {e}")
            
    def init_nmap(self):
        """Initialize Nmap scanner"""
        try:
            self.nm = nmap.PortScanner()
            self.logger.info("Nmap scanner initialized")
        except Exception as e:
            self.logger.error(f"Nmap initialization error: {e}")
            
    def load_config(self):
        """Load configuration from file"""
        self.config = configparser.ConfigParser()
        if os.path.exists(DEFAULT_CONFIG_FILE):
            self.config.read(DEFAULT_CONFIG_FILE)
            self.telegram_token = self.config.get('telegram', 'token', fallback=None)
            self.telegram_chat_id = self.config.get('telegram', 'chat_id', fallback=None)
            self.logger.info("Configuration loaded successfully")
        else:
            self.create_default_config()
            
    def create_default_config(self):
        """Create default configuration file"""
        self.config['telegram'] = {
            'token': 'YOUR_TELEGRAM_BOT_TOKEN',
            'chat_id': 'YOUR_CHAT_ID'
        }
        self.config['monitoring'] = {
            'ping_timeout': '2',
            'scan_delay': '1'
        }
        with open(DEFAULT_CONFIG_FILE, 'w') as configfile:
            self.config.write(configfile)
        self.logger.info("Default configuration file created")
        
    def save_command_history(self, command: str):
        """Save command to history"""
        timestamp = datetime.datetime.now().isoformat()
        self.command_history.append((timestamp, command))
        
        # Save to database
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                "INSERT INTO command_history (timestamp, command) VALUES (?, ?)",
                (timestamp, command)
            )
            self.db_conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"Error saving command history: {e}")
            
    def display_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════╗
║                   ACCURATE CYBER DEFENSE v{VERSION}                ║
║                    community:                                  ║
║                      Digital & Analog Security                 ║
╚════════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
        
    def print_green(self, text: str):
        """Print text in green color"""
        print(f"{Colors.GREEN}{text}{Colors.END}")
        
    def print_red(self, text: str):
        """Print text in red color"""
        print(f"{Colors.RED}{text}{Colors.END}")
        
    def print_yellow(self, text: str):
        """Print text in yellow color"""
        print(f"{Colors.YELLOW}{text}{Colors.END}")
        
    def print_cyan(self, text: str):
        """Print text in cyan color"""
        print(f"{Colors.CYAN}{text}{Colors.END}")

    def help_command(self):
        """Display help information"""
        help_text = f"""
{Colors.GREEN}{Colors.BOLD}AVAILABLE COMMANDS:{Colors.END}

{Colors.CYAN}Basic Commands:{Colors.END}
  {Colors.GREEN}help{Colors.END} - Show this help message
  {Colors.GREEN}start{Colors.END} - Start monitoring all IPs
  {Colors.GREEN}stop{Colors.END} - Stop all monitoring
  {Colors.GREEN}clear{Colors.END} - Clear the screen
  {Colors.GREEN}exit{Colors.END} - Exit the tool
  {Colors.GREEN}status{Colors.END} - Show system status
  {Colors.GREEN}reboot system{Colors.END} - Reboot the monitoring system

{Colors.CYAN}IP Management:{Colors.END}
  {Colors.GREEN}ping IP{Colors.END} - Ping a specific IP address
  {Colors.GREEN}scan IP{Colors.END} - Quick port scan on IP
  {Colors.GREEN}deep scan IP{Colors.END} - Comprehensive port scan (1-65535)
  {Colors.GREEN}analyse IP{Colors.END} - Deep analysis of IP
  {Colors.GREEN}monitoring IP{Colors.END} - Start monitoring specific IP
  {Colors.GREEN}kill IP{Colors.END} - Generate traffic to stress test IP
  {Colors.GREEN}add IP{Colors.END} - Add IP to monitoring list (supports bulk)
  {Colors.GREEN}remove IP{Colors.END} - Remove IP from monitoring
  {Colors.GREEN}location ip{Colors.END} - Get geographical location of IP

{Colors.CYAN}Threat Analysis:{Colors.END}
  {Colors.GREEN}view threats{Colors.END} - View detected threats
  {Colors.GREEN}history{Colors.END} - View command history

{Colors.CYAN}Reporting:{Colors.END}
  {Colors.GREEN}generate day report{Colors.END} - Generate daily security report
  {Colors.GREEN}generate weekly report{Colors.END} - Generate weekly security report
  {Colors.GREEN}generate monthly report{Colors.END} - Generate monthly security report
  {Colors.GREEN}generate annual report{Colors.END} - Generate annual security report
  {Colors.GREEN}export data{Colors.END} - Export data to Telegram

{Colors.CYAN}Telegram Integration:{Colors.END}
  {Colors.GREEN}config telegram token{Colors.END} - Configure Telegram bot token
  {Colors.GREEN}config telegram chat_id{Colors.END} - Configure Telegram chat ID
  {Colors.GREEN}test telegram connection{Colors.END} - Test Telegram connection

{Colors.YELLOW}Telegram Commands: /help, /start_monitoring_ip, /view, /ping_ip, /scan_ip, 
/deep_scan_ip, /kill_ip, /status, /add_ip, /location_ip, /remove_ip, 
/clear, /history, /generate_daily_report, /generate_weekly_report, 
/generate_monthly_report, /generate_annual_report, /reboot_system{Colors.END}
        """
        print(help_text)

    def ping_ip(self, ip_address: str) -> bool:
        """Ping an IP address with comprehensive analysis"""
        try:
            # Validate IP address
            try:
                socket.inet_aton(ip_address)
            except socket.error:
                self.print_red(f"Invalid IP address: {ip_address}")
                return False

            self.print_cyan(f"Pinging {ip_address} with comprehensive analysis...")
            
            # Method 1: Using system ping command
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip_address]
            
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.print_green(f"✓ {ip_address} is reachable")
                    
                    # Extract ping statistics
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if "time=" in line or "time<" in line:
                            print(f"  Response: {line.strip()}")
                    
                    # Additional network analysis
                    self.analyze_network_health(ip_address)
                    return True
                else:
                    self.print_red(f"✗ {ip_address} is not reachable")
                    return False
                    
            except subprocess.TimeoutExpired:
                self.print_red(f"✗ Ping timeout for {ip_address}")
                return False
                
        except Exception as e:
            self.logger.error(f"Ping error: {e}")
            self.print_red(f"Ping failed: {str(e)}")
            return False

    def analyze_network_health(self, ip_address: str):
        """Perform additional network health analysis"""
        try:
            # DNS resolution test
            start_time = time.time()
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                dns_time = time.time() - start_time
                self.print_cyan(f"  DNS Resolution: {hostname} ({dns_time:.3f}s)")
            except:
                self.print_yellow("  DNS Resolution: Failed")
            
            # Port connectivity quick test
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            
            if open_ports:
                self.print_yellow(f"  Open common ports: {open_ports}")
            else:
                self.print_green("  No common ports open")
                
        except Exception as e:
            self.logger.error(f"Network health analysis error: {e}")

    def scan_ip(self, ip_address: str) -> Dict:
        """Perform quick port scan on common ports"""
        try:
            self.print_cyan(f"Scanning common ports on {ip_address}...")
            
            common_ports = [21, 22, 23, 25, 53, 80, 110, 113, 135, 139, 143, 443, 
                          445, 993, 995, 1723, 3306, 3389, 5900, 8080]
            
            results = {
                'ip': ip_address,
                'scan_time': datetime.datetime.now().isoformat(),
                'open_ports': [],
                'services': {}
            }
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_address, port))
                    sock.close()
                    
                    if result == 0:
                        service_name = self.get_service_name(port)
                        results['open_ports'].append(port)
                        results['services'][port] = service_name
                        self.print_green(f"  Port {port}/tcp open - {service_name}")
                        
                except Exception as e:
                    continue
            
            self.print_cyan(f"Scan completed. Found {len(results['open_ports'])} open ports.")
            return results
            
        except Exception as e:
            self.logger.error(f"Scan error: {e}")
            self.print_red(f"Scan failed: {str(e)}")
            return {}

    def deep_scan_ip(self, ip_address: str) -> Dict:
        """Perform comprehensive port scan (1-65535)"""
        try:
            if not self.nm:
                self.print_red("Nmap scanner not available")
                return {}
                
            self.print_cyan(f"Starting deep scan on {ip_address} (ports 1-65535)...")
            self.print_yellow("This may take several minutes...")
            
            start_time = time.time()
            
            # Perform nmap scan
            self.nm.scan(ip_address, '1-65535', arguments='-sS -T4')
            
            scan_time = time.time() - start_time
            
            if ip_address in self.nm.all_hosts():
                host = self.nm[ip_address]
                results = {
                    'ip': ip_address,
                    'scan_time': datetime.datetime.now().isoformat(),
                    'scan_duration': f"{scan_time:.2f}s",
                    'state': host.state(),
                    'open_ports': [],
                    'services': {}
                }
                
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service_info = host[proto][port]
                        results['open_ports'].append(port)
                        results['services'][port] = {
                            'name': service_info.get('name', 'unknown'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'state': service_info.get('state', '')
                        }
                        
                        self.print_green(
                            f"  Port {port}/{proto} {service_info['state']} - "
                            f"{service_info.get('name', 'unknown')} "
                            f"{service_info.get('product', '')} "
                            f"{service_info.get('version', '')}"
                        )
                
                self.print_cyan(
                    f"Deep scan completed in {scan_time:.2f}s. "
                    f"Found {len(results['open_ports'])} open ports."
                )
                return results
            else:
                self.print_red(f"Host {ip_address} not found in scan results")
                return {}
                
        except Exception as e:
            self.logger.error(f"Deep scan error: {e}")
            self.print_red(f"Deep scan failed: {str(e)}")
            return {}

    def get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        service_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 113: "Ident", 135: "RPC", 139: "NetBIOS",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Proxy"
        }
        return service_map.get(port, "Unknown")

    def kill_ip(self, ip_address: str):
        """Generate network traffic to stress test IP"""
        try:
            self.print_cyan(f"Starting traffic generation to {ip_address}...")
            self.print_yellow("Warning: Use responsibly and only on authorized systems")
            
            # Generate various types of traffic
            threads = []
            
            # ICMP flood
            icmp_thread = threading.Thread(target=self._icmp_flood, args=(ip_address,))
            threads.append(icmp_thread)
            
            # TCP SYN flood
            tcp_thread = threading.Thread(target=self._tcp_syn_flood, args=(ip_address,))
            threads.append(tcp_thread)
            
            # UDP flood
            udp_thread = threading.Thread(target=self._udp_flood, args=(ip_address,))
            threads.append(udp_thread)
            
            for thread in threads:
                thread.daemon = True
                thread.start()
            
            # Run for 30 seconds
            self.print_cyan("Traffic generation started for 30 seconds...")
            time.sleep(30)
            
            self.print_green("Traffic generation completed")
            
        except Exception as e:
            self.logger.error(f"Kill IP error: {e}")
            self.print_red(f"Traffic generation failed: {str(e)}")

    def _icmp_flood(self, ip_address: str):
        """Generate ICMP flood"""
        try:
            packet = IP(dst=ip_address)/ICMP()
            for _ in range(1000):  # Limited for safety
                scapy.send(packet, verbose=0)
                time.sleep(0.01)
        except Exception as e:
            self.logger.error(f"ICMP flood error: {e}")

    def _tcp_syn_flood(self, ip_address: str):
        """Generate TCP SYN flood"""
        try:
            for port in range(80, 90):  # Limited port range
                packet = IP(dst=ip_address)/TCP(dport=port, flags='S')
                for _ in range(100):  # Limited for safety
                    scapy.send(packet, verbose=0)
                    time.sleep(0.01)
        except Exception as e:
            self.logger.error(f"TCP SYN flood error: {e}")

    def _udp_flood(self, ip_address: str):
        """Generate UDP flood"""
        try:
            packet = IP(dst=ip_address)/UDP(dport=53)
            for _ in range(1000):  # Limited for safety
                scapy.send(packet, verbose=0)
                time.sleep(0.01)
        except Exception as e:
            self.logger.error(f"UDP flood error: {e}")

    def add_ip(self, ip_address: str):
        """Add IP address to monitoring list"""
        try:
            # Validate IP
            try:
                socket.inet_aton(ip_address)
            except socket.error:
                self.print_red(f"Invalid IP address: {ip_address}")
                return
            
            if ip_address in self.monitored_ips:
                self.print_yellow(f"IP {ip_address} is already being monitored")
                return
            
            self.monitored_ips.add(ip_address)
            
            # Save to database
            cursor = self.db_conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO monitoring (ip_address, added_date, status) VALUES (?, ?, ?)",
                (ip_address, datetime.datetime.now().isoformat(), 'active')
            )
            self.db_conn.commit()
            
            self.print_green(f"✓ Added {ip_address} to monitoring list")
            self.logger.info(f"Added IP {ip_address} to monitoring")
            
        except Exception as e:
            self.logger.error(f"Add IP error: {e}")
            self.print_red(f"Failed to add IP: {str(e)}")

    def remove_ip(self, ip_address: str):
        """Remove IP address from monitoring list"""
        try:
            if ip_address in self.monitored_ips:
                self.monitored_ips.remove(ip_address)
                
                # Remove from database
                cursor = self.db_conn.cursor()
                cursor.execute("DELETE FROM monitoring WHERE ip_address = ?", (ip_address,))
                self.db_conn.commit()
                
                # Stop monitoring thread if running
                if ip_address in self.monitoring_threads:
                    self.monitoring_threads[ip_address]['stop'] = True
                    del self.monitoring_threads[ip_address]
                
                self.print_green(f"✓ Removed {ip_address} from monitoring list")
                self.logger.info(f"Removed IP {ip_address} from monitoring")
            else:
                self.print_yellow(f"IP {ip_address} is not in monitoring list")
                
        except Exception as e:
            self.logger.error(f"Remove IP error: {e}")
            self.print_red(f"Failed to remove IP: {str(e)}")

    def start_monitoring(self, specific_ip: str = None):
        """Start monitoring IP addresses"""
        try:
            if specific_ip:
                ips_to_monitor = [specific_ip]
                self.print_cyan(f"Starting monitoring for {specific_ip}")
            else:
                ips_to_monitor = list(self.monitored_ips)
                self.print_cyan(f"Starting monitoring for {len(ips_to_monitor)} IPs")
            
            for ip_address in ips_to_monitor:
                if ip_address in self.monitoring_threads:
                    self.print_yellow(f"Already monitoring {ip_address}")
                    continue
                
                # Start monitoring thread
                stop_event = threading.Event()
                thread = threading.Thread(
                    target=self._monitor_ip,
                    args=(ip_address, stop_event)
                )
                thread.daemon = True
                thread.start()
                
                self.monitoring_threads[ip_address] = {
                    'thread': thread,
                    'stop': stop_event
                }
                
                self.print_green(f"✓ Started monitoring {ip_address}")
                
        except Exception as e:
            self.logger.error(f"Start monitoring error: {e}")
            self.print_red(f"Failed to start monitoring: {str(e)}")

    def _monitor_ip(self, ip_address: str, stop_event: threading.Event):
        """Monitor IP address for changes and threats"""
        last_status = None
        
        while not stop_event.is_set():
            try:
                # Check if IP is reachable
                is_reachable = self.ping_ip_silent(ip_address)
                current_status = "online" if is_reachable else "offline"
                
                if last_status is not None and current_status != last_status:
                    message = f"IP {ip_address} status changed: {last_status} → {current_status}"
                    self.print_yellow(message)
                    self.log_threat(ip_address, "Status Change", "medium", message)
                    
                    # Send Telegram notification if configured
                    if self.telegram_token and self.telegram_chat_id:
                        self.send_telegram_message(message)
                
                last_status = current_status
                
                # Perform periodic security checks
                self._perform_security_checks(ip_address)
                
                # Wait before next check
                stop_event.wait(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Monitoring error for {ip_address}: {e}")
                stop_event.wait(30)  # Wait 30 seconds on error

    def ping_ip_silent(self, ip_address: str) -> bool:
        """Silent ping for monitoring purposes"""
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", ip_address]
            result = subprocess.run(command, capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def _perform_security_checks(self, ip_address: str):
        """Perform security checks on monitored IP"""
        try:
            # Check for open suspicious ports
            suspicious_ports = [23, 135, 139, 445, 1433, 3389]
            for port in suspicious_ports:
                if self._is_port_open(ip_address, port):
                    threat_msg = f"Suspicious port {port} open on {ip_address}"
                    self.log_threat(ip_address, "Suspicious Port", "high", threat_msg)
                    
                    if self.telegram_token and self.telegram_chat_id:
                        self.send_telegram_message(f"🚨 THREAT: {threat_msg}")
                        
        except Exception as e:
            self.logger.error(f"Security check error for {ip_address}: {e}")

    def _is_port_open(self, ip_address: str, port: int) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except:
            return False

    def log_threat(self, ip_address: str, threat_type: str, severity: str, description: str, port: int = None):
        """Log security threat to database"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                """INSERT INTO threats 
                (timestamp, ip_address, threat_type, severity, description, port) 
                VALUES (?, ?, ?, ?, ?, ?)""",
                (datetime.datetime.now().isoformat(), ip_address, threat_type, 
                 severity, description, port)
            )
            self.db_conn.commit()
            
            # Add to in-memory list
            self.threats_detected.append({
                'timestamp': datetime.datetime.now().isoformat(),
                'ip_address': ip_address,
                'threat_type': threat_type,
                'severity': severity,
                'description': description
            })
            
            self.logger.warning(f"Threat detected: {threat_type} - {description}")
            
        except Exception as e:
            self.logger.error(f"Error logging threat: {e}")

    def view_threats(self):
        """Display detected threats"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT 50")
            threats = cursor.fetchall()
            
            if not threats:
                self.print_green("No threats detected")
                return
            
            self.print_cyan(f"\n{'='*80}")
            self.print_cyan("DETECTED THREATS")
            self.print_cyan(f"{'='*80}")
            
            for threat in threats:
                id, timestamp, ip, threat_type, severity, description, port, protocol = threat
                
                color = Colors.GREEN
                if severity.lower() == 'high':
                    color = Colors.RED
                elif severity.lower() == 'medium':
                    color = Colors.YELLOW
                
                print(f"{color}[{severity.upper()}]{Colors.END} {timestamp}")
                print(f"  IP: {ip} | Type: {threat_type}")
                print(f"  Description: {description}")
                if port:
                    print(f"  Port: {port}")
                print()
                
        except Exception as e:
            self.logger.error(f"View threats error: {e}")
            self.print_red(f"Failed to view threats: {str(e)}")

    def get_ip_location(self, ip_address: str):
        """Get geographical location of IP address"""
        try:
            self.print_cyan(f"Getting location for {ip_address}...")
            
            # Using ipapi.co service
            response = requests.get(f"http://ipapi.co/{ip_address}/json/", timeout=10)
            data = response.json()
            
            if 'error' not in data:
                self.print_green(f"Location information for {ip_address}:")
                print(f"  Country: {data.get('country_name', 'Unknown')}")
                print(f"  Region: {data.get('region', 'Unknown')}")
                print(f"  City: {data.get('city', 'Unknown')}")
                print(f"  ISP: {data.get('org', 'Unknown')}")
                print(f"  Timezone: {data.get('timezone', 'Unknown')}")
                print(f"  Coordinates: {data.get('latitude', 'Unknown')}, {data.get('longitude', 'Unknown')}")
            else:
                self.print_red("Unable to retrieve location information")
                
        except Exception as e:
            self.logger.error(f"Location lookup error: {e}")
            self.print_red(f"Location lookup failed: {str(e)}")

    def generate_report(self, period: str):
        """Generate security reports"""
        try:
            cursor = self.db_conn.cursor()
            
            # Calculate date range based on period
            end_date = datetime.datetime.now()
            if period == 'day':
                start_date = end_date - datetime.timedelta(days=1)
            elif period == 'week':
                start_date = end_date - datetime.timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - datetime.timedelta(days=30)
            elif period == 'annual':
                start_date = end_date - datetime.timedelta(days=365)
            else:
                self.print_red("Invalid period specified")
                return
            
            # Get threats for period
            cursor.execute(
                "SELECT * FROM threats WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC",
                (start_date.isoformat(), end_date.isoformat())
            )
            threats = cursor.fetchall()
            
            # Generate report
            report = {
                'period': period,
                'generated_at': datetime.datetime.now().isoformat(),
                'time_range': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'summary': {
                    'total_threats': len(threats),
                    'high_severity': len([t for t in threats if t[4].lower() == 'high']),
                    'medium_severity': len([t for t in threats if t[4].lower() == 'medium']),
                    'low_severity': len([t for t in threats if t[4].lower() == 'low'])
                },
                'threats': threats
            }
            
            # Display report
            self._display_report(report)
            
            # Save report to file
            filename = f"security_report_{period}_{end_date.strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.print_green(f"Report saved as {filename}")
            
        except Exception as e:
            self.logger.error(f"Report generation error: {e}")
            self.print_red(f"Failed to generate report: {str(e)}")

    def _display_report(self, report: Dict):
        """Display generated report"""
        self.print_cyan(f"\n{'='*80}")
        self.print_cyan(f"SECURITY REPORT - {report['period'].upper()}")
        self.print_cyan(f"{'='*80}")
        
        summary = report['summary']
        print(f"Period: {report['time_range']['start']} to {report['time_range']['end']}")
        print(f"Generated: {report['generated_at']}")
        print(f"\nSummary:")
        print(f"  Total Threats: {summary['total_threats']}")
        print(f"  High Severity: {summary['high_severity']}")
        print(f"  Medium Severity: {summary['medium_severity']}")
        print(f"  Low Severity: {summary['low_severity']}")
        
        if report['threats']:
            self.print_cyan(f"\nRecent Threats:")
            for threat in report['threats'][:10]:  # Show last 10 threats
                id, timestamp, ip, threat_type, severity, description, port, protocol = threat
                color = Colors.RED if severity.lower() == 'high' else Colors.YELLOW
                print(f"  {color}{severity.upper()}{Colors.END} {timestamp} - {ip} - {threat_type}")

    def config_telegram_token(self, token: str):
        """Configure Telegram bot token"""
        try:
            self.telegram_token = token
            self.config['telegram']['token'] = token
            with open(DEFAULT_CONFIG_FILE, 'w') as configfile:
                self.config.write(configfile)
            self.print_green("✓ Telegram token configured successfully")
        except Exception as e:
            self.logger.error(f"Telegram token config error: {e}")
            self.print_red(f"Failed to configure token: {str(e)}")

    def config_telegram_chat_id(self, chat_id: str):
        """Configure Telegram chat ID"""
        try:
            self.telegram_chat_id = chat_id
            self.config['telegram']['chat_id'] = chat_id
            with open(DEFAULT_CONFIG_FILE, 'w') as configfile:
                self.config.write(configfile)
            self.print_green("✓ Telegram chat ID configured successfully")
        except Exception as e:
            self.logger.error(f"Telegram chat ID config error: {e}")
            self.print_red(f"Failed to configure chat ID: {str(e)}")

    def test_telegram_connection(self):
        """Test Telegram connection"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                self.print_red("Telegram token or chat ID not configured")
                return
            
            self.print_cyan("Testing Telegram connection...")
            
            response = requests.get(
                f"{TELEGRAM_API_URL}{self.telegram_token}/getMe",
                timeout=10
            )
            
            if response.status_code == 200:
                bot_info = response.json()
                if bot_info['ok']:
                    self.print_green("✓ Telegram connection successful")
                    print(f"  Bot: {bot_info['result']['first_name']}")
                    print(f"  Username: @{bot_info['result']['username']}")
                    
                    # Test message sending
                    message_response = self.send_telegram_message("🔒 ACCurate Cyber Defense Security Tool - Connection Test Successful!")
                    if message_response:
                        self.print_green("✓ Test message sent successfully")
                    else:
                        self.print_red("✗ Failed to send test message")
                else:
                    self.print_red("✗ Telegram connection failed")
            else:
                self.print_red(f"✗ Telegram API error: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Telegram connection test error: {e}")
            self.print_red(f"Telegram connection test failed: {str(e)}")

    def send_telegram_message(self, message: str) -> bool:
        """Send message to Telegram chat"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return False
            
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/sendMessage"
            payload = {
                'chat_id': self.telegram_chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200
            
        except Exception as e:
            self.logger.error(f"Send Telegram message error: {e}")
            return False

    def process_telegram_commands(self):
        """Process incoming Telegram commands"""
        try:
            if not self.telegram_token:
                return
            
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/getUpdates"
            params = {'offset': self.telegram_last_update_id + 1, 'timeout': 30}
            
            response = requests.get(url, params=params, timeout=35)
            if response.status_code == 200:
                updates = response.json()
                if updates['ok']:
                    for update in updates['result']:
                        self.telegram_last_update_id = update['update_id']
                        
                        if 'message' in update and 'text' in update['message']:
                            message = update['message']['text']
                            chat_id = update['message']['chat']['id']
                            
                            # Process command
                            self._handle_telegram_command(message, chat_id)
                            
        except Exception as e:
            self.logger.error(f"Telegram command processing error: {e}")

    def _handle_telegram_command(self, command: str, chat_id: str):
        """Handle Telegram bot commands"""
        try:
            original_chat_id = self.telegram_chat_id
            self.telegram_chat_id = chat_id  # Temporarily set for response
            
            if command.startswith('/'):
                cmd = command[1:].lower()
                
                if cmd == 'help':
                    help_text = """
🔒 <b>Cyber Security War Tool - Telegram Commands</b>

<b>Basic Commands:</b>
/help - Show this help
/status - System status
/reboot_system - Reboot monitoring

<b>IP Management:</b>
/ping_ip [IP] - Ping IP address
/scan_ip [IP] - Quick port scan
/deep_scan_ip [IP] - Deep port scan
/location_ip [IP] - Get IP location
/add_ip [IP] - Add IP to monitoring
/remove_ip [IP] - Remove IP from monitoring

<b>Monitoring:</b>
/start_monitoring_ip [IP] - Start monitoring IP
/view - View current threats

<b>Reporting:</b>
/generate_daily_report - Daily security report
/generate_weekly_report - Weekly security report
/generate_monthly_report - Monthly security report
/generate_annual_report - Annual security report
                    """
                    self.send_telegram_message(help_text)
                    
                elif cmd == 'status':
                    status_msg = f"🖥️ <b>System Status</b>\nStatus: {self.system_status}\nMonitored IPs: {len(self.monitored_ips)}\nActive Threats: {len(self.threats_detected)}"
                    self.send_telegram_message(status_msg)
                    
                elif cmd.startswith('ping_ip '):
                    ip = cmd[8:].strip()
                    if self.ping_ip(ip):
                        self.send_telegram_message(f"✅ {ip} is reachable")
                    else:
                        self.send_telegram_message(f"❌ {ip} is not reachable")
                        
                elif cmd.startswith('scan_ip '):
                    ip = cmd[8:].strip()
                    results = self.scan_ip(ip)
                    if results and results['open_ports']:
                        ports = ', '.join(map(str, results['open_ports']))
                        self.send_telegram_message(f"🔍 Scan results for {ip}:\nOpen ports: {ports}")
                    else:
                        self.send_telegram_message(f"🔍 No open ports found on {ip}")
                        
                elif cmd == 'view':
                    cursor = self.db_conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM threats WHERE timestamp > datetime('now', '-1 day')")
                    recent_threats = cursor.fetchone()[0]
                    self.send_telegram_message(f"⚠️ Recent threats (24h): {recent_threats}")
                    
            self.telegram_chat_id = original_chat_id
            
        except Exception as e:
            self.logger.error(f"Telegram command handling error: {e}")

    def reboot_system(self):
        """Reboot the monitoring system"""
        try:
            self.print_cyan("Rebooting monitoring system...")
            
            # Stop all monitoring threads
            for ip, monitor_info in self.monitoring_threads.items():
                monitor_info['stop'].set()
            
            self.monitoring_threads.clear()
            
            # Clear temporary data
            self.threats_detected.clear()
            
            # Restart monitoring for all IPs
            time.sleep(2)
            self.start_monitoring()
            
            self.system_status = "REBOOTED"
            self.print_green("✓ System rebooted successfully")
            
        except Exception as e:
            self.logger.error(f"System reboot error: {e}")
            self.print_red(f"System reboot failed: {str(e)}")

    def show_status(self):
        """Display system status"""
        self.print_cyan(f"\n{'='*50}")
        self.print_cyan("SYSTEM STATUS")
        self.print_cyan(f"{'='*50}")
        
        print(f"Tool Version: {VERSION}")
        print(f"System Status: {self.system_status}")
        print(f"Monitored IPs: {len(self.monitored_ips)}")
        print(f"Active Monitoring Threads: {len(self.monitoring_threads)}")
        print(f"Threats Detected: {len(self.threats_detected)}")
        print(f"Telegram Connected: {bool(self.telegram_token and self.telegram_chat_id)}")
        print(f"Database: {'Connected' if self.db_conn else 'Disconnected'}")
        
        # Show recent activity
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threats WHERE timestamp > datetime('now', '-1 hour')")
        recent_threats = cursor.fetchone()[0]
        print(f"Threats (last hour): {recent_threats}")

    def export_data(self):
        """Export data to Telegram"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                self.print_red("Telegram not configured")
                return
            
            self.print_cyan("Exporting data to Telegram...")
            
            # Create export package
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                export_data = {
                    'export_time': datetime.datetime.now().isoformat(),
                    'monitored_ips': list(self.monitored_ips),
                    'recent_threats': self.threats_detected[-50:] if self.threats_detected else [],
                    'system_status': self.system_status
                }
                json.dump(export_data, f, indent=2)
                temp_file = f.name
            
            # Send file via Telegram
            url = f"{TELEGRAM_API_URL}{self.telegram_token}/sendDocument"
            with open(temp_file, 'rb') as document:
                response = requests.post(
                    url,
                    data={'chat_id': self.telegram_chat_id},
                    files={'document': document}
                )
            
            # Clean up
            os.unlink(temp_file)
            
            if response.status_code == 200:
                self.print_green("✓ Data exported to Telegram successfully")
            else:
                self.print_red("✗ Failed to export data to Telegram")
                
        except Exception as e:
            self.logger.error(f"Export data error: {e}")
            self.print_red(f"Export failed: {str(e)}")

    def show_history(self):
        """Show command history"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT timestamp, command FROM command_history ORDER BY timestamp DESC LIMIT 20")
            history = cursor.fetchall()
            
            if not history:
                self.print_green("No command history")
                return
            
            self.print_cyan(f"\n{'='*60}")
            self.print_cyan("COMMAND HISTORY")
            self.print_cyan(f"{'='*60}")
            
            for timestamp, command in history:
                dt = datetime.datetime.fromisoformat(timestamp)
                print(f"{dt.strftime('%Y-%m-%d %H:%M:%S')} - {command}")
                
        except Exception as e:
            self.logger.error(f"Show history error: {e}")
            self.print_red(f"Failed to show history: {str(e)}")

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.display_banner()

    def analyse_ip(self, ip_address: str):
        """Perform comprehensive analysis on IP"""
        try:
            self.print_cyan(f"Starting comprehensive analysis for {ip_address}...")
            
            analysis_results = {
                'basic_info': {},
                'network_health': {},
                'security_assessment': {},
                'services': {},
                'recommendations': []
            }
            
            # Basic information
            analysis_results['basic_info'] = self._get_basic_ip_info(ip_address)
            
            # Network health
            analysis_results['network_health'] = self._assess_network_health(ip_address)
            
            # Security assessment
            analysis_results['security_assessment'] = self._perform_security_assessment(ip_address)
            
            # Service discovery
            analysis_results['services'] = self._discover_services(ip_address)
            
            # Display results
            self._display_analysis_results(ip_address, analysis_results)
            
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"IP analysis error: {e}")
            self.print_red(f"Analysis failed: {str(e)}")
            return {}

    def _get_basic_ip_info(self, ip_address: str) -> Dict:
        """Get basic IP information"""
        info = {}
        try:
            # DNS resolution
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
                info['hostname'] = hostname
            except:
                info['hostname'] = "Unknown"
            
            # IP type (public/private)
            if ip_address.startswith(('10.', '172.16.', '192.168.')):
                info['type'] = 'Private'
            else:
                info['type'] = 'Public'
                
        except Exception as e:
            self.logger.error(f"Basic IP info error: {e}")
            
        return info

    def _assess_network_health(self, ip_address: str) -> Dict:
        """Assess network health"""
        health = {}
        try:
            # Ping statistics
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip_address]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                health['reachability'] = 'Excellent'
                health['packet_loss'] = '0%'
            else:
                health['reachability'] = 'Poor'
                health['packet_loss'] = '100%'
                
        except Exception as e:
            self.logger.error(f"Network health assessment error: {e}")
            
        return health

    def _perform_security_assessment(self, ip_address: str) -> Dict:
        """Perform security assessment"""
        assessment = {'risk_level': 'Low', 'issues': []}
        try:
            # Check for common vulnerable ports
            vulnerable_ports = [21, 23, 135, 139, 445, 1433, 3389]
            for port in vulnerable_ports:
                if self._is_port_open(ip_address, port):
                    assessment['issues'].append(f"Vulnerable port {port} open")
                    assessment['risk_level'] = 'High'
            
            if not assessment['issues']:
                assessment['issues'].append("No obvious security issues detected")
                
        except Exception as e:
            self.logger.error(f"Security assessment error: {e}")
            
        return assessment

    def _discover_services(self, ip_address: str) -> Dict:
        """Discover running services"""
        services = {}
        try:
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3389]
            for port in common_ports:
                if self._is_port_open(ip_address, port):
                    services[port] = self.get_service_name(port)
                    
        except Exception as e:
            self.logger.error(f"Service discovery error: {e}")
            
        return services

    def _display_analysis_results(self, ip_address: str, results: Dict):
        """Display analysis results"""
        self.print_cyan(f"\n{'='*70}")
        self.print_cyan(f"COMPREHENSIVE ANALYSIS FOR {ip_address}")
        self.print_cyan(f"{'='*70}")
        
        # Basic Info
        self.print_green("\n[BASIC INFORMATION]")
        for key, value in results['basic_info'].items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        
        # Network Health
        self.print_green("\n[NETWORK HEALTH]")
        for key, value in results['network_health'].items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        
        # Security Assessment
        self.print_green("\n[SECURITY ASSESSMENT]")
        print(f"  Risk Level: {results['security_assessment']['risk_level']}")
        for issue in results['security_assessment']['issues']:
            print(f"  Issue: {issue}")
        
        # Services
        self.print_green("\n[DISCOVERED SERVICES]")
        if results['services']:
            for port, service in results['services'].items():
                print(f"  Port {port}: {service}")
        else:
            print("  No common services detected")

    def run(self):
        """Main tool execution loop"""
        self.display_banner()
        self.print_green("Cyber Security War Tool initialized successfully!")
        self.print_yellow("Type 'help' for available commands\n")
        
        # Start Telegram polling in background
        telegram_thread = threading.Thread(target=self._telegram_polling_loop, daemon=True)
        telegram_thread.start()
        
        while self.running:
            try:
                command = input(f"{Colors.GREEN}cyber-tool>{Colors.END} ").strip()
                
                if not command:
                    continue
                    
                self.save_command_history(command)
                self.process_command(command)
                
            except KeyboardInterrupt:
                self.print_yellow("\nUse 'exit' to quit the tool")
            except EOFError:
                break
            except Exception as e:
                self.logger.error(f"Main loop error: {e}")
                self.print_red(f"Error: {str(e)}")

    def _telegram_polling_loop(self):
        """Background thread for Telegram polling"""
        while self.running:
            try:
                self.process_telegram_commands()
                time.sleep(2)
            except Exception as e:
                self.logger.error(f"Telegram polling error: {e}")
                time.sleep(10)

    def process_command(self, command: str):
        """Process user commands"""
        cmd_lower = command.lower()
        
        try:
            if cmd_lower == 'help':
                self.help_command()
                
            elif cmd_lower == 'exit':
                self.shutdown()
                
            elif cmd_lower == 'clear':
                self.clear_screen()
                
            elif cmd_lower == 'status':
                self.show_status()
                
            elif cmd_lower == 'view threats':
                self.view_threats()
                
            elif cmd_lower == 'history':
                self.show_history()
                
            elif cmd_lower == 'start':
                self.start_monitoring()
                
            elif cmd_lower == 'stop':
                self.stop_monitoring()
                
            elif cmd_lower == 'reboot system':
                self.reboot_system()
                
            elif cmd_lower == 'export data':
                self.export_data()
                
            elif cmd_lower == 'test telegram connection':
                self.test_telegram_connection()
                
            elif cmd_lower.startswith('ping '):
                ip = command[5:].strip()
                self.ping_ip(ip)
                
            elif cmd_lower.startswith('scan '):
                ip = command[5:].strip()
                self.scan_ip(ip)
                
            elif cmd_lower.startswith('deep scan '):
                ip = command[10:].strip()
                self.deep_scan_ip(ip)
                
            elif cmd_lower.startswith('analyse '):
                ip = command[8:].strip()
                self.analyse_ip(ip)
                
            elif cmd_lower.startswith('monitoring '):
                ip = command[11:].strip()
                self.start_monitoring(ip)
                
            elif cmd_lower.startswith('kill '):
                ip = command[5:].strip()
                self.kill_ip(ip)
                
            elif cmd_lower.startswith('add '):
                ip = command[4:].strip()
                self.add_ip(ip)
                
            elif cmd_lower.startswith('remove '):
                ip = command[7:].strip()
                self.remove_ip(ip)
                
            elif cmd_lower.startswith('location '):
                ip = command[9:].strip()
                self.get_ip_location(ip)
                
            elif cmd_lower.startswith('config telegram token '):
                token = command[22:].strip()
                self.config_telegram_token(token)
                
            elif cmd_lower.startswith('config telegram chat_id '):
                chat_id = command[24:].strip()
                self.config_telegram_chat_id(chat_id)
                
            elif cmd_lower == 'generate day report':
                self.generate_report('day')
                
            elif cmd_lower == 'generate weekly report':
                self.generate_report('week')
                
            elif cmd_lower == 'generate monthly report':
                self.generate_report('month')
                
            elif cmd_lower == 'generate annual report':
                self.generate_report('annual')
                
            else:
                self.print_red(f"Unknown command: {command}")
                self.print_yellow("Type 'help' for available commands")
                
        except Exception as e:
            self.logger.error(f"Command processing error: {e}")
            self.print_red(f"Error executing command: {str(e)}")

    def stop_monitoring(self):
        """Stop all monitoring activities"""
        try:
            for ip, monitor_info in self.monitoring_threads.items():
                monitor_info['stop'].set()
            
            self.monitoring_threads.clear()
            self.print_green("✓ All monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"Stop monitoring error: {e}")
            self.print_red(f"Failed to stop monitoring: {str(e)}")

    def shutdown(self):
        """Graceful shutdown"""
        self.print_cyan("\nShutting down Cyber Security War Tool...")
        
        # Stop all monitoring
        self.stop_monitoring()
        
        # Close database connection
        if self.db_conn:
            self.db_conn.close()
            
        self.print_green("✓ Tool shutdown completed")
        self.running = False

def main():
    """Main entry point"""
    try:
        # Check for root privileges on Linux
        if os.name != 'nt' and os.geteuid() != 0:
            print("Warning: Some features may require root privileges")
        
        tool = CyberSecurityTool()
        tool.run()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Tool interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Critical error: {e}{Colors.END}")
        logging.error(f"Critical error: {e}")

if __name__ == "__main__":
    main()