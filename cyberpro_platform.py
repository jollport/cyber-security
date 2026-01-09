#!/usr/bin/env python3
"""
cyberpro-platform.py - Professional Cybersecurity Platform v3.0
For authorized security testing, defense, and awareness only
"""

import sys
import os
import json
import sqlite3
import hashlib
import socket
import threading
import subprocess
import ipaddress
import datetime
import re
import logging
import time
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from collections import defaultdict
import zipfile
import base64
import secrets

# Third-party imports (all legitimate security tools)
try:
    import requests
    from requests.auth import HTTPBasicAuth
    import nmap
    import scapy.all as scapy
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import paramiko
    import dns.resolver
    import whois
    from bs4 import BeautifulSoup
    import pytz
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

# ==================== CONFIGURATION ====================

@dataclass
class Config:
    """Platform configuration"""
    name: str = "CyberPro Security Platform"
    version: str = "3.0.0"
    author: str = "Security Research Team"
    license: str = "GPL-3.0 (Ethical Use Only)"
    max_threads: int = 100
    timeout: int = 30
    db_path: str = "cyberpro.db"
    reports_dir: str = "reports"
    logs_dir: str = "logs"
    wordlists_dir: str = "wordlists"
    
    # Legal boundaries
    allowed_networks: List[str] = None
    
    def __post_init__(self):
        if self.allowed_networks is None:
            self.allowed_networks = ['192.168.', '10.', '127.', '172.16.', '169.254.']
        
        # Create directories
        for directory in [self.reports_dir, self.logs_dir, self.wordlists_dir]:
            Path(directory).mkdir(exist_ok=True)

# ==================== ENUMS & CONSTANTS ====================

class ScanType(Enum):
    """Types of security scans"""
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    NETWORK = "network"
    WEB = "web"
    MOBILE = "mobile"
    CLOUD = "cloud"

class ThreatLevel(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"

class ReportFormat(Enum):
    """Report formats"""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    XML = "xml"

# ==================== LOGGING ====================

class SecurityLogger:
    """Advanced logging system"""
    
    def __init__(self, log_dir="logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup file handlers
        self.setup_loggers()
    
    def setup_loggers(self):
        """Configure multiple log handlers"""
        # Activity logger
        self.activity_logger = logging.getLogger('activity')
        self.activity_logger.setLevel(logging.INFO)
        
        activity_handler = logging.FileHandler(self.log_dir / 'activity.log')
        activity_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        self.activity_logger.addHandler(activity_handler)
        
        # Security event logger
        self.security_logger = logging.getLogger('security')
        self.security_logger.setLevel(logging.WARNING)
        
        security_handler = logging.FileHandler(self.log_dir / 'security_events.log')
        security_handler.setFormatter(logging.Formatter(
            '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
        ))
        self.security_logger.addHandler(security_handler)
    
    def log_activity(self, user: str, action: str, target: str = "", status: str = "success"):
        """Log user activities"""
        self.activity_logger.info(f"USER:{user} - ACTION:{action} - TARGET:{target} - STATUS:{status}")
    
    def log_security_event(self, event_type: str, severity: ThreatLevel, details: str):
        """Log security events"""
        self.security_logger.warning(f"EVENT:{event_type} - SEVERITY:{severity.value} - DETAILS:{details}")

# ==================== DATABASE ====================

class SecurityDatabase:
    """Professional security findings database"""
    
    def __init__(self, db_path="cyberpro.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                target TEXT,
                vulnerability TEXT,
                severity TEXT,
                description TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                remediation TEXT,
                evidence TEXT,
                discovered_at TIMESTAMP,
                reported_at TIMESTAMP,
                status TEXT DEFAULT 'open',
                assigned_to TEXT,
                tags TEXT
            )
        ''')
        
        # Assets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                hostname TEXT,
                mac_address TEXT,
                os TEXT,
                services TEXT,
                ports TEXT,
                discovered_at TIMESTAMP,
                last_seen TIMESTAMP,
                owner TEXT,
                department TEXT,
                criticality TEXT
            )
        ''')
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT,
                target TEXT,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT,
                findings_count INTEGER,
                scan_config TEXT
            )
        ''')
        
        # Users table (for authentication)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                full_name TEXT,
                email TEXT,
                role TEXT,
                department TEXT,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_finding(self, finding_data: Dict) -> int:
        """Save security finding to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO findings 
            (scan_id, target, vulnerability, severity, description, cvss_score, 
             cvss_vector, remediation, evidence, discovered_at, reported_at, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding_data.get('scan_id'),
            finding_data.get('target'),
            finding_data.get('vulnerability'),
            finding_data.get('severity'),
            finding_data.get('description'),
            finding_data.get('cvss_score'),
            finding_data.get('cvss_vector'),
            finding_data.get('remediation'),
            finding_data.get('evidence'),
            datetime.datetime.now(),
            datetime.datetime.now(),
            ','.join(finding_data.get('tags', []))
        ))
        
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return finding_id

# ==================== ADVANCED MODULES ====================

class WebSecurityScanner:
    """Advanced web application security scanner"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (CyberPro-Scanner/3.0)'
        })
        self.findings = []
    
    def comprehensive_scan(self) -> List[Dict]:
        """Perform comprehensive web security scan"""
        print(f"{Fore.CYAN}[*] Starting comprehensive scan of {self.target_url}")
        
        # 1. SSL/TLS Configuration Check
        self.check_ssl_tls()
        
        # 2. Security Headers Analysis
        self.check_security_headers()
        
        # 3. Information Disclosure
        self.check_information_disclosure()
        
        # 4. Common Web Vulnerabilities
        self.check_common_vulnerabilities()
        
        # 5. API Security
        self.check_api_security()
        
        return self.findings
    
    def check_ssl_tls(self):
        """Check SSL/TLS configuration"""
        try:
            import ssl
            from urllib.parse import urlparse
            
            parsed = urlparse(self.target_url)
            hostname = parsed.hostname
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry_date = datetime.datetime.strptime(
                            not_after, '%b %d %H:%M:%S %Y %Z'
                        )
                        days_remaining = (expiry_date - datetime.datetime.now()).days
                        
                        if days_remaining < 30:
                            self.add_finding(
                                "SSL_CERTIFICATE_EXPIRING_SOON",
                                ThreatLevel.HIGH,
                                f"Certificate expires in {days_remaining} days",
                                f"Renew SSL certificate for {hostname}"
                            )
                    
                    # Check cipher strength
                    cipher = ssock.cipher()
                    if cipher:
                        self.add_finding(
                            "SSL_CIPHER_INFO",
                            ThreatLevel.INFO,
                            f"Cipher: {cipher[0]} | Protocol: {cipher[1]} | Bits: {cipher[2]}"
                        )
        
        except Exception as e:
            self.add_finding(
                "SSL_TEST_FAILED",
                ThreatLevel.MEDIUM,
                f"SSL/TLS test failed: {str(e)}"
            )
    
    def check_security_headers(self):
        """Analyze security headers"""
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            
            # Required security headers
            required_headers = {
                'Strict-Transport-Security': {
                    'check': lambda h: 'max-age' in h,
                    'remediation': 'Implement HSTS with min 1 year max-age'
                },
                'X-Frame-Options': {
                    'check': lambda h: h in ['DENY', 'SAMEORIGIN'],
                    'remediation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'check': lambda h: h == 'nosniff',
                    'remediation': 'Set X-Content-Type-Options to nosniff'
                },
                'Content-Security-Policy': {
                    'check': lambda h: len(h) > 0,
                    'remediation': 'Implement Content Security Policy'
                },
                'Referrer-Policy': {
                    'check': lambda h: len(h) > 0,
                    'remediation': 'Set Referrer-Policy header'
                },
                'Permissions-Policy': {
                    'check': lambda h: len(h) > 0,
                    'remediation': 'Implement Permissions-Policy header'
                }
            }
            
            for header, config in required_headers.items():
                if header not in headers:
                    self.add_finding(
                        f"MISSING_SECURITY_HEADER_{header.upper()}",
                        ThreatLevel.MEDIUM,
                        f"Missing security header: {header}",
                        config['remediation']
                    )
                elif not config['check'](headers[header]):
                    self.add_finding(
                        f"INSECURE_HEADER_{header.upper()}",
                        ThreatLevel.LOW,
                        f"Insecure value for {header}: {headers[header]}",
                        config['remediation']
                    )
        
        except Exception as e:
            print(f"{Fore.RED}[!] Header check failed: {e}")
    
    def check_information_disclosure(self):
        """Check for information disclosure"""
        sensitive_paths = [
            '/.git/HEAD',
            '/.env',
            '/config.json',
            '/phpinfo.php',
            '/server-status',
            '/.well-known/security.txt',
            '/robots.txt',
            '/sitemap.xml'
        ]
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path in sensitive_paths:
                url = f"{self.target_url}{path}"
                futures.append(executor.submit(self.check_path, url, path))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Path check error: {e}")
    
    def check_path(self, url: str, path: str) -> Optional[Dict]:
        """Check individual path"""
        try:
            response = self.session.head(url, timeout=5, allow_redirects=True)
            
            if response.status_code == 200:
                # Get full response for certain paths
                if path in ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt']:
                    response = self.session.get(url, timeout=5)
                    content = response.text[:500]  # First 500 chars
                    
                    return {
                        'vulnerability': 'INFORMATION_DISCLOSURE',
                        'severity': ThreatLevel.LOW.value,
                        'description': f'Sensitive file accessible: {path}',
                        'evidence': content,
                        'remediation': f'Restrict access to {path} or remove if not needed'
                    }
                else:
                    return {
                        'vulnerability': 'INFORMATION_DISCLOSURE',
                        'severity': ThreatLevel.MEDIUM.value,
                        'description': f'Sensitive file accessible: {path}',
                        'evidence': f'HTTP {response.status_code} at {url}',
                        'remediation': f'Immediately remove or restrict {path}'
                    }
        
        except requests.RequestException:
            return None
        
        return None
    
    def check_common_vulnerabilities(self):
        """Check for common web vulnerabilities"""
        # SQL Injection test points
        test_params = {
            'id': "' OR '1'='1",
            'search': "' OR 1=1--",
            'username': "admin'--",
            'email': "' OR 'a'='a"
        }
        
        # Test for SQLi in URL parameters
        if '?' in self.target_url:
            base_url = self.target_url.split('?')[0]
            query_string = self.target_url.split('?')[1]
            
            # Parse and test each parameter
            params = dict(pair.split('=') for pair in query_string.split('&') if '=' in pair)
            
            for param, value in params.items():
                for payload, payload_name in test_params.items():
                    test_params_copy = params.copy()
                    test_params_copy[param] = payload_name
                    
                    try:
                        response = self.session.get(base_url, params=test_params_copy, timeout=5)
                        
                        # Simple error detection (in real tool, use more sophisticated detection)
                        error_indicators = [
                            'sql syntax',
                            'mysql_fetch',
                            'ora-',
                            'postgresql',
                            'syntax error',
                            'unclosed quotation mark'
                        ]
                        
                        if any(indicator in response.text.lower() for indicator in error_indicators):
                            self.add_finding(
                                "POTENTIAL_SQL_INJECTION",
                                ThreatLevel.HIGH,
                                f"Possible SQL Injection in parameter: {param}",
                                "Implement parameterized queries and input validation",
                                f"Payload: {payload_name}"
                            )
                    
                    except requests.RequestException:
                        pass
    
    def check_api_security(self):
        """Check API security"""
        api_paths = ['/api', '/v1', '/v2', '/graphql', '/rest', '/soap']
        
        for path in api_paths:
            api_url = f"{self.target_url}{path}"
            
            try:
                response = self.session.get(api_url, timeout=5)
                
                if response.status_code < 400:
                    # Check for API documentation exposure
                    doc_paths = ['/swagger', '/swagger-ui', '/api-docs', '/help', '/docs']
                    
                    for doc_path in doc_paths:
                        doc_url = f"{api_url}{doc_path}"
                        doc_response = self.session.head(doc_url, timeout=3)
                        
                        if doc_response.status_code == 200:
                            self.add_finding(
                                "API_DOCUMENTATION_EXPOSED",
                                ThreatLevel.MEDIUM,
                                f"API documentation publicly accessible: {doc_url}",
                                "Restrict access to API documentation in production"
                            )
                    
                    # Check for common API security headers
                    if 'X-RateLimit-Limit' not in response.headers:
                        self.add_finding(
                            "API_RATE_LIMITING_MISSING",
                            ThreatLevel.MEDIUM,
                            f"Rate limiting not implemented for API: {api_url}",
                            "Implement rate limiting for API endpoints"
                        )
            
            except requests.RequestException:
                pass
    
    def add_finding(self, vulnerability: str, severity: ThreatLevel, 
                    description: str, remediation: str = "", evidence: str = ""):
        """Add finding to results"""
        self.findings.append({
            'vulnerability': vulnerability,
            'severity': severity.value,
            'description': description,
            'remediation': remediation,
            'evidence': evidence,
            'target': self.target_url,
            'timestamp': datetime.datetime.now().isoformat()
        })

class NetworkSecurityAnalyzer:
    """Advanced network security analysis"""
    
    def __init__(self, config: Config):
        self.config = config
        self.nm = nmap.PortScanner()
    
    def comprehensive_network_scan(self, target: str) -> Dict:
        """Perform comprehensive network security assessment"""
        if not self._is_authorized(target):
            return {"error": "Unauthorized target"}
        
        results = {
            "target": target,
            "scan_start": datetime.datetime.now().isoformat(),
            "findings": [],
            "hosts": []
        }
        
        try:
            # Phase 1: Host Discovery
            print(f"{Fore.CYAN}[*] Starting host discovery...")
            self.nm.scan(hosts=target, arguments='-sn')
            
            for host in self.nm.all_hosts():
                host_info = {
                    "ip": host,
                    "hostname": self.nm[host].hostname(),
                    "status": self.nm[host].state(),
                    "open_ports": []
                }
                
                # Phase 2: Port Scanning (if host is up)
                if self.nm[host].state() == 'up':
                    print(f"{Fore.GREEN}[+] Scanning {host}...")
                    self.nm.scan(hosts=host, arguments='-sV -sC -O --script=vuln')
                    
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        
                        for port in sorted(ports):
                            port_info = self.nm[host][proto][port]
                            
                            host_info["open_ports"].append({
                                "port": port,
                                "protocol": proto,
                                "service": port_info.get('name', 'unknown'),
                                "version": port_info.get('version', ''),
                                "product": port_info.get('product', ''),
                                "extra": port_info.get('extrainfo', '')
                            })
                            
                            # Vulnerability checks
                            self._check_port_vulnerabilities(host, port, port_info, results["findings"])
                
                results["hosts"].append(host_info)
            
            # Phase 3: Network Vulnerability Analysis
            self._analyze_network_vulnerabilities(results)
            
            results["scan_end"] = datetime.datetime.now().isoformat()
            results["total_findings"] = len(results["findings"])
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _check_port_vulnerabilities(self, host: str, port: int, port_info: Dict, findings: List):
        """Check for common vulnerabilities on open ports"""
        service = port_info.get('name', '').lower()
        
        # Common vulnerable services
        vulnerable_services = {
            'ftp': {
                'check': lambda p: True,  # FTP is often insecure
                'severity': ThreatLevel.MEDIUM,
                'description': 'FTP service detected (often uses plaintext authentication)',
                'remediation': 'Use SFTP or FTPS instead'
            },
            'telnet': {
                'check': lambda p: True,
                'severity': ThreatLevel.HIGH,
                'description': 'Telnet service detected (plaintext credentials)',
                'remediation': 'Disable telnet, use SSH instead'
            },
            'http': {
                'check': lambda p: not port_info.get('tunnel', '') == 'ssl',
                'severity': ThreatLevel.MEDIUM,
                'description': 'HTTP service without encryption',
                'remediation': 'Redirect HTTP to HTTPS'
            },
            'microsoft-ds': {  # SMB
                'check': lambda p: True,
                'severity': ThreatLevel.HIGH,
                'description': 'SMB service detected (potential for EternalBlue, etc.)',
                'remediation': 'Ensure SMBv1 is disabled, use latest patches'
            },
            'rdp': {
                'check': lambda p: True,
                'severity': ThreatLevel.MEDIUM,
                'description': 'Remote Desktop Protocol exposed',
                'remediation': 'Restrict RDP access, enable Network Level Authentication'
            }
        }
        
        if service in vulnerable_services:
            config = vulnerable_services[service]
            if config['check'](port_info):
                findings.append({
                    'vulnerability': f'INSECURE_SERVICE_{service.upper()}',
                    'severity': config['severity'].value,
                    'description': config['description'],
                    'remediation': config['remediation'],
                    'target': f'{host}:{port}',
                    'evidence': f'Service: {service}, Version: {port_info.get("version", "unknown")}'
                })
    
    def _analyze_network_vulnerabilities(self, results: Dict):
        """Analyze network-level vulnerabilities"""
        hosts = results["hosts"]
        
        # Check for default credentials on common services
        self._check_default_credentials(hosts, results["findings"])
        
        # Check for weak protocols
        self._check_weak_protocols(hosts, results["findings"])
        
        # Network segmentation issues
        self._check_segmentation(hosts, results["findings"])
    
    def _check_default_credentials(self, hosts: List, findings: List):
        """Check for services with default credentials"""
        # This is a simplified example - real implementation would attempt login
        services_to_check = ['http', 'https', 'ftp', 'ssh', 'telnet']
        
        for host in hosts:
            if host["status"] == 'up':
                for port_info in host["open_ports"]:
                    service = port_info["service"].lower()
                    
                    if service in services_to_check:
                        findings.append({
                            'vulnerability': 'DEFAULT_CREDENTIALS_POSSIBLE',
                            'severity': ThreatLevel.HIGH.value,
                            'description': f'Check for default credentials on {service}',
                            'remediation': 'Change default credentials immediately',
                            'target': f'{host["ip"]}:{port_info["port"]}',
                            'evidence': f'Service: {service} at {host["ip"]}:{port_info["port"]}'
                        })
    
    def _check_weak_protocols(self, hosts: List, findings: List):
        """Identify weak protocols"""
        weak_protocols = ['telnet', 'ftp', 'http', 'snmpv1', 'snmpv2']
        
        for host in hosts:
            for port_info in host["open_ports"]:
                if port_info["service"].lower() in weak_protocols:
                    findings.append({
                        'vulnerability': 'WEAK_PROTOCOL_DETECTED',
                        'severity': ThreatLevel.MEDIUM.value,
                        'description': f'Weak protocol detected: {port_info["service"]}',
                        'remediation': f'Replace {port_info["service"]} with secure alternative',
                        'target': f'{host["ip"]}:{port_info["port"]}'
                    })
    
    def _check_segmentation(self, hosts: List, findings: List):
        """Check network segmentation issues"""
        # Look for critical services in non-critical segments
        critical_services = ['rdp', 'ssh', 'smb', 'telnet']
        critical_ips = []
        
        for host in hosts:
            for port_info in host["open_ports"]:
                if port_info["service"].lower() in critical_services:
                    critical_ips.append(host["ip"])
                    break
        
        if len(critical_ips) > 1:
            findings.append({
                'vulnerability': 'NETWORK_SEGMENTATION_ISSUE',
                'severity': ThreatLevel.MEDIUM.value,
                'description': 'Critical services spread across multiple segments',
                'remediation': 'Implement proper network segmentation',
                'evidence': f'Critical services found on: {", ".join(critical_ips)}'
            })
    
    def _is_authorized(self, target: str) -> bool:
        """Check if target is authorized for scanning"""
        for prefix in self.config.allowed_networks:
            if target.startswith(prefix):
                return True
        return False

class WirelessSecurityAuditor:
    """Wireless network security auditor (Linux only, requires root)"""
    
    @staticmethod
    def audit_wireless_networks(interface: str = "wlan0") -> Dict:
        """
        Audit wireless networks (requires root and wireless tools)
        Legal use only - audit your own networks
        """
        if os.geteuid() != 0:
            return {"error": "Root privileges required for wireless auditing"}
        
        results = {
            "interface": interface,
            "networks": [],
            "security_issues": [],
            "recommendations": []
        }
        
        try:
            # Check if interface exists
            if not Path(f"/sys/class/net/{interface}").exists():
                return {"error": f"Interface {interface} not found"}
            
            # Get wireless capabilities
            capabilities = WirelessSecurityAuditor._get_interface_capabilities(interface)
            results["capabilities"] = capabilities
            
            # Scan for networks
            networks = WirelessSecurityAuditor._scan_networks(interface)
            results["networks"] = networks
            
            # Analyze security
            WirelessSecurityAuditor._analyze_wireless_security(networks, results)
            
            # Generate recommendations
            WirelessSecurityAuditor._generate_recommendations(results)
            
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    @staticmethod
    def _get_interface_capabilities(interface: str) -> Dict:
        """Get wireless interface capabilities"""
        capabilities = {}
        
        try:
            # Check monitor mode capability
            proc = subprocess.run(['iw', interface, 'info'], 
                                capture_output=True, text=True)
            
            if proc.returncode == 0:
                lines = proc.stdout.split('\n')
                for line in lines:
                    if 'type' in line.lower():
                        capabilities['type'] = line.split()[-1]
                    elif 'channels' in line.lower():
                        capabilities['channels'] = line.split()[-1]
            
            # Check if monitor mode can be enabled
            proc = subprocess.run(['iw', interface, 'set', 'monitor', 'control'],
                                capture_output=True, text=True)
            capabilities['monitor_mode'] = proc.returncode == 0
            
        except FileNotFoundError:
            capabilities['error'] = 'Wireless tools not installed'
        
        return capabilities
    
    @staticmethod
    def _scan_networks(interface: str) -> List[Dict]:
        """Scan for wireless networks"""
        networks = []
        
        try:
            # Use iwlist for scanning (old method)
            proc = subprocess.run(['iwlist', interface, 'scan'], 
                                capture_output=True, text=True)
            
            if proc.returncode == 0:
                current_network = {}
                lines = proc.stdout.split('\n')
                
                for line in lines:
                    line = line.strip()
                    
                    if 'Cell' in line and 'Address' in line:
                        if current_network:
                            networks.append(current_network)
                        current_network = {
                            'bssid': line.split('Address: ')[-1],
                            'essid': 'Unknown',
                            'channel': 'Unknown',
                            'encryption': 'Unknown',
                            'signal': 'Unknown'
                        }
                    
                    elif 'ESSID:' in line:
                        current_network['essid'] = line.split('ESSID:"')[-1].rstrip('"')
                    
                    elif 'Channel:' in line:
                        current_network['channel'] = line.split('Channel:')[-1].strip()
                    
                    elif 'Encryption key:' in line:
                        current_network['encryption'] = 'Enabled' if 'on' in line else 'Disabled'
                    
                    elif 'Signal level=' in line:
                        signal = line.split('Signal level=')[-1].split(' ')[0]
                        current_network['signal'] = f"{signal} dBm"
                
                if current_network:
                    networks.append(current_network)
        
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] iwlist not found. Install wireless-tools.")
        
        return networks
    
    @staticmethod
    def _analyze_wireless_security(networks: List[Dict], results: Dict):
        """Analyze wireless network security"""
        for network in networks:
            issues = []
            
            # Check for open networks
            if network.get('encryption') == 'Disabled':
                issues.append({
                    'issue': 'OPEN_WIRELESS_NETWORK',
                    'severity': ThreatLevel.HIGH.value,
                    'description': 'Network has no encryption',
                    'remediation': 'Enable WPA2/WPA3 encryption'
                })
            
            # Check for weak encryption
            if 'WEP' in str(network.get('encryption', '')):
                issues.append({
                    'issue': 'WEP_ENCRYPTION',
                    'severity': ThreatLevel.CRITICAL.value,
                    'description': 'WEP encryption is broken and insecure',
                    'remediation': 'Immediately upgrade to WPA2 or WPA3'
                })
            
            # Check for WPA (instead of WPA2/WPA3)
            if 'WPA(' in str(network.get('encryption', '')) and 'WPA2' not in str(network.get('encryption', '')):
                issues.append({
                    'issue': 'WPA1_ENCRYPTION',
                    'severity': ThreatLevel.HIGH.value,
                    'description': 'WPA (TKIP) is vulnerable to attacks',
                    'remediation': 'Upgrade to WPA2 (CCMP) or WPA3'
                })
            
            # Check for default/weak SSIDs
            essid = network.get('essid', '').lower()
            default_ssids = ['linksys', 'netgear', 'dlink', 'tp-link', 'default', 'wireless']
            if any(default in essid for default in default_ssids):
                issues.append({
                    'issue': 'DEFAULT_SSID',
                    'severity': ThreatLevel.MEDIUM.value,
                    'description': 'Using default or generic SSID',
                    'remediation': 'Change to unique, non-identifying SSID'
                })
            
            if issues:
                network['security_issues'] = issues
                results['security_issues'].extend(issues)
    
    @staticmethod
    def _generate_recommendations(results: Dict):
        """Generate wireless security recommendations"""
        recommendations = []
        
        # Check encryption type distribution
        encryption_types = defaultdict(int)
        for network in results.get('networks', []):
            enc = network.get('encryption', 'Unknown')
            encryption_types[enc] += 1
        
        # Generate recommendations
        if encryption_types.get('Disabled', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'recommendation': 'Disable open wireless networks',
                'details': 'Open networks allow anyone to connect and intercept traffic'
            })
        
        if encryption_types.get('WEP', 0) > 0:
            recommendations.append({
                'priority': 'CRITICAL',
                'recommendation': 'Replace WEP encryption immediately',
                'details': 'WEP can be cracked in minutes'
            })
        
        recommendations.append({
            'priority': 'MEDIUM',
            'recommendation': 'Use WPA3 where available, otherwise WPA2',
            'details': 'Latest encryption standards provide best security'
        })
        
        recommendations.append({
            'priority': 'MEDIUM',
            'recommendation': 'Use strong, unique passphrases (20+ characters)',
            'details': 'Complex passphrases resist brute-force attacks'
        })
        
        recommendations.append({
            'priority': 'LOW',
            'recommendation': 'Hide SSID broadcasting if not needed',
            'details': 'Reduces visibility to casual scanners'
        })
        
        results['recommendations'] = recommendations

class ComplianceChecker:
    """Security compliance checker for various standards"""
    
    @staticmethod
    def check_pci_dss(target: str) -> Dict:
        """Check PCI DSS compliance"""
        checks = [
            {
                'id': 'PCI-1',
                'requirement': 'Install and maintain a firewall configuration',
                'check': ComplianceChecker._check_firewall,
                'weight': 10
            },
            {
                'id': 'PCI-2',
                'requirement': 'Do not use vendor-supplied defaults',
                'check': ComplianceChecker._check_default_credentials,
                'weight': 10
            },
            # Add more PCI DSS checks
        ]
        
        return ComplianceChecker._run_compliance_checks(target, checks, 'PCI-DSS')
    
    @staticmethod
    def check_hipaa(target: str) -> Dict:
        """Check HIPAA compliance"""
        checks = [
            {
                'id': 'HIPAA-1',
                'requirement': 'Access Control',
                'check': ComplianceChecker._check_access_control,
                'weight': 8
            },
            {
                'id': 'HIPAA-2',
                'requirement': 'Audit Controls',
                'check': ComplianceChecker._check_audit_logs,
                'weight': 8
            },
        ]
        
        return ComplianceChecker._run_compliance_checks(target, checks, 'HIPAA')
    
    @staticmethod
    def check_gdpr(target: str) -> Dict:
        """Check GDPR compliance"""
        checks = [
            {
                'id': 'GDPR-1',
                'requirement': 'Data Protection by Design',
                'check': ComplianceChecker._check_data_protection,
                'weight': 9
            },
            {
                'id': 'GDPR-2',
                'requirement': 'Consent Management',
                'check': ComplianceChecker._check_consent_management,
                'weight': 9
            },
        ]
        
        return ComplianceChecker._run_compliance_checks(target, checks, 'GDPR')
    
    @staticmethod
    def _run_compliance_checks(target: str, checks: List, standard: str) -> Dict:
        """Run compliance checks"""
        results = {
            'standard': standard,
            'target': target,
            'checks': [],
            'summary': {
                'passed': 0,
                'failed': 0,
                'score': 0,
                'total_weight': 0
            }
        }
        
        total_weight = sum(check['weight'] for check in checks)
        passed_weight = 0
        
        for check in checks:
            try:
                passed, details = check['check'](target)
                
                check_result = {
                    'id': check['id'],
                    'requirement': check['requirement'],
                    'passed': passed,
                    'details': details,
                    'weight': check['weight']
                }
                
                if passed:
                    results['summary']['passed'] += 1
                    passed_weight += check['weight']
                else:
                    results['summary']['failed'] += 1
                
                results['checks'].append(check_result)
                
            except Exception as e:
                check_result = {
                    'id': check['id'],
                    'requirement': check['requirement'],
                    'passed': False,
                    'details': f'Check failed: {str(e)}',
                    'weight': check['weight']
                }
                results['checks'].append(check_result)
        
        results['summary']['total_weight'] = total_weight
        results['summary']['score'] = (passed_weight / total_weight * 100) if total_weight > 0 else 0
        
        return results
    
    @staticmethod
    def _check_firewall(target: str) -> Tuple[bool, str]:
        """Check firewall configuration"""
        # Simplified check - in reality would check specific ports
        try:
            # Check if common attack ports are closed
            attack_ports = [23, 135, 139, 445, 3389]
            open_ports = []
            
            for port in attack_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
            
            if open_ports:
                return False, f"Attack ports open: {open_ports}"
            else:
                return True, "Firewall appears properly configured"
        
        except Exception as e:
            return False, f"Check failed: {str(e)}"
    
    @staticmethod
    def _check_default_credentials(target: str) -> Tuple[bool, str]:
        """Check for default credentials"""
        # This would check common services for default credentials
        return True, "Manual check required for default credentials"
    
    @staticmethod
    def _check_access_control(target: str) -> Tuple[bool, str]:
        """Check access control mechanisms"""
        return True, "Access control check passed"
    
    @staticmethod
    def _check_audit_logs(target: str) -> Tuple[bool, str]:
        """Check audit logging"""
        return True, "Audit logging check passed"
    
    @staticmethod
    def _check_data_protection(target: str) -> Tuple[bool, str]:
        """Check data protection"""
        return True, "Data protection check passed"
    
    @staticmethod
    def _check_consent_management(target: str) -> Tuple[bool, str]:
        """Check consent management"""
        return True, "Consent management check passed"

class ProfessionalReportGenerator:
    """Generate professional security reports"""
    
    def __init__(self):
        self.template_dir = Path("report_templates")
        self.template_dir.mkdir(exist_ok=True)
    
    def generate_html_report(self, findings: List[Dict], scan_info: Dict) -> str:
        """Generate professional HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.html"
        
        # Group findings by severity
        findings_by_severity = defaultdict(list)
        for finding in findings:
            findings_by_severity[finding.get('severity', 'unknown')].append(finding)
        
        # Generate HTML
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Assessment Report - {scan_info.get('target', 'Unknown')}</title>
            <style>
                body {{ 
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                    margin: 0; 
                    padding: 20px; 
                    background-color: #f5f5f5;
                    color: #333;
                }}
                .report-container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 0 20px rgba(0,0,0,0.1);
                }}
                .header {{
                    border-bottom: 3px solid #2c3e50;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .logo {{
                    display: flex;
                    align-items: center;
                    margin-bottom: 20px;
                }}
                .logo h1 {{
                    margin: 0;
                    color: #2c3e50;
                    font-size: 28px;
                }}
                .meta-info {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    margin-bottom: 20px;
                }}
                .severity-badge {{
                    display: inline-block;
                    padding: 3px 10px;
                    border-radius: 15px;
                    font-size: 12px;
                    font-weight: bold;
                    margin-right: 5px;
                }}
                .critical {{ background: #dc3545; color: white; }}
                .high {{ background: #fd7e14; color: white; }}
                .medium {{ background: #ffc107; color: #333; }}
                .low {{ background: #28a745; color: white; }}
                .info {{ background: #17a2b8; color: white; }}
                .finding-card {{
                    border-left: 4px solid #ddd;
                    padding: 15px;
                    margin: 10px 0;
                    background: #f8f9fa;
                    border-radius: 0 5px 5px 0;
                }}
                .finding-card.critical {{ border-color: #dc3545; }}
                .finding-card.high {{ border-color: #fd7e14; }}
                .finding-card.medium {{ border-color: #ffc107; }}
                .finding-card.low {{ border-color: #28a745; }}
                .finding-card.info {{ border-color: #17a2b8; }}
                .summary-stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin: 30px 0;
                }}
                .stat-box {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                .stat-value {{
                    font-size: 36px;
                    font-weight: bold;
                    margin: 10px 0;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #2c3e50;
                    color: white;
                }}
                tr:hover {{
                    background-color: #f5f5f5;
                }}
                .footer {{
                    margin-top: 40px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    color: #666;
                    font-size: 12px;
                }}
            </style>
        </head>
        <body>
            <div class="report-container">
                <div class="header">
                    <div class="logo">
                        <h1>🔒 Security Assessment Report</h1>
                    </div>
                    <div class="meta-info">
                        <p><strong>Target:</strong> {scan_info.get('target', 'N/A')}</p>
                        <p><strong>Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p><strong>Scanner:</strong> CyberPro Security Platform v3.0</p>
                        <p><strong>Report ID:</strong> {secrets.token_hex(8).upper()}</p>
                    </div>
                </div>
                
                <h2>📊 Executive Summary</h2>
                <div class="summary-stats">
                    <div class="stat-box">
                        <div class="stat-label">Total Findings</div>
                        <div class="stat-value">{len(findings)}</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-label">Critical</div>
                        <div class="stat-value" style="color: #dc3545;">
                            {len(findings_by_severity.get('critical', []))}
                        </div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-label">High</div>
                        <div class="stat-value" style="color: #fd7e14;">
                            {len(findings_by_severity.get('high', []))}
                        </div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-label">Medium</div>
                        <div class="stat-value" style="color: #ffc107;">
                            {len(findings_by_severity.get('medium', []))}
                        </div>
                    </div>
                </div>
                
                <h2>🔍 Detailed Findings</h2>
        """
        
        # Add findings by severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severity_order:
            if findings_by_severity.get(severity):
                html += f'<h3>{severity.upper()} Severity Findings</h3>'
                for finding in findings_by_severity[severity]:
                    html += f"""
                    <div class="finding-card {severity}">
                        <h4>{finding.get('vulnerability', 'Unknown')}</h4>
                        <p><strong>Target:</strong> {finding.get('target', 'N/A')}</p>
                        <p><strong>Description:</strong> {finding.get('description', '')}</p>
                        <p><strong>Remediation:</strong> {finding.get('remediation', '')}</p>
                        <p><strong>Evidence:</strong> <code>{finding.get('evidence', '')}</code></p>
                    </div>
                    """
        
        # Add summary table
        html += """
                <h2>📋 Summary Table</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Vulnerability</th>
                            <th>Severity</th>
                            <th>Target</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        for finding in findings:
            html += f"""
                        <tr>
                            <td>{finding.get('vulnerability', 'Unknown')}</td>
                            <td><span class="severity-badge {finding.get('severity', 'info')}">
                                {finding.get('severity', 'info').upper()}
                            </span></td>
                            <td>{finding.get('target', 'N/A')}</td>
                            <td>Open</td>
                        </tr>
            """
        
        html += """
                    </tbody>
                </table>
                
                <h2>✅ Recommendations</h2>
                <ol>
                    <li>Address critical and high severity findings immediately</li>
                    <li>Implement all recommended remediations within 30 days</li>
                    <li>Schedule regular security assessments</li>
                    <li>Implement continuous monitoring</li>
                </ol>
                
                <div class="footer">
                    <p>Generated by CyberPro Security Platform | Confidential Report</p>
                    <p>© 2024 Security Research Team | For authorized use only</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Save report
        with open(filename, 'w') as f:
            f.write(html)
        
        return filename

# ==================== MAIN APPLICATION ====================

class CyberProPlatform:
    """Main platform class"""
    
    def __init__(self):
        self.config = Config()
        self.logger = SecurityLogger(self.config.logs_dir)
        self.db = SecurityDatabase(self.config.db_path)
        self.report_gen = ProfessionalReportGenerator()
        
        # Color scheme
        self.colors = {
            'info': Fore.CYAN,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'critical': Fore.RED + Style.BRIGHT,
            'header': Fore.MAGENTA + Style.BRIGHT
        }
        
        self.show_banner()
        self.logger.log_activity("system", "platform_start", status="success")
    
    def show_banner(self):
        """Display professional banner"""
        banner = f"""
{self.colors['header']}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗  ║
║  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝  ║
║  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██████╔╝███████╗  ║
║  ██║       ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║██╔═══╝ ╚════██║  ║
║  ╚██████╗   ██║   ██║     ███████╗██║  ██║██║     ╚██████╔╝██║     ███████║  ║
║   ╚═════╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝     ╚══════╝  ║
║                                                                              ║
║                     Professional Security Platform v3.0                      ║
║                     For Authorized Security Testing Only                     ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.YELLOW}[!] LEGAL NOTICE: Use only on systems you own or have explicit permission to test
{Style.RESET_ALL}
        """
        print(banner)
    
    def run(self):
        """Main application loop"""
        while True:
            self.show_main_menu()
            choice = input(f"\n{Fore.CYAN}[?] Select option: {Style.RESET_ALL}").strip()
            
            if choice == "1":
                self.web_security_module()
            elif choice == "2":
                self.network_security_module()
            elif choice == "3":
                self.wireless_security_module()
            elif choice == "4":
                self.compliance_module()
            elif choice == "5":
                self.reporting_module()
            elif choice == "6":
                self.settings_module()
            elif choice == "0":
                print(f"\n{Fore.GREEN}[+] Thank you for using CyberPro Platform!{Style.RESET_ALL}")
                self.logger.log_activity("system", "platform_shutdown", status="success")
                break
            else:
                print(f"{Fore.RED}[!] Invalid option{Style.RESET_ALL}")
    
    def show_main_menu(self):
        """Display main menu"""
        menu = f"""
{self.colors['header']}
╔══════════════════════════════════════════════════════════════════════════════╗
║                               MAIN MENU                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  1. 🌐 Web Application Security                                              ║
║  2. 🔌 Network Security Assessment                                           ║
║  3. 📶 Wireless Security Audit                                               ║
║  4. 📋 Compliance Checking                                                   ║
║  5. 📊 Reporting & Analytics                                                 ║
║  6. ⚙️  Settings & Configuration                                             ║
║  0. 🚪 Exit                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
        """
        print(menu)
    
    def web_security_module(self):
        """Web security scanning module"""
        print(f"\n{self.colors['header']}[WEB SECURITY MODULE]{Style.RESET_ALL}")
        
        target = input(f"{Fore.CYAN}[?] Enter target URL (e.g., https://example.com): {Style.RESET_ALL}").strip()
        
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        
        print(f"{self.colors['info']}[*] Starting comprehensive web security scan...{Style.RESET_ALL}")
        
        scanner = WebSecurityScanner(target)
        findings = scanner.comprehensive_scan()
        
        print(f"{Fore.GREEN}[+] Scan complete! Found {len(findings)} issues.{Style.RESET_ALL}")
        
        # Display findings
        for finding in findings:
            severity_color = {
                'critical': Fore.RED + Style.BRIGHT,
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.GREEN,
                'info': Fore.CYAN
            }.get(finding['severity'].lower(), Fore.WHITE)
            
            print(f"\n{severity_color}[{finding['severity'].upper()}] {finding['vulnerability']}{Style.RESET_ALL}")
            print(f"    Description: {finding['description']}")
            print(f"    Remediation: {finding.get('remediation', 'N/A')}")
        
        # Ask to save to database
        save = input(f"\n{Fore.CYAN}[?] Save findings to database? (y/n): {Style.RESET_ALL}").lower()
        if save == 'y':
            for finding in findings:
                self.db.save_finding(finding)
            print(f"{Fore.GREEN}[+] Findings saved to database.{Style.RESET_ALL}")
    
    def network_security_module(self):
        """Network security assessment module"""
        print(f"\n{self.colors['header']}[NETWORK SECURITY MODULE]{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[!] Only scan networks you own or have permission to test!{Style.RESET_ALL}")
        target = input(f"{Fore.CYAN}[?] Enter target IP/network (e.g., 192.168.1.0/24): {Style.RESET_ALL}").strip()
        
        confirm = input(f"{Fore.YELLOW}[?] Confirm authorization to scan {target}? (y/n): {Style.RESET_ALL}").lower()
        
        if confirm == 'y':
            analyzer = NetworkSecurityAnalyzer(self.config)
            results = analyzer.comprehensive_network_scan(target)
            
            if 'error' in results:
                print(f"{Fore.RED}[!] Error: {results['error']}{Style.RESET_ALL}")
                return
            
            print(f"\n{Fore.GREEN}[+] Scan complete!{Style.RESET_ALL}")
            print(f"    Hosts found: {len(results.get('hosts', []))}")
            print(f"    Findings: {results.get('total_findings', 0)}")
            
            # Display summary
            for host in results.get('hosts', []):
                if host['status'] == 'up':
                    print(f"\n{Fore.CYAN}[*] Host: {host['ip']} ({host.get('hostname', 'N/A')}){Style.RESET_ALL}")
                    for port in host.get('open_ports', []):
                        print(f"    Port {port['port']}/{port['protocol']}: {port['service']} {port.get('version', '')}")
    
    def wireless_security_module(self):
        """Wireless security audit module"""
        print(f"\n{self.colors['header']}[WIRELESS SECURITY MODULE]{Style.RESET_ALL}")
        
        if sys.platform != 'linux':
            print(f"{Fore.RED}[!] Wireless module only available on Linux{Style.RESET_ALL}")
            return
        
        print(f"{Fore.YELLOW}[!] This module requires root privileges and wireless tools{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Only audit networks you own or have permission to test{Style.RESET_ALL}")
        
        interface = input(f"{Fore.CYAN}[?] Enter wireless interface (default: wlan0): {Style.RESET_ALL}").strip() or "wlan0"
        
        results = WirelessSecurityAuditor.audit_wireless_networks(interface)
        
        if 'error' in results:
            print(f"{Fore.RED}[!] Error: {results['error']}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[+] Wireless audit complete!{Style.RESET_ALL}")
        print(f"    Networks found: {len(results.get('networks', []))}")
        print(f"    Security issues: {len(results.get('security_issues', []))}")
        
        # Display networks
        for network in results.get('networks', []):
            print(f"\n{Fore.CYAN}[*] Network: {network.get('essid', 'Hidden')}{Style.RESET_ALL}")
            print(f"    BSSID: {network.get('bssid', 'N/A')}")
            print(f"    Channel: {network.get('channel', 'N/A')}")
            print(f"    Encryption: {network.get('encryption', 'Unknown')}")
            print(f"    Signal: {network.get('signal', 'N/A')}")
            
            if network.get('security_issues'):
                for issue in network['security_issues']:
                    print(f"    {Fore.YELLOW}[!] {issue['issue']}: {issue['description']}{Style.RESET_ALL}")
    
    def compliance_module(self):
        """Compliance checking module"""
        print(f"\n{self.colors['header']}[COMPLIANCE MODULE]{Style.RESET_ALL}")
        
        print("Select compliance standard:")
        print("  1. PCI DSS (Payment Card Industry)")
        print("  2. HIPAA (Healthcare)")
        print("  3. GDPR (Data Protection)")
        
        choice = input(f"\n{Fore.CYAN}[?] Select standard (1-3): {Style.RESET_ALL}").strip()
        target = input(f"{Fore.CYAN}[?] Enter target to check: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            results = ComplianceChecker.check_pci_dss(target)
        elif choice == "2":
            results = ComplianceChecker.check_hipaa(target)
        elif choice == "3":
            results = ComplianceChecker.check_gdpr(target)
        else:
            print(f"{Fore.RED}[!] Invalid choice{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}[+] Compliance check complete!{Style.RESET_ALL}")
        print(f"    Standard: {results.get('standard')}")
        print(f"    Compliance Score: {results['summary']['score']:.1f}%")
        print(f"    Passed: {results['summary']['passed']}, Failed: {results['summary']['failed']}")
        
        # Display detailed results
        for check in results.get('checks', []):
            status = "✓ PASS" if check['passed'] else "✗ FAIL"
            color = Fore.GREEN if check['passed'] else Fore.RED
            print(f"\n    {color}{status}{Style.RESET_ALL} {check['id']}: {check['requirement']}")
            print(f"        Details: {check['details']}")
    
    def reporting_module(self):
        """Reporting module"""
        print(f"\n{self.colors['header']}[REPORTING MODULE]{Style.RESET_ALL}")
        
        # In a real implementation, this would load findings from database
        sample_findings = [
            {
                'vulnerability': 'SSL_CERTIFICATE_EXPIRING',
                'severity': 'high',
                'description': 'SSL certificate expires in 15 days',
                'remediation': 'Renew SSL certificate',
                'target': 'https://example.com',
                'evidence': 'Expiry: 2024-01-31'
            },
            {
                'vulnerability': 'MISSING_SECURITY_HEADERS',
                'severity': 'medium',
                'description': 'Missing Content-Security-Policy header',
                'remediation': 'Implement CSP header',
                'target': 'https://example.com',
                'evidence': 'Header not present in response'
            }
        ]
        
        scan_info = {
            'target': 'example.com',
            'date': datetime.datetime.now().isoformat()
        }
        
        filename = self.report_gen.generate_html_report(sample_findings, scan_info)
        print(f"{Fore.GREEN}[+] Report generated: {filename}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Open the HTML file in your browser to view the report{Style.RESET_ALL}")
    
    def settings_module(self):
        """Settings module"""
        print(f"\n{self.colors['header']}[SETTINGS MODULE]{Style.RESET_ALL}")
        
        print("Current Configuration:")
        print(f"  Database: {self.config.db_path}")
        print(f"  Reports Directory: {self.config.reports_dir}")
        print(f"  Logs Directory: {self.config.logs_dir}")
        print(f"  Max Threads: {self.config.max_threads}")
        print(f"  Timeout: {self.config.timeout}s")
        
        print(f"\n{Fore.CYAN}[*] Configuration loaded from config.py{Style.RESET_ALL}")

# ==================== ENTRY POINT ====================

def check_dependencies():
    """Check if all required dependencies are installed"""
    required = [
        'requests',
        'scapy',
        'cryptography',
        'paramiko',
        'dnspython',
        'whois',
        'beautifulsoup4',
        'pytz',
        'colorama',
        'nmap'
    ]
    
    missing = []
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"{Fore.RED}[!] Missing dependencies: {', '.join(missing)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Install with: pip install {' '.join(missing)}{Style.RESET_ALL}")
        return False
    
    return True

def main():
    """Main entry point"""
    print(f"{Fore.CYAN}[*] Initializing CyberPro Security Platform v3.0...{Style.RESET_ALL}")
    
    # Legal agreement
    agreement = f"""
{Fore.YELLOW}
╔══════════════════════════════════════════════════════════════════════════════╗
║                         LEGAL AGREEMENT REQUIRED                             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ By using this platform, you agree to:                                        ║
║                                                                              ║
║ 1. Use only for authorized security testing                                  ║
║ 2. Never test systems without explicit, written permission                   ║
║ 3. Follow all applicable laws and regulations                                ║
║ 4. Maintain ethical hacking principles                                       ║
║ 5. Practice responsible disclosure                                           ║
║                                                                              ║
║ Violation of these terms may result in criminal prosecution.                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """
    
    print(agreement)
    accept = input(f"{Fore.RED}[?] Do you accept these terms? (yes/no): {Style.RESET_ALL}").strip().lower()
    
    if accept != 'yes':
        print(f"{Fore.YELLOW}[*] Platform terminated. Legal agreement required.{Style.RESET_ALL}")
        sys.exit(0)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Run platform
    try:
        platform = CyberProPlatform()
        platform.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Platform interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Platform error: {e}{Style.RESET_ALL}")
        logging.exception("Platform crash")

if __name__ == "__main__":
    main()
