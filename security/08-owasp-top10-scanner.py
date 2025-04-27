#!/usr/bin/env python3

import requests
import json
import argparse
import logging
import concurrent.futures
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import re
import time
from datetime import datetime
import html
import base64
import sqlite3
import os
import sys
from bs4 import BeautifulSoup

@dataclass
class Vulnerability:
    name: str
    category: str
    severity: str
    description: str
    evidence: str
    recommendation: str
    cwe_id: str

class OWASPTop10Scanner:
    def __init__(self, target_url: str, headers: Dict = None, cookies: Dict = None):
        self.target_url = target_url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.vulnerabilities: List[Vulnerability] = []
        self.endpoints: Set[str] = set()
        self.forms: List[Dict] = []
        self.parameters: Set[str] = set()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('OWASPScanner')
        
        # Initialize session
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.session.cookies.update(self.cookies)
        
        # Initialize database for storing scan results
        self.db_path = "owasp_scan_results.db"
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for storing scan results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT,
            scan_date TEXT,
            total_vulnerabilities INTEGER
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            name TEXT,
            category TEXT,
            severity TEXT,
            description TEXT,
            evidence TEXT,
            recommendation TEXT,
            cwe_id TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        )
        ''')
        
        conn.commit()
        conn.close()

    def crawl(self) -> Set[str]:
        """Crawl the website to discover endpoints and forms"""
        self.logger.info("Starting web crawling...")
        
        discovered_urls = set()
        visited_urls = set()
        urls_to_visit = {self.target_url}
        
        while urls_to_visit and len(visited_urls) < 100:  # Limit crawling to 100 pages
            url = urls_to_visit.pop()
            if url in visited_urls:
                continue
                
            try:
                self.logger.info(f"Crawling: {url}")
                response = self.session.get(url, timeout=10)
                visited_urls.add(url)
                
                if response.status_code == 200:
                    # Parse HTML content
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract forms
                    for form in soup.find_all('form'):
                        form_data = {
                            'action': form.get('action', ''),
                            'method': form.get('method', 'get').upper(),
                            'inputs': []
                        }
                        
                        for input_field in form.find_all(['input', 'textarea']):
                            input_data = {
                                'name': input_field.get('name', ''),
                                'type': input_field.get('type', 'text'),
                                'value': input_field.get('value', '')
                            }
                            form_data['inputs'].append(input_data)
                            if input_data['name']:
                                self.parameters.add(input_data['name'])
                        
                        self.forms.append(form_data)
                    
                    # Extract links
                    for link in soup.find_all('a'):
                        href = link.get('href')
                        if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                            absolute_url = urljoin(url, href)
                            if self.target_url in absolute_url and absolute_url not in visited_urls:
                                urls_to_visit.add(absolute_url)
                                discovered_urls.add(absolute_url)
                    
                    # Extract parameters from URL
                    parsed_url = urlparse(url)
                    query_params = parse_qs(parsed_url.query)
                    for param in query_params:
                        self.parameters.add(param)
                    
                    # Add the URL to discovered endpoints
                    self.endpoints.add(parsed_url.path)
                    
            except requests.RequestException as e:
                self.logger.error(f"Error crawling {url}: {str(e)}")
        
        return discovered_urls

    def check_broken_access_control(self) -> List[Vulnerability]:
        """Check for broken access control (OWASP #1)"""
        self.logger.info("Checking for broken access control...")
        vulnerabilities = []
        
        # Test for IDOR vulnerabilities
        for endpoint in self.endpoints:
            if '/user/' in endpoint or '/profile/' in endpoint or '/account/' in endpoint:
                # Try to access another user's data
                test_ids = ['1', '2', '3', 'admin', '0']
                for test_id in test_ids:
                    try:
                        url = urljoin(self.target_url, endpoint.replace('{id}', test_id))
                        response = self.session.get(url, timeout=5)
                        
                        if response.status_code == 200:
                            vulnerabilities.append(Vulnerability(
                                name="Insecure Direct Object Reference (IDOR)",
                                category="Broken Access Control",
                                severity="High",
                                description=f"Endpoint {endpoint} may be vulnerable to IDOR",
                                evidence=f"Successfully accessed resource with ID: {test_id}",
                                recommendation="Implement proper authorization checks",
                                cwe_id="CWE-639"
                            ))
                    except requests.RequestException:
                        continue
        
        return vulnerabilities

    def check_cryptographic_failures(self) -> List[Vulnerability]:
        """Check for cryptographic failures (OWASP #2)"""
        self.logger.info("Checking for cryptographic failures...")
        vulnerabilities = []
        
        # Check for HTTP (non-HTTPS) usage
        if not self.target_url.startswith('https://'):
            vulnerabilities.append(Vulnerability(
                name="Insecure Communication",
                category="Cryptographic Failures",
                severity="High",
                description="Website does not use HTTPS",
                evidence=f"URL starts with http:// instead of https://",
                recommendation="Implement HTTPS for all communications",
                cwe_id="CWE-319"
            ))
        
        # Check for weak password policies in forms
        for form in self.forms:
            if form['action'] and ('login' in form['action'].lower() or 'signin' in form['action'].lower()):
                password_fields = [input_field for input_field in form['inputs'] 
                                 if input_field['type'] == 'password']
                
                if password_fields:
                    # Check if there's a password confirmation field
                    confirm_fields = [input_field for input_field in form['inputs'] 
                                    if 'confirm' in input_field['name'].lower() and 
                                    input_field['type'] == 'password']
                    
                    if not confirm_fields:
                        vulnerabilities.append(Vulnerability(
                            name="Weak Password Policy",
                            category="Cryptographic Failures",
                            severity="Medium",
                            description="Login form lacks password confirmation",
                            evidence=f"Form at {form['action']} has no password confirmation field",
                            recommendation="Implement password confirmation and strong password requirements",
                            cwe_id="CWE-521"
                        ))
        
        return vulnerabilities

    def check_injection(self) -> List[Vulnerability]:
        """Check for injection vulnerabilities (OWASP #3)"""
        self.logger.info("Checking for injection vulnerabilities...")
        vulnerabilities = []
        
        # Test payloads for various injection attacks
        test_payloads = {
            'SQL Injection': ["' OR '1'='1", "1; DROP TABLE users", "1 UNION SELECT username,password FROM users"],
            'NoSQL Injection': ['{"$gt": ""}', '{"$ne": null}', '{"$regex": ".*"}'],
            'Command Injection': ["& cat /etc/passwd", "| dir", "; ls -la", "`whoami`"],
            'LDAP Injection': ["*", "(|(uid=*)(userPassword=*))", "admin*"],
            'XML Injection': ["<!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><test>&xxe;</test>"],
            'Template Injection': ["${7*7}", "{{7*7}}", "<%= 7*7 %>"]
        }
        
        # Test GET parameters
        for endpoint in self.endpoints:
            url = urljoin(self.target_url, endpoint)
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param_name in query_params:
                for attack_type, payloads in test_payloads.items():
                    for payload in payloads:
                        try:
                            test_params = query_params.copy()
                            test_params[param_name] = [payload]
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                            
                            response = self.session.get(test_url, timeout=5)
                            
                            # Check for successful injection
                            if any(indicator in response.text for indicator in [
                                "mysql_fetch_array()", "ORA-", "SQL syntax", "PostgreSQL", "SQLite",
                                "root:", "uid=", "gid=", "home/", "Directory of", "Volume Serial Number",
                                "uid=0", "gid=0", "home/", "root:x:", "uid=", "gid=", "home/",
                                "49", "7*7", "error in your SQL syntax", "ORA-", "PostgreSQL", "SQLite"
                            ]):
                                vulnerabilities.append(Vulnerability(
                                    name=f"{attack_type}",
                                    category="Injection",
                                    severity="High",
                                    description=f"Parameter '{param_name}' in {endpoint} may be vulnerable to {attack_type}",
                                    evidence=f"Payload '{payload}' produced suspicious response",
                                    recommendation=f"Implement proper input validation and parameterized queries for {attack_type}",
                                    cwe_id="CWE-89" if attack_type == "SQL Injection" else "CWE-78"
                                ))
                        except requests.RequestException:
                            continue
        
        # Test POST forms
        for form in self.forms:
            if form['method'] == 'POST':
                for input_field in form['inputs']:
                    if input_field['name']:
                        for attack_type, payloads in test_payloads.items():
                            for payload in payloads:
                                try:
                                    data = {input_field['name']: payload}
                                    response = self.session.post(
                                        urljoin(self.target_url, form['action']),
                                        data=data,
                                        timeout=5
                                    )
                                    
                                    # Check for successful injection
                                    if any(indicator in response.text for indicator in [
                                        "mysql_fetch_array()", "ORA-", "SQL syntax", "PostgreSQL", "SQLite",
                                        "root:", "uid=", "gid=", "home/", "Directory of", "Volume Serial Number",
                                        "uid=0", "gid=0", "home/", "root:x:", "uid=", "gid=", "home/",
                                        "49", "7*7", "error in your SQL syntax", "ORA-", "PostgreSQL", "SQLite"
                                    ]):
                                        vulnerabilities.append(Vulnerability(
                                            name=f"{attack_type}",
                                            category="Injection",
                                            severity="High",
                                            description=f"Form field '{input_field['name']}' in {form['action']} may be vulnerable to {attack_type}",
                                            evidence=f"Payload '{payload}' produced suspicious response",
                                            recommendation=f"Implement proper input validation and parameterized queries for {attack_type}",
                                            cwe_id="CWE-89" if attack_type == "SQL Injection" else "CWE-78"
                                        ))
                                except requests.RequestException:
                                    continue
        
        return vulnerabilities

    def check_design(self) -> List[Vulnerability]:
        """Check for insecure design (OWASP #4)"""
        self.logger.info("Checking for insecure design...")
        vulnerabilities = []
        
        # Check for default credentials
        default_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', ''),
            ('root', 'root'),
            ('root', 'password'),
            ('administrator', 'administrator'),
            ('guest', 'guest'),
            ('user', 'user'),
            ('test', 'test')
        ]
        
        # Find login forms
        login_forms = [form for form in self.forms 
                      if form['action'] and ('login' in form['action'].lower() or 
                                            'signin' in form['action'].lower() or 
                                            'auth' in form['action'].lower())]
        
        for form in login_forms:
            username_fields = [input_field for input_field in form['inputs'] 
                             if input_field['type'] == 'text' or 
                             'user' in input_field['name'].lower() or 
                             'email' in input_field['name'].lower()]
            
            password_fields = [input_field for input_field in form['inputs'] 
                             if input_field['type'] == 'password']
            
            if username_fields and password_fields:
                username_field = username_fields[0]['name']
                password_field = password_fields[0]['name']
                
                for username, password in default_credentials:
                    try:
                        data = {username_field: username, password_field: password}
                        response = self.session.post(
                            urljoin(self.target_url, form['action']),
                            data=data,
                            timeout=5
                        )
                        
                        # Check for successful login
                        if response.status_code == 200 and (
                            'welcome' in response.text.lower() or 
                            'dashboard' in response.text.lower() or 
                            'logout' in response.text.lower() or
                            'profile' in response.text.lower()
                        ):
                            vulnerabilities.append(Vulnerability(
                                name="Default Credentials",
                                category="Insecure Design",
                                severity="High",
                                description=f"Default credentials {username}:{password} work on login form",
                                evidence=f"Successfully logged in with default credentials",
                                recommendation="Change default credentials and implement strong password policy",
                                cwe_id="CWE-521"
                            ))
                    except requests.RequestException:
                        continue
        
        return vulnerabilities

    def check_security_misconfiguration(self) -> List[Vulnerability]:
        """Check for security misconfiguration (OWASP #5)"""
        self.logger.info("Checking for security misconfiguration...")
        vulnerabilities = []
        
        # Check for default error pages
        try:
            response = self.session.get(self.target_url, timeout=5)
            
            # Check for server information disclosure
            server_header = response.headers.get('Server', '')
            if server_header:
                vulnerabilities.append(Vulnerability(
                    name="Server Information Disclosure",
                    category="Security Misconfiguration",
                    severity="Medium",
                    description="Server header reveals technology information",
                    evidence=f"Server header: {server_header}",
                    recommendation="Remove or customize server header",
                    cwe_id="CWE-200"
                ))
            
            # Check for X-Powered-By header
            powered_by = response.headers.get('X-Powered-By', '')
            if powered_by:
                vulnerabilities.append(Vulnerability(
                    name="Technology Information Disclosure",
                    category="Security Misconfiguration",
                    severity="Low",
                    description="X-Powered-By header reveals technology information",
                    evidence=f"X-Powered-By header: {powered_by}",
                    recommendation="Remove X-Powered-By header",
                    cwe_id="CWE-200"
                ))
            
            # Check for directory listing
            test_paths = ['/images/', '/img/', '/css/', '/js/', '/assets/', '/static/']
            for path in test_paths:
                try:
                    dir_response = self.session.get(urljoin(self.target_url, path), timeout=5)
                    if 'Index of' in dir_response.text or 'Directory listing' in dir_response.text:
                        vulnerabilities.append(Vulnerability(
                            name="Directory Listing Enabled",
                            category="Security Misconfiguration",
                            severity="Medium",
                            description=f"Directory listing is enabled at {path}",
                            evidence=f"Directory listing page found at {path}",
                            recommendation="Disable directory listing",
                            cwe_id="CWE-548"
                        ))
                except requests.RequestException:
                    continue
            
            # Check for default error pages
            try:
                error_response = self.session.get(urljoin(self.target_url, 'nonexistent-page-12345'), timeout=5)
                if '404' in error_response.text and ('apache' in error_response.text.lower() or 
                                                    'nginx' in error_response.text.lower() or 
                                                    'iis' in error_response.text.lower()):
                    vulnerabilities.append(Vulnerability(
                        name="Default Error Pages",
                        category="Security Misconfiguration",
                        severity="Low",
                        description="Default server error pages are being used",
                        evidence="Default 404 error page detected",
                        recommendation="Customize error pages to prevent information disclosure",
                        cwe_id="CWE-209"
                    ))
            except requests.RequestException:
                pass
                
        except requests.RequestException:
            pass
        
        return vulnerabilities

    def check_vulnerable_components(self) -> List[Vulnerability]:
        """Check for vulnerable components (OWASP #6)"""
        self.logger.info("Checking for vulnerable components...")
        vulnerabilities = []
        
        # Check for JavaScript libraries with known vulnerabilities
        try:
            response = self.session.get(self.target_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for jQuery
            jquery_scripts = soup.find_all('script', src=re.compile(r'jquery.*\.js'))
            for script in jquery_scripts:
                src = script.get('src', '')
                if 'jquery-1.' in src or 'jquery-2.' in src or 'jquery-3.0' in src or 'jquery-3.1' in src:
                    vulnerabilities.append(Vulnerability(
                        name="Outdated jQuery",
                        category="Vulnerable Components",
                        severity="Medium",
                        description="Outdated jQuery version detected",
                        evidence=f"jQuery script: {src}",
                        recommendation="Update to the latest jQuery version",
                        cwe_id="CWE-937"
                    ))
            
            # Check for Bootstrap
            bootstrap_scripts = soup.find_all('script', src=re.compile(r'bootstrap.*\.js'))
            bootstrap_css = soup.find_all('link', href=re.compile(r'bootstrap.*\.css'))
            for resource in bootstrap_scripts + bootstrap_css:
                src = resource.get('src', '') or resource.get('href', '')
                if 'bootstrap-3.' in src or 'bootstrap-4.0' in src or 'bootstrap-4.1' in src:
                    vulnerabilities.append(Vulnerability(
                        name="Outdated Bootstrap",
                        category="Vulnerable Components",
                        severity="Low",
                        description="Outdated Bootstrap version detected",
                        evidence=f"Bootstrap resource: {src}",
                        recommendation="Update to the latest Bootstrap version",
                        cwe_id="CWE-937"
                    ))
            
            # Check for AngularJS
            angular_scripts = soup.find_all('script', src=re.compile(r'angular.*\.js'))
            for script in angular_scripts:
                src = script.get('src', '')
                if 'angular-1.' in src:
                    vulnerabilities.append(Vulnerability(
                        name="Outdated AngularJS",
                        category="Vulnerable Components",
                        severity="High",
                        description="Outdated AngularJS version detected",
                        evidence=f"AngularJS script: {src}",
                        recommendation="Update to the latest Angular version or migrate to Angular",
                        cwe_id="CWE-937"
                    ))
                    
        except requests.RequestException:
            pass
        
        return vulnerabilities

    def check_auth_failures(self) -> List[Vulnerability]:
        """Check for authentication failures (OWASP #7)"""
        self.logger.info("Checking for authentication failures...")
        vulnerabilities = []
        
        # Check for password reset functionality
        for form in self.forms:
            if form['action'] and ('reset' in form['action'].lower() or 'forgot' in form['action'].lower()):
                # Check if password reset uses predictable tokens
                reset_links = [input_field for input_field in form['inputs'] 
                             if 'email' in input_field['name'].lower() or 
                             'username' in input_field['name'].lower()]
                
                if reset_links:
                    vulnerabilities.append(Vulnerability(
                        name="Password Reset Functionality",
                        category="Authentication Failures",
                        severity="Medium",
                        description="Password reset functionality detected",
                        evidence=f"Password reset form found at {form['action']}",
                        recommendation="Ensure password reset tokens are cryptographically secure and time-limited",
                        cwe_id="CWE-640"
                    ))
        
        # Check for session management
        try:
            response = self.session.get(self.target_url, timeout=5)
            
            # Check for secure and HttpOnly flags on cookies
            cookies = response.cookies
            for cookie in cookies:
                if not cookie.secure:
                    vulnerabilities.append(Vulnerability(
                        name="Insecure Cookie",
                        category="Authentication Failures",
                        severity="Medium",
                        description="Cookie is not set with Secure flag",
                        evidence=f"Cookie {cookie.name} lacks Secure flag",
                        recommendation="Set Secure flag on all cookies",
                        cwe_id="CWE-614"
                    ))
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    vulnerabilities.append(Vulnerability(
                        name="Cookie without HttpOnly",
                        category="Authentication Failures",
                        severity="Medium",
                        description="Cookie is not set with HttpOnly flag",
                        evidence=f"Cookie {cookie.name} lacks HttpOnly flag",
                        recommendation="Set HttpOnly flag on all cookies",
                        cwe_id="CWE-1004"
                    ))
                    
        except requests.RequestException:
            pass
        
        return vulnerabilities

    def check_software_data_integrity_failures(self) -> List[Vulnerability]:
        """Check for software and data integrity failures (OWASP #8)"""
        self.logger.info("Checking for software and data integrity failures...")
        vulnerabilities = []
        
        # Check for external JavaScript resources without integrity checks
        try:
            response = self.session.get(self.target_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            external_scripts = soup.find_all('script', src=re.compile(r'^https?://'))
            for script in external_scripts:
                src = script.get('src', '')
                integrity = script.get('integrity', '')
                
                if not integrity:
                    vulnerabilities.append(Vulnerability(
                        name="Missing Subresource Integrity",
                        category="Software and Data Integrity Failures",
                        severity="Medium",
                        description="External JavaScript resource without integrity check",
                        evidence=f"Script {src} lacks integrity attribute",
                        recommendation="Add Subresource Integrity (SRI) checks for external resources",
                        cwe_id="CWE-829"
                    ))
                    
        except requests.RequestException:
            pass
        
        return vulnerabilities

    def check_logging_monitoring_failures(self) -> List[Vulnerability]:
        """Check for logging and monitoring failures (OWASP #9)"""
        self.logger.info("Checking for logging and monitoring failures...")
        vulnerabilities = []
        
        # Check for error messages that might reveal sensitive information
        for endpoint in self.endpoints:
            try:
                # Try to trigger errors with invalid input
                url = urljoin(self.target_url, endpoint)
                response = self.session.get(url, params={'invalid_param': "' OR '1'='1"}, timeout=5)
                
                # Check for detailed error messages
                if any(error in response.text.lower() for error in [
                    'error in your sql syntax',
                    'ora-', 'postgresql', 'sqlite', 'mysql_fetch_array()',
                    'stack trace', 'exception', 'at java.', 'at python.',
                    'warning:', 'notice:', 'undefined variable', 'undefined index',
                    'fatal error', 'syntax error', 'parse error'
                ]):
                    vulnerabilities.append(Vulnerability(
                        name="Detailed Error Messages",
                        category="Logging and Monitoring Failures",
                        severity="Medium",
                        description=f"Detailed error messages revealed at {endpoint}",
                        evidence="Error message contains technical details",
                        recommendation="Implement proper error handling that doesn't reveal sensitive information",
                        cwe_id="CWE-209"
                    ))
            except requests.RequestException:
                continue
        
        return vulnerabilities

    def check_ssrf(self) -> List[Vulnerability]:
        """Check for SSRF vulnerabilities (OWASP #10)"""
        self.logger.info("Checking for SSRF vulnerabilities...")
        vulnerabilities = []
        
        # Test payloads for SSRF
        ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
            'http://169.254.169.254',  # AWS metadata
            'http://metadata.google.internal',  # GCP metadata
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata path
            'file:///etc/passwd',
            'file:///c:/windows/win.ini',
            'dict://localhost:11211/',
            'ftp://localhost:21',
            'gopher://localhost/_',
            'http://attacker.com',
            'https://attacker.com'
        ]
        
        # Test URL parameters
        for endpoint in self.endpoints:
            parsed_url = urlparse(urljoin(self.target_url, endpoint))
            query_params = parse_qs(parsed_url.query)
            
            for param_name in query_params:
                if any(keyword in param_name.lower() for keyword in ['url', 'uri', 'src', 'source', 'path', 'file', 'redirect', 'redirect_uri', 'callback', 'return', 'returnTo', 'next', 'target', 'site', 'html', 'data', 'reference', 'ref', 'link']):
                    for payload in ssrf_payloads:
                        try:
                            test_params = query_params.copy()
                            test_params[param_name] = [payload]
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"
                            
                            response = self.session.get(test_url, timeout=5)
                            
                            # Check for successful SSRF
                            if any(indicator in response.text for indicator in [
                                'root:', 'uid=', 'gid=', 'home/', 'Directory of', 'Volume Serial Number',
                                'uid=0', 'gid=0', 'home/', 'root:x:', 'uid=', 'gid=', 'home/',
                                'AWS', 'EC2', 'metadata', 'instance-id', 'ami-id', 'security-credentials',
                                'Google Cloud', 'GCP', 'project-id', 'instance-id', 'zone',
                                'Microsoft Azure', 'Azure', 'VM', 'subscription', 'resource-group'
                            ]):
                                vulnerabilities.append(Vulnerability(
                                    name="Server-Side Request Forgery (SSRF)",
                                    category="OWASP Top 10 #10",
                                    severity="High",
                                    description=f"Parameter '{param_name}' in {endpoint} may be vulnerable to SSRF",
                                    evidence=f"Payload '{payload}' produced suspicious response",
                                    recommendation="Implement proper URL validation and whitelist allowed domains",
                                    cwe_id="CWE-918"
                                ))
                        except requests.RequestException:
                            continue
        
        return vulnerabilities

    def scan(self) -> List[Vulnerability]:
        """Perform complete OWASP Top 10 security scan"""
        self.logger.info(f"Starting OWASP Top 10 security scan of {self.target_url}")
        
        # Crawl the website
        self.crawl()
        
        # Run all checks
        checks = [
            self.check_broken_access_control,
            self.check_cryptographic_failures,
            self.check_injection,
            self.check_design,
            self.check_security_misconfiguration,
            self.check_vulnerable_components,
            self.check_auth_failures,
            self.check_software_data_integrity_failures,
            self.check_logging_monitoring_failures,
            self.check_ssrf
        ]
        
        # Run checks concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_check = {executor.submit(check): check.__name__ for check in checks}
            for future in concurrent.futures.as_completed(future_to_check):
                check_name = future_to_check[future]
                try:
                    vulnerabilities = future.result()
                    self.vulnerabilities.extend(vulnerabilities)
                    self.logger.info(f"Completed {check_name}: found {len(vulnerabilities)} vulnerabilities")
                except Exception as e:
                    self.logger.error(f"Error in {check_name}: {str(e)}")
        
        # Save scan results to database
        self._save_scan_results()
        
        return self.vulnerabilities

    def _save_scan_results(self):
        """Save scan results to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert scan record
        cursor.execute(
            "INSERT INTO scans (target_url, scan_date, total_vulnerabilities) VALUES (?, ?, ?)",
            (self.target_url, datetime.now().isoformat(), len(self.vulnerabilities))
        )
        scan_id = cursor.lastrowid
        
        # Insert vulnerabilities
        for vuln in self.vulnerabilities:
            cursor.execute(
                "INSERT INTO vulnerabilities (scan_id, name, category, severity, description, evidence, recommendation, cwe_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, vuln.name, vuln.category, vuln.severity, vuln.description, vuln.evidence, vuln.recommendation, vuln.cwe_id)
            )
        
        conn.commit()
        conn.close()

    def generate_report(self) -> Dict:
        """Generate a detailed security report"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'target_url': self.target_url,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_by_category': {},
            'vulnerabilities_by_severity': {
                'High': len([v for v in self.vulnerabilities if v.severity == 'High']),
                'Medium': len([v for v in self.vulnerabilities if v.severity == 'Medium']),
                'Low': len([v for v in self.vulnerabilities if v.severity == 'Low'])
            },
            'discovered_endpoints': list(self.endpoints),
            'vulnerabilities': [
                {
                    'name': v.name,
                    'category': v.category,
                    'severity': v.severity,
                    'description': v.description,
                    'evidence': v.evidence,
                    'recommendation': v.recommendation,
                    'cwe_id': v.cwe_id
                }
                for v in self.vulnerabilities
            ]
        }
        
        # Group vulnerabilities by category
        for vuln in self.vulnerabilities:
            if vuln.category not in report['vulnerabilities_by_category']:
                report['vulnerabilities_by_category'][vuln.category] = 0
            report['vulnerabilities_by_category'][vuln.category] += 1
        
        return report

def main():
    parser = argparse.ArgumentParser(description='OWASP Top 10 Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--headers', help='JSON file containing custom headers')
    parser.add_argument('--cookies', help='JSON file containing custom cookies')
    parser.add_argument('--output', help='Output file for the scan report')
    args = parser.parse_args()

    # Load custom headers if provided
    headers = {}
    if args.headers:
        try:
            with open(args.headers, 'r') as f:
                headers = json.load(f)
        except Exception as e:
            print(f"Error loading headers: {e}")
            return

    # Load custom cookies if provided
    cookies = {}
    if args.cookies:
        try:
            with open(args.cookies, 'r') as f:
                cookies = json.load(f)
        except Exception as e:
            print(f"Error loading cookies: {e}")
            return

    # Initialize and run scanner
    scanner = OWASPTop10Scanner(args.url, headers, cookies)
    vulnerabilities = scanner.scan()
    
    # Generate and save report
    report = scanner.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {args.output}")
    else:
        print("\nOWASP Top 10 Security Scan Report")
        print("=================================")
        print(f"Target URL: {report['target_url']}")
        print(f"Scan Date: {report['scan_date']}")
        print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
        
        print("\nVulnerabilities by Category:")
        for category, count in report['vulnerabilities_by_category'].items():
            print(f"- {category}: {count}")
        
        print("\nVulnerabilities by Severity:")
        for severity, count in report['vulnerabilities_by_severity'].items():
            print(f"- {severity}: {count}")
        
        print("\nDiscovered Endpoints:")
        for endpoint in report['discovered_endpoints']:
            print(f"- {endpoint}")
        
        print("\nDetailed Vulnerabilities:")
        for vuln in report['vulnerabilities']:
            print(f"\n{vuln['name']} ({vuln['severity']}) - {vuln['category']}")
            print(f"Description: {vuln['description']}")
            print(f"Evidence: {vuln['evidence']}")
            print(f"Recommendation: {vuln['recommendation']}")
            print(f"CWE ID: {vuln['cwe_id']}")

if __name__ == "__main__":
    main() 