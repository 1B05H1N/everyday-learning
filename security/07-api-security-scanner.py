#!/usr/bin/env python3

import requests
import json
import argparse
import logging
import concurrent.futures
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import re
import time
from datetime import datetime

@dataclass
class SecurityVulnerability:
    name: str
    severity: str
    description: str
    evidence: str
    recommendation: str

class APISecurityScanner:
    def __init__(self, target_url: str, headers: Dict = None):
        self.target_url = target_url
        self.headers = headers or {}
        self.vulnerabilities: List[SecurityVulnerability] = []
        self.endpoints: Set[str] = set()
        self.auth_tokens: Set[str] = set()
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('APISecurityScanner')
        
        # Initialize session
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def discover_endpoints(self) -> Set[str]:
        """Discover API endpoints through various methods"""
        self.logger.info("Starting endpoint discovery...")
        
        # Common API paths to check
        common_paths = [
            '/api', '/api/v1', '/api/v2',
            '/swagger', '/swagger-ui', '/swagger.json',
            '/openapi.json', '/graphql',
            '/docs', '/redoc', '/api-docs'
        ]
        
        discovered_endpoints = set()
        
        # Check common paths
        for path in common_paths:
            url = urljoin(self.target_url, path)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code != 404:
                    discovered_endpoints.add(path)
                    self.logger.info(f"Discovered endpoint: {path}")
            except requests.RequestException:
                continue
        
        self.endpoints = discovered_endpoints
        return discovered_endpoints

    def check_authentication(self) -> List[SecurityVulnerability]:
        """Check for authentication-related vulnerabilities"""
        self.logger.info("Checking authentication security...")
        vulnerabilities = []
        
        # Test endpoints without authentication
        for endpoint in self.endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code == 200:
                    vulnerabilities.append(SecurityVulnerability(
                        name="Missing Authentication",
                        severity="High",
                        description=f"Endpoint {endpoint} is accessible without authentication",
                        evidence=f"GET {url} returned 200",
                        recommendation="Implement proper authentication mechanism"
                    ))
            except requests.RequestException:
                continue
        
        return vulnerabilities

    def check_rate_limiting(self) -> List[SecurityVulnerability]:
        """Check for rate limiting implementation"""
        self.logger.info("Checking rate limiting...")
        vulnerabilities = []
        
        # Test rate limiting by making rapid requests
        for endpoint in self.endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                responses = []
                for _ in range(50):  # Make 50 rapid requests
                    response = self.session.get(url, timeout=5)
                    responses.append(response.status_code)
                    time.sleep(0.1)  # Small delay between requests
                
                # Check if all requests succeeded (potential lack of rate limiting)
                if all(code == 200 for code in responses):
                    vulnerabilities.append(SecurityVulnerability(
                        name="Missing Rate Limiting",
                        severity="Medium",
                        description=f"Endpoint {endpoint} lacks rate limiting",
                        evidence="50 rapid requests all succeeded",
                        recommendation="Implement rate limiting to prevent abuse"
                    ))
            except requests.RequestException:
                continue
        
        return vulnerabilities

    def check_cors(self) -> List[SecurityVulnerability]:
        """Check for CORS misconfigurations"""
        self.logger.info("Checking CORS configuration...")
        vulnerabilities = []
        
        # Test CORS with different origins
        test_origins = [
            'https://evil.com',
            'null',
            'https://attacker.com'
        ]
        
        for endpoint in self.endpoints:
            url = urljoin(self.target_url, endpoint)
            for origin in test_origins:
                try:
                    headers = {'Origin': origin}
                    response = self.session.get(url, headers=headers, timeout=5)
                    
                    # Check for overly permissive CORS
                    cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                    if cors_header == '*' or origin in cors_header:
                        vulnerabilities.append(SecurityVulnerability(
                            name="Overly Permissive CORS",
                            severity="High",
                            description=f"Endpoint {endpoint} has overly permissive CORS",
                            evidence=f"CORS allows origin: {origin}",
                            recommendation="Restrict CORS to specific trusted origins"
                        ))
                except requests.RequestException:
                    continue
        
        return vulnerabilities

    def check_input_validation(self) -> List[SecurityVulnerability]:
        """Check for input validation vulnerabilities"""
        self.logger.info("Checking input validation...")
        vulnerabilities = []
        
        # Test payloads for various injection attacks
        test_payloads = {
            'SQL Injection': ["' OR '1'='1", "1; DROP TABLE users"],
            'XSS': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            'Command Injection': ["& cat /etc/passwd", "| dir"],
            'Path Traversal': ["../../../etc/passwd", "..\\..\\..\\windows\\system32"]
        }
        
        for endpoint in self.endpoints:
            url = urljoin(self.target_url, endpoint)
            for attack_type, payloads in test_payloads.items():
                for payload in payloads:
                    try:
                        # Test GET parameters
                        params = {'q': payload, 'id': payload, 'search': payload}
                        response = self.session.get(url, params=params, timeout=5)
                        
                        # Test POST data
                        data = {'input': payload, 'query': payload, 'data': payload}
                        response_post = self.session.post(url, json=data, timeout=5)
                        
                        # Check for successful injection
                        if any(payload in str(response.text) for response in [response, response_post]):
                            vulnerabilities.append(SecurityVulnerability(
                                name=f"Input Validation - {attack_type}",
                                severity="High",
                                description=f"Endpoint {endpoint} may be vulnerable to {attack_type}",
                                evidence=f"Payload '{payload}' was reflected in response",
                                recommendation="Implement proper input validation and sanitization"
                            ))
                    except requests.RequestException:
                        continue
        
        return vulnerabilities

    def check_ssl_tls(self) -> List[SecurityVulnerability]:
        """Check SSL/TLS configuration"""
        self.logger.info("Checking SSL/TLS configuration...")
        vulnerabilities = []
        
        try:
            response = self.session.get(self.target_url, timeout=5)
            cert = response.raw.connection.sock.getpeercert()
            
            # Check certificate expiration
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if not_after < datetime.now():
                vulnerabilities.append(SecurityVulnerability(
                    name="Expired SSL Certificate",
                    severity="High",
                    description="SSL certificate has expired",
                    evidence=f"Certificate expired on {not_after}",
                    recommendation="Renew SSL certificate"
                ))
            
            # Check for weak protocols
            if 'TLSv1' in str(response.raw.connection.sock.version):
                vulnerabilities.append(SecurityVulnerability(
                    name="Weak SSL/TLS Protocol",
                    severity="Medium",
                    description="Server supports weak SSL/TLS protocol",
                    evidence=f"Protocol version: {response.raw.connection.sock.version}",
                    recommendation="Disable support for weak SSL/TLS protocols"
                ))
        except requests.RequestException:
            vulnerabilities.append(SecurityVulnerability(
                name="SSL/TLS Error",
                severity="High",
                description="Could not establish secure connection",
                evidence="Failed to connect with SSL/TLS",
                recommendation="Check SSL/TLS configuration"
            ))
        
        return vulnerabilities

    def scan(self) -> List[SecurityVulnerability]:
        """Perform complete security scan"""
        self.logger.info(f"Starting security scan of {self.target_url}")
        
        # Discover endpoints
        self.discover_endpoints()
        
        # Run all checks
        checks = [
            self.check_authentication,
            self.check_rate_limiting,
            self.check_cors,
            self.check_input_validation,
            self.check_ssl_tls
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
        
        return self.vulnerabilities

    def generate_report(self) -> Dict:
        """Generate a detailed security report"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'target_url': self.target_url,
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities_by_severity': {
                'High': len([v for v in self.vulnerabilities if v.severity == 'High']),
                'Medium': len([v for v in self.vulnerabilities if v.severity == 'Medium']),
                'Low': len([v for v in self.vulnerabilities if v.severity == 'Low'])
            },
            'discovered_endpoints': list(self.endpoints),
            'vulnerabilities': [
                {
                    'name': v.name,
                    'severity': v.severity,
                    'description': v.description,
                    'evidence': v.evidence,
                    'recommendation': v.recommendation
                }
                for v in self.vulnerabilities
            ]
        }
        
        return report

def main():
    parser = argparse.ArgumentParser(description='API Security Scanner')
    parser.add_argument('url', help='Target API URL to scan')
    parser.add_argument('--headers', help='JSON file containing custom headers')
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

    # Initialize and run scanner
    scanner = APISecurityScanner(args.url, headers)
    vulnerabilities = scanner.scan()
    
    # Generate and save report
    report = scanner.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Report saved to {args.output}")
    else:
        print("\nSecurity Scan Report")
        print("===================")
        print(f"Target URL: {report['target_url']}")
        print(f"Scan Date: {report['scan_date']}")
        print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
        print("\nVulnerabilities by Severity:")
        for severity, count in report['vulnerabilities_by_severity'].items():
            print(f"- {severity}: {count}")
        
        print("\nDiscovered Endpoints:")
        for endpoint in report['discovered_endpoints']:
            print(f"- {endpoint}")
        
        print("\nDetailed Vulnerabilities:")
        for vuln in report['vulnerabilities']:
            print(f"\n{vuln['name']} ({vuln['severity']})")
            print(f"Description: {vuln['description']}")
            print(f"Evidence: {vuln['evidence']}")
            print(f"Recommendation: {vuln['recommendation']}")

if __name__ == "__main__":
    main() 