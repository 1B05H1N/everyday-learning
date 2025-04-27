#!/usr/bin/env python3

import re
import json
import time
import logging
import argparse
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
import ipaddress
from datetime import datetime, timedelta

@dataclass
class SecurityRule:
    name: str
    pattern: str
    action: str
    description: str
    severity: str

class WAFSimulator:
    def __init__(self):
        self.rules: List[SecurityRule] = []
        self.ip_blacklist: Set[str] = set()
        self.ip_whitelist: Set[str] = set()
        self.rate_limits: Dict[str, List[float]] = defaultdict(list)
        self.request_logs: List[Dict] = []
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('WAFSimulator')
        
        # Initialize default rules
        self._initialize_default_rules()
        
    def _initialize_default_rules(self):
        """Initialize default security rules"""
        default_rules = [
            SecurityRule(
                name="SQL Injection",
                pattern=r"(?i)(union\s+select|insert\s+into|delete\s+from|drop\s+table|--|;|xp_)",
                action="block",
                description="Detect SQL injection attempts",
                severity="high"
            ),
            SecurityRule(
                name="XSS Attack",
                pattern=r"(?i)(<script.*?>|javascript:|onerror=|onload=)",
                action="block",
                description="Detect Cross-Site Scripting attempts",
                severity="high"
            ),
            SecurityRule(
                name="Path Traversal",
                pattern=r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f)",
                action="block",
                description="Detect path traversal attempts",
                severity="high"
            ),
            SecurityRule(
                name="Command Injection",
                pattern=r"(?i)(;.*?;|&.*?&|\|.*?\|)",
                action="block",
                description="Detect command injection attempts",
                severity="high"
            ),
            SecurityRule(
                name="Sensitive Data Exposure",
                pattern=r"(?i)(password|credit\s*card|ssn|social\s*security)",
                action="log",
                description="Detect potential sensitive data exposure",
                severity="medium"
            )
        ]
        self.rules.extend(default_rules)

    def add_rule(self, rule: SecurityRule) -> None:
        """Add a new security rule"""
        self.rules.append(rule)
        self.logger.info(f"Added new rule: {rule.name}")

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a security rule by name"""
        for i, rule in enumerate(self.rules):
            if rule.name.lower() == rule_name.lower():
                del self.rules[i]
                self.logger.info(f"Removed rule: {rule_name}")
                return True
        return False

    def add_ip_to_blacklist(self, ip: str) -> bool:
        """Add an IP address to the blacklist"""
        try:
            ipaddress.ip_address(ip)
            self.ip_blacklist.add(ip)
            self.logger.info(f"Added IP to blacklist: {ip}")
            return True
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return False

    def add_ip_to_whitelist(self, ip: str) -> bool:
        """Add an IP address to the whitelist"""
        try:
            ipaddress.ip_address(ip)
            self.ip_whitelist.add(ip)
            self.logger.info(f"Added IP to whitelist: {ip}")
            return True
        except ValueError:
            self.logger.error(f"Invalid IP address: {ip}")
            return False

    def check_rate_limit(self, ip: str, limit: int = 100, window: int = 60) -> bool:
        """Check if an IP has exceeded rate limits"""
        current_time = time.time()
        # Clean old entries
        self.rate_limits[ip] = [t for t in self.rate_limits[ip] 
                              if current_time - t < window]
        
        if len(self.rate_limits[ip]) >= limit:
            return False
        
        self.rate_limits[ip].append(current_time)
        return True

    def analyze_request(self, request: Dict) -> Tuple[bool, List[Dict]]:
        """
        Analyze a request for security violations
        Returns: (is_safe, violations)
        """
        violations = []
        ip = request.get('ip', '')
        
        # Check IP blacklist/whitelist
        if ip in self.ip_blacklist:
            violations.append({
                'type': 'blacklist',
                'description': f'IP {ip} is blacklisted',
                'severity': 'high'
            })
            return False, violations
            
        if ip in self.ip_whitelist:
            return True, violations
            
        # Check rate limits
        if not self.check_rate_limit(ip):
            violations.append({
                'type': 'rate_limit',
                'description': f'Rate limit exceeded for IP {ip}',
                'severity': 'medium'
            })
            return False, violations
            
        # Check against security rules
        for rule in self.rules:
            if re.search(rule.pattern, str(request)):
                violations.append({
                    'type': rule.name,
                    'description': rule.description,
                    'severity': rule.severity
                })
                if rule.action == 'block':
                    return False, violations
                    
        return True, violations

    def log_request(self, request: Dict, is_safe: bool, violations: List[Dict]) -> None:
        """Log request details and analysis results"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': request.get('ip', ''),
            'method': request.get('method', ''),
            'path': request.get('path', ''),
            'is_safe': is_safe,
            'violations': violations
        }
        self.request_logs.append(log_entry)
        self.logger.info(f"Request logged: {json.dumps(log_entry)}")

    def get_statistics(self) -> Dict:
        """Get WAF statistics"""
        total_requests = len(self.request_logs)
        blocked_requests = sum(1 for log in self.request_logs if not log['is_safe'])
        
        violation_types = defaultdict(int)
        for log in self.request_logs:
            for violation in log['violations']:
                violation_types[violation['type']] += 1
                
        return {
            'total_requests': total_requests,
            'blocked_requests': blocked_requests,
            'block_rate': (blocked_requests / total_requests * 100) if total_requests > 0 else 0,
            'violation_types': dict(violation_types),
            'active_rules': len(self.rules),
            'blacklisted_ips': len(self.ip_blacklist),
            'whitelisted_ips': len(self.ip_whitelist)
        }

def main():
    parser = argparse.ArgumentParser(description='WAF Simulator')
    parser.add_argument('--log-file', help='Path to log file')
    args = parser.parse_args()

    waf = WAFSimulator()
    
    # Example usage
    print("WAF Simulator Started")
    print("====================")
    
    # Add some test rules
    waf.add_rule(SecurityRule(
        name="Custom Rule",
        pattern=r"(?i)(admin|root|sudo)",
        action="log",
        description="Detect admin access attempts",
        severity="medium"
    ))
    
    # Test some requests
    test_requests = [
        {
            'ip': '192.168.1.1',
            'method': 'GET',
            'path': '/api/users',
            'body': 'SELECT * FROM users'
        },
        {
            'ip': '192.168.1.2',
            'method': 'POST',
            'path': '/api/login',
            'body': '<script>alert("xss")</script>'
        },
        {
            'ip': '192.168.1.3',
            'method': 'GET',
            'path': '/api/data',
            'body': '../../../etc/passwd'
        }
    ]
    
    for request in test_requests:
        is_safe, violations = waf.analyze_request(request)
        waf.log_request(request, is_safe, violations)
        
        print(f"\nAnalyzing request from {request['ip']}:")
        print(f"Path: {request['path']}")
        print(f"Safe: {is_safe}")
        if violations:
            print("Violations found:")
            for violation in violations:
                print(f"- {violation['type']}: {violation['description']}")
    
    # Print statistics
    stats = waf.get_statistics()
    print("\nWAF Statistics:")
    print("==============")
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Blocked Requests: {stats['blocked_requests']}")
    print(f"Block Rate: {stats['block_rate']:.2f}%")
    print("\nViolation Types:")
    for vtype, count in stats['violation_types'].items():
        print(f"- {vtype}: {count}")

if __name__ == "__main__":
    main() 