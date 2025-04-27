from dataclasses import dataclass
from typing import Dict, List, Optional
import re

@dataclass
class SecurityHeaders:
    def __init__(self):
        # Default security headers with recommended values
        self.headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'Cache-Control': 'no-store, max-age=0',
            'Pragma': 'no-cache'
        }
        
    def add_header(self, name: str, value: str):
        """
        Add or update a security header.
        
        Args:
            name: Header name
            value: Header value
        """
        self.headers[name] = value
        
    def remove_header(self, name: str):
        """
        Remove a security header.
        
        Args:
            name: Header name to remove
        """
        if name in self.headers:
            del self.headers[name]
            
    def get_headers(self) -> Dict[str, str]:
        """
        Get all configured security headers.
        
        Returns:
            Dict[str, str]: Dictionary of header name-value pairs
        """
        return self.headers.copy()
        
    def set_csp(self, directives: Dict[str, List[str]]):
        """
        Set Content Security Policy directives.
        
        Args:
            directives: Dictionary of CSP directives and their values
        """
        csp_parts = []
        for directive, sources in directives.items():
            csp_parts.append(f"{directive} {' '.join(sources)}")
        self.headers['Content-Security-Policy'] = '; '.join(csp_parts)
        
    def set_hsts(self, max_age: int = 31536000, include_subdomains: bool = True, preload: bool = False):
        """
        Set HTTP Strict Transport Security header.
        
        Args:
            max_age: Maximum age in seconds
            include_subdomains: Whether to include subdomains
            preload: Whether to allow preloading
        """
        hsts_value = f"max-age={max_age}"
        if include_subdomains:
            hsts_value += "; includeSubDomains"
        if preload:
            hsts_value += "; preload"
        self.headers['Strict-Transport-Security'] = hsts_value
        
    def set_permissions_policy(self, features: Dict[str, List[str]]):
        """
        Set Permissions Policy header.
        
        Args:
            features: Dictionary of features and their allowed values
        """
        policy_parts = []
        for feature, values in features.items():
            policy_parts.append(f"{feature}=({' '.join(values)})")
        self.headers['Permissions-Policy'] = ', '.join(policy_parts)
        
    def validate_headers(self) -> List[str]:
        """
        Validate security headers for common issues.
        
        Returns:
            List[str]: List of validation warnings
        """
        warnings = []
        
        # Check for missing essential headers
        essential_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security'
        ]
        for header in essential_headers:
            if header not in self.headers:
                warnings.append(f"Missing essential header: {header}")
                
        # Validate CSP syntax
        if 'Content-Security-Policy' in self.headers:
            csp = self.headers['Content-Security-Policy']
            if not re.match(r'^[a-zA-Z0-9\s\-\'\"\*\.;=]+$', csp):
                warnings.append("Invalid characters in Content-Security-Policy")
                
        # Validate HSTS max-age
        if 'Strict-Transport-Security' in self.headers:
            hsts = self.headers['Strict-Transport-Security']
            if 'max-age=' in hsts:
                try:
                    max_age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                    if max_age < 31536000:  # Less than 1 year
                        warnings.append("HSTS max-age should be at least 1 year")
                except:
                    warnings.append("Invalid HSTS max-age value")
                    
        return warnings

# Example usage
if __name__ == "__main__":
    # Initialize security headers
    security = SecurityHeaders()
    
    # Set custom CSP
    security.set_csp({
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'", "https://api.example.com"]
    })
    
    # Set HSTS
    security.set_hsts(max_age=63072000, include_subdomains=True, preload=True)
    
    # Set Permissions Policy
    security.set_permissions_policy({
        'geolocation': ["'self'"],
        'camera': ["'none'"],
        'microphone': ["'none'"],
        'payment': ["'self'"]
    })
    
    # Add custom header
    security.add_header('X-Custom-Header', 'value')
    
    # Get all headers
    headers = security.get_headers()
    print("Security Headers:")
    for name, value in headers.items():
        print(f"{name}: {value}")
        
    # Validate headers
    warnings = security.validate_headers()
    if warnings:
        print("\nValidation Warnings:")
        for warning in warnings:
            print(f"- {warning}")
    else:
        print("\nAll headers are valid!") 