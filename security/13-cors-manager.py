from dataclasses import dataclass
from typing import List, Set, Dict, Optional
import re
from urllib.parse import urlparse

@dataclass
class CORSPolicy:
    def __init__(self):
        self.allowed_origins: Set[str] = set()
        self.allowed_methods: Set[str] = {'GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'}
        self.allowed_headers: Set[str] = {'Content-Type', 'Authorization'}
        self.exposed_headers: Set[str] = set()
        self.max_age: int = 86400  # 24 hours
        self.allow_credentials: bool = True
        self.origin_patterns: List[str] = []  # For regex-based origin matching
        
    def add_allowed_origin(self, origin: str):
        """
        Add an allowed origin.
        
        Args:
            origin: The origin to allow (e.g., 'https://example.com')
        """
        if self._is_valid_origin(origin):
            self.allowed_origins.add(origin)
            
    def add_origin_pattern(self, pattern: str):
        """
        Add a regex pattern for matching origins.
        
        Args:
            pattern: Regex pattern for matching origins
        """
        try:
            re.compile(pattern)
            self.origin_patterns.append(pattern)
        except re.error:
            raise ValueError(f"Invalid regex pattern: {pattern}")
            
    def add_allowed_method(self, method: str):
        """
        Add an allowed HTTP method.
        
        Args:
            method: HTTP method to allow
        """
        self.allowed_methods.add(method.upper())
        
    def add_allowed_header(self, header: str):
        """
        Add an allowed header.
        
        Args:
            header: Header name to allow
        """
        self.allowed_headers.add(header)
        
    def add_exposed_header(self, header: str):
        """
        Add an exposed header.
        
        Args:
            header: Header name to expose
        """
        self.exposed_headers.add(header)
        
    def set_max_age(self, seconds: int):
        """
        Set the max-age for preflight requests.
        
        Args:
            seconds: Number of seconds to cache preflight results
        """
        if seconds < 0:
            raise ValueError("Max age must be non-negative")
        self.max_age = seconds
        
    def set_allow_credentials(self, allow: bool):
        """
        Set whether to allow credentials.
        
        Args:
            allow: Whether to allow credentials
        """
        self.allow_credentials = allow
        
    def is_origin_allowed(self, origin: str) -> bool:
        """
        Check if an origin is allowed.
        
        Args:
            origin: The origin to check
            
        Returns:
            bool: True if the origin is allowed
        """
        if origin in self.allowed_origins:
            return True
            
        for pattern in self.origin_patterns:
            if re.match(pattern, origin):
                return True
                
        return False
        
    def get_cors_headers(self, origin: str) -> Dict[str, str]:
        """
        Get CORS headers for a specific origin.
        
        Args:
            origin: The requesting origin
            
        Returns:
            Dict[str, str]: Dictionary of CORS headers
        """
        if not self.is_origin_allowed(origin):
            return {}
            
        headers = {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Methods': ', '.join(sorted(self.allowed_methods)),
            'Access-Control-Allow-Headers': ', '.join(sorted(self.allowed_headers)),
            'Access-Control-Max-Age': str(self.max_age)
        }
        
        if self.exposed_headers:
            headers['Access-Control-Expose-Headers'] = ', '.join(sorted(self.exposed_headers))
            
        if self.allow_credentials:
            headers['Access-Control-Allow-Credentials'] = 'true'
            
        return headers
        
    def _is_valid_origin(self, origin: str) -> bool:
        """
        Validate an origin string.
        
        Args:
            origin: The origin to validate
            
        Returns:
            bool: True if the origin is valid
        """
        try:
            parsed = urlparse(origin)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
            
    def validate_policy(self) -> List[str]:
        """
        Validate the CORS policy configuration.
        
        Returns:
            List[str]: List of validation warnings
        """
        warnings = []
        
        # Check for wildcard origin with credentials
        if self.allow_credentials and '*' in self.allowed_origins:
            warnings.append("Wildcard origin (*) is not allowed with credentials")
            
        # Check for required methods
        required_methods = {'GET', 'OPTIONS'}
        if not required_methods.issubset(self.allowed_methods):
            warnings.append(f"Missing required methods: {required_methods - self.allowed_methods}")
            
        # Check for required headers
        required_headers = {'Content-Type'}
        if not required_headers.issubset(self.allowed_headers):
            warnings.append(f"Missing required headers: {required_headers - self.allowed_headers}")
            
        # Validate origin patterns
        for pattern in self.origin_patterns:
            try:
                re.compile(pattern)
            except re.error:
                warnings.append(f"Invalid origin pattern: {pattern}")
                
        return warnings

# Example usage
if __name__ == "__main__":
    # Initialize CORS policy
    cors = CORSPolicy()
    
    # Add allowed origins
    cors.add_allowed_origin('https://example.com')
    cors.add_allowed_origin('https://api.example.com')
    cors.add_origin_pattern(r'https://.*\.example\.com')
    
    # Add allowed methods
    cors.add_allowed_method('PATCH')
    
    # Add allowed headers
    cors.add_allowed_header('X-Custom-Header')
    
    # Add exposed headers
    cors.add_exposed_header('X-Total-Count')
    
    # Set max age
    cors.set_max_age(3600)  # 1 hour
    
    # Test origin validation
    test_origins = [
        'https://example.com',
        'https://api.example.com',
        'https://sub.example.com',
        'https://malicious.com'
    ]
    
    print("Origin Validation:")
    for origin in test_origins:
        print(f"{origin}: {'Allowed' if cors.is_origin_allowed(origin) else 'Blocked'}")
        
    # Get CORS headers
    print("\nCORS Headers for https://example.com:")
    headers = cors.get_cors_headers('https://example.com')
    for name, value in headers.items():
        print(f"{name}: {value}")
        
    # Validate policy
    warnings = cors.validate_policy()
    if warnings:
        print("\nPolicy Warnings:")
        for warning in warnings:
            print(f"- {warning}")
    else:
        print("\nPolicy is valid!") 