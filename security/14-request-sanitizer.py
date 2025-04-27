from dataclasses import dataclass
import re
import html
import json
from typing import Dict, List, Union, Any
import bleach
from urllib.parse import unquote

@dataclass
class RequestSanitizer:
    def __init__(self):
        # Common attack patterns
        self.xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'data:',
            r'vbscript:',
            r'eval\(',
            r'expression\(',
            r'<iframe.*?>',
            r'<object.*?>',
            r'<embed.*?>',
            r'<applet.*?>'
        ]
        
        # SQL injection patterns
        self.sql_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE)\b)',
            r'--',
            r';',
            r'/\*.*?\*/',
            r'xp_.*?',
            r'sp_.*?'
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r'\.\./',
            r'\.\.\\',
            r'%2e%2e%2f',
            r'%2e%2e/',
            r'..%2f',
            r'%2e%2e%5c',
            r'%2e%2e\\',
            r'..%5c'
        ]
        
        # Command injection patterns
        self.command_injection_patterns = [
            r'[;&|`]',
            r'\$\(.*?\)',
            r'`.*?`',
            r'\|\|.*?',
            r'&&.*?'
        ]
        
    def sanitize_input(self, data: str) -> str:
        """
        Sanitize string input to prevent XSS and other attacks.
        
        Args:
            data: Input string to sanitize
            
        Returns:
            str: Sanitized string
        """
        # URL decode
        data = unquote(data)
        
        # Remove potential XSS
        for pattern in self.xss_patterns:
            data = re.sub(pattern, '', data, flags=re.IGNORECASE)
            
        # HTML encode special characters
        data = html.escape(data)
        
        # Use bleach for additional sanitization
        data = bleach.clean(data, strip=True)
        
        return data
        
    def sanitize_json(self, data: Union[dict, list]) -> Union[dict, list]:
        """
        Sanitize JSON data recursively.
        
        Args:
            data: JSON data to sanitize
            
        Returns:
            Union[dict, list]: Sanitized JSON data
        """
        def sanitize_value(value: Any) -> Any:
            if isinstance(value, str):
                return self.sanitize_input(value)
            elif isinstance(value, dict):
                return {k: sanitize_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [sanitize_value(item) for item in value]
            return value
            
        return sanitize_value(data)
        
    def validate_input(self, data: str, input_type: str = 'text') -> List[str]:
        """
        Validate input against common attack patterns.
        
        Args:
            data: Input to validate
            input_type: Type of input ('text', 'sql', 'path', 'command')
            
        Returns:
            List[str]: List of detected issues
        """
        issues = []
        
        if input_type == 'text':
            # Check for XSS
            for pattern in self.xss_patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    issues.append(f"Potential XSS detected: {pattern}")
                    
        elif input_type == 'sql':
            # Check for SQL injection
            for pattern in self.sql_patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    issues.append(f"Potential SQL injection detected: {pattern}")
                    
        elif input_type == 'path':
            # Check for path traversal
            for pattern in self.path_traversal_patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    issues.append(f"Potential path traversal detected: {pattern}")
                    
        elif input_type == 'command':
            # Check for command injection
            for pattern in self.command_injection_patterns:
                if re.search(pattern, data, re.IGNORECASE):
                    issues.append(f"Potential command injection detected: {pattern}")
                    
        return issues
        
    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize HTTP headers.
        
        Args:
            headers: Headers to sanitize
            
        Returns:
            Dict[str, str]: Sanitized headers
        """
        sanitized = {}
        for name, value in headers.items():
            # Sanitize header name
            safe_name = re.sub(r'[^a-zA-Z0-9\-_]', '', name)
            # Sanitize header value
            safe_value = self.sanitize_input(value)
            sanitized[safe_name] = safe_value
        return sanitized
        
    def sanitize_url(self, url: str) -> str:
        """
        Sanitize URL to prevent various attacks.
        
        Args:
            url: URL to sanitize
            
        Returns:
            str: Sanitized URL
        """
        # Remove potential XSS
        url = self.sanitize_input(url)
        
        # Check for path traversal
        for pattern in self.path_traversal_patterns:
            url = re.sub(pattern, '', url, flags=re.IGNORECASE)
            
        # Remove dangerous protocols
        url = re.sub(r'^(javascript|data|vbscript):', '', url, flags=re.IGNORECASE)
        
        return url

# Example usage
if __name__ == "__main__":
    # Initialize sanitizer
    sanitizer = RequestSanitizer()
    
    # Test string sanitization
    test_input = """
    <script>alert('xss')</script>
    Hello <img src="javascript:alert('xss')" />
    <a href="javascript:alert('xss')">Click me</a>
    """
    print("Original input:")
    print(test_input)
    print("\nSanitized input:")
    print(sanitizer.sanitize_input(test_input))
    
    # Test JSON sanitization
    test_json = {
        "name": "<script>alert('xss')</script>",
        "data": {
            "html": "<img src='x' onerror='alert(1)'>",
            "text": "Normal text"
        },
        "list": [
            "<script>alert('xss')</script>",
            "Safe text"
        ]
    }
    print("\nOriginal JSON:")
    print(json.dumps(test_json, indent=2))
    print("\nSanitized JSON:")
    print(json.dumps(sanitizer.sanitize_json(test_json), indent=2))
    
    # Test input validation
    test_cases = [
        ("<script>alert('xss')</script>", "text"),
        ("SELECT * FROM users; DROP TABLE users;", "sql"),
        ("../../../etc/passwd", "path"),
        ("ls; rm -rf /", "command")
    ]
    
    print("\nInput Validation:")
    for input_data, input_type in test_cases:
        issues = sanitizer.validate_input(input_data, input_type)
        print(f"\nInput: {input_data}")
        print(f"Type: {input_type}")
        if issues:
            print("Issues found:")
            for issue in issues:
                print(f"- {issue}")
        else:
            print("No issues found")
            
    # Test header sanitization
    test_headers = {
        "Content-Type": "text/html; charset=utf-8",
        "X-Custom-Header": "<script>alert('xss')</script>",
        "User-Agent": "Mozilla/5.0 (XSS)"
    }
    print("\nOriginal Headers:")
    print(json.dumps(test_headers, indent=2))
    print("\nSanitized Headers:")
    print(json.dumps(sanitizer.sanitize_headers(test_headers), indent=2))
    
    # Test URL sanitization
    test_urls = [
        "https://example.com/path/../../../etc/passwd",
        "javascript:alert('xss')",
        "data:text/html,<script>alert('xss')</script>"
    ]
    print("\nURL Sanitization:")
    for url in test_urls:
        print(f"\nOriginal URL: {url}")
        print(f"Sanitized URL: {sanitizer.sanitize_url(url)}") 