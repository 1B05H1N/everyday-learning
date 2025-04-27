from dataclasses import dataclass
from datetime import datetime, timedelta
import jwt
import uuid
from typing import Dict, List, Optional, Set
import json

@dataclass
class JWTManager:
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.blacklisted_tokens: Set[str] = set()
        self.token_store: Dict[str, dict] = {}  # For tracking token metadata
        
    def create_token(self, 
                    user_id: str, 
                    roles: List[str], 
                    expires_in: int = 3600,
                    additional_claims: dict = None) -> str:
        """
        Create a new JWT token.
        
        Args:
            user_id: The user identifier
            roles: List of user roles
            expires_in: Token expiration time in seconds
            additional_claims: Additional claims to include in the token
            
        Returns:
            str: The generated JWT token
        """
        # Generate a unique token ID
        token_id = str(uuid.uuid4())
        
        # Prepare the token payload
        payload = {
            'sub': user_id,
            'roles': roles,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=expires_in),
            'jti': token_id
        }
        
        # Add additional claims if provided
        if additional_claims:
            payload.update(additional_claims)
            
        # Generate the token
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        
        # Store token metadata
        self.token_store[token_id] = {
            'user_id': user_id,
            'roles': roles,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(seconds=expires_in)
        }
        
        return token
        
    def verify_token(self, token: str) -> Optional[dict]:
        """
        Verify a JWT token.
        
        Args:
            token: The JWT token to verify
            
        Returns:
            dict: The decoded token payload if valid, None otherwise
            
        Raises:
            ValueError: If the token is invalid or has been revoked
        """
        # Check if token is blacklisted
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            if payload['jti'] in self.blacklisted_tokens:
                raise ValueError("Token has been revoked")
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
            
    def revoke_token(self, token: str) -> bool:
        """
        Revoke a JWT token.
        
        Args:
            token: The JWT token to revoke
            
        Returns:
            bool: True if token was successfully revoked, False otherwise
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            token_id = payload['jti']
            self.blacklisted_tokens.add(token_id)
            if token_id in self.token_store:
                del self.token_store[token_id]
            return True
        except:
            return False
            
    def get_token_info(self, token: str) -> Optional[dict]:
        """
        Get information about a token.
        
        Args:
            token: The JWT token
            
        Returns:
            dict: Token information if found, None otherwise
        """
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            token_id = payload['jti']
            return self.token_store.get(token_id)
        except:
            return None
            
    def cleanup_expired_tokens(self):
        """Remove expired tokens from storage."""
        current_time = datetime.utcnow()
        expired_tokens = [
            token_id for token_id, data in self.token_store.items()
            if data['expires_at'] < current_time
        ]
        for token_id in expired_tokens:
            del self.token_store[token_id]
            self.blacklisted_tokens.add(token_id)

# Example usage
if __name__ == "__main__":
    # Initialize JWT manager with a secret key
    jwt_manager = JWTManager("your-secret-key-here")
    
    # Create a token
    token = jwt_manager.create_token(
        user_id="user123",
        roles=["admin", "user"],
        additional_claims={"email": "user@example.com"}
    )
    print(f"Created token: {token}")
    
    # Verify token
    try:
        payload = jwt_manager.verify_token(token)
        print(f"Token payload: {json.dumps(payload, indent=2, default=str)}")
    except ValueError as e:
        print(f"Token verification failed: {e}")
        
    # Get token info
    token_info = jwt_manager.get_token_info(token)
    print(f"Token info: {json.dumps(token_info, indent=2, default=str)}")
    
    # Revoke token
    if jwt_manager.revoke_token(token):
        print("Token revoked successfully")
        
    # Try to verify revoked token
    try:
        jwt_manager.verify_token(token)
    except ValueError as e:
        print(f"Expected error for revoked token: {e}")
        
    # Cleanup expired tokens
    jwt_manager.cleanup_expired_tokens() 