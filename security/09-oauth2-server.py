from dataclasses import dataclass
from datetime import datetime, timedelta
import jwt
import uuid
import hashlib
from typing import Dict, Optional

@dataclass
class OAuth2Server:
    def __init__(self):
        self.clients: Dict[str, dict] = {}  # client_id -> client_secret
        self.tokens: Dict[str, dict] = {}   # access_token -> token_data
        self.authorization_codes: Dict[str, dict] = {}  # code -> code_data
        self.user_credentials: Dict[str, str] = {}  # username -> password_hash
        self.refresh_tokens: Dict[str, dict] = {}  # refresh_token -> token_data
        
    def register_client(self, client_name: str, redirect_uri: str) -> tuple:
        """Register a new OAuth2 client."""
        client_id = str(uuid.uuid4())
        client_secret = str(uuid.uuid4())
        self.clients[client_id] = {
            'secret': client_secret,
            'name': client_name,
            'redirect_uri': redirect_uri,
            'created_at': datetime.now()
        }
        return client_id, client_secret
        
    def register_user(self, username: str, password: str) -> bool:
        """Register a new user."""
        if username in self.user_credentials:
            return False
        self.user_credentials[username] = hashlib.sha256(password.encode()).hexdigest()
        return True
        
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate a user."""
        if username not in self.user_credentials:
            return False
        return self.user_credentials[username] == hashlib.sha256(password.encode()).hexdigest()
        
    def generate_auth_code(self, client_id: str, user_id: str, scope: str = "") -> str:
        """Generate an authorization code."""
        if client_id not in self.clients:
            raise ValueError("Invalid client ID")
            
        code = str(uuid.uuid4())
        self.authorization_codes[code] = {
            'client_id': client_id,
            'user_id': user_id,
            'scope': scope,
            'expires_at': datetime.now() + timedelta(minutes=10)
        }
        return code
        
    def exchange_code_for_token(self, code: str, client_id: str, client_secret: str) -> tuple:
        """Exchange authorization code for access and refresh tokens."""
        if code not in self.authorization_codes:
            raise ValueError("Invalid authorization code")
            
        code_data = self.authorization_codes[code]
        if code_data['client_id'] != client_id:
            raise ValueError("Client ID mismatch")
            
        if datetime.now() > code_data['expires_at']:
            raise ValueError("Authorization code expired")
            
        # Generate access token
        access_token = str(uuid.uuid4())
        self.tokens[access_token] = {
            'user_id': code_data['user_id'],
            'client_id': client_id,
            'scope': code_data['scope'],
            'expires_at': datetime.now() + timedelta(hours=1)
        }
        
        # Generate refresh token
        refresh_token = str(uuid.uuid4())
        self.refresh_tokens[refresh_token] = {
            'user_id': code_data['user_id'],
            'client_id': client_id,
            'scope': code_data['scope'],
            'expires_at': datetime.now() + timedelta(days=30)
        }
        
        del self.authorization_codes[code]
        return access_token, refresh_token
        
    def refresh_access_token(self, refresh_token: str, client_id: str, client_secret: str) -> str:
        """Generate new access token using refresh token."""
        if refresh_token not in self.refresh_tokens:
            raise ValueError("Invalid refresh token")
            
        token_data = self.refresh_tokens[refresh_token]
        if token_data['client_id'] != client_id:
            raise ValueError("Client ID mismatch")
            
        if datetime.now() > token_data['expires_at']:
            raise ValueError("Refresh token expired")
            
        # Generate new access token
        access_token = str(uuid.uuid4())
        self.tokens[access_token] = {
            'user_id': token_data['user_id'],
            'client_id': client_id,
            'scope': token_data['scope'],
            'expires_at': datetime.now() + timedelta(hours=1)
        }
        
        return access_token
        
    def validate_token(self, token: str) -> Optional[dict]:
        """Validate an access token."""
        if token not in self.tokens:
            return None
            
        token_data = self.tokens[token]
        if datetime.now() > token_data['expires_at']:
            del self.tokens[token]
            return None
            
        return token_data

# Example usage
if __name__ == "__main__":
    # Initialize OAuth2 server
    oauth_server = OAuth2Server()
    
    # Register a client
    client_id, client_secret = oauth_server.register_client(
        "Test Client",
        "http://localhost:8000/callback"
    )
    print(f"Registered client: {client_id}")
    
    # Register a user
    oauth_server.register_user("testuser", "password123")
    
    # Generate authorization code
    auth_code = oauth_server.generate_auth_code(client_id, "testuser", "read write")
    print(f"Generated auth code: {auth_code}")
    
    # Exchange code for tokens
    access_token, refresh_token = oauth_server.exchange_code_for_token(
        auth_code,
        client_id,
        client_secret
    )
    print(f"Access token: {access_token}")
    print(f"Refresh token: {refresh_token}")
    
    # Validate token
    token_data = oauth_server.validate_token(access_token)
    print(f"Token data: {token_data}")
    
    # Refresh token
    new_access_token = oauth_server.refresh_access_token(
        refresh_token,
        client_id,
        client_secret
    )
    print(f"New access token: {new_access_token}") 