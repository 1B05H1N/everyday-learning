from dataclasses import dataclass
import redis
import time
from typing import Optional, Dict, List, Tuple
import json
from datetime import datetime, timedelta

@dataclass
class RateLimiter:
    def __init__(self, redis_url: str):
        """
        Initialize rate limiter with Redis connection.
        
        Args:
            redis_url: Redis connection URL
        """
        self.redis = redis.from_url(redis_url)
        self.default_window = 60  # 1 minute
        self.default_limit = 100  # 100 requests per minute
        
    def check_rate_limit(self, 
                        key: str, 
                        limit: int = None, 
                        window: int = None) -> Tuple[bool, Optional[int]]:
        """
        Check if a request should be rate limited.
        
        Args:
            key: Unique identifier for the rate limit (e.g., IP address)
            limit: Maximum number of requests allowed in the window
            window: Time window in seconds
            
        Returns:
            Tuple[bool, Optional[int]]: (is_allowed, retry_after)
        """
        limit = limit or self.default_limit
        window = window or self.default_window
        
        current = int(time.time())
        window_key = f"{key}:{current // window}"
        
        pipe = self.redis.pipeline()
        pipe.incr(window_key)
        pipe.expire(window_key, window)
        result = pipe.execute()
        
        count = result[0]
        if count > limit:
            return False, window - (current % window)
            
        return True, None
        
    def get_rate_limit_info(self, key: str) -> Dict:
        """
        Get rate limit information for a key.
        
        Args:
            key: The rate limit key
            
        Returns:
            Dict: Rate limit information
        """
        current = int(time.time())
        window_key = f"{key}:{current // self.default_window}"
        
        count = self.redis.get(window_key)
        ttl = self.redis.ttl(window_key)
        
        return {
            "key": key,
            "current_count": int(count) if count else 0,
            "window_seconds": self.default_window,
            "limit": self.default_limit,
            "remaining": self.default_limit - (int(count) if count else 0),
            "reset_in_seconds": ttl if ttl > 0 else 0
        }
        
    def reset_rate_limit(self, key: str) -> bool:
        """
        Reset rate limit for a key.
        
        Args:
            key: The rate limit key
            
        Returns:
            bool: True if reset was successful
        """
        current = int(time.time())
        window_key = f"{key}:{current // self.default_window}"
        return bool(self.redis.delete(window_key))
        
    def set_rate_limit(self, key: str, limit: int, window: int) -> bool:
        """
        Set custom rate limit for a key.
        
        Args:
            key: The rate limit key
            limit: Maximum number of requests
            window: Time window in seconds
            
        Returns:
            bool: True if set was successful
        """
        try:
            self.redis.hset(
                "rate_limits",
                key,
                json.dumps({"limit": limit, "window": window})
            )
            return True
        except:
            return False
            
    def get_rate_limit_settings(self, key: str) -> Optional[Dict]:
        """
        Get custom rate limit settings for a key.
        
        Args:
            key: The rate limit key
            
        Returns:
            Optional[Dict]: Rate limit settings if found
        """
        try:
            settings = self.redis.hget("rate_limits", key)
            return json.loads(settings) if settings else None
        except:
            return None
            
    def remove_rate_limit_settings(self, key: str) -> bool:
        """
        Remove custom rate limit settings for a key.
        
        Args:
            key: The rate limit key
            
        Returns:
            bool: True if removal was successful
        """
        return bool(self.redis.hdel("rate_limits", key))
        
    def get_all_rate_limits(self) -> Dict[str, Dict]:
        """
        Get all rate limit settings.
        
        Returns:
            Dict[str, Dict]: All rate limit settings
        """
        try:
            all_settings = self.redis.hgetall("rate_limits")
            return {
                key.decode(): json.loads(value.decode())
                for key, value in all_settings.items()
            }
        except:
            return {}
            
    def cleanup_expired_keys(self):
        """Clean up expired rate limit keys."""
        pattern = "*:*"
        for key in self.redis.scan_iter(pattern):
            if self.redis.ttl(key) <= 0:
                self.redis.delete(key)

# Example usage
if __name__ == "__main__":
    # Initialize rate limiter
    limiter = RateLimiter("redis://localhost:6379/0")
    
    # Test basic rate limiting
    test_key = "test_user"
    print("\nTesting basic rate limiting:")
    for i in range(5):
        allowed, retry_after = limiter.check_rate_limit(test_key, limit=3, window=60)
        print(f"Request {i+1}: {'Allowed' if allowed else 'Blocked'}")
        if not allowed:
            print(f"Retry after {retry_after} seconds")
            
    # Get rate limit info
    print("\nRate limit information:")
    info = limiter.get_rate_limit_info(test_key)
    print(json.dumps(info, indent=2))
    
    # Set custom rate limit
    print("\nSetting custom rate limit:")
    limiter.set_rate_limit("vip_user", limit=1000, window=3600)
    settings = limiter.get_rate_limit_settings("vip_user")
    print(json.dumps(settings, indent=2))
    
    # Test custom rate limit
    print("\nTesting custom rate limit:")
    allowed, retry_after = limiter.check_rate_limit("vip_user", limit=1000, window=3600)
    print(f"Request: {'Allowed' if allowed else 'Blocked'}")
    
    # Reset rate limit
    print("\nResetting rate limit:")
    if limiter.reset_rate_limit(test_key):
        print("Rate limit reset successfully")
        
    # Get all rate limits
    print("\nAll rate limits:")
    all_limits = limiter.get_all_rate_limits()
    print(json.dumps(all_limits, indent=2))
    
    # Remove custom rate limit
    print("\nRemoving custom rate limit:")
    if limiter.remove_rate_limit_settings("vip_user"):
        print("Custom rate limit removed successfully")
        
    # Cleanup expired keys
    print("\nCleaning up expired keys:")
    limiter.cleanup_expired_keys()
    print("Cleanup completed") 