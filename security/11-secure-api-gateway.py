#!/usr/bin/env python3

import asyncio
import aiohttp
import jwt
import logging
import argparse
import json
import time
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from aiohttp import web
from cryptography.fernet import Fernet
import hashlib
import base64
import redis
import yaml
import ratelimit
import prometheus_client as prom

@dataclass
class APIEndpoint:
    path: str
    upstream_url: str
    methods: List[str]
    auth_required: bool
    rate_limit: Optional[Dict]
    cache_ttl: Optional[int]
    transform_request: Optional[Dict]
    transform_response: Optional[Dict]

class SecureAPIGateway:
    def __init__(self, config_path: str):
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('SecureAPIGateway')
        
        # Load configuration
        self.config = self._load_config(config_path)
        
        # Initialize components
        self.app = web.Application(middlewares=[
            self.auth_middleware,
            self.rate_limit_middleware,
            self.security_headers_middleware,
            self.validation_middleware
        ])
        
        # Initialize Redis for rate limiting and caching
        self.redis = redis.Redis(
            host=self.config['redis']['host'],
            port=self.config['redis']['port'],
            db=self.config['redis']['db']
        )
        
        # Initialize encryption key
        self.fernet = Fernet(self.config['security']['encryption_key'].encode())
        
        # Initialize JWT settings
        self.jwt_secret = self.config['security']['jwt_secret']
        self.jwt_algorithm = 'HS256'
        
        # Initialize metrics
        self.setup_metrics()
        
        # Setup routes
        self.setup_routes()

    def _load_config(self, config_path: str) -> Dict:
        """Load and validate configuration file"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            
        required_fields = ['endpoints', 'security', 'redis']
        for field in required_fields:
            if field not in config:
                raise ValueError(f"Missing required configuration field: {field}")
                
        return config

    def setup_metrics(self):
        """Setup Prometheus metrics"""
        self.request_count = prom.Counter(
            'api_requests_total',
            'Total API requests',
            ['method', 'endpoint', 'status']
        )
        self.request_latency = prom.Histogram(
            'api_request_latency_seconds',
            'API request latency',
            ['method', 'endpoint']
        )
        self.error_count = prom.Counter(
            'api_errors_total',
            'Total API errors',
            ['method', 'endpoint', 'error_type']
        )

    def setup_routes(self):
        """Setup API routes from configuration"""
        for endpoint_config in self.config['endpoints']:
            endpoint = APIEndpoint(**endpoint_config)
            self.app.router.add_route(
                '*',
                endpoint.path,
                self.handle_request
            )
        
        # Add metrics endpoint
        self.app.router.add_get('/metrics', self.handle_metrics)

    @web.middleware
    async def auth_middleware(self, request: web.Request, handler) -> web.Response:
        """Authentication and authorization middleware"""
        endpoint = self._get_endpoint_config(request.path)
        
        if endpoint and endpoint.auth_required:
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                raise web.HTTPUnauthorized(reason="Missing authorization header")
            
            try:
                token = auth_header.split(' ')[1]
                payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
                
                # Check token expiration
                if datetime.fromtimestamp(payload['exp']) < datetime.now():
                    raise web.HTTPUnauthorized(reason="Token expired")
                
                # Add user info to request
                request['user'] = payload
                
            except (jwt.InvalidTokenError, IndexError) as e:
                self.error_count.labels(
                    method=request.method,
                    endpoint=request.path,
                    error_type='auth_error'
                ).inc()
                raise web.HTTPUnauthorized(reason="Invalid token")
        
        return await handler(request)

    @web.middleware
    async def rate_limit_middleware(self, request: web.Request, handler) -> web.Response:
        """Rate limiting middleware"""
        endpoint = self._get_endpoint_config(request.path)
        
        if endpoint and endpoint.rate_limit:
            key = f"ratelimit:{request.path}:{request.remote}"
            current = self.redis.get(key)
            
            if current and int(current) >= endpoint.rate_limit['max_requests']:
                self.error_count.labels(
                    method=request.method,
                    endpoint=request.path,
                    error_type='rate_limit'
                ).inc()
                raise web.HTTPTooManyRequests(reason="Rate limit exceeded")
            
            pipe = self.redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, endpoint.rate_limit['window'])
            pipe.execute()
        
        return await handler(request)

    @web.middleware
    async def security_headers_middleware(self, request: web.Request, handler) -> web.Response:
        """Add security headers to response"""
        response = await handler(request)
        
        # Add security headers
        response.headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': "default-src 'self'",
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Cache-Control': 'no-store, no-cache, must-revalidate'
        })
        
        return response

    @web.middleware
    async def validation_middleware(self, request: web.Request, handler) -> web.Response:
        """Validate request and response data"""
        endpoint = self._get_endpoint_config(request.path)
        
        if endpoint:
            # Validate request
            if endpoint.transform_request:
                try:
                    if request.content_type == 'application/json':
                        data = await request.json()
                        self._validate_data(data, endpoint.transform_request)
                except (json.JSONDecodeError, ValueError) as e:
                    self.error_count.labels(
                        method=request.method,
                        endpoint=request.path,
                        error_type='validation_error'
                    ).inc()
                    raise web.HTTPBadRequest(reason=str(e))
        
        response = await handler(request)
        
        # Validate response
        if endpoint and endpoint.transform_response:
            try:
                if response.content_type == 'application/json':
                    data = await response.json()
                    self._validate_data(data, endpoint.transform_response)
            except (json.JSONDecodeError, ValueError) as e:
                self.error_count.labels(
                    method=request.method,
                    endpoint=request.path,
                    error_type='validation_error'
                ).inc()
                raise web.HTTPInternalServerError(reason=str(e))
        
        return response

    def _validate_data(self, data: Dict, schema: Dict):
        """Validate data against schema"""
        for field, rules in schema.items():
            if field not in data and rules.get('required', False):
                raise ValueError(f"Missing required field: {field}")
            
            if field in data:
                value = data[field]
                
                # Type validation
                if 'type' in rules:
                    if rules['type'] == 'string' and not isinstance(value, str):
                        raise ValueError(f"Field {field} must be a string")
                    elif rules['type'] == 'number' and not isinstance(value, (int, float)):
                        raise ValueError(f"Field {field} must be a number")
                
                # Pattern validation
                if 'pattern' in rules and isinstance(value, str):
                    if not re.match(rules['pattern'], value):
                        raise ValueError(f"Field {field} does not match pattern: {rules['pattern']}")
                
                # Range validation
                if 'min' in rules and value < rules['min']:
                    raise ValueError(f"Field {field} must be >= {rules['min']}")
                if 'max' in rules and value > rules['max']:
                    raise ValueError(f"Field {field} must be <= {rules['max']}")

    def _get_endpoint_config(self, path: str) -> Optional[APIEndpoint]:
        """Get endpoint configuration by path"""
        for endpoint in self.config['endpoints']:
            if endpoint['path'] == path:
                return APIEndpoint(**endpoint)
        return None

    async def handle_request(self, request: web.Request) -> web.Response:
        """Handle API requests"""
        endpoint = self._get_endpoint_config(request.path)
        if not endpoint:
            raise web.HTTPNotFound()
        
        # Check allowed methods
        if request.method not in endpoint.methods:
            raise web.HTTPMethodNotAllowed(
                method=request.method,
                allowed_methods=endpoint.methods
            )
        
        # Start timing
        start_time = time.time()
        
        try:
            # Check cache
            if endpoint.cache_ttl:
                cache_key = f"cache:{request.path}:{request.query_string}"
                cached = self.redis.get(cache_key)
                if cached:
                    return web.Response(
                        body=self.fernet.decrypt(cached),
                        content_type='application/json'
                    )
            
            # Forward request to upstream
            async with aiohttp.ClientSession() as session:
                method = getattr(session, request.method.lower())
                async with method(
                    endpoint.upstream_url,
                    headers=self._forward_headers(request),
                    params=request.query,
                    data=await request.read()
                ) as upstream_response:
                    body = await upstream_response.read()
                    
                    # Cache response if needed
                    if endpoint.cache_ttl:
                        encrypted_body = self.fernet.encrypt(body)
                        self.redis.setex(
                            cache_key,
                            endpoint.cache_ttl,
                            encrypted_body
                        )
                    
                    response = web.Response(
                        body=body,
                        status=upstream_response.status,
                        headers=upstream_response.headers
                    )
            
            # Record metrics
            self.request_count.labels(
                method=request.method,
                endpoint=request.path,
                status=response.status
            ).inc()
            
            self.request_latency.labels(
                method=request.method,
                endpoint=request.path
            ).observe(time.time() - start_time)
            
            return response
            
        except Exception as e:
            self.error_count.labels(
                method=request.method,
                endpoint=request.path,
                error_type='upstream_error'
            ).inc()
            raise web.HTTPInternalServerError(reason=str(e))

    def _forward_headers(self, request: web.Request) -> Dict:
        """Forward selected headers to upstream"""
        headers = {}
        forwarded_headers = [
            'Content-Type',
            'Accept',
            'User-Agent',
            'X-Request-ID',
            'X-Real-IP'
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                headers[header] = request.headers[header]
        
        # Add X-Forwarded headers
        headers['X-Forwarded-For'] = request.remote
        headers['X-Forwarded-Proto'] = request.scheme
        headers['X-Forwarded-Host'] = request.host
        
        return headers

    async def handle_metrics(self, request: web.Request) -> web.Response:
        """Handle Prometheus metrics endpoint"""
        resp = web.Response(body=prom.generate_latest())
        resp.content_type = prom.CONTENT_TYPE_LATEST
        return resp

def main():
    parser = argparse.ArgumentParser(description='Secure API Gateway')
    parser.add_argument('config', help='Path to configuration file')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    args = parser.parse_args()

    # Create and run gateway
    gateway = SecureAPIGateway(args.config)
    web.run_app(gateway.app, host=args.host, port=args.port)

if __name__ == "__main__":
    main() 