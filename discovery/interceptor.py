import asyncio
import json
import sqlite3
from datetime import datetime
from typing import Dict, Any, List
import argparse
import signal
import sys

from mitmproxy import ctx
from mitmproxy import http
from mitmproxy import options
from mitmproxy.proxy.config import ProxyConfig
from mitmproxy.proxy.server import ProxyServer
from mitmproxy.tools.dump import DumpMaster

from models import APIEndpoint, APIDiscoverySession, DiscoveryConfig
from parser import APIParser

class APIDiscoveryInterceptor:
    """Interceptor for capturing and analyzing API traffic"""
    
    def __init__(self, config: DiscoveryConfig):
        self.config = config
        self.parser = APIParser()
        self.discovered_endpoints: Dict[str, APIEndpoint] = {}
        self.session = None
        self.db_path = "discovery.db"
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for storing discovered endpoints"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create endpoints table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                scheme TEXT NOT NULL,
                query_params TEXT,
                headers TEXT,
                body TEXT,
                status_code INTEGER,
                response_headers TEXT,
                response_body TEXT,
                auth_type TEXT NOT NULL,
                has_auth BOOLEAN NOT NULL,
                security_level TEXT NOT NULL,
                contains_sensitive_data BOOLEAN NOT NULL,
                potential_idor BOOLEAN NOT NULL,
                missing_auth BOOLEAN NOT NULL,
                discovered_at TIMESTAMP NOT NULL,
                last_seen TIMESTAMP NOT NULL,
                request_count INTEGER DEFAULT 1,
                UNIQUE(path, method, host, port)
            )
        ''')
        
        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                target_host TEXT NOT NULL,
                target_port INTEGER NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                total_requests INTEGER DEFAULT 0,
                unique_endpoints INTEGER DEFAULT 0,
                auth_endpoints INTEGER DEFAULT 0,
                sensitive_endpoints INTEGER DEFAULT 0,
                vulnerable_endpoints INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
        
        # Create new session
        self.create_session()
    
    def create_session(self):
        """Create a new discovery session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO sessions (session_name, target_host, target_port, start_time)
            VALUES (?, ?, ?, ?)
        ''', (
            self.config.session_name,
            self.config.target_host,
            self.config.target_port,
            datetime.utcnow()
        ))
        
        self.session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        print(f"🚀 Started API discovery session: {self.config.session_name}")
        print(f"📡 Monitoring: {self.config.target_host}:{self.config.target_port}")
        print(f"🔍 Proxy running on port: {self.config.proxy_port}")
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Handle incoming request"""
        # Only capture requests to our target
        if flow.request.pretty_host != self.config.target_host or flow.request.port != self.config.target_port:
            return
        
        # Store request data for later processing
        flow.request_data = {
            'url': flow.request.pretty_url,
            'method': flow.request.method,
            'headers': dict(flow.request.headers),
            'body': flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else None
        }
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response"""
        # Only process if we have request data
        if not hasattr(flow, 'request_data'):
            return
        
        # Prepare flow data for parsing
        flow_data = {
            'request': flow.request_data,
            'response': {
                'status_code': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body': flow.response.content.decode('utf-8', errors='ignore') if flow.response.content else None
            }
        }
        
        # Parse the endpoint
        try:
            endpoint = self.parser.parse_request(flow_data)
            self.store_endpoint(endpoint)
            self.update_session_stats()
            
            # Print discovery info
            self.print_discovery_info(endpoint)
            
        except Exception as e:
            ctx.log.error(f"Error parsing endpoint: {e}")
    
    def store_endpoint(self, endpoint: APIEndpoint):
        """Store endpoint in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if endpoint already exists
        cursor.execute('''
            SELECT id, request_count FROM endpoints 
            WHERE path = ? AND method = ? AND host = ? AND port = ?
        ''', (endpoint.path, endpoint.method.value, endpoint.host, endpoint.port))
        
        existing = cursor.fetchone()
        
        if existing:
            # Update existing endpoint
            endpoint_id, current_count = existing
            cursor.execute('''
                UPDATE endpoints SET
                    last_seen = ?,
                    request_count = ?,
                    status_code = ?,
                    response_headers = ?,
                    response_body = ?,
                    contains_sensitive_data = ?,
                    potential_idor = ?,
                    missing_auth = ?
                WHERE id = ?
            ''', (
                endpoint.last_seen,
                current_count + 1,
                endpoint.status_code,
                json.dumps(endpoint.response_headers),
                json.dumps(endpoint.response_body) if endpoint.response_body else None,
                endpoint.contains_sensitive_data,
                endpoint.potential_idor,
                endpoint.missing_auth,
                endpoint_id
            ))
        else:
            # Insert new endpoint
            cursor.execute('''
                INSERT INTO endpoints (
                    path, method, host, port, scheme, query_params, headers, body,
                    status_code, response_headers, response_body, auth_type, has_auth,
                    security_level, contains_sensitive_data, potential_idor, missing_auth,
                    discovered_at, last_seen, request_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                endpoint.path,
                endpoint.method.value,
                endpoint.host,
                endpoint.port,
                endpoint.scheme,
                json.dumps(endpoint.query_params),
                json.dumps(endpoint.headers),
                json.dumps(endpoint.body) if endpoint.body else None,
                endpoint.status_code,
                json.dumps(endpoint.response_headers),
                json.dumps(endpoint.response_body) if endpoint.response_body else None,
                endpoint.auth_type.value,
                endpoint.has_auth,
                endpoint.security_level.value,
                endpoint.contains_sensitive_data,
                endpoint.potential_idor,
                endpoint.missing_auth,
                endpoint.discovered_at,
                endpoint.last_seen,
                endpoint.request_count
            ))
        
        conn.commit()
        conn.close()
    
    def update_session_stats(self):
        """Update session statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get session stats
        cursor.execute('''
            SELECT 
                COUNT(*) as total_requests,
                COUNT(DISTINCT path || method) as unique_endpoints,
                SUM(CASE WHEN has_auth = 1 THEN 1 ELSE 0 END) as auth_endpoints,
                SUM(CASE WHEN contains_sensitive_data = 1 THEN 1 ELSE 0 END) as sensitive_endpoints,
                SUM(CASE WHEN potential_idor = 1 OR missing_auth = 1 THEN 1 ELSE 0 END) as vulnerable_endpoints
            FROM endpoints
        ''')
        
        stats = cursor.fetchone()
        
        # Update session
        cursor.execute('''
            UPDATE sessions SET
                total_requests = ?,
                unique_endpoints = ?,
                auth_endpoints = ?,
                sensitive_endpoints = ?,
                vulnerable_endpoints = ?
            WHERE id = ?
        ''', (*stats, self.session_id))
        
        conn.commit()
        conn.close()
    
    def print_discovery_info(self, endpoint: APIEndpoint):
        """Print discovery information to console"""
        # Security indicators
        indicators = []
        if endpoint.contains_sensitive_data:
            indicators.append("🔴 SENSITIVE DATA")
        if endpoint.potential_idor:
            indicators.append("⚠️  POTENTIAL IDOR")
        if endpoint.missing_auth:
            indicators.append("🚨 MISSING AUTH")
        
        indicator_str = " ".join(indicators) if indicators else "✅ SECURE"
        
        print(f"🔍 {endpoint.method.value} {endpoint.path} {indicator_str}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get discovery summary"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get session info
        cursor.execute('''
            SELECT * FROM sessions WHERE id = ?
        ''', (self.session_id,))
        
        session_data = cursor.fetchone()
        
        # Get endpoint summary
        cursor.execute('''
            SELECT 
                path, method, security_level, request_count,
                contains_sensitive_data, potential_idor, missing_auth
            FROM endpoints
            ORDER BY request_count DESC
            LIMIT 10
        ''')
        
        top_endpoints = cursor.fetchall()
        
        conn.close()
        
        return {
            'session': session_data,
            'top_endpoints': top_endpoints
        }

def run_interceptor(config: DiscoveryConfig):
    """Run the API discovery interceptor"""
    
    # Create interceptor
    interceptor = APIDiscoveryInterceptor(config)
    
    # Set up mitmproxy
    opts = options.Options(
        listen_host='0.0.0.0',
        listen_port=config.proxy_port,
        ssl_insecure=True
    )
    
    # Create proxy server
    config = ProxyConfig(opts)
    master = DumpMaster(opts)
    master.server = ProxyServer(config)
    
    # Add interceptor
    master.addons.add(interceptor)
    
    # Handle shutdown gracefully
    def signal_handler(signum, frame):
        print("\n🛑 Shutting down API discovery...")
        master.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        print("🚀 Starting API discovery interceptor...")
        print(f"📡 Proxy listening on port {config.proxy_port}")
        print(f"🎯 Target: {config.target_host}:{config.target_port}")
        print("💡 To use the proxy, set your HTTP_PROXY environment variable:")
        print(f"   export HTTP_PROXY=http://localhost:{config.proxy_port}")
        print("   export HTTPS_PROXY=http://localhost:{config.proxy_port}")
        print("\n🔍 Press Ctrl+C to stop discovery\n")
        
        master.run()
        
    except KeyboardInterrupt:
        print("\n🛑 Discovery stopped by user")
    finally:
        # Print summary
        summary = interceptor.get_summary()
        print("\n📊 Discovery Summary:")
        print(f"   Total requests: {summary['session'][6]}")
        print(f"   Unique endpoints: {summary['session'][7]}")
        print(f"   Auth endpoints: {summary['session'][8]}")
        print(f"   Sensitive endpoints: {summary['session'][9]}")
        print(f"   Vulnerable endpoints: {summary['session'][10]}")
        
        master.shutdown()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="LevoLite API Discovery Tool")
    parser.add_argument("--host", default="localhost", help="Target host to monitor")
    parser.add_argument("--port", type=int, default=8000, help="Target port to monitor")
    parser.add_argument("--proxy-port", type=int, default=8080, help="Proxy port")
    parser.add_argument("--session", default="default", help="Session name")
    
    args = parser.parse_args()
    
    config = DiscoveryConfig(
        target_host=args.host,
        target_port=args.port,
        proxy_port=args.proxy_port,
        session_name=args.session
    )
    
    run_interceptor(config)

if __name__ == "__main__":
    main() 