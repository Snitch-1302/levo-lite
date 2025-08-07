import sqlite3
import json
import argparse
from datetime import datetime
from typing import List, Dict, Any
from tabulate import tabulate

class DiscoveryCLI:
    """CLI interface for API discovery results"""
    
    def __init__(self, db_path: str = "discovery.db"):
        self.db_path = db_path
    
    def list_endpoints(self, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """List discovered endpoints with optional filters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build query
        query = '''
            SELECT 
                path, method, security_level, request_count,
                has_auth, contains_sensitive_data, potential_idor, missing_auth,
                discovered_at, last_seen
            FROM endpoints
        '''
        
        params = []
        where_clauses = []
        
        if filters:
            if filters.get('method'):
                where_clauses.append("method = ?")
                params.append(filters['method'])
            
            if filters.get('security_level'):
                where_clauses.append("security_level = ?")
                params.append(filters['security_level'])
            
            if filters.get('has_auth') is not None:
                where_clauses.append("has_auth = ?")
                params.append(1 if filters['has_auth'] else 0)
            
            if filters.get('sensitive_data') is not None:
                where_clauses.append("contains_sensitive_data = ?")
                params.append(1 if filters['sensitive_data'] else 0)
            
            if filters.get('vulnerable') is not None:
                if filters['vulnerable']:
                    where_clauses.append("(potential_idor = 1 OR missing_auth = 1)")
                else:
                    where_clauses.append("(potential_idor = 0 AND missing_auth = 0)")
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
        
        query += " ORDER BY request_count DESC, discovered_at DESC"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        
        # Convert to list of dicts
        endpoints = []
        for row in results:
            endpoints.append({
                'path': row[0],
                'method': row[1],
                'security_level': row[2],
                'request_count': row[3],
                'has_auth': bool(row[4]),
                'contains_sensitive_data': bool(row[5]),
                'potential_idor': bool(row[6]),
                'missing_auth': bool(row[7]),
                'discovered_at': row[8],
                'last_seen': row[9]
            })
        
        conn.close()
        return endpoints
    
    def get_summary(self) -> Dict[str, Any]:
        """Get discovery summary statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get overall stats
        cursor.execute('''
            SELECT 
                COUNT(*) as total_endpoints,
                COUNT(DISTINCT path) as unique_paths,
                COUNT(DISTINCT method) as unique_methods,
                SUM(CASE WHEN has_auth = 1 THEN 1 ELSE 0 END) as auth_endpoints,
                SUM(CASE WHEN contains_sensitive_data = 1 THEN 1 ELSE 0 END) as sensitive_endpoints,
                SUM(CASE WHEN potential_idor = 1 THEN 1 ELSE 0 END) as idor_endpoints,
                SUM(CASE WHEN missing_auth = 1 THEN 1 ELSE 0 END) as missing_auth_endpoints,
                SUM(request_count) as total_requests
            FROM endpoints
        ''')
        
        stats = cursor.fetchone()
        
        # Get method breakdown
        cursor.execute('''
            SELECT method, COUNT(*) as count
            FROM endpoints
            GROUP BY method
            ORDER BY count DESC
        ''')
        
        method_stats = cursor.fetchall()
        
        # Get security level breakdown
        cursor.execute('''
            SELECT security_level, COUNT(*) as count
            FROM endpoints
            GROUP BY security_level
            ORDER BY count DESC
        ''')
        
        security_stats = cursor.fetchall()
        
        # Get sessions
        cursor.execute('''
            SELECT session_name, target_host, target_port, start_time, 
                   total_requests, unique_endpoints, vulnerable_endpoints
            FROM sessions
            ORDER BY start_time DESC
        ''')
        
        sessions = cursor.fetchall()
        
        conn.close()
        
        return {
            'overall': {
                'total_endpoints': stats[0],
                'unique_paths': stats[1],
                'unique_methods': stats[2],
                'auth_endpoints': stats[3],
                'sensitive_endpoints': stats[4],
                'idor_endpoints': stats[5],
                'missing_auth_endpoints': stats[6],
                'total_requests': stats[7]
            },
            'methods': method_stats,
            'security_levels': security_stats,
            'sessions': sessions
        }
    
    def get_endpoint_details(self, path: str, method: str) -> Dict[str, Any]:
        """Get detailed information about a specific endpoint"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT *
            FROM endpoints
            WHERE path = ? AND method = ?
        ''', (path, method))
        
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            return None
        
        # Get column names
        cursor.execute('PRAGMA table_info(endpoints)')
        columns = [col[1] for col in cursor.fetchall()]
        
        # Create dict
        endpoint_data = dict(zip(columns, row))
        
        # Parse JSON fields
        for field in ['query_params', 'headers', 'body', 'response_headers', 'response_body']:
            if endpoint_data.get(field):
                try:
                    endpoint_data[field] = json.loads(endpoint_data[field])
                except:
                    pass
        
        conn.close()
        return endpoint_data
    
    def export_json(self, output_file: str = None) -> str:
        """Export all endpoints to JSON format"""
        endpoints = self.list_endpoints()
        
        # Get detailed data for each endpoint
        detailed_endpoints = []
        for endpoint in endpoints:
            details = self.get_endpoint_details(endpoint['path'], endpoint['method'])
            if details:
                detailed_endpoints.append(details)
        
        export_data = {
            'exported_at': datetime.utcnow().isoformat(),
            'summary': self.get_summary(),
            'endpoints': detailed_endpoints
        }
        
        json_data = json.dumps(export_data, indent=2, default=str)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_data)
            return f"Exported to {output_file}"
        else:
            return json_data
    
    def print_endpoints_table(self, endpoints: List[Dict[str, Any]], show_details: bool = False):
        """Print endpoints in a formatted table"""
        if not endpoints:
            print("No endpoints found.")
            return
        
        # Prepare table data
        table_data = []
        for endpoint in endpoints:
            # Security indicators
            indicators = []
            if endpoint['contains_sensitive_data']:
                indicators.append("🔴")
            if endpoint['potential_idor']:
                indicators.append("⚠️")
            if endpoint['missing_auth']:
                indicators.append("🚨")
            
            indicator_str = " ".join(indicators) if indicators else "✅"
            
            row = [
                endpoint['method'],
                endpoint['path'][:50] + "..." if len(endpoint['path']) > 50 else endpoint['path'],
                endpoint['security_level'],
                indicator_str,
                endpoint['request_count'],
                "Yes" if endpoint['has_auth'] else "No",
                endpoint['discovered_at'][:19] if endpoint['discovered_at'] else "N/A"
            ]
            
            if show_details:
                row.extend([
                    "Yes" if endpoint['contains_sensitive_data'] else "No",
                    "Yes" if endpoint['potential_idor'] else "No",
                    "Yes" if endpoint['missing_auth'] else "No"
                ])
            
            table_data.append(row)
        
        # Table headers
        headers = ["Method", "Path", "Security", "Status", "Requests", "Auth", "Discovered"]
        if show_details:
            headers.extend(["Sensitive", "IDOR", "Missing Auth"])
        
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    def print_summary(self):
        """Print discovery summary"""
        summary = self.get_summary()
        
        print("📊 API Discovery Summary")
        print("=" * 50)
        
        overall = summary['overall']
        print(f"Total Endpoints: {overall['total_endpoints']}")
        print(f"Unique Paths: {overall['unique_paths']}")
        print(f"Total Requests: {overall['total_requests']}")
        print(f"Auth Endpoints: {overall['auth_endpoints']}")
        print(f"Sensitive Endpoints: {overall['sensitive_endpoints']}")
        print(f"Potential IDOR: {overall['idor_endpoints']}")
        print(f"Missing Auth: {overall['missing_auth_endpoints']}")
        
        print("\n📈 Method Breakdown:")
        for method, count in summary['methods']:
            print(f"  {method}: {count}")
        
        print("\n🔒 Security Level Breakdown:")
        for level, count in summary['security_levels']:
            print(f"  {level}: {count}")
        
        print("\n📅 Discovery Sessions:")
        for session in summary['sessions']:
            print(f"  {session[0]} - {session[1]}:{session[2]} ({session[4]} requests, {session[5]} endpoints)")

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(description="LevoLite API Discovery CLI")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List discovered endpoints')
    list_parser.add_argument('--method', help='Filter by HTTP method')
    list_parser.add_argument('--security-level', help='Filter by security level')
    list_parser.add_argument('--auth', action='store_true', help='Show only authenticated endpoints')
    list_parser.add_argument('--no-auth', action='store_true', help='Show only non-authenticated endpoints')
    list_parser.add_argument('--sensitive', action='store_true', help='Show only endpoints with sensitive data')
    list_parser.add_argument('--vulnerable', action='store_true', help='Show only potentially vulnerable endpoints')
    list_parser.add_argument('--details', action='store_true', help='Show detailed information')
    list_parser.add_argument('--limit', type=int, help='Limit number of results')
    
    # Summary command
    subparsers.add_parser('summary', help='Show discovery summary')
    
    # Details command
    details_parser = subparsers.add_parser('details', help='Show details for specific endpoint')
    details_parser.add_argument('path', help='Endpoint path')
    details_parser.add_argument('method', help='HTTP method')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export endpoints to JSON')
    export_parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cli = DiscoveryCLI()
    
    if args.command == 'list':
        # Build filters
        filters = {}
        if args.method:
            filters['method'] = args.method
        if args.security_level:
            filters['security_level'] = args.security_level
        if args.auth:
            filters['has_auth'] = True
        if args.no_auth:
            filters['has_auth'] = False
        if args.sensitive:
            filters['sensitive_data'] = True
        if args.vulnerable:
            filters['vulnerable'] = True
        
        endpoints = cli.list_endpoints(filters)
        
        if args.limit:
            endpoints = endpoints[:args.limit]
        
        cli.print_endpoints_table(endpoints, args.details)
        print(f"\nFound {len(endpoints)} endpoints")
    
    elif args.command == 'summary':
        cli.print_summary()
    
    elif args.command == 'details':
        details = cli.get_endpoint_details(args.path, args.method)
        if details:
            print(f"📋 Endpoint Details: {args.method} {args.path}")
            print("=" * 60)
            for key, value in details.items():
                if key in ['query_params', 'headers', 'body', 'response_headers', 'response_body']:
                    print(f"{key}:")
                    print(json.dumps(value, indent=2) if value else "None")
                else:
                    print(f"{key}: {value}")
        else:
            print(f"Endpoint {args.method} {args.path} not found")
    
    elif args.command == 'export':
        result = cli.export_json(args.output)
        print(result)

if __name__ == "__main__":
    main() 