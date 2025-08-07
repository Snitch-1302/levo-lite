import React, { useState, useEffect } from 'react';
import { MagnifyingGlassIcon, FunnelIcon } from '@heroicons/react/24/outline';
import StatusBadge from '../components/StatusBadge';
import { fetchDiscoveryData } from '../services/api';
import { formatDistanceToNow } from 'date-fns';

function Discovery() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterMethod, setFilterMethod] = useState('all');
  const [filterAuth, setFilterAuth] = useState('all');

  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const discoveryData = await fetchDiscoveryData();
        setData(discoveryData);
      } catch (error) {
        console.error('Failed to load discovery data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  const filteredEndpoints = data?.endpoints?.filter(endpoint => {
    const matchesSearch = endpoint.path.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesMethod = filterMethod === 'all' || endpoint.method === filterMethod;
    const matchesAuth = filterAuth === 'all' || 
      (filterAuth === 'auth' && endpoint.auth_required) ||
      (filterAuth === 'no-auth' && !endpoint.auth_required);
    
    return matchesSearch && matchesMethod && matchesAuth;
  }) || [];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">API Discovery</h1>
          <p className="text-gray-600 mt-1">Discovered API endpoints and their characteristics</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-sm text-gray-500">
            Total: <span className="font-semibold">{data?.summary?.total_endpoints || 0}</span>
          </div>
          <div className="text-sm text-gray-500">
            Authenticated: <span className="font-semibold text-green-600">{data?.summary?.authenticated || 0}</span>
          </div>
          <div className="text-sm text-gray-500">
            Unauthenticated: <span className="font-semibold text-red-600">{data?.summary?.unauthenticated || 0}</span>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search endpoints..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
          </div>

          {/* Method Filter */}
          <div className="flex items-center space-x-2">
            <FunnelIcon className="h-5 w-5 text-gray-400" />
            <select
              value={filterMethod}
              onChange={(e) => setFilterMethod(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Methods</option>
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>

          {/* Auth Filter */}
          <div className="flex items-center space-x-2">
            <select
              value={filterAuth}
              onChange={(e) => setFilterAuth(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Auth</option>
              <option value="auth">Authenticated</option>
              <option value="no-auth">Unauthenticated</option>
            </select>
          </div>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">
            Discovered Endpoints ({filteredEndpoints.length})
          </h3>
        </div>
        
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Endpoint
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Method
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Auth
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Sensitive Data
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Calls
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Last Seen
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredEndpoints.map((endpoint) => (
                <tr key={endpoint.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-gray-900 font-mono">
                      {endpoint.path}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      endpoint.method === 'GET' ? 'bg-green-100 text-green-800' :
                      endpoint.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                      endpoint.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-red-100 text-red-800'
                    }`}>
                      {endpoint.method}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      endpoint.status_code >= 200 && endpoint.status_code < 300 ? 'bg-green-100 text-green-800' :
                      endpoint.status_code >= 400 && endpoint.status_code < 500 ? 'bg-yellow-100 text-yellow-800' :
                      'bg-red-100 text-red-800'
                    }`}>
                      {endpoint.status_code}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {endpoint.auth_required ? (
                      <span className="inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">
                        Required
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">
                        None
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {endpoint.sensitive_data ? (
                      <span className="inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full bg-orange-100 text-orange-800">
                        Yes
                      </span>
                    ) : (
                      <span className="inline-flex items-center px-2 py-1 text-xs font-semibold rounded-full bg-gray-100 text-gray-800">
                        No
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                    {endpoint.call_count}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatDistanceToNow(new Date(endpoint.last_seen), { addSuffix: true })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredEndpoints.length === 0 && (
          <div className="text-center py-8">
            <p className="text-gray-500">No endpoints found matching your criteria.</p>
          </div>
        )}
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Methods Distribution</h3>
          <div className="space-y-2">
            {Object.entries(data?.summary?.methods || {}).map(([method, count]) => (
              <div key={method} className="flex justify-between items-center">
                <span className="text-sm text-gray-600">{method}</span>
                <span className="text-sm font-semibold text-gray-900">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Authentication</h3>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">Authenticated</span>
              <span className="text-sm font-semibold text-green-600">{data?.summary?.authenticated || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">Unauthenticated</span>
              <span className="text-sm font-semibold text-red-600">{data?.summary?.unauthenticated || 0}</span>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Sensitive Data</h3>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">With Sensitive Data</span>
              <span className="text-sm font-semibold text-orange-600">{data?.summary?.with_sensitive_data || 0}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-sm text-gray-600">Safe</span>
              <span className="text-sm font-semibold text-green-600">
                {(data?.summary?.total_endpoints || 0) - (data?.summary?.with_sensitive_data || 0)}
              </span>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Score</h3>
          <div className="text-center">
            <div className="text-3xl font-bold text-green-600">
              {Math.round(((data?.summary?.authenticated || 0) / (data?.summary?.total_endpoints || 1)) * 100)}%
            </div>
            <p className="text-sm text-gray-600 mt-1">Endpoints with Auth</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Discovery; 