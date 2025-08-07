import React, { useState, useEffect } from 'react';
import { ShieldExclamationIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline';
import StatusBadge from '../components/StatusBadge';
import { fetchVulnerabilityData } from '../services/api';

function Vulnerabilities() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');

  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const vulnData = await fetchVulnerabilityData();
        setData(vulnData);
      } catch (error) {
        console.error('Failed to load vulnerability data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  const filteredVulnerabilities = data?.vulnerabilities?.filter(vuln => {
    const matchesSeverity = filterSeverity === 'all' || vuln.severity === filterSeverity;
    const matchesStatus = filterStatus === 'all' || vuln.status === filterStatus;
    return matchesSeverity && matchesStatus;
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
          <h1 className="text-3xl font-bold text-gray-900">Vulnerabilities</h1>
          <p className="text-gray-600 mt-1">Security vulnerabilities found in API endpoints</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-sm text-gray-500">
            Total: <span className="font-semibold">{data?.summary?.total || 0}</span>
          </div>
          <div className="text-sm text-gray-500">
            Critical: <span className="font-semibold text-red-600">{data?.summary?.critical || 0}</span>
          </div>
          <div className="text-sm text-gray-500">
            High: <span className="font-semibold text-orange-600">{data?.summary?.high || 0}</span>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <ExclamationTriangleIcon className="h-6 w-6 text-red-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Critical</p>
              <p className="text-2xl font-bold text-red-600">{data?.summary?.critical || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-orange-100 rounded-lg">
              <ExclamationTriangleIcon className="h-6 w-6 text-orange-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">High</p>
              <p className="text-2xl font-bold text-orange-600">{data?.summary?.high || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <ExclamationTriangleIcon className="h-6 w-6 text-yellow-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Medium</p>
              <p className="text-2xl font-bold text-yellow-600">{data?.summary?.medium || 0}</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-blue-100 rounded-lg">
              <ShieldExclamationIcon className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Low</p>
              <p className="text-2xl font-bold text-blue-600">{data?.summary?.low || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-gray-700">Severity:</span>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-gray-700">Status:</span>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Status</option>
              <option value="open">Open</option>
              <option value="fixed">Fixed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">
            Vulnerabilities ({filteredVulnerabilities.length})
          </h3>
        </div>
        
        <div className="divide-y divide-gray-200">
          {filteredVulnerabilities.map((vuln) => (
            <div key={vuln.id} className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <StatusBadge status={vuln.severity} />
                    <h4 className="text-lg font-semibold text-gray-900">{vuln.name}</h4>
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      vuln.status === 'open' ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                    }`}>
                      {vuln.status}
                    </span>
                  </div>
                  
                  <p className="text-gray-600 mb-3">{vuln.description}</p>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <p className="text-sm font-medium text-gray-700">Endpoint</p>
                      <p className="text-sm text-gray-900 font-mono">{vuln.endpoint}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-700">CWE</p>
                      <p className="text-sm text-gray-900">{vuln.cwe}</p>
                    </div>
                  </div>
                  
                  <div className="mb-4">
                    <p className="text-sm font-medium text-gray-700 mb-1">Evidence</p>
                    <div className="bg-gray-50 rounded-md p-3">
                      <p className="text-sm text-gray-900 font-mono">{vuln.evidence}</p>
                    </div>
                  </div>
                  
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">Recommendation</p>
                    <p className="text-sm text-gray-900">{vuln.recommendation}</p>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {filteredVulnerabilities.length === 0 && (
          <div className="text-center py-8">
            <p className="text-gray-500">No vulnerabilities found matching your criteria.</p>
          </div>
        )}
      </div>

      {/* Security Score */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Score</h3>
        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <div className="w-full bg-gray-200 rounded-full h-4">
              <div 
                className="bg-green-600 h-4 rounded-full transition-all duration-300"
                style={{ 
                  width: `${Math.max(0, 100 - ((data?.summary?.critical || 0) * 20 + (data?.summary?.high || 0) * 10 + (data?.summary?.medium || 0) * 5))}%` 
                }}
              ></div>
            </div>
          </div>
          <div className="text-2xl font-bold text-gray-900">
            {Math.max(0, 100 - ((data?.summary?.critical || 0) * 20 + (data?.summary?.high || 0) * 10 + (data?.summary?.medium || 0) * 5))}/100
          </div>
        </div>
        <p className="text-sm text-gray-600 mt-2">
          Score based on vulnerability severity and count
        </p>
      </div>
    </div>
  );
}

export default Vulnerabilities; 