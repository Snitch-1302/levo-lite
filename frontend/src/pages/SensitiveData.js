import React, { useState, useEffect } from 'react';
import { DocumentTextIcon, EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import StatusBadge from '../components/StatusBadge';
import { fetchSensitiveData } from '../services/api';

function SensitiveData() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterRisk, setFilterRisk] = useState('all');
  const [showValues, setShowValues] = useState(false);

  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const sensitiveData = await fetchSensitiveData();
        setData(sensitiveData);
      } catch (error) {
        console.error('Failed to load sensitive data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  const filteredMatches = data?.matches?.filter(match => {
    return filterRisk === 'all' || match.exposure_risk === filterRisk;
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
          <h1 className="text-3xl font-bold text-gray-900">Sensitive Data</h1>
          <p className="text-gray-600 mt-1">PII and sensitive data detection results</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-sm text-gray-500">
            Total: <span className="font-semibold">{data?.summary?.total_matches || 0}</span>
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
              <DocumentTextIcon className="h-6 w-6 text-red-600" />
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
              <DocumentTextIcon className="h-6 w-6 text-orange-600" />
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
              <DocumentTextIcon className="h-6 w-6 text-yellow-600" />
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
              <DocumentTextIcon className="h-6 w-6 text-blue-600" />
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-600">Low</p>
              <p className="text-2xl font-bold text-blue-600">{data?.summary?.low || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters and Controls */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex items-center space-x-2">
            <span className="text-sm font-medium text-gray-700">Risk Level:</span>
            <select
              value={filterRisk}
              onChange={(e) => setFilterRisk(e.target.value)}
              className="border border-gray-300 rounded-md px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Risks</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <button
            onClick={() => setShowValues(!showValues)}
            className="flex items-center space-x-2 px-4 py-2 border border-gray-300 rounded-md hover:bg-gray-50 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
          >
            {showValues ? (
              <>
                <EyeSlashIcon className="h-4 w-4" />
                <span>Hide Values</span>
              </>
            ) : (
              <>
                <EyeIcon className="h-4 w-4" />
                <span>Show Values</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Data Types Chart */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Data Types Distribution</h3>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {Object.entries(data?.summary?.data_types || {}).map(([type, count]) => (
            <div key={type} className="text-center">
              <div className="text-2xl font-bold text-primary-600">{count}</div>
              <div className="text-sm text-gray-600 capitalize">{type}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Sensitive Data List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">
            Sensitive Data Matches ({filteredMatches.length})
          </h3>
        </div>
        
        <div className="divide-y divide-gray-200">
          {filteredMatches.map((match) => (
            <div key={match.id} className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <StatusBadge status={match.exposure_risk} />
                    <h4 className="text-lg font-semibold text-gray-900 capitalize">{match.data_type}</h4>
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      match.masked ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'
                    }`}>
                      {match.masked ? 'Masked' : 'Exposed'}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <p className="text-sm font-medium text-gray-700">Field Name</p>
                      <p className="text-sm text-gray-900 font-mono">{match.field_name}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-700">Location</p>
                      <p className="text-sm text-gray-900 capitalize">{match.location.replace('_', ' ')}</p>
                    </div>
                  </div>
                  
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">Endpoint</p>
                    <p className="text-sm text-gray-900 font-mono">{match.endpoint}</p>
                  </div>
                  
                  {showValues && (
                    <div className="mt-4">
                      <p className="text-sm font-medium text-gray-700 mb-1">Value</p>
                      <div className="bg-gray-50 rounded-md p-3">
                        <p className="text-sm text-gray-900 font-mono break-all">
                          {match.masked ? '***MASKED***' : match.value}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>

        {filteredMatches.length === 0 && (
          <div className="text-center py-8">
            <p className="text-gray-500">No sensitive data found matching your criteria.</p>
          </div>
        )}
      </div>

      {/* Compliance Score */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Data Protection Score</h3>
        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <div className="w-full bg-gray-200 rounded-full h-4">
              <div 
                className="bg-green-600 h-4 rounded-full transition-all duration-300"
                style={{ 
                  width: `${Math.max(0, 100 - ((data?.summary?.critical || 0) * 15 + (data?.summary?.high || 0) * 10 + (data?.summary?.medium || 0) * 5))}%` 
                }}
              ></div>
            </div>
          </div>
          <div className="text-2xl font-bold text-gray-900">
            {Math.max(0, 100 - ((data?.summary?.critical || 0) * 15 + (data?.summary?.high || 0) * 10 + (data?.summary?.medium || 0) * 5))}/100
          </div>
        </div>
        <p className="text-sm text-gray-600 mt-2">
          Score based on sensitive data exposure risk
        </p>
      </div>
    </div>
  );
}

export default SensitiveData; 