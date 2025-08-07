import React, { useState, useEffect } from 'react';
import { ClipboardDocumentListIcon } from '@heroicons/react/24/outline';
import StatusBadge from '../components/StatusBadge';
import { fetchPolicyData } from '../services/api';

function Policies() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('all');

  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const policyData = await fetchPolicyData();
        setData(policyData);
      } catch (error) {
        console.error('Failed to load policy data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  const filteredEvaluations = data?.evaluations?.filter(evaluation => {
    return filterSeverity === 'all' || evaluation.severity === filterSeverity;
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
          <h1 className="text-3xl font-bold text-gray-900">Policy Engine</h1>
          <p className="text-gray-600 mt-1">Policy evaluation and compliance results</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-sm text-gray-500">
            Total Violations: <span className="font-semibold">{data?.summary?.total_violations || 0}</span>
          </div>
          <div className="text-sm text-gray-500">
            Rules Evaluated: <span className="font-semibold">{data?.summary?.rules_evaluated || 0}</span>
          </div>
          <div className="text-sm text-gray-500">
            Rules Passed: <span className="font-semibold text-green-600">{data?.summary?.rules_passed || 0}</span>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <div className="flex items-center">
            <div className="p-2 bg-red-100 rounded-lg">
              <ClipboardDocumentListIcon className="h-6 w-6 text-red-600" />
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
              <ClipboardDocumentListIcon className="h-6 w-6 text-orange-600" />
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
              <ClipboardDocumentListIcon className="h-6 w-6 text-yellow-600" />
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
              <ClipboardDocumentListIcon className="h-6 w-6 text-blue-600" />
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
      </div>

      {/* Policy Violations */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">
            Policy Violations ({filteredEvaluations.length})
          </h3>
        </div>
        
        <div className="divide-y divide-gray-200">
          {filteredEvaluations.map((evaluation) => (
            <div key={evaluation.id} className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <StatusBadge status={evaluation.severity} />
                    <h4 className="text-lg font-semibold text-gray-900">{evaluation.rule_name}</h4>
                  </div>
                  
                  <p className="text-gray-600 mb-3">{evaluation.description}</p>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                      <p className="text-sm font-medium text-gray-700">Endpoint</p>
                      <p className="text-sm text-gray-900 font-mono">{evaluation.endpoint}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-700">Timestamp</p>
                      <p className="text-sm text-gray-900">
                        {new Date(evaluation.timestamp).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  
                  <div>
                    <p className="text-sm font-medium text-gray-700 mb-1">Evidence</p>
                    <div className="bg-gray-50 rounded-md p-3">
                      <p className="text-sm text-gray-900 font-mono">{evaluation.evidence}</p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        {filteredEvaluations.length === 0 && (
          <div className="text-center py-8">
            <p className="text-gray-500">No policy violations found matching your criteria.</p>
          </div>
        )}
      </div>

      {/* Compliance Score */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Policy Compliance Score</h3>
        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <div className="w-full bg-gray-200 rounded-full h-4">
              <div 
                className="bg-green-600 h-4 rounded-full transition-all duration-300"
                style={{ 
                  width: `${Math.round(((data?.summary?.rules_passed || 0) / (data?.summary?.rules_evaluated || 1)) * 100)}%` 
                }}
              ></div>
            </div>
          </div>
          <div className="text-2xl font-bold text-gray-900">
            {Math.round(((data?.summary?.rules_passed || 0) / (data?.summary?.rules_evaluated || 1)) * 100)}%
          </div>
        </div>
        <p className="text-sm text-gray-600 mt-2">
          {data?.summary?.rules_passed || 0} of {data?.summary?.rules_evaluated || 0} rules passed
        </p>
      </div>
    </div>
  );
}

export default Policies; 