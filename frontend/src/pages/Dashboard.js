import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import {
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
  DocumentTextIcon,
  ClipboardDocumentListIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon
} from '@heroicons/react/24/outline';
import StatCard from '../components/StatCard';
import StatusBadge from '../components/StatusBadge';
import { formatDistanceToNow } from 'date-fns';
import { ChartBarIcon } from '@heroicons/react/24/outline';

function Dashboard({ data }) {
  const [dashboardData, setDashboardData] = useState(data || {});

  useEffect(() => {
    if (data) {
      setDashboardData(data);
    }
  }, [data]);

  if (!dashboardData.summary) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="spinner"></div>
      </div>
    );
  }

  const { summary, recent_activity, charts } = dashboardData;

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'critical':
        return '#ef4444';
      case 'high':
        return '#f97316';
      case 'medium':
        return '#eab308';
      case 'low':
        return '#3b82f6';
      default:
        return '#6b7280';
    }
  };

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-600 mt-1">API Security Overview</p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-500">Overall Status:</span>
          <StatusBadge status={summary.overall_status} size="lg" />
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Total Endpoints"
          value={summary.total_endpoints}
          icon={MagnifyingGlassIcon}
          color="primary"
        />
        <StatCard
          title="Vulnerabilities"
          value={summary.vulnerabilities}
          icon={ShieldExclamationIcon}
          color="danger"
        />
        <StatCard
          title="Policy Violations"
          value={summary.policy_violations}
          icon={ClipboardDocumentListIcon}
          color="warning"
        />
        <StatCard
          title="PII Exposures"
          value={summary.pii_exposures}
          icon={DocumentTextIcon}
          color="warning"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerabilities by Severity */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Vulnerabilities by Severity</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={charts.vulnerabilities_by_severity}
                cx="50%"
                cy="50%"
                outerRadius={80}
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}`}
              >
                {charts.vulnerabilities_by_severity.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Endpoints by Method */}
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Endpoints by Method</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={charts.endpoints_by_method}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Bar dataKey="value" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">Recent Activity</h3>
        </div>
        <div className="divide-y divide-gray-200">
          {recent_activity.map((activity) => (
            <div key={activity.id} className="px-6 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="flex-shrink-0">
                    {activity.type === 'vulnerability' ? (
                      <ExclamationTriangleIcon className="h-5 w-5 text-red-500" />
                    ) : (
                      <ClipboardDocumentListIcon className="h-5 w-5 text-yellow-500" />
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">
                      {activity.description}
                    </p>
                    <p className="text-sm text-gray-500">
                      {activity.endpoint}
                    </p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <StatusBadge status={activity.severity} />
                  <span className="text-sm text-gray-500">
                    {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500">
            <MagnifyingGlassIcon className="h-5 w-5 mr-2" />
            Run Discovery
          </button>
          <button className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500">
            <ShieldExclamationIcon className="h-5 w-5 mr-2" />
            Scan Vulnerabilities
          </button>
          <button className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500">
            <ChartBarIcon className="h-5 w-5 mr-2" />
            Generate Report
          </button>
        </div>
      </div>
    </div>
  );
}

export default Dashboard; 