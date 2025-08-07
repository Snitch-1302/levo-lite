import React, { useState, useEffect } from 'react';
import { ChartBarIcon, DocumentArrowDownIcon, EyeIcon } from '@heroicons/react/24/outline';
import { fetchReports, exportReport } from '../services/api';
import { formatDistanceToNow } from 'date-fns';

function Reports() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    const loadData = async () => {
      try {
        setLoading(true);
        const reportsData = await fetchReports();
        setData(reportsData);
      } catch (error) {
        console.error('Failed to load reports data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, []);

  const handleExport = async (reportType, format = 'json') => {
    try {
      setExporting(true);
      await exportReport(reportType, format);
    } catch (error) {
      console.error('Export failed:', error);
    } finally {
      setExporting(false);
    }
  };

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
          <h1 className="text-3xl font-bold text-gray-900">Reports</h1>
          <p className="text-gray-600 mt-1">Security analysis reports and exports</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="text-sm text-gray-500">
            Total Reports: <span className="font-semibold">{data?.reports?.length || 0}</span>
          </div>
        </div>
      </div>

      {/* Quick Export Actions */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Quick Export</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <button
            onClick={() => handleExport('vulnerability', 'json')}
            disabled={exporting}
            className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
          >
            <DocumentArrowDownIcon className="h-5 w-5 mr-2" />
            Export Vulnerability Report
          </button>
          
          <button
            onClick={() => handleExport('sensitive', 'json')}
            disabled={exporting}
            className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
          >
            <DocumentArrowDownIcon className="h-5 w-5 mr-2" />
            Export Sensitive Data Report
          </button>
          
          <button
            onClick={() => handleExport('policy', 'json')}
            disabled={exporting}
            className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
          >
            <DocumentArrowDownIcon className="h-5 w-5 mr-2" />
            Export Policy Report
          </button>
          
          <button
            onClick={() => handleExport('openapi', 'yaml')}
            disabled={exporting}
            className="flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
          >
            <DocumentArrowDownIcon className="h-5 w-5 mr-2" />
            Export OpenAPI Spec
          </button>
        </div>
        
        {exporting && (
          <div className="mt-4 text-center">
            <div className="spinner inline-block mr-2"></div>
            <span className="text-sm text-gray-600">Exporting...</span>
          </div>
        )}
      </div>

      {/* Available Reports */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-semibold text-gray-900">
            Available Reports ({data?.reports?.length || 0})
          </h3>
        </div>
        
        <div className="divide-y divide-gray-200">
          {data?.reports?.map((report) => (
            <div key={report.id} className="p-6">
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <ChartBarIcon className="h-5 w-5 text-primary-600" />
                    <h4 className="text-lg font-semibold text-gray-900">{report.name}</h4>
                    <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                      report.status === 'completed' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'
                    }`}>
                      {report.status}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                    <div>
                      <p className="text-sm font-medium text-gray-700">Type</p>
                      <p className="text-sm text-gray-900 capitalize">{report.type}</p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-700">Generated</p>
                      <p className="text-sm text-gray-900">
                        {formatDistanceToNow(new Date(report.generated_at), { addSuffix: true })}
                      </p>
                    </div>
                    <div>
                      <p className="text-sm font-medium text-gray-700">Size</p>
                      <p className="text-sm text-gray-900">{report.file_size}</p>
                    </div>
                  </div>
                </div>
                
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => handleExport(report.type, 'json')}
                    disabled={exporting}
                    className="flex items-center px-3 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
                  >
                    <DocumentArrowDownIcon className="h-4 w-4 mr-1" />
                    Export
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>

        {(!data?.reports || data.reports.length === 0) && (
          <div className="text-center py-8">
            <ChartBarIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-500">No reports available yet.</p>
            <p className="text-sm text-gray-400 mt-1">Run security scans to generate reports.</p>
          </div>
        )}
      </div>

      {/* Report Types Info */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Report Types</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium text-gray-900">Vulnerability Report</h4>
              <p className="text-sm text-gray-600">Detailed analysis of security vulnerabilities found in API endpoints</p>
            </div>
            <div>
              <h4 className="font-medium text-gray-900">Sensitive Data Report</h4>
              <p className="text-sm text-gray-600">PII and sensitive data detection results with exposure risk assessment</p>
            </div>
            <div>
              <h4 className="font-medium text-gray-900">Policy Report</h4>
              <p className="text-sm text-gray-600">Policy evaluation results and compliance violations</p>
            </div>
            <div>
              <h4 className="font-medium text-gray-900">OpenAPI Specification</h4>
              <p className="text-sm text-gray-600">Generated OpenAPI 3.0 specification from discovered endpoints</p>
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Export Formats</h3>
          <div className="space-y-3">
            <div>
              <h4 className="font-medium text-gray-900">JSON</h4>
              <p className="text-sm text-gray-600">Machine-readable format for integration with other tools</p>
            </div>
            <div>
              <h4 className="font-medium text-gray-900">YAML</h4>
              <p className="text-sm text-gray-600">Human-readable format for OpenAPI specifications</p>
            </div>
            <div>
              <h4 className="font-medium text-gray-900">Markdown</h4>
              <p className="text-sm text-gray-600">Documentation-friendly format for reports</p>
            </div>
            <div>
              <h4 className="font-medium text-gray-900">HTML</h4>
              <p className="text-sm text-gray-600">Web-ready format with styling and charts</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Reports; 