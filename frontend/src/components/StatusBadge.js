import React from 'react';

function StatusBadge({ status, size = 'sm' }) {
  const getStatusConfig = () => {
    switch (status.toLowerCase()) {
      case 'critical':
        return {
          classes: 'bg-red-100 text-red-800 border-red-200',
          icon: '🚨'
        };
      case 'high':
        return {
          classes: 'bg-orange-100 text-orange-800 border-orange-200',
          icon: '⚠️'
        };
      case 'medium':
        return {
          classes: 'bg-yellow-100 text-yellow-800 border-yellow-200',
          icon: '⚡'
        };
      case 'low':
        return {
          classes: 'bg-blue-100 text-blue-800 border-blue-200',
          icon: 'ℹ️'
        };
      case 'pass':
        return {
          classes: 'bg-green-100 text-green-800 border-green-200',
          icon: '✅'
        };
      case 'warning':
        return {
          classes: 'bg-yellow-100 text-yellow-800 border-yellow-200',
          icon: '⚠️'
        };
      default:
        return {
          classes: 'bg-gray-100 text-gray-800 border-gray-200',
          icon: '❓'
        };
    }
  };

  const config = getStatusConfig();
  const sizeClasses = size === 'lg' ? 'px-3 py-1 text-sm' : 'px-2 py-0.5 text-xs';

  return (
    <span className={`inline-flex items-center font-medium rounded-full border ${sizeClasses} ${config.classes}`}>
      <span className="mr-1">{config.icon}</span>
      {status}
    </span>
  );
}

export default StatusBadge; 