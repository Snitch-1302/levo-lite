import React from 'react';
import { formatDistanceToNow } from 'date-fns';

function StatCard({ title, value, change, changeType, icon: Icon, color = 'primary' }) {
  const getColorClasses = () => {
    switch (color) {
      case 'success':
        return 'bg-success-50 text-success-600 border-success-200';
      case 'warning':
        return 'bg-warning-50 text-warning-600 border-warning-200';
      case 'danger':
        return 'bg-danger-50 text-danger-600 border-danger-200';
      default:
        return 'bg-primary-50 text-primary-600 border-primary-200';
    }
  };

  const getChangeColor = () => {
    if (!change) return '';
    return changeType === 'positive' ? 'text-success-600' : 'text-danger-600';
  };

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6 card-hover">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-3xl font-bold text-gray-900 mt-2">{value}</p>
          {change && (
            <p className={`text-sm font-medium mt-1 ${getChangeColor()}`}>
              {changeType === 'positive' ? '+' : ''}{change}
            </p>
          )}
        </div>
        {Icon && (
          <div className={`p-3 rounded-lg border ${getColorClasses()}`}>
            <Icon className="h-6 w-6" />
          </div>
        )}
      </div>
    </div>
  );
}

export default StatCard; 