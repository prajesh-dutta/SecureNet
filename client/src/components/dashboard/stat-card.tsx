import { ReactNode } from 'react';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: string | number;
  changeType?: 'positive' | 'negative' | 'neutral';
  subtitle?: string;
  icon: ReactNode;
  iconColor: 'primary' | 'secondary' | 'tertiary' | 'danger';
}

export default function StatCard({
  title,
  value,
  change,
  changeType = 'neutral',
  subtitle,
  icon,
  iconColor,
}: StatCardProps) {
  const colorMap = {
    primary: 'bg-accent-primary/20 text-accent-primary',
    secondary: 'bg-accent-secondary/20 text-accent-secondary',
    tertiary: 'bg-accent-tertiary/20 text-accent-tertiary',
    danger: 'bg-accent-danger/20 text-accent-danger',
  };
  
  const changeColorMap = {
    positive: 'text-accent-secondary',
    negative: 'text-accent-danger',
    neutral: 'text-accent-primary',
  };
  
  return (
    <div className="glass-effect rounded-lg p-4 flex items-center justify-between">
      <div>
        <p className="text-sm text-text-secondary">{title}</p>
        <div className="flex items-end">
          <h3 className="text-2xl font-semibold font-inter">{value}</h3>
          {change && (
            <span className={`ml-2 text-xs font-medium ${changeColorMap[changeType]}`}>
              {change}
            </span>
          )}
        </div>
        {subtitle && <p className="text-xs text-text-secondary mt-1">{subtitle}</p>}
      </div>
      <div className={`w-10 h-10 rounded-full flex items-center justify-center ${colorMap[iconColor]}`}>
        {icon}
      </div>
    </div>
  );
}
