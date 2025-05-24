import { useLocation } from 'wouter';
import { 
  LayoutDashboard, 
  Radar, 
  Bug, 
  Flame, 
  HeartPulse, 
  File,
  Settings,
  HelpCircle,
  ShieldCheck
} from 'lucide-react';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';

export default function Sidebar() {
  const [location, navigate] = useLocation();
  
  const sidebarItems = [
    { icon: LayoutDashboard, path: '/', label: 'Dashboard' },
    { icon: Radar, path: '/ids', label: 'IDS' },
    { icon: Bug, path: '/vulnerabilities', label: 'Vulnerabilities' },
    { icon: Flame, path: '/firewall', label: 'Firewall' },
    { icon: HeartPulse, path: '/system-health', label: 'System Health' },
    { icon: File, path: '/logs', label: 'Logs' },
  ];
  
  return (
    <aside className="hidden md:flex md:flex-col w-16 bg-background-secondary border-r border-gray-800">
      <div className="flex flex-col items-center py-4">
        <div className="w-10 h-10 rounded-lg bg-accent-primary flex items-center justify-center mb-6">
          <ShieldCheck className="text-white h-5 w-5" />
        </div>
        
        <div className="flex flex-col space-y-4 w-full">
          {sidebarItems.map((item) => (
            <div 
              key={item.path}
              className={`sidebar-icon p-3 flex justify-center cursor-pointer ${location === item.path ? 'active-sidebar-icon' : ''}`}
              onClick={() => navigate(item.path)}
              aria-label={item.label}
            >
              <item.icon className={`h-5 w-5 ${location === item.path ? 'text-accent-primary' : 'text-text-secondary'}`} />
            </div>
          ))}
        </div>
      </div>
      
      <div className="mt-auto mb-4 flex flex-col items-center">
        <div className="sidebar-icon p-3 flex justify-center cursor-pointer">
          <Settings className="h-5 w-5 text-text-secondary" />
        </div>
        <div className="sidebar-icon p-3 flex justify-center cursor-pointer">
          <HelpCircle className="h-5 w-5 text-text-secondary" />
        </div>
        <Avatar className="w-8 h-8 bg-accent-tertiary mt-4">
          <AvatarFallback className="text-xs font-semibold">JS</AvatarFallback>
        </Avatar>
      </div>
    </aside>
  );
}
