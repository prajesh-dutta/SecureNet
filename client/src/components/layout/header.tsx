import { useLocation, Link } from 'wouter';
import { Bell, Search, MoreHorizontal } from 'lucide-react';

export default function Header() {
  const [location] = useLocation();
  
  const tabs = [
    { name: "Network Dashboard", path: "/" },
    { name: "IDS", path: "/ids" },
    { name: "Vulnerabilities", path: "/vulnerabilities" },
    { name: "Firewall", path: "/firewall" },
    { name: "System Health", path: "/system-health" },
    { name: "Logs", path: "/logs" },
  ];
  
  return (
    <header className="h-16 flex items-center justify-between px-6 border-b border-gray-800 bg-background-secondary">
      <div className="flex items-center">
        <h1 className="text-xl font-semibold font-inter text-white">
          <span className="text-accent-primary">Secure</span>Net
        </h1>
        <div className="flex ml-8">
          {tabs.map((tab) => (
            <Link key={tab.path} href={tab.path}>
              <a className={`px-4 py-2 text-sm font-medium cursor-pointer ${location === tab.path ? 'active-tab' : 'text-text-secondary'}`}>
                {tab.name}
              </a>
            </Link>
          ))}
        </div>
      </div>
      
      <div className="flex items-center space-x-4">
        <div className="relative">
          <button className="p-2 rounded-full hover:bg-background-tertiary">
            <Bell className="h-5 w-5 text-text-secondary" />
          </button>
          <span className="absolute top-1 right-1 w-2 h-2 bg-accent-danger rounded-full"></span>
        </div>
        <button className="p-2 rounded-full hover:bg-background-tertiary">
          <Search className="h-5 w-5 text-text-secondary" />
        </button>
        <span className="h-6 border-l border-gray-700"></span>
        <div className="flex items-center">
          <span className="text-sm font-medium mr-2">Prajesh Dutta</span>
          <span className="text-xs px-2 py-1 rounded-full bg-background-tertiary text-accent-primary">SOC Admin</span>
        </div>
      </div>
    </header>
  );
}
