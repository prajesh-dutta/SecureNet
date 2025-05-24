import { ReactNode } from 'react';
import Sidebar from './sidebar';
import Header from './header';

interface MainLayoutProps {
  children: ReactNode;
}

export default function MainLayout({ children }: MainLayoutProps) {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6 bg-background-primary">
          {children}
        </main>
      </div>
    </div>
  );
}
