import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from './providers/theme-provider';
import { Toaster } from './components/ui/toaster';
import MainLayout from './components/layout/main-layout';
import Dashboard from './pages/dashboard';
import IDS from './pages/ids';
import Vulnerabilities from './pages/vulnerabilities';
import Firewall from './pages/firewall';
import SystemHealth from './pages/system-health';
import Logs from './pages/logs';
import WebSocketTest from './pages/websocket-test';
import NotFound from './pages/not-found';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 2,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider defaultTheme="dark">
        <Router>
          <div className="min-h-screen bg-background">
            <MainLayout>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/ids" element={<IDS />} />
                <Route path="/vulnerabilities" element={<Vulnerabilities />} />
                <Route path="/firewall" element={<Firewall />} />
                <Route path="/system-health" element={<SystemHealth />} />
                <Route path="/logs" element={<Logs />} />
                <Route path="/websocket-test" element={<WebSocketTest />} />
                <Route path="*" element={<NotFound />} />
              </Routes>
            </MainLayout>
          </div>
        </Router>
        <Toaster />
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
