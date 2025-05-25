import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import Dashboard from "@/pages/dashboard";
import IDS from "@/pages/ids";
import Vulnerabilities from "@/pages/vulnerabilities";
import Firewall from "@/pages/firewall";
import SystemHealth from "@/pages/system-health";
import Logs from "@/pages/logs";
import WebSocketTest from "@/pages/websocket-test";
import MainLayout from "@/components/layout/main-layout";

function Router() {
  return (
    <MainLayout>
      <Switch>
        <Route path="/" component={Dashboard} />
        <Route path="/ids" component={IDS} />
        <Route path="/vulnerabilities" component={Vulnerabilities} />
        <Route path="/firewall" component={Firewall} />
        <Route path="/system-health" component={SystemHealth} />
        <Route path="/logs" component={Logs} />
        <Route path="/websocket-test" component={WebSocketTest} />
        <Route component={NotFound} />
      </Switch>
    </MainLayout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
