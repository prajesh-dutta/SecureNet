import { Button } from "@/components/ui/button";
import { useLocation } from "wouter";

export default function Landing() {
  const [, setLocation] = useLocation();

  return (
    <div className="min-h-screen bg-background-primary overflow-hidden relative">
      {/* Animated background with gradient and animated cyber elements */}
      <div className="absolute inset-0 bg-grid-pattern opacity-10"></div>
      <div className="absolute inset-0 bg-gradient-to-br from-blue-950/30 via-black to-cyan-950/30"></div>
      
      {/* Animated particles */}
      <div className="absolute inset-0">
        <div className="absolute w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl animate-pulse top-20 -left-20"></div>
        <div className="absolute w-80 h-80 bg-green-500/5 rounded-full blur-3xl animate-pulse bottom-20 right-10 animation-delay-2000"></div>
        <div className="absolute w-60 h-60 bg-cyan-500/10 rounded-full blur-3xl animate-pulse top-40 right-20 animation-delay-1000"></div>
      </div>
      
      {/* Content */}
      <div className="container mx-auto px-4 py-16 relative z-10">
        <div className="flex flex-col items-center justify-center min-h-[80vh]">
          <div className="text-center max-w-4xl mx-auto">
            <div className="mb-8 flex justify-center">
              <div className="rounded-full bg-cyan-500/10 p-4 border border-cyan-500/20 backdrop-blur-sm">
                <svg 
                  xmlns="http://www.w3.org/2000/svg" 
                  width="64" 
                  height="64" 
                  viewBox="0 0 24 24" 
                  fill="none" 
                  stroke="currentColor" 
                  strokeWidth="2" 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  className="text-cyan-400"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
                  <path d="M8 11V9" />
                  <path d="M12 11V9" />
                  <path d="M16 11V9" />
                </svg>
              </div>
            </div>
            
            <h1 className="text-5xl md:text-7xl font-bold mb-6 tracking-tighter bg-gradient-to-r from-cyan-400 via-white to-emerald-400 text-transparent bg-clip-text">
              SecureNet
            </h1>
            
            <p className="text-2xl md:text-3xl text-muted-foreground mb-8">
              Advanced cybersecurity dashboard for real-time threat monitoring and network protection
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12 text-left">
              <div className="bg-black/30 backdrop-blur-md p-6 rounded-xl border border-border/40">
                <div className="rounded-full bg-cyan-950/50 w-12 h-12 flex items-center justify-center mb-4">
                  <svg 
                    xmlns="http://www.w3.org/2000/svg" 
                    width="24" 
                    height="24" 
                    viewBox="0 0 24 24" 
                    fill="none" 
                    stroke="currentColor" 
                    strokeWidth="2" 
                    strokeLinecap="round" 
                    strokeLinejoin="round" 
                    className="text-cyan-400"
                  >
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
                    <path d="m14.5 9-5 5" />
                    <path d="m9.5 9 5 5" />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2 text-white">Threat Detection</h3>
                <p className="text-muted-foreground">Real-time monitoring and alerts for malware, intrusions, and suspicious activities</p>
              </div>
              
              <div className="bg-black/30 backdrop-blur-md p-6 rounded-xl border border-border/40">
                <div className="rounded-full bg-emerald-950/50 w-12 h-12 flex items-center justify-center mb-4">
                  <svg 
                    xmlns="http://www.w3.org/2000/svg" 
                    width="24" 
                    height="24" 
                    viewBox="0 0 24 24" 
                    fill="none" 
                    stroke="currentColor" 
                    strokeWidth="2" 
                    strokeLinecap="round" 
                    strokeLinejoin="round" 
                    className="text-emerald-400"
                  >
                    <rect width="20" height="14" x="2" y="7" rx="2" />
                    <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16" />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2 text-white">Network Monitoring</h3>
                <p className="text-muted-foreground">Comprehensive visibility into network traffic, patterns, and anomalies</p>
              </div>
              
              <div className="bg-black/30 backdrop-blur-md p-6 rounded-xl border border-border/40">
                <div className="rounded-full bg-blue-950/50 w-12 h-12 flex items-center justify-center mb-4">
                  <svg 
                    xmlns="http://www.w3.org/2000/svg" 
                    width="24" 
                    height="24" 
                    viewBox="0 0 24 24" 
                    fill="none" 
                    stroke="currentColor" 
                    strokeWidth="2" 
                    strokeLinecap="round" 
                    strokeLinejoin="round" 
                    className="text-blue-400"
                  >
                    <path d="m21 8-2 2-2-2" />
                    <path d="M19 10V4a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6" />
                    <path d="M8 8h3" />
                    <path d="M8 12h8" />
                    <path d="M8 16h3" />
                  </svg>
                </div>
                <h3 className="text-xl font-semibold mb-2 text-white">Vulnerability Scanner</h3>
                <p className="text-muted-foreground">Identify and remediate security weaknesses across your systems</p>
              </div>
            </div>
            
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Button 
                onClick={() => setLocation('/login')}
                className="bg-accent-primary hover:bg-accent-primary/90 text-black px-8 py-6 text-lg"
                size="lg"
              >
                Log In
              </Button>
              <Button 
                onClick={() => setLocation('/signup')}
                variant="outline" 
                className="bg-transparent border-accent-primary text-accent-primary hover:bg-accent-primary/10 px-8 py-6 text-lg"
                size="lg"
              >
                Sign Up
              </Button>
            </div>
          </div>
        </div>
      </div>
      
      {/* Footer */}
      <footer className="py-8 text-center text-muted-foreground relative z-10">
        <div className="container mx-auto">
          <p>© 2025 SecureNet. Enterprise-grade security monitoring platform.</p>
        </div>
      </footer>
    </div>
  );
}