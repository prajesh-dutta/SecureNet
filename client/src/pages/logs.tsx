import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Logs() {
  return (
    <div className="space-y-6">
      <Card className="glass-effect">
        <CardHeader>
          <CardTitle>Security Logs Viewer</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-text-secondary">
            Security Logs Viewer module is coming soon
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
