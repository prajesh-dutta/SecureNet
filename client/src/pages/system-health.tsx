import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function SystemHealth() {
  return (
    <div className="space-y-6">
      <Card className="glass-effect">
        <CardHeader>
          <CardTitle>System Health Monitoring</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-text-secondary">
            System Health Monitoring module is coming soon
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
