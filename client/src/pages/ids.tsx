import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function IDS() {
  return (
    <div className="space-y-6">
      <Card className="glass-effect">
        <CardHeader>
          <CardTitle>Intrusion Detection System</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-text-secondary">
            IDS module is coming soon
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
