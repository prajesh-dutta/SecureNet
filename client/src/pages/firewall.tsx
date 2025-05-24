import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Firewall() {
  return (
    <div className="space-y-6">
      <Card className="glass-effect">
        <CardHeader>
          <CardTitle>Firewall Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-text-secondary">
            Firewall Configuration module is coming soon
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
