import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export default function Vulnerabilities() {
  return (
    <div className="space-y-6">
      <Card className="glass-effect">
        <CardHeader>
          <CardTitle>Vulnerability Scanner</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64 flex items-center justify-center text-text-secondary">
            Vulnerability Scanner module is coming soon
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
