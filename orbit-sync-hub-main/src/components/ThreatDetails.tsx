import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, CheckCircle, Info } from "lucide-react";

interface ThreatDetailsProps {
  scanResults: any;
}

export const ThreatDetails = ({ scanResults }: ThreatDetailsProps) => {
  if (!scanResults || scanResults.error) {
    return (
      <div className="p-4 border rounded-lg bg-orange-50 border-orange-200">
        <div className="flex items-start gap-2">
          <AlertTriangle className="h-5 w-5 text-orange-600 mt-0.5" />
          <div>
            <p className="font-medium text-orange-900">Analysis Error</p>
            <p className="text-sm text-orange-700">{scanResults?.error || "Failed to analyze file"}</p>
          </div>
        </div>
      </div>
    );
  }

  const { threat_status, threat_score, total_records, threat_count, safe_count, average_confidence, threat_details } = scanResults;

  return (
    <div className="space-y-4">
      {/* Summary Card */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            {threat_status === "threat" ? (
              <AlertTriangle className="h-5 w-5 text-destructive" />
            ) : (
              <CheckCircle className="h-5 w-5 text-green-600" />
            )}
            Analysis Summary
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-muted-foreground">Total Records</p>
              <p className="text-lg font-semibold">{total_records}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Avg Confidence</p>
              <p className="text-lg font-semibold text-primary">{average_confidence}%</p>
            </div>
            <div>
              <p className="text-muted-foreground">Threats Found</p>
              <p className="text-lg font-semibold text-destructive">{threat_count}</p>
            </div>
            <div>
              <p className="text-muted-foreground">Safe Records</p>
              <p className="text-lg font-semibold text-green-600">{safe_count}</p>
            </div>
          </div>
          
          <div>
            <p className="text-sm text-muted-foreground mb-1">Threat Score</p>
            <div className="flex items-center gap-2">
              <div className="flex-1 h-2 bg-muted rounded-full overflow-hidden">
                <div 
                  className={`h-full ${threat_score > 0.5 ? 'bg-destructive' : 'bg-green-600'}`}
                  style={{ width: `${threat_score * 100}%` }}
                />
              </div>
              <span className="text-sm font-medium">{(threat_score * 100).toFixed(1)}%</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Threat Details */}
      {threat_details && threat_details.length > 0 && (
        <Card className="border-destructive/20 bg-red-50/50">
          <CardHeader>
            <CardTitle className="text-base text-destructive">Detected Threats</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {threat_details.map((detail: any, idx: number) => (
              <div key={idx} className="p-3 bg-background border rounded-lg space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="destructive" className="text-xs">Record #{detail.record_number}</Badge>
                    {detail.threat_type && (
                      <Badge variant="outline" className="text-xs bg-destructive/10">
                        {detail.threat_type}
                      </Badge>
                    )}
                    {detail.severity && (
                      <Badge variant="outline" className="text-xs">
                        {detail.severity}
                      </Badge>
                    )}
                  </div>
                  <div className="flex flex-col items-end gap-1">
                    <span className="text-sm font-semibold text-destructive">
                      {detail.threat_score}%
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {detail.confidence}% Confidence
                    </span>
                  </div>
                </div>
                
                {detail.source_ip && (
                  <div className="text-xs">
                    <span className="font-medium text-muted-foreground">Source IP:</span>{" "}
                    <span className="font-mono">{detail.source_ip}</span>
                  </div>
                )}
                
                {detail.indicators && detail.indicators.length > 0 && (
                  <div className="text-xs space-y-1">
                    <p className="font-medium text-destructive">Threat Indicators:</p>
                    <ul className="list-disc list-inside space-y-0.5 text-muted-foreground">
                      {detail.indicators.map((indicator: string, i: number) => (
                        <li key={i}>{indicator}</li>
                      ))}
                    </ul>
                  </div>
                )}
                
                {detail.sample_data && (
                  <div className="text-xs">
                    <p className="font-medium text-muted-foreground mb-1">Sample Data:</p>
                    <div className="font-mono text-xs bg-muted/50 p-2 rounded overflow-x-auto">
                      {Object.entries(detail.sample_data).slice(0, 3).map(([key, value]: [string, any]) => (
                        <div key={key}>
                          {key}: {typeof value === 'number' ? value.toFixed(2) : value}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
            
            {threat_count > threat_details.length && (
              <p className="text-xs text-muted-foreground text-center">
                Showing {threat_details.length} of {threat_count} threats
              </p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
};
