import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { FileText, AlertTriangle, CheckCircle, Clock, ChevronDown, ChevronUp } from "lucide-react";
import { ThreatDetails } from "./ThreatDetails";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

interface Document {
  id: string;
  file_name: string;
  threat_status: string;
  threat_score: number | null;
  uploaded_at: string;
  scan_results: any;
}

interface DocumentListProps {
  userId: string;
}

export const DocumentList = ({ userId }: DocumentListProps) => {
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedDoc, setExpandedDoc] = useState<string | null>(null);

  const fetchDocuments = async () => {
    if (!userId) return;

    const { data, error } = await supabase
      .from("documents")
      .select("*")
      .eq("user_id", userId)
      .order("uploaded_at", { ascending: false })
      .limit(10);

    if (error) {
      console.error("Error fetching documents:", error);
    } else {
      setDocuments(data || []);
    }
    setLoading(false);
  };

  useEffect(() => {
    fetchDocuments();

    // Listen for upload events
    const handleUpload = () => fetchDocuments();
    window.addEventListener("document-uploaded", handleUpload);

    return () => {
      window.removeEventListener("document-uploaded", handleUpload);
    };
  }, [userId]);

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "safe":
        return <CheckCircle className="h-4 w-4 text-green-600" />;
      case "threat":
        return <AlertTriangle className="h-4 w-4 text-destructive" />;
      default:
        return <Clock className="h-4 w-4 text-muted-foreground" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "safe":
        return <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">Safe</Badge>;
      case "threat":
        return <Badge variant="destructive">Threat</Badge>;
      case "error":
        return <Badge variant="outline" className="bg-orange-50 text-orange-700 border-orange-200">Error</Badge>;
      default:
        return <Badge variant="secondary">Pending</Badge>;
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (documents.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        <FileText className="h-12 w-12 mx-auto mb-2 opacity-50" />
        <p>No documents uploaded yet</p>
      </div>
    );
  }

  return (
    <ScrollArea className="h-[500px] pr-4">
      <div className="space-y-4">
        {documents.map((doc) => (
          <Collapsible
            key={doc.id}
            open={expandedDoc === doc.id}
            onOpenChange={() => setExpandedDoc(expandedDoc === doc.id ? null : doc.id)}
          >
            <div className="border rounded-lg overflow-hidden">
              <div className="flex items-start justify-between p-3 hover:bg-accent/50 transition-colors">
                <div className="flex items-start gap-3 flex-1">
                  <div className="mt-1">
                    {getStatusIcon(doc.threat_status)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm truncate">{doc.file_name}</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(doc.uploaded_at).toLocaleDateString()} at{" "}
                      {new Date(doc.uploaded_at).toLocaleTimeString()}
                    </p>
                    {doc.threat_score !== null && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Threat Score: {(doc.threat_score * 100).toFixed(1)}%
                      </p>
                    )}
                    {doc.scan_results && doc.scan_results.total_records && (
                      <p className="text-xs text-muted-foreground">
                        Records: {doc.scan_results.total_records} 
                        {doc.scan_results.threat_count ? ` (${doc.scan_results.threat_count} threats)` : ''}
                      </p>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 ml-2">
                  {getStatusBadge(doc.threat_status)}
                  {(doc.scan_results && !doc.scan_results.error) && (
                    <CollapsibleTrigger asChild>
                      <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                        {expandedDoc === doc.id ? (
                          <ChevronUp className="h-4 w-4" />
                        ) : (
                          <ChevronDown className="h-4 w-4" />
                        )}
                      </Button>
                    </CollapsibleTrigger>
                  )}
                </div>
              </div>
              
              <CollapsibleContent>
                <div className="p-3 bg-muted/30 border-t">
                  <ThreatDetails scanResults={doc.scan_results} />
                </div>
              </CollapsibleContent>
            </div>
          </Collapsible>
        ))}
      </div>
    </ScrollArea>
  );
};