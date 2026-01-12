import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import { Upload, Loader2 } from "lucide-react";

interface DocumentUploadProps {
  userId: string;
}

export const DocumentUpload = ({ userId }: DocumentUploadProps) => {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!file || !userId) {
      toast.error("Please select a file");
      return;
    }

    setUploading(true);

    try {
      // Upload to storage
      const filePath = `${userId}/${Date.now()}_${file.name}`;
      const { error: uploadError } = await supabase.storage
        .from("documents")
        .upload(filePath, file);

      if (uploadError) throw uploadError;

      // Create database record
      const { data: docData, error: dbError } = await supabase
        .from("documents")
        .insert({
          user_id: userId,
          file_name: file.name,
          file_path: filePath,
          file_size: file.size,
          file_type: file.type,
          threat_status: "pending",
        })
        .select()
        .single();

      if (dbError) throw dbError;

      toast.success("Document uploaded successfully! Analyzing...");
      setFile(null);
      
      // Reset file input
      const fileInput = document.getElementById("file-upload") as HTMLInputElement;
      if (fileInput) fileInput.value = "";

      // Trigger refresh
      window.dispatchEvent(new Event("document-uploaded"));

      // Analyze the file in the background
      analyzeDocument(docData.id, filePath, file);
    } catch (error: any) {
      toast.error(error.message || "Error uploading document");
    } finally {
      setUploading(false);
    }
  };

  const analyzeDocument = async (docId: string, filePath: string, file: File) => {
    try {
      // Read file content
      const fileContent = await file.text();
      
      console.log('Analyzing document:', file.name, 'Type:', file.type);
      console.log('Content preview:', fileContent.substring(0, 200));
      
      // Call the Python edge function
      const { data, error } = await supabase.functions.invoke('analyze-threat', {
        body: {
          log_content: fileContent,
          file_type: file.type
        }
      });

      console.log('Analysis response:', data, 'Error:', error);

      if (error) {
        console.error('Edge function error:', error);
        throw new Error(error.message || 'Analysis failed');
      }

      if (!data || data.error) {
        throw new Error(data?.error || 'Invalid analysis response');
      }

      // Update document with results
      const { error: updateError } = await supabase
        .from("documents")
        .update({
          threat_status: data.threat_status,
          threat_score: data.threat_score,
          scan_results: data
        })
        .eq('id', docId);

      if (updateError) {
        console.error('Database update error:', updateError);
        throw updateError;
      }

      // Trigger refresh to show updated results
      window.dispatchEvent(new Event("document-uploaded"));
      
      if (data.threat_status === 'threat') {
        toast.error(`⚠️ ${data.threat_count} threat(s) detected! Confidence: ${(data.threat_score * 100).toFixed(1)}%`);
      } else {
        toast.success(`✓ Analysis complete - All ${data.total_records} records are safe`);
      }
    } catch (error: any) {
      console.error('Analysis error:', error);
      const errorMsg = error.message || 'Analysis failed';
      toast.error(`Analysis error: ${errorMsg}`);
      
      // Update status to show error with details
      await supabase
        .from("documents")
        .update({ 
          threat_status: "error",
          scan_results: { error: errorMsg }
        })
        .eq('id', docId);
      
      // Trigger refresh to show error
      window.dispatchEvent(new Event("document-uploaded"));
    }
  };

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="file-upload">Select Document</Label>
        <Input
          id="file-upload"
          type="file"
          onChange={handleFileChange}
          accept=".log,.csv,.json,.txt"
          disabled={uploading}
        />
        <p className="text-xs text-muted-foreground">
          Supported formats: System logs (.log, .csv, .json, .txt)
        </p>
        <p className="text-xs text-orange-600">
          Note: Upload CSV/JSON files with numeric log data for threat analysis
        </p>
      </div>

      <Button
        onClick={handleUpload}
        disabled={!file || uploading}
        className="w-full"
      >
        {uploading ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Uploading...
          </>
        ) : (
          <>
            <Upload className="mr-2 h-4 w-4" />
            Upload Document
          </>
        )}
      </Button>
    </div>
  );
};