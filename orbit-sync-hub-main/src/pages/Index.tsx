import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Shield, Upload, FileText, CheckCircle } from "lucide-react";

const Index = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5">
      <div className="container mx-auto px-4 py-16">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="flex justify-center mb-6">
            <Shield className="h-20 w-20 text-primary" />
          </div>
          <h1 className="text-5xl font-bold mb-4 bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
            Cyber Threat Detection System
          </h1>
          <p className="text-xl text-muted-foreground mb-8">
            Advanced AI-powered document analysis to detect and prevent cybersecurity threats
          </p>
          <Button size="lg" onClick={() => navigate("/auth")} className="text-lg px-8">
            Get Started
          </Button>
        </div>

        <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
          <div className="text-center p-6 rounded-lg border bg-card">
            <Upload className="h-12 w-12 mx-auto mb-4 text-primary" />
            <h3 className="text-xl font-semibold mb-2">Upload Documents</h3>
            <p className="text-muted-foreground">
              Securely upload your files for comprehensive threat analysis
            </p>
          </div>

          <div className="text-center p-6 rounded-lg border bg-card">
            <FileText className="h-12 w-12 mx-auto mb-4 text-primary" />
            <h3 className="text-xl font-semibold mb-2">AI Analysis</h3>
            <p className="text-muted-foreground">
              Advanced algorithms scan for malware, phishing, and suspicious content
            </p>
          </div>

          <div className="text-center p-6 rounded-lg border bg-card">
            <CheckCircle className="h-12 w-12 mx-auto mb-4 text-primary" />
            <h3 className="text-xl font-semibold mb-2">Stay Protected</h3>
            <p className="text-muted-foreground">
              Get instant alerts and detailed reports on potential threats
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Index;
