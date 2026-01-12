import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { User } from "@supabase/supabase-js";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { Upload, FileText, Shield, LogOut, AlertTriangle, CheckCircle, Clock } from "lucide-react";
import { DocumentUpload } from "@/components/DocumentUpload";
import { DocumentList } from "@/components/DocumentList";

const Dashboard = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({ total: 0, threats: 0, safe: 0 });

  const fetchStats = async (userId: string) => {
    const { data, error } = await supabase
      .from("documents")
      .select("threat_status")
      .eq("user_id", userId);

    if (error) {
      console.error("Error fetching stats:", error);
      return;
    }

    const total = data?.length || 0;
    const threats = data?.filter((d) => d.threat_status === "threat").length || 0;
    const safe = data?.filter((d) => d.threat_status === "safe").length || 0;

    setStats({ total, threats, safe });
  };

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      if (session) {
        setUser(session.user);
        fetchStats(session.user.id);
      } else {
        navigate("/auth");
      }
      setLoading(false);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) {
        setUser(session.user);
        fetchStats(session.user.id);
      } else {
        setUser(null);
        navigate("/auth");
      }
    });

    // Listen for upload events
    const handleUpload = () => {
      if (user?.id) fetchStats(user.id);
    };
    window.addEventListener("document-uploaded", handleUpload);

    return () => {
      subscription.unsubscribe();
      window.removeEventListener("document-uploaded", handleUpload);
    };
  }, [navigate, user?.id]);

  const handleLogout = async () => {
    const { error } = await supabase.auth.signOut();
    if (error) {
      toast.error("Error logging out");
    } else {
      toast.success("Logged out successfully");
      navigate("/auth");
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-primary/5">
      <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-xl font-bold">Cyber Threat Detection</h1>
              <p className="text-sm text-muted-foreground">Welcome, {user?.email}</p>
            </div>
          </div>
          <Button onClick={handleLogout} variant="outline" size="sm">
            <LogOut className="h-4 w-4 mr-2" />
            Logout
          </Button>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="grid gap-6 md:grid-cols-3 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Documents</CardTitle>
              <FileText className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats.total}</div>
              <p className="text-xs text-muted-foreground">Uploaded for analysis</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Threats Detected</CardTitle>
              <AlertTriangle className="h-4 w-4 text-destructive" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-destructive">{stats.threats}</div>
              <p className="text-xs text-muted-foreground">Suspicious files found</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Safe Documents</CardTitle>
              <CheckCircle className="h-4 w-4 text-green-600" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{stats.safe}</div>
              <p className="text-xs text-muted-foreground">No threats found</p>
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="h-5 w-5" />
                Upload Document
              </CardTitle>
              <CardDescription>
                Upload files to scan for cybersecurity threats
              </CardDescription>
            </CardHeader>
            <CardContent>
              <DocumentUpload userId={user?.id || ""} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="h-5 w-5" />
                Recent Documents
              </CardTitle>
              <CardDescription>
                View your uploaded documents and their threat status
              </CardDescription>
            </CardHeader>
            <CardContent>
              <DocumentList userId={user?.id || ""} />
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;