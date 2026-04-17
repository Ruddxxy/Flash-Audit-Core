"use client";

import { useEffect, useState } from "react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { api, type Repository } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { FolderGit2, Bug, CheckCircle, EyeOff } from "lucide-react";

export default function RepositoriesPage() {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.repositories
      .list()
      .then(setRepos)
      .catch((err) => setError(err.message || "Failed to load repositories"))
      .finally(() => setLoading(false));
  }, []);

  return (
    <DashboardLayout>
      <h1 className="mb-6 text-2xl font-bold">Repositories</h1>

      {error && (
        <div className="mb-4 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">Loading...</div>
      ) : repos.length === 0 ? (
        <div className="flex h-64 items-center justify-center text-muted-foreground">
          No repositories yet. Connect your scanner to start tracking.
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {repos.map((repo) => (
            <Card key={repo.id}>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <FolderGit2 className="h-4 w-4" />
                  <span className="truncate">{repo.name}</span>
                  {repo.active_findings === 0 && (
                    <Badge variant="outline" className="ml-auto text-green-600 border-green-300">
                      Clean
                    </Badge>
                  )}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="flex items-center justify-center gap-1 text-destructive">
                      <Bug className="h-3.5 w-3.5" />
                      <span className="text-lg font-bold">{repo.active_findings}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">Active</p>
                  </div>
                  <div>
                    <div className="flex items-center justify-center gap-1 text-green-600">
                      <CheckCircle className="h-3.5 w-3.5" />
                      <span className="text-lg font-bold">{repo.fixed_findings}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">Fixed</p>
                  </div>
                  <div>
                    <div className="flex items-center justify-center gap-1 text-muted-foreground">
                      <EyeOff className="h-3.5 w-3.5" />
                      <span className="text-lg font-bold">{repo.ignored_findings}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">Ignored</p>
                  </div>
                </div>
                <p className="mt-3 text-xs text-muted-foreground">
                  Added {new Date(repo.created_at).toLocaleDateString()}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </DashboardLayout>
  );
}
