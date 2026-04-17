"use client";

import { useEffect, useState } from "react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api, type AnalyticsSummary, type TrendsResponse } from "@/lib/api";
import { Bug, CheckCircle, Shield, FolderGit2 } from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  unknown: "#94a3b8",
};

export default function HomePage() {
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [trends, setTrends] = useState<TrendsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.analytics.summary(), api.analytics.trends({ days: 30, period: "day" })])
      .then(([s, t]) => {
        setSummary(s);
        setTrends(t);
      })
      .catch((err) => setError(err.message || "Failed to load dashboard data"))
      .finally(() => setLoading(false));
  }, []);

  const pieData = summary
    ? Object.entries(summary.by_severity).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <DashboardLayout>
      <h1 className="mb-6 text-2xl font-bold">Dashboard</h1>

      {error && (
        <div className="mb-4 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="mb-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard
          title="Active Findings"
          value={summary?.active_findings ?? "-"}
          icon={<Bug className="h-5 w-5 text-destructive" />}
        />
        <SummaryCard
          title="Fixed"
          value={summary?.fixed_findings ?? "-"}
          icon={<CheckCircle className="h-5 w-5 text-green-500" />}
        />
        <SummaryCard
          title="Repositories"
          value={summary?.total_repositories ?? "-"}
          icon={<FolderGit2 className="h-5 w-5 text-blue-500" />}
        />
        <SummaryCard
          title="Clean Repos"
          value={summary?.clean_repos ?? "-"}
          icon={<Shield className="h-5 w-5 text-green-500" />}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Findings Trend (30 days)</CardTitle>
          </CardHeader>
          <CardContent>
            {trends && trends.trends.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={trends.trends}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="date"
                    tickFormatter={(d) => new Date(d).toLocaleDateString("en", { month: "short", day: "numeric" })}
                    fontSize={12}
                  />
                  <YAxis fontSize={12} />
                  <Tooltip labelFormatter={(d) => new Date(d as string).toLocaleDateString()} />
                  <Area type="monotone" dataKey="total_active" stroke="#ef4444" fill="#ef444420" name="Active" />
                  <Area type="monotone" dataKey="new_findings" stroke="#f97316" fill="#f9731620" name="New" />
                  <Area type="monotone" dataKey="fixed_findings" stroke="#22c55e" fill="#22c55e20" name="Fixed" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center text-muted-foreground">
                {loading ? "Loading..." : "No data yet. Run your first scan!"}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">By Severity</CardTitle>
          </CardHeader>
          <CardContent>
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, value }) => `${name}: ${value}`}>
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || SEVERITY_COLORS.unknown} />
                    ))}
                  </Pie>
                  <Legend />
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center text-muted-foreground">
                {loading ? "Loading..." : "No findings yet"}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {summary?.avg_mttr_hours != null && (
        <Card className="mt-6">
          <CardContent className="pt-6">
            <p className="text-sm text-muted-foreground">Average Time to Remediate</p>
            <p className="text-3xl font-bold">
              {summary.avg_mttr_hours < 24
                ? `${summary.avg_mttr_hours}h`
                : `${Math.round(summary.avg_mttr_hours / 24)}d`}
            </p>
          </CardContent>
        </Card>
      )}
    </DashboardLayout>
  );
}

function SummaryCard({ title, value, icon }: { title: string; value: number | string; icon: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-4 pt-6">
        <div className="rounded-lg bg-muted p-3">{icon}</div>
        <div>
          <p className="text-sm text-muted-foreground">{title}</p>
          <p className="text-2xl font-bold">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}
