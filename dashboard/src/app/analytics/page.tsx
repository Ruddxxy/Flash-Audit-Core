"use client";

import { useEffect, useState } from "react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { api, type AnalyticsSummary, type TrendsResponse } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

export default function AnalyticsPage() {
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [trends, setTrends] = useState<TrendsResponse | null>(null);
  const [period, setPeriod] = useState("day");
  const [days, setDays] = useState(30);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.analytics.summary().then(setSummary).catch((err) => setError(err.message || "Failed to load analytics"));
  }, []);

  useEffect(() => {
    api.analytics.trends({ period, days }).then(setTrends).catch((err) => setError(err.message || "Failed to load trends"));
  }, [period, days]);

  const severityData = summary
    ? Object.entries(summary.by_severity).map(([name, value]) => ({ name, count: value }))
    : [];

  return (
    <DashboardLayout>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold">Analytics</h1>
        {error && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
            {error}
          </div>
        )}
        <div className="flex gap-2">
          <Select value={period} onValueChange={setPeriod}>
            <SelectTrigger className="w-[120px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="day">Daily</SelectItem>
              <SelectItem value="week">Weekly</SelectItem>
              <SelectItem value="month">Monthly</SelectItem>
            </SelectContent>
          </Select>
          <Select value={String(days)} onValueChange={(v) => setDays(Number(v))}>
            <SelectTrigger className="w-[120px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">7 days</SelectItem>
              <SelectItem value="30">30 days</SelectItem>
              <SelectItem value="90">90 days</SelectItem>
              <SelectItem value="365">1 year</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* New vs Fixed Over Time */}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle className="text-base">New vs Fixed Findings</CardTitle>
        </CardHeader>
        <CardContent>
          {trends && trends.trends.length > 0 ? (
            <ResponsiveContainer width="100%" height={350}>
              <AreaChart data={trends.trends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="date"
                  tickFormatter={(d) => new Date(d).toLocaleDateString("en", { month: "short", day: "numeric" })}
                  fontSize={12}
                />
                <YAxis fontSize={12} />
                <Tooltip labelFormatter={(d) => new Date(d as string).toLocaleDateString()} />
                <Legend />
                <Area type="monotone" dataKey="new_findings" stroke="#f97316" fill="#f9731630" name="New" />
                <Area type="monotone" dataKey="fixed_findings" stroke="#22c55e" fill="#22c55e30" name="Fixed" />
                <Area type="monotone" dataKey="total_active" stroke="#ef4444" fill="#ef444415" name="Total Active" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[350px] items-center justify-center text-muted-foreground">
              No trend data available
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Severity Distribution */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Active Findings by Severity</CardTitle>
          </CardHeader>
          <CardContent>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={severityData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" fontSize={12} />
                  <YAxis fontSize={12} />
                  <Tooltip />
                  <Bar dataKey="count" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[300px] items-center justify-center text-muted-foreground">
                No data
              </div>
            )}
          </CardContent>
        </Card>

        {/* Summary Stats */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Key Metrics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <Metric label="Total Repositories" value={summary?.total_repositories ?? 0} />
            <Metric label="Total Findings (All Time)" value={summary?.total_findings ?? 0} />
            <Metric label="Active Findings" value={summary?.active_findings ?? 0} />
            <Metric label="Fixed Findings" value={summary?.fixed_findings ?? 0} />
            <Metric label="Clean Repositories" value={summary?.clean_repos ?? 0} />
            <Metric
              label="Avg. Time to Remediate"
              value={
                summary?.avg_mttr_hours != null
                  ? summary.avg_mttr_hours < 24
                    ? `${summary.avg_mttr_hours} hours`
                    : `${Math.round(summary.avg_mttr_hours / 24)} days`
                  : "N/A"
              }
            />
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-muted-foreground">{label}</span>
      <span className="text-lg font-bold">{value}</span>
    </div>
  );
}
