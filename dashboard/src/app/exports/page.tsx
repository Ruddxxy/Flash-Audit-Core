"use client";

import { useState } from "react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { api } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Download, FileText } from "lucide-react";

export default function ExportsPage() {
  const [framework, setFramework] = useState("SOC2");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGeneratePdf = async () => {
    setGenerating(true);
    setError(null);
    try {
      const blob = await api.exports.complianceReport({
        framework,
        date_from: dateFrom || undefined,
        date_to: dateTo || undefined,
      });

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `flashaudit_${framework.toLowerCase()}_report.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to generate report";
      setError(message);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <DashboardLayout>
      <h1 className="mb-6 text-2xl font-bold">Exports</h1>

      {error && (
        <div className="mb-4 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* CSV Export */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Download className="h-5 w-5" />
              CSV Export
            </CardTitle>
            <CardDescription>
              Download all findings as a spreadsheet
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Exports all findings with the current filters applied from the Findings page.
            </p>
            <Button onClick={() => api.exports.csv({})}>
              <Download className="mr-2 h-4 w-4" />
              Download CSV
            </Button>
          </CardContent>
        </Card>

        {/* Compliance Report */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Compliance Report
            </CardTitle>
            <CardDescription>
              Generate PDF reports for audit frameworks
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Framework</Label>
              <Select value={framework} onValueChange={setFramework}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="SOC2">SOC 2</SelectItem>
                  <SelectItem value="PCI-DSS">PCI-DSS</SelectItem>
                  <SelectItem value="ISO27001">ISO 27001</SelectItem>
                  <SelectItem value="HIPAA">HIPAA</SelectItem>
                  <SelectItem value="GENERAL">General Report</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-2">
                <Label>From</Label>
                <Input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
              </div>
              <div className="space-y-2">
                <Label>To</Label>
                <Input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
              </div>
            </div>
            <Button onClick={handleGeneratePdf} disabled={generating}>
              <FileText className="mr-2 h-4 w-4" />
              {generating ? "Generating..." : "Generate PDF"}
            </Button>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
