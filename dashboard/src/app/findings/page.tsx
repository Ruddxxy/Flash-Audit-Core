"use client";

import { useEffect, useState, useCallback } from "react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { api, type Finding, type PaginatedResponse, type RemediationPlaybook } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  ChevronLeft,
  ChevronRight,
  Eye,
  EyeOff,
  Flag,
  Wrench,
  ExternalLink,
  ShieldCheck,
  Clock,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
} from "lucide-react";

const STATUS_COLORS: Record<string, string> = {
  active: "destructive",
  fixed: "default",
  ignored: "secondary",
  false_positive: "outline",
  rotated: "default",
};

const IMPACT_COLORS: Record<string, string> = {
  critical: "destructive",
  high: "destructive",
  medium: "default",
  low: "secondary",
};

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffMs = now - then;
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  if (hours < 1) return "< 1 hour ago";
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

function urgencyColor(dateStr: string): string {
  const hours = (Date.now() - new Date(dateStr).getTime()) / (1000 * 60 * 60);
  if (hours < 24) return "text-yellow-600";
  if (hours < 72) return "text-orange-600";
  return "text-red-600";
}

function RemediationPanel({
  finding,
  onRotated,
}: {
  finding: Finding;
  onRotated: () => void;
}) {
  const [playbook, setPlaybook] = useState<RemediationPlaybook | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    api.findings
      .remediation(finding.id)
      .then((data) => setPlaybook(data))
      .catch((err) => setError(err.message || "No playbook available"))
      .finally(() => setLoading(false));
  }, [finding.id]);

  if (loading) {
    return (
      <div className="p-4 text-sm text-muted-foreground">
        Loading remediation playbook...
      </div>
    );
  }

  if (error || !playbook) {
    return (
      <div className="p-4 text-sm text-muted-foreground">
        No remediation playbook available for this rule type.
      </div>
    );
  }

  const handleRotate = async () => {
    await api.findings.triage(finding.id, "rotated");
    onRotated();
  };

  return (
    <div className="border-t bg-muted/30 p-4 space-y-4">
      {/* Header: Provider + Urgency */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Wrench className="h-4 w-4 text-primary" />
          <span className="font-semibold text-sm">{playbook.provider}</span>
          {playbook.auto_revocable && (
            <Badge variant="outline" className="text-xs">
              Auto-revocable
            </Badge>
          )}
          {playbook.estimated_minutes && (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              <Clock className="h-3 w-3" />
              ~{playbook.estimated_minutes} min to rotate
            </span>
          )}
        </div>
        <span
          className={`flex items-center gap-1 text-xs font-medium ${urgencyColor(finding.first_seen)}`}
        >
          <AlertTriangle className="h-3 w-3" />
          Detected {timeAgo(finding.first_seen)}
        </span>
      </div>

      {/* Blast Radius */}
      <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3">
        <p className="text-xs font-semibold text-destructive mb-1">
          Blast Radius
        </p>
        <p className="text-sm">{playbook.blast_radius}</p>
      </div>

      {/* Rotation Steps */}
      <div>
        <p className="text-xs font-semibold mb-2">Rotation Steps</p>
        <ol className="list-decimal list-inside space-y-1.5 text-sm">
          {playbook.steps.map((step, i) => (
            <li key={i} className="leading-relaxed">
              {step}
            </li>
          ))}
        </ol>
      </div>

      {/* Vault Alternative */}
      {playbook.vault_alternative && (
        <div className="rounded-md border bg-blue-50 dark:bg-blue-950/20 p-3">
          <p className="text-xs font-semibold text-blue-700 dark:text-blue-400 mb-1">
            Long-term Fix
          </p>
          <p className="text-sm">{playbook.vault_alternative}</p>
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 pt-1">
        {playbook.console_url && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => window.open(playbook.console_url!, "_blank")}
          >
            <ExternalLink className="mr-1 h-3 w-3" />
            Open Console
          </Button>
        )}
        {finding.status === "active" && (
          <Button size="sm" onClick={handleRotate}>
            <ShieldCheck className="mr-1 h-3 w-3" />
            Mark as Rotated
          </Button>
        )}
        {playbook.references.length > 0 && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => window.open(playbook.references[0], "_blank")}
          >
            Docs
            <ExternalLink className="ml-1 h-3 w-3" />
          </Button>
        )}
      </div>
    </div>
  );
}

export default function FindingsPage() {
  const [data, setData] = useState<PaginatedResponse<Finding> | null>(null);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [searchInput, setSearchInput] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState("last_seen");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearchQuery(searchInput);
      setPage(1);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string | number> = { page, page_size: 25, sort_by: sortBy, sort_order: sortOrder };
      if (statusFilter !== "all") params.status = statusFilter;
      if (riskFilter !== "all") params.risk_impact = riskFilter;
      if (searchQuery) params.search = searchQuery;
      const result = await api.findings.list(params);
      setData(result);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  }, [page, statusFilter, riskFilter, searchQuery, sortBy, sortOrder]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  const toggleSort = (column: string) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortBy(column);
      setSortOrder("desc");
    }
    setPage(1);
  };

  const handleTriage = async (id: number, status: string) => {
    await api.findings.triage(id, status);
    setExpandedId(null);
    fetchFindings();
  };

  const toggleRemediation = (id: number) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <DashboardLayout>
      <h1 className="mb-6 text-2xl font-bold">Findings</h1>

      {error && (
        <div className="mb-4 rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Search & Filters */}
      <div className="mb-4 flex flex-wrap gap-3">
        <Input
          placeholder="Search rule, file, hash..."
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          className="w-[240px]"
        />

        <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); setPage(1); }}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="fixed">Fixed</SelectItem>
            <SelectItem value="ignored">Ignored</SelectItem>
            <SelectItem value="false_positive">False Positive</SelectItem>
            <SelectItem value="rotated">Rotated</SelectItem>
          </SelectContent>
        </Select>

        <Select value={riskFilter} onValueChange={(v) => { setRiskFilter(v); setPage(1); }}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Risk Impact" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>

        <Button
          variant="outline"
          onClick={() => api.exports.csv({
            ...(statusFilter !== "all" && { status: statusFilter }),
            ...(riskFilter !== "all" && { risk_impact: riskFilter }),
          })}
        >
          Export CSV
        </Button>
      </div>

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("rule_id")}>
                  Rule {sortBy === "rule_id" && (sortOrder === "asc" ? <ChevronUp className="inline h-3 w-3" /> : <ChevronDown className="inline h-3 w-3" />)}
                </TableHead>
                <TableHead>File</TableHead>
                <TableHead>Repository</TableHead>
                <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("risk_impact")}>
                  Severity {sortBy === "risk_impact" && (sortOrder === "asc" ? <ChevronUp className="inline h-3 w-3" /> : <ChevronDown className="inline h-3 w-3" />)}
                </TableHead>
                <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("status")}>
                  Status {sortBy === "status" && (sortOrder === "asc" ? <ChevronUp className="inline h-3 w-3" /> : <ChevronDown className="inline h-3 w-3" />)}
                </TableHead>
                <TableHead className="cursor-pointer select-none" onClick={() => toggleSort("first_seen")}>
                  First Seen {sortBy === "first_seen" && (sortOrder === "asc" ? <ChevronUp className="inline h-3 w-3" /> : <ChevronDown className="inline h-3 w-3" />)}
                </TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={7} className="h-32 text-center text-muted-foreground">
                    Loading...
                  </TableCell>
                </TableRow>
              ) : data && data.items.length > 0 ? (
                data.items.map((f: Finding) => (
                  <>
                    <TableRow key={f.id} className={expandedId === f.id ? "border-b-0" : ""}>
                      <TableCell className="font-mono text-xs">{f.rule_id || "-"}</TableCell>
                      <TableCell className="max-w-[200px] truncate font-mono text-xs" title={f.file_path || ""}>
                        {f.file_path || "-"}
                        {f.line_number ? `:${f.line_number}` : ""}
                      </TableCell>
                      <TableCell className="text-sm">{f.repo_name || "-"}</TableCell>
                      <TableCell>
                        <Badge variant={IMPACT_COLORS[f.risk_impact || ""] as "destructive" | "default" | "secondary" || "secondary"}>
                          {f.risk_impact || "unknown"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant={STATUS_COLORS[f.status] as "destructive" | "default" | "secondary" | "outline" || "default"}>
                          {f.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {new Date(f.first_seen).toLocaleDateString()}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-1">
                          {/* How to Fix button */}
                          {f.rule_id && (f.status === "active" || f.status === "fixed") && (
                            <Button
                              variant={expandedId === f.id ? "secondary" : "ghost"}
                              size="icon"
                              title="How to Fix"
                              onClick={() => toggleRemediation(f.id)}
                            >
                              {expandedId === f.id ? (
                                <ChevronUp className="h-4 w-4" />
                              ) : (
                                <Wrench className="h-4 w-4" />
                              )}
                            </Button>
                          )}

                          {/* Triage actions */}
                          {f.status === "active" && (
                            <>
                              <Button
                                variant="ghost"
                                size="icon"
                                title="Mark as Ignored"
                                onClick={() => handleTriage(f.id, "ignored")}
                              >
                                <EyeOff className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="ghost"
                                size="icon"
                                title="Mark as False Positive"
                                onClick={() => handleTriage(f.id, "false_positive")}
                              >
                                <Flag className="h-4 w-4" />
                              </Button>
                            </>
                          )}
                          {(f.status === "ignored" || f.status === "false_positive") && (
                            <Button
                              variant="ghost"
                              size="icon"
                              title="Re-activate"
                              onClick={() => handleTriage(f.id, "active")}
                            >
                              <Eye className="h-4 w-4" />
                            </Button>
                          )}
                          {f.status === "rotated" && (
                            <span className="flex items-center gap-1 text-xs text-muted-foreground px-2">
                              <ShieldCheck className="h-3 w-3 text-green-600" />
                              Rotated
                            </span>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                    {/* Expanded remediation panel */}
                    {expandedId === f.id && (
                      <TableRow key={`${f.id}-remediation`}>
                        <TableCell colSpan={7} className="p-0">
                          <RemediationPanel
                            finding={f}
                            onRotated={() => {
                              setExpandedId(null);
                              fetchFindings();
                            }}
                          />
                        </TableCell>
                      </TableRow>
                    )}
                  </>
                ))
              ) : (
                <TableRow>
                  <TableCell colSpan={7} className="h-32 text-center text-muted-foreground">
                    No findings found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Pagination */}
      {data && data.total_pages > 1 && (
        <div className="mt-4 flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            Page {data.page} of {data.total_pages} ({data.total} total)
          </p>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={page <= 1}
              onClick={() => setPage((p) => p - 1)}
            >
              <ChevronLeft className="h-4 w-4" /> Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={page >= data.total_pages}
              onClick={() => setPage((p) => p + 1)}
            >
              Next <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </DashboardLayout>
  );
}
