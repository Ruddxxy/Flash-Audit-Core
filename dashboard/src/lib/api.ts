const API_URL = process.env.NEXT_PUBLIC_API_URL || "__FLASHAUDIT_API_URL__";

type RequestOptions = {
  method?: string;
  body?: unknown;
  params?: Record<string, string | number | undefined>;
};

class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, params } = opts;

  let url = `${API_URL}${path}`;
  if (params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        searchParams.set(key, String(value));
      }
    }
    const qs = searchParams.toString();
    if (qs) url += `?${qs}`;
  }

  const headers: Record<string, string> = {};
  if (body) headers["Content-Type"] = "application/json";

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    credentials: "include",
  });

  if (!res.ok) {
    const data = await res.json().catch(() => ({ error: res.statusText }));
    throw new ApiError(res.status, data.error || data.detail || res.statusText);
  }

  if (res.status === 204) return undefined as T;

  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return res.json();
  }

  return res.blob() as unknown as T;
}

// Auth
export const api = {
  auth: {
    login: (email: string, password: string) =>
      request<{ message: string; user: User }>("/api/v1/auth/login", {
        method: "POST",
        body: { email, password },
      }),
    logout: () => request<{ message: string }>("/api/v1/auth/logout", { method: "POST" }),
    me: () => request<User>("/api/v1/auth/me"),
    register: (data: { email: string; password: string; name: string; role?: string }) =>
      request<User>("/api/v1/auth/register", { method: "POST", body: data }),
  },

  findings: {
    list: (params?: Record<string, string | number | undefined>) =>
      request<PaginatedResponse<Finding>>("/api/v1/findings", { params }),
    get: (id: number) => request<Finding>(`/api/v1/findings/${id}`),
    triage: (id: number, status: string) =>
      request<Finding>(`/api/v1/findings/${id}`, { method: "PATCH", body: { status } }),
    remediation: (id: number) =>
      request<RemediationPlaybook>(`/api/v1/findings/${id}/remediation`),
  },

  repositories: {
    list: () => request<Repository[]>("/api/v1/repositories"),
    summary: (id: number) => request<RepositorySummary>(`/api/v1/repositories/${id}/summary`),
  },

  analytics: {
    trends: (params?: Record<string, string | number | undefined>) =>
      request<TrendsResponse>("/api/v1/analytics/trends", { params }),
    summary: () => request<AnalyticsSummary>("/api/v1/analytics/summary"),
  },

  exports: {
    csv: (params?: Record<string, string | number | undefined>) => {
      const searchParams = new URLSearchParams();
      if (params) {
        for (const [key, value] of Object.entries(params)) {
          if (value !== undefined) searchParams.set(key, String(value));
        }
      }
      const qs = searchParams.toString();
      const url = `${API_URL}/api/v1/exports/findings.csv${qs ? `?${qs}` : ""}`;
      window.open(url, "_blank");
    },
    complianceReport: (data: {
      framework: string;
      date_from?: string;
      date_to?: string;
      repo_ids?: number[];
    }) =>
      request<Blob>("/api/v1/exports/compliance-report", { method: "POST", body: data }),
  },

  settings: {
    webhooks: {
      list: () => request<Webhook[]>("/api/v1/settings/webhooks"),
      create: (data: { url: string; events: string[]; is_active?: boolean }) =>
        request<Webhook>("/api/v1/settings/webhooks", { method: "POST", body: data }),
      delete: (id: number) =>
        request<void>(`/api/v1/settings/webhooks/${id}`, { method: "DELETE" }),
    },
    policies: {
      list: () => request<Policy[]>("/api/v1/settings/policies"),
      create: (data: { name: string; conditions: object; action: string; is_active?: boolean }) =>
        request<Policy>("/api/v1/settings/policies", { method: "POST", body: data }),
      delete: (id: number) =>
        request<void>(`/api/v1/settings/policies/${id}`, { method: "DELETE" }),
    },
    users: {
      list: () => request<User[]>("/api/v1/settings/users"),
      create: (data: { email: string; password: string; name: string; role?: string }) =>
        request<User>("/api/v1/settings/users", { method: "POST", body: data }),
      delete: (id: number) =>
        request<void>(`/api/v1/settings/users/${id}`, { method: "DELETE" }),
    },
  },
};

// Types
export type User = {
  id: number;
  org_id: number;
  email: string;
  name: string;
  role: "admin" | "member" | "viewer";
  is_active: boolean;
  created_at: string;
  last_login: string | null;
};

export type Finding = {
  id: number;
  repo_id: number;
  secret_hash: string;
  rule_id: string | null;
  file_path: string | null;
  line_number: number | null;
  risk_class: string | null;
  risk_impact: string | null;
  status: "active" | "fixed" | "ignored" | "false_positive" | "rotated";
  first_seen: string;
  last_seen: string;
  fixed_at: string | null;
  rotated_at: string | null;
  repo_name: string | null;
};

export type Repository = {
  id: number;
  org_id: number;
  name: string;
  created_at: string;
  active_findings: number;
  fixed_findings: number;
  ignored_findings: number;
  total_findings: number;
};

export type RepositorySummary = {
  id: number;
  name: string;
  by_risk_class: Record<string, number>;
  by_risk_impact: Record<string, number>;
  by_rule: Record<string, number>;
  timeline: unknown[];
};

export type TrendPoint = {
  date: string;
  new_findings: number;
  fixed_findings: number;
  total_active: number;
};

export type TrendsResponse = {
  trends: TrendPoint[];
  period: string;
};

export type AnalyticsSummary = {
  total_repositories: number;
  total_findings: number;
  active_findings: number;
  fixed_findings: number;
  ignored_findings: number;
  by_severity: Record<string, number>;
  avg_mttr_hours: number | null;
  rotated_findings: number;
  avg_rotation_time_hours: number | null;
  clean_repos: number;
};

export type PaginatedResponse<T> = {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
};

export type Webhook = {
  id: number;
  org_id: number;
  url: string;
  events: string[];
  is_active: boolean;
  created_at: string;
};

export type Policy = {
  id: number;
  org_id: number;
  name: string;
  conditions: object;
  action: "block" | "alert";
  is_active: boolean;
  created_at: string;
};

export type RemediationPlaybook = {
  rule_id: string;
  provider: string;
  blast_radius: string;
  steps: string[];
  console_url: string | null;
  estimated_minutes: number | null;
  auto_revocable: boolean;
  vault_alternative: string | null;
  references: string[];
};

export { ApiError };
