import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "./api";

// Query key factory for consistent cache management
export const queryKeys = {
  findings: (params?: Record<string, string | number>) => ["findings", params] as const,
  repositories: () => ["repositories"] as const,
  repositorySummary: (id: number) => ["repositories", id, "summary"] as const,
  analytics: {
    summary: () => ["analytics", "summary"] as const,
    trends: (params?: Record<string, string | number>) => ["analytics", "trends", params] as const,
  },
  settings: {
    webhooks: () => ["settings", "webhooks"] as const,
    policies: () => ["settings", "policies"] as const,
    users: () => ["settings", "users"] as const,
  },
};

// --- Analytics ---

export function useAnalyticsSummary() {
  return useQuery({
    queryKey: queryKeys.analytics.summary(),
    queryFn: () => api.analytics.summary(),
  });
}

export function useAnalyticsTrends(params?: Record<string, string | number>) {
  return useQuery({
    queryKey: queryKeys.analytics.trends(params),
    queryFn: () => api.analytics.trends(params),
  });
}

// --- Repositories ---

export function useRepositories() {
  return useQuery({
    queryKey: queryKeys.repositories(),
    queryFn: () => api.repositories.list(),
  });
}

// --- Settings ---

export function useWebhooks() {
  return useQuery({
    queryKey: queryKeys.settings.webhooks(),
    queryFn: () => api.settings.webhooks.list(),
  });
}

export function useCreateWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { url: string; events: string[] }) =>
      api.settings.webhooks.create(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.webhooks() }),
  });
}

export function useDeleteWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.settings.webhooks.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.webhooks() }),
  });
}

export function usePolicies() {
  return useQuery({
    queryKey: queryKeys.settings.policies(),
    queryFn: () => api.settings.policies.list(),
  });
}

export function useCreatePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { name: string; conditions: Record<string, unknown>; action: string }) =>
      api.settings.policies.create(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.policies() }),
  });
}

export function useDeletePolicy() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.settings.policies.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.policies() }),
  });
}

export function useUsers() {
  return useQuery({
    queryKey: queryKeys.settings.users(),
    queryFn: () => api.settings.users.list(),
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: { email: string; password: string; name: string; role: string }) =>
      api.settings.users.create(data),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.users() }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.settings.users.delete(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: queryKeys.settings.users() }),
  });
}
