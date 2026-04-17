"use client";

import { useEffect, useState } from "react";
import { DashboardLayout } from "@/components/dashboard-layout";
import { useAuth } from "@/lib/auth-context";
import { api, type Webhook, type Policy, type User } from "@/lib/api";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Trash2, Plus } from "lucide-react";

export default function SettingsPage() {
  const { user: currentUser } = useAuth();
  const isAdmin = currentUser?.role === "admin";

  return (
    <DashboardLayout>
      <h1 className="mb-6 text-2xl font-bold">Settings</h1>

      <Tabs defaultValue="webhooks">
        <TabsList>
          <TabsTrigger value="webhooks">Webhooks</TabsTrigger>
          <TabsTrigger value="policies">Policies</TabsTrigger>
          {isAdmin && <TabsTrigger value="users">Users</TabsTrigger>}
        </TabsList>

        <TabsContent value="webhooks" className="mt-4">
          <WebhooksTab />
        </TabsContent>
        <TabsContent value="policies" className="mt-4">
          <PoliciesTab isAdmin={isAdmin} />
        </TabsContent>
        {isAdmin && (
          <TabsContent value="users" className="mt-4">
            <UsersTab />
          </TabsContent>
        )}
      </Tabs>
    </DashboardLayout>
  );
}

function WebhooksTab() {
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setError(null);
    api.settings.webhooks.list().then(setWebhooks).catch((err) => setError(err.message || "Failed to load webhooks")).finally(() => setLoading(false));
  };

  useEffect(load, []);

  const handleCreate = async () => {
    if (!url) return;
    try {
      await api.settings.webhooks.create({ url, events: ["new_finding", "finding_fixed"] });
      setUrl("");
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create webhook");
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await api.settings.webhooks.delete(id);
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to delete webhook");
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Webhooks</CardTitle>
        <CardDescription>Receive notifications when findings are created or fixed</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
            {error}
          </div>
        )}
        <div className="flex gap-2">
          <Input
            placeholder="https://example.com/webhook"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <Button onClick={handleCreate} disabled={!url}>
            <Plus className="mr-1 h-4 w-4" /> Add
          </Button>
        </div>
        {webhooks.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>URL</TableHead>
                <TableHead>Events</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {webhooks.map((wh) => (
                <TableRow key={wh.id}>
                  <TableCell className="max-w-[300px] truncate font-mono text-xs">{wh.url}</TableCell>
                  <TableCell>
                    {wh.events.map((e) => (
                      <Badge key={e} variant="secondary" className="mr-1 text-xs">
                        {e}
                      </Badge>
                    ))}
                  </TableCell>
                  <TableCell>
                    <Badge variant={wh.is_active ? "default" : "secondary"}>
                      {wh.is_active ? "Active" : "Inactive"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="icon" onClick={() => handleDelete(wh.id)}>
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function PoliciesTab({ isAdmin }: { isAdmin: boolean | undefined }) {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [name, setName] = useState("");
  const [action, setAction] = useState("alert");
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setError(null);
    api.settings.policies.list().then(setPolicies).catch((err) => setError(err.message || "Failed to load policies"));
  };

  useEffect(load, []);

  const handleCreate = async () => {
    if (!name) return;
    try {
      await api.settings.policies.create({ name, conditions: {}, action });
      setName("");
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create policy");
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await api.settings.policies.delete(id);
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to delete policy");
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Policies</CardTitle>
        <CardDescription>Define rules that trigger actions on findings</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
            {error}
          </div>
        )}
        {isAdmin && (
          <div className="flex gap-2">
            <Input
              placeholder="Policy name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="flex-1"
            />
            <Select value={action} onValueChange={setAction}>
              <SelectTrigger className="w-[120px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="alert">Alert</SelectItem>
                <SelectItem value="block">Block</SelectItem>
              </SelectContent>
            </Select>
            <Button onClick={handleCreate} disabled={!name}>
              <Plus className="mr-1 h-4 w-4" /> Add
            </Button>
          </div>
        )}
        {policies.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {policies.map((p) => (
                <TableRow key={p.id}>
                  <TableCell>{p.name}</TableCell>
                  <TableCell>
                    <Badge variant={p.action === "block" ? "destructive" : "default"}>
                      {p.action}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={p.is_active ? "default" : "secondary"}>
                      {p.is_active ? "Active" : "Inactive"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {isAdmin && (
                      <Button variant="ghost" size="icon" onClick={() => handleDelete(p.id)}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function UsersTab() {
  const [users, setUsers] = useState<User[]>([]);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("member");
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setError(null);
    api.settings.users.list().then(setUsers).catch((err) => setError(err.message || "Failed to load users"));
  };

  useEffect(load, []);

  const handleCreate = async () => {
    if (!email || !name || !password) return;
    try {
      await api.settings.users.create({ email, password, name, role });
      setEmail("");
      setName("");
      setPassword("");
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to create user");
    }
  };

  const handleDeactivate = async (id: number) => {
    try {
      await api.settings.users.delete(id);
      load();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to deactivate user");
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Users</CardTitle>
        <CardDescription>Manage team members in your organization</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && (
          <div className="rounded-md border border-destructive/50 bg-destructive/10 p-3 text-sm text-destructive">
            {error}
          </div>
        )}
        <div className="flex gap-2">
          <Input placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} className="flex-1" />
          <Input placeholder="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="flex-1" />
          <Input placeholder="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="w-40" />
          <Select value={role} onValueChange={setRole}>
            <SelectTrigger className="w-[120px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="admin">Admin</SelectItem>
              <SelectItem value="member">Member</SelectItem>
              <SelectItem value="viewer">Viewer</SelectItem>
            </SelectContent>
          </Select>
          <Button onClick={handleCreate} disabled={!email || !name || !password}>
            <Plus className="mr-1 h-4 w-4" /> Add
          </Button>
        </div>
        {users.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Email</TableHead>
                <TableHead>Role</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Login</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map((u) => (
                <TableRow key={u.id}>
                  <TableCell>{u.name}</TableCell>
                  <TableCell className="font-mono text-xs">{u.email}</TableCell>
                  <TableCell>
                    <Badge variant={u.role === "admin" ? "default" : "secondary"}>{u.role}</Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={u.is_active ? "default" : "destructive"}>
                      {u.is_active ? "Active" : "Disabled"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {u.last_login ? new Date(u.last_login).toLocaleDateString() : "Never"}
                  </TableCell>
                  <TableCell>
                    {u.is_active && (
                      <Button variant="ghost" size="icon" onClick={() => handleDeactivate(u.id)}>
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
