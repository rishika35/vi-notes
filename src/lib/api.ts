import { WritingSession, UserProfile } from "../types";

const API_BASE = "/api";

export const api = {
  auth: {
    async me(): Promise<{ user: UserProfile | null }> {
      try {
        const res = await fetch(`${API_BASE}/auth/me`, { credentials: "include" });
        if (!res.ok) return { user: null };
        return await res.json();
      } catch {
        return { user: null };
      }
    },
    async login(email: string, password: string): Promise<{ user?: UserProfile; error?: string }> {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
        credentials: "include",
      });
      const data = await res.json();
      if (!res.ok) return { error: data.error };
      return data;
    },
    async register(email: string, password: string, displayName: string): Promise<{ user?: UserProfile; error?: string }> {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, displayName }),
        credentials: "include",
      });
      const data = await res.json();
      if (!res.ok) return { error: data.error };
      return data;
    },
    async logout(): Promise<void> {
      await fetch(`${API_BASE}/auth/logout`, { method: "POST", credentials: "include" });
    },
  },
  sessions: {
    async list(): Promise<WritingSession[]> {
      const res = await fetch(`${API_BASE}/sessions`, { credentials: "include" });
      if (!res.ok) return [];
      return await res.json();
    },
    async get(id: string): Promise<WritingSession | null> {
      const res = await fetch(`${API_BASE}/sessions/${id}`, { credentials: "include" });
      if (!res.ok) return null;
      return await res.json();
    },
    async save(session: Partial<WritingSession>): Promise<WritingSession> {
      const res = await fetch(`${API_BASE}/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(session),
        credentials: "include",
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || "Failed to save session");
      }
      return await res.json();
    },
    async update(id: string, updates: { title: string }): Promise<WritingSession> {
      const res = await fetch(`${API_BASE}/sessions/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(updates),
        credentials: "include",
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || "Failed to update session");
      }
      return await res.json();
    },
    async delete(id: string): Promise<void> {
      const res = await fetch(`${API_BASE}/sessions/${id}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || "Failed to delete session");
      }
    },
  },
};
