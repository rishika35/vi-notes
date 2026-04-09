import React, { createContext, useContext, useState, useEffect } from "react";
import { UserProfile } from "../types";
import { api } from "../lib/api";

interface AuthContextType {
  user: UserProfile | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName: string) => Promise<void>;
  logout: () => Promise<void>;
  error: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.auth.me().then(({ user }) => {
      setUser(user);
      setLoading(false);
    });
  }, []);

  const login = async (email: string, password: string) => {
    setLoading(true);
    setError(null);
    const { user, error } = await api.auth.login(email, password);
    if (error) {
      setError(error);
      setLoading(false);
    } else if (user) {
      setUser(user);
      setLoading(false);
    }
  };

  const register = async (email: string, password: string, displayName: string) => {
    setLoading(true);
    setError(null);
    const { user, error } = await api.auth.register(email, password, displayName);
    if (error) {
      setError(error);
      setLoading(false);
    } else if (user) {
      setUser(user);
      setLoading(false);
    }
  };

  const logout = async () => {
    await api.auth.logout();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, error }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
