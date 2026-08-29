import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { api, authStore } from "../api.js";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => authStore.user || null);
  const [org, setOrgState] = useState(() => {
    try { return localStorage.getItem("baraq-org") || ""; } catch { return ""; }
  });

  // Restore session from httpOnly cookie on mount
  useEffect(() => {
    if (authStore.user) return;
    api.me().then((res) => {
      if (res?.user) {
        authStore.user = res.user;
        setUser(res.user);
      }
    }).catch(() => {});
  }, []);

  const login = useCallback((loginResult) => {
    if (loginResult?.token) {
      authStore.set(loginResult.token);
    }
    if (loginResult?.user) {
      authStore.user = loginResult.user;
    }
    setUser(authStore.user || loginResult?.user || null);
  }, []);

  const logout = useCallback(() => {
    api.logout();
    setUser(null);
  }, []);

  const setOrg = useCallback((o) => {
    setOrgState(o);
    try { localStorage.setItem("baraq-org", o); } catch {}
    api.setOrg?.(o);
  }, []);

  const refreshUser = useCallback(() => {
    setUser(authStore.user ? { ...authStore.user } : null);
  }, []);

  const isAdmin = user?.role === "admin";

  const hasRole = useCallback((role) => {
    if (!user) return false;
    if (user.role === "admin") return true;
    return user.role === role;
  }, [user]);

  const value = useMemo(() => ({
    user,
    org,
    login,
    logout,
    setOrg,
    refreshUser,
    isAdmin,
    hasRole,
    isAuthenticated: !!user,
    mfaEnabled: user?.mfa_enabled || false,
  }), [user, org, login, logout, setOrg, refreshUser, isAdmin, hasRole]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
