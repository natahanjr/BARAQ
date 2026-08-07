import { useEffect, useState } from "react";
import { api, authStore } from "../api.js";

export default function Login({ onAuthenticated }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [challenge, setChallenge] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sso, setSso] = useState(null);

  useEffect(() => {
    api
      .get("/api/auth/oidc/status")
      .then(setSso)
      .catch(() => setSso(null));
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (challenge) {
        const res = await api.mfaVerify(challenge, code.trim());
        authStore.set(res.token);
        onAuthenticated(res.user);
        return;
      }
      const res = await api.login(username.trim(), password);
      if (res.mfa_required) {
        setChallenge(res.challenge);
        return;
      }
      authStore.set(res.token);
      onAuthenticated(res.user);
    } catch (err) {
      setError(err.message.replace(/^\d+: /, ""));
    } finally {
      setBusy(false);
    }
  };

  const cancelMfa = () => {
    setChallenge("");
    setCode("");
    setError("");
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <svg className="h-16 w-16" viewBox="0 0 64 64">
            <defs>
              <linearGradient id="lgShield" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stopColor="#06b6d4" />
                <stop offset="100%" stopColor="#0e7490" />
              </linearGradient>
            </defs>
            <path
              d="M32 6 L52 12 L52 28 Q52 42 32 52 Q12 42 12 28 L12 12 Z"
              fill="url(#lgShield)"
              opacity="0.9"
            />
            <circle cx="32" cy="28" r="6" fill="none" stroke="#22d3ee" strokeWidth="1.2" opacity="0.7" />
            <path d="M28.5 28 L31 30.5 L35.5 25.5" stroke="#34d399" strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div className="text-center">
            <h1 className="text-2xl font-bold tracking-wide text-white">SentinelSOC</h1>
            <p className="mt-1 text-xs font-semibold uppercase tracking-[0.25em] text-cyan-400">
              Operator Access
            </p>
          </div>
        </div>

        <form
          onSubmit={submit}
          className="space-y-4 rounded-2xl border border-slate-800/70 bg-slate-900/60 p-6 shadow-2xl backdrop-blur"
        >
          {challenge ? (
            <div>
              <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="code">
                Verification code
              </label>
              <input
                id="code"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                autoFocus
                required
                placeholder="6-digit authenticator code"
                className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-center font-mono text-lg tracking-[0.5em] text-slate-100 outline-none transition-colors placeholder:text-sm placeholder:tracking-normal placeholder:text-slate-600 focus:border-cyan-500"
              />
              <p className="mt-2 text-center text-[11px] text-slate-500">
                Password verified for{" "}
                <span className="font-mono text-cyan-400">{username}</span> — enter
                the code from your authenticator app.
              </p>
            </div>
          ) : (
            <>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="username">
                  Username
                </label>
                <input
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                  autoFocus
                  required
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-slate-100 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-500"
                  placeholder="e.g. admin"
                />
              </div>
              <div>
                <label className="mb-1.5 block text-xs font-medium text-slate-400" htmlFor="password">
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  required
                  className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3.5 py-2.5 text-sm text-slate-100 outline-none transition-colors placeholder:text-slate-600 focus:border-cyan-500"
                  placeholder="••••••••"
                />
              </div>
            </>
          )}

          {error && (
            <p className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 px-4 py-2.5 text-sm font-semibold text-white transition-all hover:from-cyan-500 hover:to-cyan-400 disabled:opacity-50"
          >
            {busy ? "Signing in…" : challenge ? "Verify Code" : "Sign In"}
          </button>

          {challenge && (
            <button
              type="button"
              onClick={cancelMfa}
              disabled={busy}
              className="w-full rounded-lg border border-slate-700 px-4 py-2 text-xs font-medium text-slate-400 transition-colors hover:border-slate-500 hover:text-slate-200 disabled:opacity-50"
            >
              ← Back to sign in
            </button>
          )}

          {!challenge && (sso?.oidc || sso?.ldap) && (
            <>
              <div className="flex items-center gap-3">
                <span className="h-px flex-1 bg-slate-800" />
                <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-600">
                  Single sign-on
                </span>
                <span className="h-px flex-1 bg-slate-800" />
              </div>
              {sso?.oidc && (
                <a
                  href="/api/auth/oidc/login"
                  className="block w-full rounded-lg border border-slate-600 bg-slate-800 px-4 py-2.5 text-center text-sm font-semibold text-slate-200 transition-colors hover:border-slate-400 hover:bg-slate-700"
                >
                  Continue with SSO
                </a>
              )}
              {sso?.ldap && !sso?.oidc && (
                <p className="text-center text-[11px] text-slate-500">
                  Directory accounts sign in below with their corporate credentials.
                </p>
              )}
            </>
          )}

          <p className="text-center text-[11px] text-slate-600">
            Default account: <span className="font-mono text-slate-500">admin / sentineladmin</span>
          </p>
        </form>
      </div>
    </div>
  );
}
