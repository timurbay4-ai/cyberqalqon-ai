import { useState, type FormEvent } from "react";

import { BrandMark } from "./brand-mark";
import type { LoginCredentials } from "../types/auth";

interface LoginPageProps {
  busy: boolean;
  checking: boolean;
  error: string | null;
  onLogin(credentials: LoginCredentials): Promise<void>;
  onRetry(): void;
}

export function LoginPage({ busy, checking, error, onLogin, onRetry }: LoginPageProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void onLogin({ username, password }).finally(() => setPassword(""));
  };
  return (
    <main className="login-shell">
      <section className="login-card" aria-labelledby="login-title">
        <div className="login-brand"><BrandMark /><div><strong>CyberQalqon</strong><span>Security Operations</span></div></div>
        <span className="eyebrow">Protected analyst workspace</span>
        <h1 id="login-title">Analyst sign in</h1>
        <p>The dashboard remains locked until the backend validates a human analyst session.</p>
        {checking ? <div className="login-checking" role="status"><span className="spinner" />Validating existing session…</div> : (
          <form className="login-form" onSubmit={submit}>
            <label className="field"><span>Username</span><input autoComplete="username" required minLength={3} maxLength={64} value={username} onChange={(event) => setUsername(event.target.value)} /></label>
            <label className="field"><span>Password</span><input autoComplete="current-password" required type="password" maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} /></label>
            {error && <p className="form-message form-message--error" role="alert">{error}</p>}
            <button className="button button--primary" disabled={busy} type="submit">{busy ? "Signing in…" : "Sign in"}</button>
            {error?.includes("unavailable") && <button className="button button--ghost" disabled={busy} type="button" onClick={onRetry}>Retry backend</button>}
          </form>
        )}
      </section>
    </main>
  );
}
