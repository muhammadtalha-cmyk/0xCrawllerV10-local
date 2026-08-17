"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "@/lib/auth";
import { RadarIcon, ShieldIcon, DatabaseIcon, ActivityIcon } from "@/components/Icons";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const router = useRouter();
  const { setUser } = useAuth();

  const handleLogin = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setIsSubmitting(true);
    setError("");

    try {
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || "";

      const res = await fetch(`${baseUrl}/api/auth/login`, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      if (!res.ok) {
        let message = "Invalid username or password";

        try {
          const body = await res.json();
          if (typeof body?.detail === "string") {
            message = body.detail;
          }
        } catch {
          // Keep default.
        }
        throw new Error(message);
      }

      const data = await res.json();
      setUser(data.user);
      router.push("/");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to sign in");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="auth-page">
      {/* Left branding panel */}
      <div className="auth-branding-panel">
        <div className="auth-brand">
          <span className="auth-brand-logo">
            <RadarIcon />
          </span>
          <strong>0xCRAWLLER</strong>
        </div>

        <div className="auth-branding-content">
          <h1>
            Advanced <span>Reconnaissance</span> &amp; Attack Surface Intelligence
          </h1>
          <p>
            An enterprise-grade cyber reconnaissance orchestration platform. Map your attack surface, scan for security vulnerabilities, and generate consolidated intelligence reports in real-time.
          </p>

          <div className="auth-feature-list">
            <div className="auth-feature-item">
              <ShieldIcon />
              <div>
                <strong>SOC Operations Ready</strong>
                <span>Continuous security posture assessment and discovery logging.</span>
              </div>
            </div>

            <div className="auth-feature-item">
              <DatabaseIcon />
              <div>
                <strong>Normalized Asset Inventories</strong>
                <span>Automatic deduplication, technology stacking, and DNS mapping.</span>
              </div>
            </div>

            <div className="auth-feature-item">
              <ActivityIcon />
              <div>
                <strong>WebSocket Orchestration</strong>
                <span>Track multi-stage active scans in real-time with zero packet loss.</span>
              </div>
            </div>
          </div>
        </div>

        <div className="auth-branding-footer">
          &copy; 2026 0xCrawller Security Inc. All rights reserved.
        </div>
      </div>

      {/* Right form panel */}
      <div className="auth-card-panel">
        <div className="auth-card">
          <div className="auth-card-header">
            <h2>Authentication Portal</h2>
            <p>Access your cybersecurity control panel</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            {error && (
              <div className="error-banner mb-4">
                {error}
              </div>
            )}

            <div className="auth-input-group">
              <label className="auth-label">Username</label>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="auth-input"
                placeholder="Enter username"
                autoComplete="username"
              />
            </div>

            <div className="auth-input-group">
              <label className="auth-label">Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="auth-input"
                placeholder="Enter password"
                autoComplete="current-password"
              />
            </div>

            <button type="submit" disabled={isSubmitting} className="auth-btn">
              {isSubmitting ? "Verifying Credentials..." : "Authenticate"}
            </button>
          </form>

          <p className="auth-link-hint">
            Don't have an account?{" "}
            <Link href="/register" className="auth-link">
              Create Account
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}