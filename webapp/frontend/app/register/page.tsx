"use client";

import { FormEvent, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { RadarIcon, ShieldIcon, DatabaseIcon, ActivityIcon } from "@/components/Icons";

export default function RegisterPage() {
  const router = useRouter();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleRegister(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    setError("");
    setSuccess("");

    const cleanUsername = username.trim();

    if (cleanUsername.length < 3) {
      setError("Username must contain at least 3 characters.");
      return;
    }

    if (password.length < 8) {
      setError("Password must contain at least 8 characters.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setIsSubmitting(true);

    try {
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || "";

      const response = await fetch(`${baseUrl}/api/auth/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        credentials: "include",
        body: JSON.stringify({
          username: cleanUsername,
          password,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.detail || "Unable to create your account");
      }

      setSuccess("Account created successfully. Redirecting to login...");

      setTimeout(() => {
        router.replace("/login");
      }, 900);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Unable to create your account");
    } finally {
      setIsSubmitting(false);
    }
  }

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
            <h2>Create Account</h2>
            <p>Register a new operator profile</p>
          </div>

          <form onSubmit={handleRegister} className="space-y-4">
            {error && (
              <div className="error-banner mb-4">
                {error}
              </div>
            )}

            {success && (
              <div className="success-banner mb-4">
                {success}
              </div>
            )}

            <div className="auth-input-group">
              <label className="auth-label">Username</label>
              <input
                type="text"
                required
                minLength={3}
                maxLength={100}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="auth-input"
                placeholder="Choose operator name"
                autoComplete="username"
              />
            </div>

            <div className="auth-input-group">
              <label className="auth-label">Password</label>
              <input
                type="password"
                required
                minLength={8}
                maxLength={200}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="auth-input"
                placeholder="At least 8 characters"
                autoComplete="new-password"
              />
            </div>

            <div className="auth-input-group">
              <label className="auth-label">Confirm Password</label>
              <input
                type="password"
                required
                minLength={8}
                maxLength={200}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="auth-input"
                placeholder="Confirm password"
                autoComplete="new-password"
              />
            </div>

            <button type="submit" disabled={isSubmitting} className="auth-btn">
              {isSubmitting ? "Creating Profile..." : "Register Operator"}
            </button>
          </form>

          <p className="auth-link-hint">
            Already have an account?{" "}
            <Link href="/login" className="auth-link">
              Sign In
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}