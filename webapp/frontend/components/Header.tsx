"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { GlobeIcon, MoonIcon, PlusIcon, RadarIcon, ShieldIcon, SunIcon, UserIcon } from "./Icons";
import { useAuth } from "@/lib/auth";

export function Header({ target }: { target?: string }) {
  const { user, logout } = useAuth();
  const pathname = usePathname() || "";
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    try {
      const saved = (localStorage.getItem("crawller_theme") as "dark" | "light") ||
        (document.documentElement.getAttribute("data-theme") as "dark" | "light") ||
        "dark";
      setTheme(saved);
      document.documentElement.setAttribute("data-theme", saved);
    } catch {
      // fallback
    }
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === "dark" ? "light" : "dark";
    setTheme(nextTheme);
    try {
      localStorage.setItem("crawller_theme", nextTheme);
      document.documentElement.setAttribute("data-theme", nextTheme);
    } catch {
      // ignore
    }
  };

  return (
    <header className="topbar premium-topbar">
      <Link href="/" className="brand">
        <span className="brand-mark"><RadarIcon /></span>
        <span><strong>0xCRAWLLER</strong><small>SOC Intelligence</small></span>
      </Link>
      
      {user && (
        <nav className="topbar-nav">
          <Link href="/" className={`topbar-nav-link ${pathname === "/" ? "active" : ""}`}>
            Dashboard
          </Link>
          <Link href="/#scans" className={`topbar-nav-link ${pathname.includes("/scans") || pathname === "/#scans" ? "active" : ""}`}>
            Scans
          </Link>
          {user.role === "ADMIN" && (
            <Link href="/admin" className={`topbar-nav-link ${pathname === "/admin" ? "active" : ""}`}>
              Admin Control
            </Link>
          )}
        </nav>
      )}

      <div className="topbar-actions">
        {target && (
          <div className="topbar-target"><GlobeIcon /><span>{target}</span></div>
        )}

        {/* Theme Toggle Button */}
        <button
          type="button"
          onClick={toggleTheme}
          className="theme-toggle-btn"
          title={theme === "dark" ? "Switch to Enterprise Light Mode" : "Switch to Jet Black Dark Mode"}
          aria-label="Toggle theme"
        >
          {mounted && theme === "dark" ? (
            <>
              <SunIcon className="theme-toggle-icon" />
              <span className="theme-toggle-label">Light</span>
            </>
          ) : (
            <>
              <MoonIcon className="theme-toggle-icon" />
              <span className="theme-toggle-label">Dark</span>
            </>
          )}
        </button>

        {user && (
          <>
            <span className="authorized-badge"><ShieldIcon /> Authorized</span>
            <div className="profile-badge">
              <span className="avatar"><UserIcon /></span>
              <span className="username-text">{user.username}</span>
            </div>
            <button onClick={logout} className="logout-button-nav">Logout</button>
            <Link href="/" className="new-scan-link"><PlusIcon /> New Scan</Link>
          </>
        )}
      </div>
    </header>
  );
}
