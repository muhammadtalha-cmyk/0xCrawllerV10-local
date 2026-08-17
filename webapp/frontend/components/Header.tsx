"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { GlobeIcon, PlusIcon, RadarIcon, ShieldIcon, UserIcon } from "./Icons";
import { useAuth } from "@/lib/auth";

export function Header({ target }: { target?: string }) {
  const { user, logout } = useAuth();
  const pathname = usePathname() || "";

  return (
    <header className="topbar premium-topbar">
      <Link href="/" className="brand">
        <span className="brand-mark"><RadarIcon /></span>
        <span><strong>0xCRAWLLER</strong><small>SOC Intelligence</small></span>
      </Link>
      
      {user && (
        <>
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
          
          <div className="topbar-actions">
            {target && (
              <div className="topbar-target"><GlobeIcon /><span>{target}</span></div>
            )}
            <span className="authorized-badge"><ShieldIcon /> Authorized</span>
            <div className="profile-badge">
              <span className="avatar"><UserIcon /></span>
              <span className="username-text">{user.username}</span>
            </div>
            <button onClick={logout} className="logout-button-nav">Logout</button>
            <Link href="/" className="new-scan-link"><PlusIcon /> New Scan</Link>
          </div>
        </>
      )}
    </header>
  );
}
