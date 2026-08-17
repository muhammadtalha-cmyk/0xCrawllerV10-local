import type { SVGProps } from "react";

function Base({ children, ...props }: SVGProps<SVGSVGElement>) {
  return <svg viewBox="0 0 48 48" fill="none" aria-hidden="true" {...props}>{children}</svg>;
}

export function TechnologyLogo({ name }: { name: string }) {
  const key = name.toLowerCase();

  if (key.includes("cloudflare")) {
    return <Base className="tech-logo-svg"><path d="M15 32h22c4.2 0 7-2.2 7-5.7 0-3-2.2-5.2-5.5-5.6C37.7 14.5 32.9 10 27 10c-5.1 0-9.5 3.3-11 8-5.7.2-10 3.7-10 8.2C6 29.7 9.4 32 15 32Z" fill="currentColor" opacity=".95"/><path d="M5 36h29" stroke="currentColor" strokeWidth="3" strokeLinecap="round" opacity=".55"/></Base>;
  }
  if (key.includes("react")) {
    return <Base className="tech-logo-svg"><circle cx="24" cy="24" r="3.2" fill="currentColor"/><ellipse cx="24" cy="24" rx="19" ry="7.5" stroke="currentColor" strokeWidth="2.2"/><ellipse cx="24" cy="24" rx="19" ry="7.5" stroke="currentColor" strokeWidth="2.2" transform="rotate(60 24 24)"/><ellipse cx="24" cy="24" rx="19" ry="7.5" stroke="currentColor" strokeWidth="2.2" transform="rotate(120 24 24)"/></Base>;
  }
  if (key.includes("wordpress")) {
    return <Base className="tech-logo-svg"><circle cx="24" cy="24" r="19" stroke="currentColor" strokeWidth="3"/><path d="M12.5 16h8m-5.5 0 7 19 5.4-14.6M25 16h7.5m-3.4 0 6.2 19" stroke="currentColor" strokeWidth="2.8" strokeLinecap="round" strokeLinejoin="round"/></Base>;
  }
  if (key.includes("nginx")) {
    return <Base className="tech-logo-svg"><path d="m24 4 17 10v20L24 44 7 34V14L24 4Z" fill="currentColor" opacity=".9"/><path d="M16 33V15l16 18V15" stroke="var(--panel-deep, #07101d)" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round"/></Base>;
  }
  if (key.includes("node")) {
    return <Base className="tech-logo-svg"><path d="m24 4 17 10v20L24 44 7 34V14L24 4Z" stroke="currentColor" strokeWidth="2.8"/><path d="M16 32V16l16 16V16" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/></Base>;
  }
  if (key.includes("python")) {
    return <Base className="tech-logo-svg"><path d="M24 5c-9 0-9 4-9 9v4h15v3H10c-5 0-7 4-7 9s2 9 7 9h4v-6c0-5 4-8 9-8h8c4 0 7-3 7-7v-5c0-5-4-8-14-8Z" fill="currentColor" opacity=".95"/><circle cx="21" cy="11" r="1.8" fill="var(--panel-deep, #07101d)"/><path d="M24 43c9 0 9-4 9-9v-4H18v-3h20c5 0 7-4 7-9s-2-9-7-9h-4v6c0 5-4 8-9 8h-8c-4 0-7 3-7 7v5c0 5 4 8 14 8Z" fill="currentColor" opacity=".55"/><circle cx="27" cy="37" r="1.8" fill="var(--panel-deep, #07101d)"/></Base>;
  }
  if (key.includes("php")) {
    return <Base className="tech-logo-svg"><ellipse cx="24" cy="24" rx="21" ry="12" fill="currentColor" opacity=".8"/><text x="24" y="29" textAnchor="middle" fontSize="13" fontWeight="800" fill="var(--panel-deep, #07101d)">php</text></Base>;
  }
  if (key.includes("postgres")) {
    return <Base className="tech-logo-svg"><path d="M35 9c-4-4-17-4-22 1-5 5-3 16 1 20 2 2 5 1 7-1l2 8c1 5 7 5 9 1 1-3-1-7-1-11 6 0 10-4 10-10 0-4-2-6-6-8Z" stroke="currentColor" strokeWidth="2.5" strokeLinejoin="round"/><path d="M22 18c2-2 5-2 7 0m-7 0c1 4 1 7 1 11m6-11c1 4 1 6 2 9" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round"/><circle cx="18" cy="15" r="1.5" fill="currentColor"/></Base>;
  }
  if (key.includes("mysql") || key.includes("maria")) {
    return <Base className="tech-logo-svg"><path d="M8 31c8-12 15-17 29-15-8 1-11 5-10 11 7-1 11 2 13 8-8-5-15-5-21 1-4 4-9 2-11-5Z" fill="currentColor" opacity=".9"/><circle cx="32" cy="18" r="1.5" fill="var(--panel-deep, #07101d)"/></Base>;
  }
  if (key.includes("aws") || key.includes("amazon")) {
    return <Base className="tech-logo-svg"><text x="24" y="25" textAnchor="middle" fontSize="14" fontWeight="800" fill="currentColor">aws</text><path d="M10 31c8 5 19 6 29 0" stroke="currentColor" strokeWidth="3" strokeLinecap="round"/><path d="m35 29 5 2-3 4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></Base>;
  }
  if (key.includes("azure")) {
    return <Base className="tech-logo-svg"><path d="M20 5 7 31h12l5 12 17-4-9-34H20Zm3 10 6 17-12-2 6-15Z" fill="currentColor"/></Base>;
  }
  if (key.includes("angular")) {
    return <Base className="tech-logo-svg"><path d="m24 4 18 7-3 25-15 8-15-8-3-25 18-7Z" fill="currentColor" opacity=".9"/><path d="m24 11-9 22h5l2-6h5l2 6h5l-10-22Zm0 7 2 5h-4l2-5Z" fill="var(--panel-deep, #07101d)"/></Base>;
  }
  if (key.includes("vue")) {
    return <Base className="tech-logo-svg"><path d="M4 8h10l10 17L34 8h10L24 42 4 8Z" fill="currentColor"/><path d="M12 8h7l5 9 5-9h7L24 29 12 8Z" fill="var(--panel-deep, #07101d)" opacity=".75"/></Base>;
  }
  if (key.includes("next")) {
    return <Base className="tech-logo-svg"><circle cx="24" cy="24" r="20" fill="currentColor"/><path d="M14 34V14l21 25M31 14v13" stroke="var(--panel-deep, #07101d)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"/></Base>;
  }
  if (key.includes("apache")) {
    return <Base className="tech-logo-svg"><path d="M33 4C24 10 16 22 11 42c5-7 10-11 16-13l-5-2 8-3-5-2 8-4-4-2c3-4 5-8 4-12Z" fill="currentColor"/></Base>;
  }

  const initials = name.split(/\s+|\//).filter(Boolean).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("") || "?";
  return <span className="tech-logo-fallback" aria-hidden="true">{initials}</span>;
}
