import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aurora | 0xCrawller Security Intelligence",
  description: "Authorized reconnaissance orchestration, attack-surface intelligence, and evidence dashboard",
};

import { AuthProvider } from "@/lib/auth";

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap"
          rel="stylesheet"
        />
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var t = localStorage.getItem('crawller_theme') || 'dark';
                  document.documentElement.setAttribute('data-theme', t);
                } catch(e) {}
              })();
            `,
          }}
        />
      </head>
      <body>
        <div className="ambient ambient-one" />
        <div className="ambient ambient-two" />
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
