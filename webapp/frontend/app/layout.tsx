import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aurora | 0xCrawller Security Intelligence",
  description: "Authorized reconnaissance orchestration, attack-surface intelligence, and evidence dashboard",
};

import { AuthProvider } from "@/lib/auth";

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
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
