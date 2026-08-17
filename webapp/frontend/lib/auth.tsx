"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "react";

interface User {
  id: string;
  username: string;
  role: string;
}

interface AuthContextType {
  user: User | null;
  setUser: (user: User | null) => void;
  logout: () => void;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(
  undefined
);

const LOGGED_OUT_KEY = "logged_out";

export function AuthProvider({
  children,
}: {
  children: React.ReactNode;
}) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Prevents overlapping verification calls from racing each other
  // (e.g. mount + pageshow firing in quick succession).
  const verifyingRef = useRef(false);

  const handleSetUser = (u: User | null) => {
    if (typeof window !== "undefined") {
      if (u) {
        localStorage.removeItem(LOGGED_OUT_KEY);
      }
    }
    setUser(u);
  };

  // Single source of truth for "am I actually authenticated". Always
  // asks the server rather than trusting whatever is currently sitting
  // in memory, so it's safe to call again any time the page might be
  // showing stale state (initial mount, restored from bfcache, tab
  // refocused, etc).
  const verifySession = useCallback(async () => {
    if (verifyingRef.current) {
      return;
    }
    verifyingRef.current = true;

    if (
      typeof window !== "undefined" &&
      localStorage.getItem(LOGGED_OUT_KEY) === "true"
    ) {
      setUser(null);
      setLoading(false);
      verifyingRef.current = false;
      return;
    }

    try {
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || "";

      const res = await fetch(`${baseUrl}/api/auth/me`, {
        method: "GET",
        credentials: "include",
        cache: "no-store",
        headers: {
          Accept: "application/json",
        },
      });

      if (res.ok) {
        const data = await res.json();
        setUser(data);
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error(
        "Failed to fetch authenticated user:",
        error
      );
      setUser(null);
    } finally {
      setLoading(false);
      verifyingRef.current = false;
    }
  }, []);

  useEffect(() => {
    verifySession();
  }, [verifySession]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    // Fired when a page is restored from the browser's back/forward
    // cache. In that case React never remounts and the initial-mount
    // effect above never reruns, so without this the UI could keep
    // showing whatever auth state existed the instant before the user
    // navigated away (e.g. an admin session that has since been logged
    // out). Force a fresh server-verified check whenever that happens.
    const handlePageShow = (event: PageTransitionEvent) => {
      if (event.persisted) {
        setLoading(true);
        verifySession();
      }
    };

    // Fired when another tab changes the logged_out flag (e.g. the
    // user logs out in one tab while this one is still open). Keeps
    // every open tab's nav/protected routes in sync.
    const handleStorage = (event: StorageEvent) => {
      if (event.key === LOGGED_OUT_KEY && event.newValue === "true") {
        setUser(null);
      }
    };

    window.addEventListener("pageshow", handlePageShow);
    window.addEventListener("storage", handleStorage);

    return () => {
      window.removeEventListener("pageshow", handlePageShow);
      window.removeEventListener("storage", handleStorage);
    };
  }, [verifySession]);

  const logout = async () => {
    if (typeof window !== "undefined") {
      localStorage.setItem(LOGGED_OUT_KEY, "true");
    }

    // Clear local state immediately so any component watching `user`
    // (nav links, protected-route guards) reacts before the network
    // call even resolves.
    setUser(null);

    try {
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || "";

      await fetch(`${baseUrl}/api/auth/logout`, {
        method: "POST",
        credentials: "include",
      });
    } catch (error) {
      console.error("Logout failed:", error);
    }

    if (typeof window !== "undefined") {
      // Full document navigation, not client-side routing: this
      // guarantees every in-memory cache in the app (not just auth
      // state) is thrown away, and it starts the next page with a
      // clean mount rather than a bfcache-eligible frozen one.
      window.location.href = "/login";
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        setUser: handleSetUser,
        logout,
        loading,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error(
      "useAuth must be used within an AuthProvider"
    );
  }

  return context;
}
