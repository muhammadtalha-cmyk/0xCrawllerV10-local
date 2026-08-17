"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { Header } from "@/components/Header";
import { UserIcon, ShieldIcon, ArrowIcon } from "@/components/Icons";

interface DbUser {
  id: string;
  username: string;
  role: "ADMIN" | "USER";
  created_at: string;
}

export default function AdminPage() {
  const { user, loading } = useAuth();
  const router = useRouter();

  const [users, setUsers] = useState<DbUser[]>([]);
  const [error, setError] = useState("");
  const [fetching, setFetching] = useState(true);
  const [actionUserId, setActionUserId] = useState<string | null>(null);

  const baseUrl = process.env.NEXT_PUBLIC_API_URL || "";

  const fetchUsers = useCallback(async () => {
    if (!user || user.role !== "ADMIN") {
      return;
    }

    setFetching(true);
    setError("");

    try {
      const response = await fetch(
        `${baseUrl}/api/auth/users`,
        {
          method: "GET",
          credentials: "include",
          headers: {
            Accept: "application/json",
          },
        }
      );

      if (response.status === 401) {
        router.push("/login");
        return;
      }

      if (response.status === 403) {
        setError("You do not have administrator permission.");
        return;
      }

      if (!response.ok) {
        throw new Error(
          `Failed to fetch users (${response.status})`
        );
      }

      const data = await response.json();

      if (!Array.isArray(data)) {
        throw new Error("Invalid user list returned by server.");
      }

      setUsers(data);
    } catch (err) {
      console.error("Failed to fetch users:", err);

      setError(
        err instanceof Error
          ? err.message
          : "Failed to fetch users"
      );
    } finally {
      setFetching(false);
    }
  }, [baseUrl, router, user]);

  useEffect(() => {
    if (loading) {
      return;
    }

    if (!user) {
      router.push("/login");
      return;
    }

    if (user.role !== "ADMIN") {
      router.push("/");
      return;
    }

    fetchUsers();
  }, [loading, user, router, fetchUsers]);

  const updateRole = async (
    userId: string,
    newRole: "ADMIN" | "USER"
  ) => {
    if (userId === user?.id) {
      return;
    }

    setActionUserId(userId);
    setError("");

    try {
      const response = await fetch(
        `${baseUrl}/api/auth/users/${userId}/role`,
        {
          method: "POST",
          credentials: "include",
          headers: {
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            role: newRole,
          }),
        }
      );

      if (response.status === 401) {
        router.push("/login");
        return;
      }

      if (response.status === 403) {
        throw new Error(
          "You do not have administrator permission."
        );
      }

      if (!response.ok) {
        throw new Error(
          `Failed to update role (${response.status})`
        );
      }

      await fetchUsers();
    } catch (err) {
      console.error("Failed to update role:", err);

      setError(
        err instanceof Error
          ? err.message
          : "Failed to update role"
      );
    } finally {
      setActionUserId(null);
    }
  };

  const deleteUser = async (userId: string) => {
    if (userId === user?.id) {
      setError("You cannot delete your own administrator account.");
      return;
    }

    const targetUser = users.find(
      (item) => item.id === userId
    );

    const username = targetUser?.username || "this user";

    const confirmed = window.confirm(
      `Are you sure you want to delete "${username}"?`
    );

    if (!confirmed) {
      return;
    }

    setActionUserId(userId);
    setError("");

    try {
      const response = await fetch(
        `${baseUrl}/api/auth/users/${userId}`,
        {
          method: "DELETE",
          credentials: "include",
          headers: {
            Accept: "application/json",
          },
        }
      );

      if (response.status === 401) {
        router.push("/login");
        return;
      }

      if (response.status === 403) {
        throw new Error(
          "You do not have administrator permission."
        );
      }

      if (!response.ok) {
        throw new Error(
          `Failed to delete user (${response.status})`
        );
      }

      await fetchUsers();
    } catch (err) {
      console.error("Failed to delete user:", err);

      setError(
        err instanceof Error
          ? err.message
          : "Failed to delete user"
      );
    } finally {
      setActionUserId(null);
    }
  };

  if (loading || !user || user.role !== "ADMIN") {
    return (
      <main className="shell">
        <Header />
        <div className="empty-state page-loading">
          <div className="loader" />
          Verifying administrator access...
        </div>
      </main>
    );
  }

  const adminCount = users.filter((item) => item.role === "ADMIN").length;

  return (
    <main className="shell">
      <Header />

      <div className="breadcrumb">
        <ArrowIcon style={{ transform: "rotate(180deg)" }} />
        Dashboard / Admin Control
      </div>

      <section className="detail-hero">
        <div>
          <div className="eyebrow">
            <span />
            Admin Control Panel
          </div>

          <h1>User Management</h1>

          <div className="detail-meta">
            <span>
              <ShieldIcon />
              {users.length} users registered
            </span>
            <span>
              <UserIcon />
              {adminCount} administrator{adminCount === 1 ? "" : "s"}
            </span>
          </div>
        </div>
      </section>

      {error && (
        <div className="error-banner" style={{ marginBottom: 16 }}>
          {error}
        </div>
      )}

      <section className="pipeline-card premium-pipeline-card">
        <div className="pipeline-card-head">
          <div>
            <small>Access Control</small>
            <h2>System Users</h2>
          </div>
        </div>

        {fetching ? (
          <div className="empty-state page-loading">
            <div className="loader" />
            Loading users...
          </div>
        ) : users.length === 0 ? (
          <div className="empty-state">
            <UserIcon />
            <h3>No users registered</h3>
          </div>
        ) : (
          <div className="findings-table-wrap admin-users-table">
            <div className="findings-table-scroll">
              <table className="findings-table">
                <thead>
                  <tr>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Created At</th>
                    <th style={{ textAlign: "right" }}>Actions</th>
                  </tr>
                </thead>

                <tbody>
                  {users.map((item) => {
                    const isCurrentUser = item.id === user.id;
                    const isBusy = actionUserId === item.id;

                    return (
                      <tr key={item.id}>
                        <td>
                          <div className="user-cell">
                            <span className="user-avatar-sm">
                              <UserIcon />
                            </span>
                            <span>{item.username}</span>
                            {isCurrentUser && (
                              <span className="you-badge">You</span>
                            )}
                          </div>
                        </td>

                        <td>
                          <select
                            value={item.role}
                            onChange={(event) =>
                              updateRole(
                                item.id,
                                event.target.value as "ADMIN" | "USER"
                              )
                            }
                            disabled={isCurrentUser || isBusy}
                            className="role-select"
                          >
                            <option value="USER">USER</option>
                            <option value="ADMIN">ADMIN</option>
                          </select>
                        </td>

                        <td style={{ color: "var(--muted)" }}>
                          {new Date(item.created_at).toLocaleString()}
                        </td>

                        <td style={{ textAlign: "right" }}>
                          {!isCurrentUser && (
                            <button
                              type="button"
                              onClick={() => deleteUser(item.id)}
                              disabled={isBusy}
                              className="icon-danger-button"
                              title="Delete user"
                            >
                              {isBusy ? (
                                <span style={{ fontSize: 10 }}>...</span>
                              ) : (
                                <svg
                                  viewBox="0 0 24 24"
                                  fill="none"
                                  stroke="currentColor"
                                  strokeWidth="2"
                                >
                                  <path d="M3 6h18" />
                                  <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6" />
                                  <path d="M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                                </svg>
                              )}
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="findings-count">
              {users.length} user{users.length === 1 ? "" : "s"} total
            </div>
          </div>
        )}
      </section>
    </main>
  );
}
