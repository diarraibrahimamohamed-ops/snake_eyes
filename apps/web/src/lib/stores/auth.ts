import { create } from "zustand";
import { persist } from "zustand/middleware";

interface AuthUser {
  id: string;
  email: string;
  full_name: string;
  role: string;
  organization: string | null;
  organization_name: string | null;
}

interface AuthState {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

// Helper — écrire un cookie accessible par le middleware
function setCookie(name: string, value: string, days = 1) {
  if (typeof document === "undefined") return;
  const expires = new Date();
  expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
  document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/;SameSite=Lax`;
}

function deleteCookie(name: string) {
  if (typeof document === "undefined") return;
  document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/;`;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      isLoading: false,

      login: async (email: string, password: string) => {
        set({ isLoading: true });
        try {
          const { api } = await import("@/lib/api");
          const data = await api.login(email, password);

          // Stocker dans sessionStorage (pour l'API client)
          sessionStorage.setItem("aw_access", data.access);
          sessionStorage.setItem("aw_refresh", data.refresh);

          // Stocker dans cookie (pour le middleware Next.js)
          setCookie("aw_access", data.access, 1);

          set({
            user: data.user,
            isAuthenticated: true,
            isLoading: false,
          });
        } catch (error) {
          set({ isLoading: false });
          throw error;
        }
      },

      logout: () => {
        // Supprimer sessionStorage
        if (typeof window !== "undefined") {
          sessionStorage.removeItem("aw_access");
          sessionStorage.removeItem("aw_refresh");
        }
        // Supprimer cookie
        deleteCookie("aw_access");

        set({ user: null, isAuthenticated: false });

        if (typeof window !== "undefined") {
          window.location.href = "/login";
        }
      },
    }),
    {
      name: "aw-auth",
      partialize: (state) => ({
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);
