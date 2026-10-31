import { create } from 'zustand';
import { persist } from 'zustand/middleware';

const useAuthStore = create(
  persist(
    (set, get) => ({
      token: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,

      login: (token, refreshToken, user) => {
        set({
          token,
          refreshToken,
          user,
          isAuthenticated: true,
        });
        localStorage.setItem('ids_token', token);
        localStorage.setItem('ids_refresh_token', refreshToken);
      },

      logout: () => {
        set({
          token: null,
          refreshToken: null,
          user: null,
          isAuthenticated: false,
        });
        localStorage.removeItem('ids_token');
        localStorage.removeItem('ids_refresh_token');
      },

      updateToken: (token) => {
        set({ token });
        localStorage.setItem('ids_token', token);
      },

      updateUser: (user) => set({ user }),

      getToken: () => get().token,
      getRefreshToken: () => get().refreshToken,
    }),
    {
      name: 'ids-auth-storage',
      partialize: (state) => ({
        token: state.token,
        refreshToken: state.refreshToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);

export default useAuthStore;
