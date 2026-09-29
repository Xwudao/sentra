import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface AuthState {
  token: string
  setToken: (token: string) => void
  clear: () => void
}

export const useAuth = create<AuthState>()(
  persist(
    (set) => ({
      token: '',
      setToken: (token) => set({ token }),
      clear: () => set({ token: '' }),
    }),
    { name: 'sentra.auth' },
  ),
)

interface ThemeState {
  theme: 'dark' | 'light'
  toggle: () => void
}

function applyTheme(theme: 'dark' | 'light') {
  document.documentElement.dataset.theme = theme
}

const initialTheme: 'dark' | 'light' =
  (typeof localStorage !== 'undefined' && (localStorage.getItem('sentra.theme') as 'dark' | 'light')) ||
  'dark'
applyTheme(initialTheme)

export const useTheme = create<ThemeState>((set, get) => ({
  theme: initialTheme,
  toggle: () => {
    const next = get().theme === 'dark' ? 'light' : 'dark'
    localStorage.setItem('sentra.theme', next)
    applyTheme(next)
    set({ theme: next })
  },
}))
