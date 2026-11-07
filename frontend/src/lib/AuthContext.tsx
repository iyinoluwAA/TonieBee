import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { accountsApi, ApiError, type Me } from './api'

// Who's signed in. The session itself is an HttpOnly cookie set by the API; this only
// asks the API (`/api/auth/me`) and remembers the answer.
//   offline — the API didn't answer (accounts are unavailable, the rest of the site works)
type Status = 'loading' | 'offline' | 'signedOut' | 'signedIn'

interface AuthState {
  status: Status
  user: Me | null
  /** Re-asks the API; never shows a loading state, so it's safe to poll. */
  refresh: () => Promise<void>
  signOut: () => Promise<void>
  signOutEverywhere: () => Promise<void>
  /** After the account is deleted (the API already signed this browser out). */
  accountDeleted: () => void
  /** What just happened (signed out, deleted…), shown on the sign-in form so it never
   *  happens silently. */
  notice: string | null
  clearNotice: () => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null)
  const [status, setStatus] = useState<Status>('loading')
  const [notice, setNotice] = useState<string | null>(null)
  const clearNotice = useCallback(() => setNotice(null), [])

  const refresh = useCallback(async () => {
    try {
      setUser(await accountsApi.me())
      setStatus('signedIn')
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setUser(null)
        setStatus('signedOut')
      } else {
        // Unreachable on first load → say so; a blip later keeps what we knew.
        setStatus((current) => (current === 'loading' ? 'offline' : current))
      }
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const signedOut = useCallback((message: string) => {
    setNotice(message)
    setUser(null)
    setStatus('signedOut')
  }, [])

  const signOut = useCallback(async () => {
    await accountsApi.signOut()
    signedOut('You’re signed out on this device.')
  }, [signedOut])

  const signOutEverywhere = useCallback(async () => {
    const { sessionsEnded: s } = await accountsApi.signOutEverywhere()
    signedOut(`You’re signed out everywhere (${s} ${s === 1 ? 'device' : 'devices'}).`)
  }, [signedOut])

  const accountDeleted = useCallback(() => signedOut('Your account has been deleted.'), [signedOut])

  const value = useMemo<AuthState>(
    () => ({ status, user, refresh, signOut, signOutEverywhere, accountDeleted, notice, clearNotice }),
    [status, user, refresh, signOut, signOutEverywhere, accountDeleted, notice, clearNotice],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
