// The admin dashboard's signed-in state, shared by its pages.

import { createContext, useContext } from 'react'

export type Session = { state: 'checking' } | { state: 'signedOut' } | { state: 'signedIn'; email: string }

export const SessionContext = createContext<{ session: Session; refresh: () => Promise<void> } | null>(null)

export function useAdminSession() {
  const ctx = useContext(SessionContext)
  if (!ctx) throw new Error('inside AdminApp only')
  return ctx
}
