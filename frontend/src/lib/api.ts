// The website's link to the API (backend/). It always calls its own address (/api):
// in development Vite passes that on to the local API (vite.config.ts); live, the host
// does. Sign-in lives in HttpOnly cookies the browser sends itself — no token is ever
// readable by page scripts or kept in localStorage.

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function call<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  let res: Response
  try {
    const init: RequestInit = { method, credentials: 'same-origin' }
    if (body !== undefined) {
      init.headers = { 'Content-Type': 'application/json' }
      init.body = JSON.stringify(body)
    }
    res = await fetch(`/api${path}`, init)
  } catch {
    throw new ApiError('We can’t reach the server. Check your connection and try again.', 0)
  }
  const json = (res.headers.get('Content-Type') ?? '').includes('application/json')
  if (!json) {
    throw new ApiError(
      res.status >= 500 || res.status === 404
        ? 'The server isn’t answering right now. Please try again in a minute.'
        : `Something went wrong (${res.status}).`,
      res.status,
    )
  }
  const data = await res.json()
  if (!res.ok) throw new ApiError((data?.message as string) || `Something went wrong (${res.status}).`, res.status)
  return data as T
}

const post = <T>(path: string, body: unknown) => call<T>('POST', path, body)
const get = <T>(path: string) => call<T>('GET', path)

export interface Me {
  email: string
  name: string | null
  memberSince: string
  role: 'customer' | 'admin'
  adminSession: boolean
}

export interface SessionInfo {
  id: string
  /** e.g. "Chrome on Windows" */
  device: string
  signedInAt: string
  lastActiveAt: string
  admin: boolean
  current: boolean
}

export type LinkResult =
  | { status: 'signedIn'; user: { email: string; role: string } }
  | { status: 'showCode'; code: string; requestedFrom: string; requestedAt: string }

export type Interest = 'life' | 'critical_illness' | 'disability' | 'not_sure'

export interface NewRequest {
  name: string
  email: string
  phone: string
  province: string
  interests: Interest[]
  contactBy: 'email' | 'phone'
  bestTime: 'morning' | 'afternoon' | 'evening' | 'any'
  message: string
  consent: boolean
  consentVersion: string
  /** The hidden field bots fill in. Always empty from a real person. */
  website: string
}

export interface MyRequest {
  id: string
  createdAt: string
  interests: Interest[]
  province: string
  contactBy: 'email' | 'phone'
  status: 'new' | 'contacted' | 'closed'
}

export const accountsApi = {
  me: () => get<Me>('/auth/me'),
  /** Emails a sign-in link. The same reply for every address. */
  startEmail: (email: string) => post<{ status: 'sent' }>('/auth/email/start', { email }),
  /** The emailed link's page: same browser → signed in; elsewhere → the code + who asked. */
  openLink: (token: string) => post<LinkResult>('/auth/email/link', { token }),
  /** "This wasn't me". */
  denyLink: (token: string) => post<{ status: 'cancelled' }>('/auth/email/deny', { token }),
  verifyCode: (email: string, code: string) => post<{ status: 'signedIn' }>('/auth/email/verify', { email, code }),
  signOut: () => post<{ status: 'signedOut' }>('/auth/sign-out', {}),
  signOutEverywhere: () =>
    post<{ sessionsEnded: number; devicesForgotten: number }>('/auth/sign-out-everywhere', {}),
  updateProfile: (name: string) => post<{ status: 'saved'; name: string | null }>('/auth/profile', { name }),
  sessions: () => get<SessionInfo[]>('/auth/sessions'),
  signOutSession: (id: string) =>
    post<{ status: 'signedOut' }>(`/auth/sessions/${encodeURIComponent(id)}/sign-out`, {}),
  deleteAccount: (confirmEmail: string) => post<{ status: 'deleted' }>('/auth/delete-account', { confirmEmail }),
}

export const requestsApi = {
  send: (request: NewRequest) => post<{ status: 'received' }>('/requests', request),
  mine: () => get<MyRequest[]>('/requests/mine'),
}

export function problem(e: unknown): string {
  return e instanceof Error ? e.message : 'Something went wrong. Please try again.'
}
