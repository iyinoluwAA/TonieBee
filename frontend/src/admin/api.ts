// The admin dashboard's link to the API (backend/src/modules). It always calls the
// website's own address (/api), so the sign-in cookies are first-party; in development
// Vite passes /api on to the local API (vite.config.ts). The session lives in an
// HttpOnly cookie — nothing readable is ever stored here.

export class AdminApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'AdminApiError'
    this.status = status
  }
}

/** A sleeping server (free hosting) can take a minute to answer the first request. */
export type WakeListener = (waking: boolean) => void
let onWake: WakeListener = () => {}
export function listenForWake(listener: WakeListener) {
  onWake = listener
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

async function call<T>(method: string, path: string, body?: unknown, sameIfRepeated = method === 'GET'): Promise<T> {
  // Only reads (and requests that change nothing when repeated) are retried while the
  // server wakes: a save is never sent twice.
  const attempts = sameIfRepeated ? 6 : 1
  for (let attempt = 1; ; attempt++) {
    let res: Response
    try {
      res = await fetch(`/api${path}`, {
        method,
        credentials: 'same-origin',
        headers: body !== undefined ? { 'Content-Type': 'application/json' } : undefined,
        body: body !== undefined ? JSON.stringify(body) : undefined,
      })
    } catch {
      res = new Response(null, { status: 599 }) // offline / unreachable
    }
    const json = (res.headers.get('Content-Type') ?? '').includes('application/json')
    const waking = [502, 503, 504, 599].includes(res.status) && !json
    if (waking && attempt < attempts) {
      onWake(true)
      await sleep(Math.min(4000 * attempt, 15000))
      continue
    }
    onWake(false)
    if (!json) {
      throw new AdminApiError(
        waking
          ? 'The server isn’t answering. Check your connection and try again in a minute.'
          : 'The dashboard can’t reach the server yet.',
        res.status,
      )
    }
    const data = await res.json()
    if (!res.ok) throw new AdminApiError((data?.message as string) || `Request failed (${res.status})`, res.status)
    return data as T
  }
}

/** "Confirm it's you": the password and a code (authenticator or backup code). */
export interface Confirm {
  password: string
  code: string
}

export interface AuthenticatorSetup {
  key: string
  otpauthUrl: string
  qrSvg: string
}

export interface InviteOpened {
  email: string
  invitedBy: string | null
  expiresAt: string
  passwordMinLength: number
  authenticator: AuthenticatorSetup
}

export interface Team {
  admins: { email: string; lastSignInAt: string | null; you: boolean }[]
  invites: { id: string; email: string; invitedBy: string | null; createdAt: string; expiresAt: string }[]
}

/** Activity's two lists: who looked at or changed requests, or sign-ins and admin accounts. */
export type ActivityKind = 'requests' | 'security'

export interface ActivityEntry {
  id: number
  at: string
  who: string | null
  action: string
  detail: Record<string, unknown>
  ip: string | null
}

export type RequestStatus = 'new' | 'contacted' | 'closed'
export type Interest = 'life' | 'critical_illness' | 'disability' | 'not_sure'

export interface RequestRow {
  id: string
  name: string
  province: string
  interests: Interest[]
  contactBy: 'email' | 'phone'
  bestTime: 'morning' | 'afternoon' | 'evening' | 'any'
  status: RequestStatus
  hasMessage: boolean
  createdAt: string
}

export interface RequestPage {
  requests: RequestRow[]
  nextCursor: string | null
  counts: Record<RequestStatus, number>
}

export interface RequestDetail extends Omit<RequestRow, 'hasMessage'> {
  email: string
  phone: string | null
  message: string | null
  consentVersion: string
  consentAt: string
  adminNotes: string | null
  version: number
  signedIn: boolean
  updatedAt: string
  closedAt: string | null
}

export interface Overview {
  requests: { new: number; contacted: number; last7Days: number }
  clientAccounts: number
  email: 'on' | 'off'
}

export type RequestFilter = 'open' | RequestStatus | 'all'

const id = (value: string) => encodeURIComponent(value)

export const adminApi = {
  me: () => call<{ email: string; role: string }>('GET', '/admin/me'),
  password: (email: string, password: string) =>
    call<{ status: 'codeRequired' }>('POST', '/admin/auth/password', { email, password }),
  code: (code: string) =>
    call<{ status: 'signedIn'; backupCodesLeft: number | null }>('POST', '/admin/auth/code', { code }),
  signOut: () => call<unknown>('POST', '/auth/sign-out', {}),

  overview: () => call<Overview>('GET', '/admin/overview'),
  requests: (filter: RequestFilter, before?: string) =>
    call<RequestPage>(
      'GET',
      `/admin/requests?status=${filter}${before ? `&before=${encodeURIComponent(before)}` : ''}`,
    ),
  request: (requestId: string) => call<RequestDetail>('GET', `/admin/requests/${id(requestId)}`),
  updateRequest: (requestId: string, change: { version: number; status?: RequestStatus; notes?: string }) =>
    call<RequestDetail>('PATCH', `/admin/requests/${id(requestId)}`, change),
  deleteRequest: (requestId: string, version: number) =>
    call<{ status: 'deleted' }>('DELETE', `/admin/requests/${id(requestId)}?version=${version}`),

  activity: (kind: ActivityKind, before?: number) =>
    call<ActivityEntry[]>('GET', `/admin/activity?kind=${kind}${before ? `&before=${before}` : ''}`),

  account: () =>
    call<{ email: string; backupCodesLeft: number; lastSignInAt: string | null }>('GET', '/admin/account'),
  changePassword: (confirm: Confirm, newPassword: string) =>
    call<{ otherSessionsEnded: number }>('POST', '/admin/account/password', { ...confirm, newPassword }),
  startNewPhone: (confirm: Confirm) => call<AuthenticatorSetup>('POST', '/admin/account/new-phone', confirm),
  finishNewPhone: (code: string) =>
    call<{ otherSessionsEnded: number }>('POST', '/admin/account/new-phone/finish', { code }),
  newBackupCodes: (confirm: Confirm) =>
    call<{ backupCodes: string[] }>('POST', '/admin/account/backup-codes', confirm),

  team: () => call<Team>('GET', '/admin/admins'),
  invite: (email: string, confirm: Confirm) =>
    call<{ id: string; email: string; status: 'sent'; expiresAt: string }>('POST', '/admin/invites', {
      email,
      ...confirm,
    }),
  cancelInvite: (inviteId: string) => call<unknown>('POST', `/admin/invites/${id(inviteId)}/cancel`, {}),
  // Opening the link only shows it (the same key every time), so it can be retried.
  openInvite: (token: string) => call<InviteOpened>('POST', '/admin/invite/open', { token }, true),
  acceptInvite: (token: string, password: string, code: string) =>
    call<{ status: 'signedIn'; email: string; backupCodes: string[] }>('POST', '/admin/invite/accept', {
      token,
      password,
      code,
    }),
}

export const INTEREST_NAMES: Record<Interest, string> = {
  life: 'Life insurance',
  critical_illness: 'Critical illness',
  disability: 'Disability',
  not_sure: 'Not sure yet',
}

export const STATUS_NAMES: Record<RequestStatus, string> = {
  new: 'New',
  contacted: 'Contacted',
  closed: 'Closed',
}

export const STATUS_COLORS: Record<RequestStatus, string> = {
  new: 'orange',
  contacted: 'teal',
  closed: 'gray',
}

export const BEST_TIME_NAMES: Record<RequestRow['bestTime'], string> = {
  morning: 'Mornings',
  afternoon: 'Afternoons',
  evening: 'Evenings',
  any: 'Any time',
}
