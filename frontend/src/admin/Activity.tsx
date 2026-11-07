// Who opened or changed which consultation request, and every admin sign-in attempt —
// so with two admins, either can see what the other did. Two lists: requests, and
// sign-ins & security. Newest first, under day headings, 50 at a time.

import { Fragment, useEffect, useRef, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Alert, Box, Button, Group, Loader, Paper, SegmentedControl, Stack, Text, Title, Tooltip } from '@mantine/core'
import { adminApi, type ActivityEntry, type ActivityKind } from './api'

const KINDS: { value: ActivityKind; label: string; about: string }[] = [
  { value: 'requests', label: 'Requests', about: 'Who opened, changed or deleted which request (the law asks you to be able to show this).' },
  {
    value: 'security',
    label: 'Sign-ins & security',
    about: 'Every sign-in and wrong try, with its IP and whether the device was new.',
  },
]

/** How long the code step stays open after the right password (admin.rs → TICKET_MINUTES, plus slack). */
const CODE_STEP_MINUTES = 6

export function Activity() {
  const [params, setParams] = useSearchParams()
  const kind: ActivityKind = params.get('show') === 'security' ? 'security' : 'requests'
  const [entries, setEntries] = useState<ActivityEntry[] | null>(null)
  const [more, setMore] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Switching lists quickly: an answer for the list just left is dropped.
  const latest = useRef(0)

  const load = async (before?: number) => {
    const request = ++latest.current
    setBusy(true)
    try {
      const page = await adminApi.activity(kind, before)
      if (request !== latest.current) return
      setEntries((current) => [...(before ? (current ?? []) : []), ...page])
      setMore(page.length === 50)
      setError(null)
    } catch (e) {
      if (request === latest.current) setError(e instanceof Error ? e.message : 'The activity couldn’t load.')
    } finally {
      if (request === latest.current) setBusy(false)
    }
  }

  useEffect(() => {
    setEntries(null)
    void load()
  }, [kind])

  return (
    <Stack gap="md">
      <Stack gap={0}>
        <Title order={1} fz={26}>
          Activity
        </Title>
        <Text c="dimmed" size="sm">
          {KINDS.find((k) => k.value === kind)?.about}
        </Text>
      </Stack>
      <SegmentedControl
        fullWidth
        maw={420}
        aria-label="Which activity"
        data={KINDS.map(({ value, label }) => ({ value, label }))}
        value={kind}
        onChange={(value) => setParams(value === 'security' ? { show: 'security' } : {}, { replace: true })}
      />
      {error && (
        <Alert color="red" variant="light">
          {error}
        </Alert>
      )}
      {!entries ? (
        <Group justify="center" py={80}>
          <Loader color="navy" />
        </Group>
      ) : entries.length === 0 ? (
        <Text c="dimmed">Nothing yet.</Text>
      ) : (
        <Stack gap="xs">
          {entries.map((e, i) => {
            const heading = day(e.at)
            const alarm = warning(e)
            return (
              <Fragment key={e.id}>
                {(i === 0 || day(entries[i - 1].at) !== heading) && (
                  <Text size="xs" fw={700} c="dimmed" tt="uppercase" mt={i ? 'sm' : 0} className="tb-admin__day">
                    {heading}
                  </Text>
                )}
                <Paper p="sm" withBorder style={alarm ? { borderColor: 'var(--mantine-color-red-7)' } : undefined}>
                  <Group justify="space-between" align="flex-start" wrap="nowrap" gap="sm">
                    <Box style={{ minWidth: 0 }}>
                      <Text size="sm">
                        <Text span fw={600}>
                          {e.who ?? 'Someone'}
                        </Text>{' '}
                        {describe(e)}
                      </Text>
                      {details(e).map((line) => (
                        <Text key={line} size="xs" c="dimmed">
                          {line}
                        </Text>
                      ))}
                      {/* Shown, not on hover: phones can't hover, and a sign-in from a
                          strange IP or new device is what an admin should notice. */}
                      {e.ip && e.action.startsWith('admin.') && (
                        <Text size="xs" c="dimmed">
                          IP {e.ip}
                          {e.detail.device === 'unknown'
                            ? ' · new device'
                            : e.detail.device === 'known'
                              ? ' · known device'
                              : ''}
                        </Text>
                      )}
                      {alarm && (
                        <Text size="xs" c="red.4" fw={600} mt={2}>
                          {alarm}
                        </Text>
                      )}
                    </Box>
                    <Tooltip label={new Date(e.at).toLocaleString()} events={{ hover: true, focus: true, touch: true }}>
                      <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>
                        {when(e.at)}
                      </Text>
                    </Tooltip>
                  </Group>
                </Paper>
              </Fragment>
            )
          })}
          {more && (
            <Button variant="default" onClick={() => void load(entries[entries.length - 1]?.id)} loading={busy}>
              Older
            </Button>
          )}
        </Stack>
      )}
    </Stack>
  )
}

/** The server lists "right password" only when no sign-in followed it. Within the
 *  code step's few minutes that's someone typing the code now; after, it's a warning. */
function codeStepOpen(e: ActivityEntry): boolean {
  return Date.now() - new Date(e.at).getTime() < CODE_STEP_MINUTES * 60_000
}

/** A line in red for what an admin should act on. */
function warning(e: ActivityEntry): string | null {
  if (e.action === 'admin.password_ok' && !codeStepOpen(e))
    return 'If that wasn’t them, someone knows the password — change it.'
  return null
}

const str = (v: unknown) => (typeof v === 'string' ? v : '')

/** " (2 other devices signed out)" after a password or phone change. */
function othersSignedOut(d: Record<string, unknown>): string {
  const n = typeof d.otherSessionsEnded === 'number' ? d.otherSessionsEnded : 0
  return n ? ` (${n} other device${n === 1 ? '' : 's'} signed out)` : ''
}

/** One line saying what happened. */
function describe(e: ActivityEntry): string {
  const d = e.detail
  const request = `request ${str(d.request).slice(0, 8)}`
  switch (e.action) {
    case 'request.viewed':
      return `opened ${request}`
    case 'request.updated':
      return `updated ${request}`
    case 'request.deleted':
      return `deleted ${request}`
    case 'admin.alert_sent':
      return d.kind === 'locked'
        ? 'was emailed: sign-in paused after wrong tries'
        : 'was emailed: a sign-in from a new device'
    case 'admin.client_sign_in_attempt':
      return 'had their address typed into the client sign-in (they were emailed where to sign in instead)'
    case 'admin.signed_in':
      return `signed in${d.method === 'backup code' ? ' with a backup code' : ''}`
    case 'admin.password_ok':
      return codeStepOpen(e) ? 'entered the right password (the code step is open)' : 'entered the right password but never the code'
    case 'admin.sign_in_failed':
      return `failed to sign in${d.reason ? ` (${str(d.reason)})` : ''}`
    case 'admin.sign_in_blocked':
      return `tried to sign in while locked`
    case 'admin.locked':
      return `was locked out for ${String(d.minutes ?? 15)} minutes after 5 wrong tries`
    case 'admin.backup_code_used':
      return 'used a backup code'
    case 'admin.enrolled':
      return 'was set up as an admin (password, authenticator, backup codes)'
    case 'admin.signed_out_everywhere':
      return 'signed out on every device'
    case 'admin.invited':
      return `invited ${str(d.email)} to be an admin (a one-time link)`
    case 'admin.invite_cancelled':
      return `cancelled the invite for ${str(d.email)}`
    case 'admin.invite_accepted':
      return `set up their admin account from ${d.invitedBy ? `${str(d.invitedBy)}’s` : 'an'} invite`
    case 'admin.password_changed':
      return `changed their password${othersSignedOut(d)}`
    case 'admin.authenticator_changed':
      return `moved their authenticator app to a new phone${othersSignedOut(d)}`
    case 'admin.backup_codes_renewed':
      return 'got a new set of backup codes (the old ones stopped working)'
    case 'admin.confirm_failed':
      return `typed a ${d.reason === 'wrong code' ? 'wrong code' : 'wrong password'} while confirming an account change`
    default:
      return e.action
  }
}

const STATUS_NAMES: Record<string, string> = { new: 'New', contacted: 'Contacted', closed: 'Closed' }

/** For a request change: what changed (never the notes' text — it isn't logged). */
function details(e: ActivityEntry): string[] {
  if (e.action !== 'request.updated') return []
  const lines: string[] = []
  const status = e.detail.status as { from: string; to: string } | undefined
  if (status) lines.push(`Status: ${STATUS_NAMES[status.from] ?? status.from} → ${STATUS_NAMES[status.to] ?? status.to}`)
  if (e.detail.notesChanged) lines.push('Notes: changed')
  return lines
}

/** Beside each entry: "just now", "12 min ago", then the time of day (the heading has the day). */
function when(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`
  return new Date(iso).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })
}

/** Day heading: "Today", "Yesterday", "Tue 27 Oct" (with the year when it isn't this year). */
function day(iso: string): string {
  const date = new Date(iso)
  const now = new Date()
  const midnight = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime()
  const daysAgo = Math.round((midnight(now) - midnight(date)) / 86_400_000)
  if (daysAgo === 0) return 'Today'
  if (daysAgo === 1) return 'Yesterday'
  return date.toLocaleDateString([], {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    ...(date.getFullYear() === now.getFullYear() ? {} : { year: 'numeric' as const }),
  })
}
