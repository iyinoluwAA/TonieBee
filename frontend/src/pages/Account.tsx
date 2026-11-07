// /account: sign in by email (no password), or — signed in — your requests, your
// details, where you're signed in, and deleting the account.

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Divider,
  Group,
  Loader,
  Modal,
  Paper,
  PinInput,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import { business, PROVINCE_NAMES } from '@/content/business'
import { Section, useHead } from '@/components/Page'
import { accountsApi, problem, requestsApi, type MyRequest, type SessionInfo } from '@/lib/api'
import { useAuth } from '@/lib/AuthContext'

const LINK_MINUTES = 10
const INTEREST: Record<string, string> = {
  life: 'Life insurance',
  critical_illness: 'Critical illness',
  disability: 'Disability',
  not_sure: 'Not sure yet',
}
const STATUS: Record<MyRequest['status'], { label: string; color: string; text: string }> = {
  new: { label: 'Received', color: 'orange', text: 'We have it and will be in touch.' },
  contacted: { label: 'In progress', color: 'teal', text: 'We’ve been in touch.' },
  closed: { label: 'Closed', color: 'gray', text: 'Done.' },
}

export function Account() {
  useHead('My account')
  const { status, user, notice } = useAuth()
  return (
    <Section>
      <div className="tb-narrow">
        <Title order={1} fz="h2" mb="lg">
          {status === 'signedIn' ? 'My account' : 'Sign in'}
        </Title>
        {status === 'loading' ? (
          <Group justify="center" py="xl">
            <Loader />
          </Group>
        ) : status === 'offline' ? (
          <Alert color="orange" variant="light">
            Accounts are unavailable right now — the server isn’t answering. You can still{' '}
            <Anchor component={Link} to="/book">
              book a consultation
            </Anchor>
            .
          </Alert>
        ) : status === 'signedIn' && user?.role === 'admin' ? (
          <Alert color="navy" variant="light">
            This is an admin account. Use the <Anchor component={Link} to="/admin">dashboard</Anchor>.
          </Alert>
        ) : status === 'signedIn' && user ? (
          <SignedIn />
        ) : (
          <Paper withBorder p="xl">
            <SignInForm notice={notice} />
          </Paper>
        )}
      </div>
    </Section>
  )
}

function SignInForm({ notice }: { notice: string | null }) {
  const { refresh, clearNotice } = useAuth()
  const [step, setStep] = useState<'email' | 'sent'>('email')
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)

  const send = async (again = false) => {
    setBusy(true)
    setError(null)
    setInfo(null)
    try {
      await accountsApi.startEmail(email.trim())
      clearNotice()
      setStep('sent')
      setCode('')
      if (again) setInfo('We sent a new link. Only the newest one works.')
    } catch (e) {
      setError(problem(e))
    } finally {
      setBusy(false)
    }
  }

  const verify = async (value: string) => {
    setBusy(true)
    setError(null)
    try {
      await accountsApi.verifyCode(email.trim(), value)
      await refresh()
    } catch (e) {
      setError(problem(e))
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  // Opened the link in another tab of this browser? That signs this browser in;
  // notice it here instead of asking for a reload.
  useEffect(() => {
    if (step !== 'sent') return
    const until = Date.now() + LINK_MINUTES * 60_000
    const check = () => {
      if (Date.now() < until) void refresh()
    }
    const timer = window.setInterval(check, 4000)
    window.addEventListener('focus', check)
    return () => {
      window.clearInterval(timer)
      window.removeEventListener('focus', check)
    }
  }, [step, refresh])

  if (step === 'email') {
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void send()
        }}
      >
        <Stack gap="md">
          {notice && (
            <Alert color="navy" variant="light" role="status">
              {notice}
            </Alert>
          )}
          <Text c="dimmed">
            Enter your email and we’ll send you a link to sign in — no password to remember. New here? The same link
            creates your account.
          </Text>
          <TextInput label="Email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
          {error && (
            <Alert color="red" variant="light" role="alert">
              {error}
            </Alert>
          )}
          <Button type="submit" loading={busy}>
            Email me a sign-in link
          </Button>
        </Stack>
      </form>
    )
  }

  return (
    <Stack gap="md">
      <Text fw={700}>Check your email</Text>
      <Text c="dimmed">
        We sent a sign-in link to <b style={{ color: 'var(--tb-ink)', overflowWrap: 'anywhere' }}>{email.trim()}</b>. Open it
        on this device and you’re in — this page updates by itself.
      </Text>
      <Divider label="Opened it on another device?" labelPosition="center" />
      <Text size="sm" c="dimmed" ta="center">
        Type the 6-digit code it showed:
      </Text>
      <Group justify="center">
        <PinInput
          length={6}
          type="number"
          oneTimeCode
          value={code}
          onChange={(value) => {
            setCode(value)
            if (value.length === 6) void verify(value)
          }}
          disabled={busy}
          aria-label="6-digit sign-in code"
          ariaLabel="6-digit sign-in code"
        />
      </Group>
      {error && (
        <Alert color="red" variant="light" role="alert">
          {error}
        </Alert>
      )}
      {info && (
        <Text size="sm" ta="center" c="teal.8">
          {info}
        </Text>
      )}
      <Group justify="space-between">
        <Anchor component="button" type="button" size="sm" onClick={() => setStep('email')}>
          Use a different email
        </Anchor>
        <Anchor component="button" type="button" size="sm" disabled={busy} onClick={() => void send(true)}>
          Send a new link
        </Anchor>
      </Group>
      <Text size="xs" c="dimmed">
        The link and code work for {LINK_MINUTES} minutes. Can’t find the email? Check your spam folder.{' '}
        {business.tradingName} will never ask you for your code.
      </Text>
    </Stack>
  )
}

function SignedIn() {
  const { user, signOut } = useAuth()
  const [requests, setRequests] = useState<MyRequest[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    requestsApi
      .mine()
      .then(setRequests)
      .catch((e: unknown) => setError(problem(e)))
  }, [])

  if (!user) return null
  return (
    <Stack gap="xl">
      <Group justify="space-between" align="center">
        <Text c="dimmed" style={{ overflowWrap: 'anywhere' }}>
          Signed in as <b style={{ color: 'var(--tb-ink)' }}>{user.email}</b>
        </Text>
        <Button variant="default" size="xs" onClick={() => void signOut()}>
          Sign out
        </Button>
      </Group>

      <Stack gap="sm">
        <Group justify="space-between">
          <Title order={2} fz="h3">
            My requests
          </Title>
          <Button component={Link} to="/book" size="xs" color="orange">
            New request
          </Button>
        </Group>
        {error && (
          <Alert color="red" variant="light">
            {error}
          </Alert>
        )}
        {!requests && !error ? (
          <Loader size="sm" />
        ) : requests && requests.length === 0 ? (
          <Paper withBorder p="lg">
            <Text c="dimmed">
              No requests yet. Requests you send while signed in appear here.{' '}
              <Anchor component={Link} to="/book">
                Book a consultation
              </Anchor>
              .
            </Text>
          </Paper>
        ) : (
          requests?.map((r) => (
            <Paper key={r.id} withBorder p="md">
              <Group justify="space-between" wrap="nowrap" align="flex-start">
                <Stack gap={2}>
                  <Text fw={600}>{r.interests.map((i) => INTEREST[i] ?? i).join(', ')}</Text>
                  <Text size="sm" c="dimmed">
                    Sent {new Date(r.createdAt).toLocaleDateString()} · {PROVINCE_NAMES[r.province] ?? r.province} · by{' '}
                    {r.contactBy}
                  </Text>
                  <Text size="sm">{STATUS[r.status].text}</Text>
                </Stack>
                <Badge color={STATUS[r.status].color} variant="light">
                  {STATUS[r.status].label}
                </Badge>
              </Group>
            </Paper>
          ))
        )}
      </Stack>

      <Details />
      <Devices />
      <DeleteAccount />
    </Stack>
  )
}

function Details() {
  const { user, refresh } = useAuth()
  const [name, setName] = useState(user?.name ?? '')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null)
  const save = async () => {
    setBusy(true)
    try {
      await accountsApi.updateProfile(name)
      await refresh()
      setMessage({ ok: true, text: 'Saved.' })
    } catch (e) {
      setMessage({ ok: false, text: problem(e) })
    } finally {
      setBusy(false)
    }
  }
  return (
    <Stack gap="sm">
      <Title order={2} fz="h3">
        My details
      </Title>
      <form
        onSubmit={(e) => {
          e.preventDefault()
          void save()
        }}
      >
        <Group align="flex-end" gap="sm">
          <TextInput label="Your name" description="Used to fill in the consultation form for you." maxLength={60} value={name} onChange={(e) => setName(e.currentTarget.value)} style={{ flex: 1, minWidth: 200 }} />
          <Button type="submit" variant="default" loading={busy}>
            Save
          </Button>
        </Group>
      </form>
      {message && (
        <Text size="sm" c={message.ok ? 'teal.8' : 'red.7'} role="status">
          {message.text}
        </Text>
      )}
    </Stack>
  )
}

function Devices() {
  const { signOutEverywhere } = useAuth()
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const load = () =>
    accountsApi
      .sessions()
      .then(setSessions)
      .catch((e: unknown) => setError(problem(e)))
  useEffect(() => {
    void load()
  }, [])
  return (
    <Stack gap="sm">
      <Title order={2} fz="h3">
        Where you’re signed in
      </Title>
      {error && <Text c="red.7">{error}</Text>}
      {sessions?.map((s) => (
        <Paper key={s.id} withBorder p="sm">
          <Group justify="space-between" wrap="nowrap">
            <Stack gap={0}>
              <Text fw={600}>
                {s.device} {s.current && <Badge size="xs" variant="light">This device</Badge>}
              </Text>
              <Text size="xs" c="dimmed">
                Last active {new Date(s.lastActiveAt).toLocaleString()}
              </Text>
            </Stack>
            {!s.current && (
              <Button
                size="xs"
                variant="subtle"
                onClick={() =>
                  void accountsApi
                    .signOutSession(s.id)
                    .then(load)
                    .catch((e: unknown) => setError(problem(e)))
                }
              >
                Sign out
              </Button>
            )}
          </Group>
        </Paper>
      ))}
      <Button variant="default" w="fit-content" onClick={() => void signOutEverywhere()}>
        Sign out everywhere
      </Button>
      <Text size="xs" c="dimmed">
        Lost a phone? “Sign out everywhere” ends every session, including this one.
      </Text>
    </Stack>
  )
}

function DeleteAccount() {
  const { user, accountDeleted } = useAuth()
  const [open, setOpen] = useState(false)
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const remove = async () => {
    setBusy(true)
    setError(null)
    try {
      await accountsApi.deleteAccount(confirm)
      accountDeleted()
    } catch (e) {
      setError(problem(e))
    } finally {
      setBusy(false)
    }
  }
  return (
    <Stack gap="xs">
      <Divider />
      <Anchor component="button" type="button" c="red.7" size="sm" w="fit-content" onClick={() => setOpen(true)}>
        Delete my account
      </Anchor>
      <Modal opened={open} onClose={() => setOpen(false)} title="Delete your account?" centered>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            void remove()
          }}
        >
          <Stack gap="md">
            <Text size="sm">
              Your account and the requests you sent while signed in are deleted for good. Type your email to confirm.
            </Text>
            <TextInput label="Your email" placeholder={user?.email} value={confirm} onChange={(e) => setConfirm(e.currentTarget.value)} required />
            {error && (
              <Alert color="red" variant="light">
                {error}
              </Alert>
            )}
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setOpen(false)}>
                Keep it
              </Button>
              <Button type="submit" color="red" loading={busy}>
                Delete
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Stack>
  )
}
