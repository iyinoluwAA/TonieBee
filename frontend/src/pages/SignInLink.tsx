import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { Alert, Button, Group, Loader, Paper, Stack, Text, Title } from '@mantine/core'
import { IconAlertTriangle } from '@tabler/icons-react'
import { business } from '@/content/business'
import { Section, useHead } from '@/components/Page'
import { accountsApi, problem } from '@/lib/api'
import { useAuth } from '@/lib/AuthContext'

// The page a sign-in email opens: /sign-in/link#<token>. The token sits after "#",
// which browsers never send to any server, and is cleared from the address bar straight
// away. Same browser that asked → signed in. Any other device → shows the 6-digit code
// to type where the sign-in started, which device asked and when, and "This wasn't me".
type View =
  | { kind: 'checking' }
  | { kind: 'signedIn'; email: string }
  | { kind: 'code'; code: string; requestedFrom: string; requestedAt: string; token: string }
  | { kind: 'denied' }
  | { kind: 'problem'; message: string }

export function SignInLink() {
  useHead('Sign in')
  const { refresh } = useAuth()
  const [view, setView] = useState<View>({ kind: 'checking' })
  const [busy, setBusy] = useState(false)
  // Links already opened here (React's development mode runs effects twice).
  const opened = useRef(new Set<string>())

  useEffect(() => {
    const openFromAddress = () => {
      const token = window.location.hash.slice(1)
      if ((token === '' && opened.current.size > 0) || opened.current.has(token)) return
      opened.current.add(token)
      window.history.replaceState(null, '', window.location.pathname)
      setView({ kind: 'checking' })
      if (!/^[0-9a-f]{64}$/.test(token)) {
        setView({ kind: 'problem', message: 'This sign-in link is incomplete. Open it straight from the email, or ask for a new one.' })
        return
      }
      accountsApi
        .openLink(token)
        .then(async (result) => {
          if (result.status === 'signedIn') {
            await refresh()
            setView({ kind: 'signedIn', email: result.user.email })
          } else {
            setView({ kind: 'code', code: result.code, requestedFrom: result.requestedFrom, requestedAt: result.requestedAt, token })
          }
        })
        .catch((e: unknown) => setView({ kind: 'problem', message: problem(e) }))
    }
    openFromAddress()
    window.addEventListener('hashchange', openFromAddress)
    return () => window.removeEventListener('hashchange', openFromAddress)
  }, [refresh])

  const deny = async (token: string) => {
    setBusy(true)
    try {
      await accountsApi.denyLink(token)
      setView({ kind: 'denied' })
    } catch (e) {
      setView({ kind: 'problem', message: problem(e) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Section>
      <div className="tb-narrow">
        <Title order={1} fz="h2" ta="center" mb="lg">
          Sign in to {business.tradingName}
        </Title>
        <Paper withBorder p="xl">
          {view.kind === 'checking' && (
            <Group justify="center" gap="sm" py="md">
              <Loader size="sm" />
              <Text c="dimmed">Checking your link…</Text>
            </Group>
          )}

          {view.kind === 'signedIn' && (
            <Stack gap="md">
              <Text fw={700} fz="lg">
                You’re signed in.
              </Text>
              <Text c="dimmed" style={{ overflowWrap: 'anywhere' }}>
                {view.email}
              </Text>
              <Button component={Link} to="/account">
                Go to my account
              </Button>
            </Stack>
          )}

          {view.kind === 'code' && (
            <Stack gap="md" align="center">
              <Text c="dimmed" ta="center">
                Your sign-in code
              </Text>
              <Text
                aria-label={`Sign-in code ${view.code.split('').join(' ')}`}
                style={{ fontFamily: 'ui-monospace, Consolas, monospace', fontSize: '2.4rem', fontWeight: 700, letterSpacing: '0.2em' }}
              >
                {view.code.slice(0, 3)} {view.code.slice(3)}
              </Text>
              <Text ta="center">
                Asked for from <b>{view.requestedFrom}</b> at{' '}
                <b>{new Date(view.requestedAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}</b>. Type
                it there. It works for 10 minutes.
              </Text>
              <Alert color="red" variant="light" w="100%" icon={<IconAlertTriangle />}>
                <Text size="sm" fw={700}>
                  Never share this code with anyone.
                </Text>
                <Text size="sm">
                  {business.tradingName} will never ask you for it — not by phone, text or email. If someone asked you to
                  read it to them, or you didn’t ask to sign in, cancel it now.
                </Text>
              </Alert>
              <Button variant="default" color="red" loading={busy} onClick={() => void deny(view.token)} fullWidth>
                This wasn’t me — cancel it
              </Button>
              <Text size="xs" c="dimmed" ta="center">
                Want to sign in on this device instead? <Link to="/account">Ask for a new link here</Link>.
              </Text>
            </Stack>
          )}

          {view.kind === 'denied' && (
            <Stack gap="sm">
              <Text fw={700}>Cancelled — that code no longer works.</Text>
              <Text c="dimmed">
                Nobody can sign in with it. If you didn’t ask to sign in, someone may have typed your email by mistake;
                there’s nothing else you need to do.
              </Text>
            </Stack>
          )}

          {view.kind === 'problem' && (
            <Stack gap="md">
              <Text fw={700}>This link can’t be used</Text>
              <Text c="dimmed">{view.message}</Text>
              <Button component={Link} to="/account">
                Ask for a new link
              </Button>
            </Stack>
          )}
        </Paper>
      </div>
    </Section>
  )
}
