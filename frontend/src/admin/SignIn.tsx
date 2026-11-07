// Admin sign-in: password, then the authenticator code (or a one-time backup code).
// The server does the checking and locking (backend/src/modules/accounts/admin.rs).

import { useState } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import {
  Alert,
  Anchor,
  Box,
  Button,
  Center,
  Group,
  PasswordInput,
  PinInput,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { adminApi } from './api'
import { useAdminSession } from './session'

export function SignIn() {
  const { session, refresh } = useAdminSession()
  const navigate = useNavigate()
  const [params] = useSearchParams()
  const next = safeNext(params.get('next'))
  const [step, setStep] = useState<'password' | 'code'>('password')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [backup, setBackup] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (session.state === 'signedIn') return <Navigate to={next} replace />

  const submitPassword = async () => {
    setBusy(true)
    setError(null)
    try {
      await adminApi.password(email, password)
      setPassword('')
      setStep('code')
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Something went wrong.')
    } finally {
      setBusy(false)
    }
  }

  const submitCode = async (value: string) => {
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      const result = await adminApi.code(value)
      if (result.backupCodesLeft != null) {
        notifications.show({
          color: result.backupCodesLeft <= 3 ? 'red' : 'navy',
          title: `${result.backupCodesLeft} backup code${result.backupCodesLeft === 1 ? '' : 's'} left`,
          message:
            result.backupCodesLeft <= 3
              ? 'Get a fresh set soon: Your account (menu at the top right) → Get new codes.'
              : 'Each backup code works once.',
          autoClose: 10000,
        })
      }
      await refresh()
      navigate(next, { replace: true })
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Something went wrong.'
      setCode('')
      if (/timed out|password first/i.test(message)) {
        setStep('password')
      }
      setError(message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Center mih="100vh" p="md">
      <Box w="100%" maw={400}>
        <Stack gap="lg">
          <Stack gap={4}>
            <Text className="tb-eyebrow">Toniebee Admin</Text>
            <Title order={1} fz={28}>
              {step === 'password' ? 'Sign in' : 'One more step'}
            </Title>
          </Stack>

          {step === 'password' ? (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                void submitPassword()
              }}
            >
              <Stack gap="md">
                <TextInput
                  label="Email"
                  type="email"
                  autoComplete="username"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.currentTarget.value)}
                />
                <PasswordInput
                  label="Password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.currentTarget.value)}
                />
                <Button type="submit" loading={busy} fullWidth>
                  Continue
                </Button>
              </Stack>
            </form>
          ) : backup ? (
            <form
              onSubmit={(e) => {
                e.preventDefault()
                void submitCode(code)
              }}
            >
              <Stack gap="md">
                <Text c="dimmed" size="sm">
                  Type one of your backup codes (like ABCDE-FGHJK). Each works once.
                </Text>
                <TextInput
                  label="Backup code"
                  autoComplete="one-time-code"
                  autoCapitalize="characters"
                  required
                  value={code}
                  onChange={(e) => setCode(e.currentTarget.value)}
                />
                <Button type="submit" loading={busy} fullWidth>
                  Sign in
                </Button>
                <Anchor component="button" type="button" size="sm" onClick={() => setBackup(false)}>
                  Use the authenticator app instead
                </Anchor>
              </Stack>
            </form>
          ) : (
            <Stack gap="md">
              <Text c="dimmed" size="sm">
                Open your authenticator app (Google Authenticator) and type the 6-digit code for Toniebee.
              </Text>
              <Group justify="center">
                {/* Sent from onChange, not onComplete: see CodeBoxes in AccountParts.tsx —
                    after a wrong code, a pasted right one was never sent. */}
                <PinInput
                  length={6}
                  type="number"
                  oneTimeCode
                  value={code}
                  onChange={(value) => {
                    setCode(value)
                    if (value.length === 6) void submitCode(value)
                  }}
                  disabled={busy}
                  aria-label="6-digit code from your authenticator app"
          ariaLabel="6-digit code from your authenticator app"
                />
              </Group>
              <Anchor component="button" type="button" size="sm" ta="center" onClick={() => setBackup(true)}>
                Lost your phone? Use a backup code
              </Anchor>
            </Stack>
          )}

          {error && (
            <Alert color="red" variant="light" role="alert">
              {error}
            </Alert>
          )}
        </Stack>
      </Box>
    </Center>
  )
}

/** Only ever go back to a dashboard page (never an outside address). */
function safeNext(next: string | null): string {
  return next && next.startsWith('/admin') && !next.startsWith('//') ? next : '/admin'
}
