// The page an admin invite opens: /admin/welcome#<token>. The new admin (the owner, on
// his phone) chooses a password, adds Toniebee to his authenticator app, types its code
// and saves his backup codes — then he's signed in. No command line, no developer.
// The token is after '#', which browsers never send to a server: this page sends it in
// a request body. The server checks everything (backend/src/modules/accounts/invites.rs).

import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Alert, Anchor, Box, Button, Center, Loader, PasswordInput, Stack, Text, Title } from '@mantine/core'
import { adminApi, AdminApiError, type InviteOpened } from './api'
import { AddToAuthenticator, BackupCodesSaver, CodeBoxes, PASSWORD_HINT, passwordProblem } from './AccountParts'
import { useAdminSession } from './session'

type Step = 'password' | 'app' | 'codes'

export function Welcome() {
  const { session, refresh } = useAdminSession()
  const navigate = useNavigate()
  // Read once: the 64-character token, even if something was added after it.
  const [token] = useState(() => window.location.hash.match(/[0-9a-f]{64}/)?.[0] ?? '')
  const [invite, setInvite] = useState<InviteOpened | null>(null)
  const [dead, setDead] = useState<string | null>(null)
  const [step, setStep] = useState<Step>('password')
  const [password, setPassword] = useState('')
  const [again, setAgain] = useState('')
  const [tried, setTried] = useState(false)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null)

  useEffect(() => {
    if (!token) {
      setDead('This page needs the whole invite link. Open the link you were sent again.')
      return
    }
    adminApi
      .openInvite(token)
      .then(setInvite)
      .catch((e) => setDead(e instanceof Error ? e.message : 'This invite link can’t be opened.'))
  }, [token])

  const problem = invite
    ? (passwordProblem(password, invite.email) ?? (again !== password ? 'The two passwords don’t match.' : null))
    : null

  const finish = async (typed: string) => {
    if (!invite || busy) return
    setBusy(true)
    setError(null)
    try {
      const done = await adminApi.acceptInvite(token, password, typed)
      setPassword('')
      setAgain('')
      // The link is used up; take it out of the address bar and history.
      window.history.replaceState(window.history.state, '', '/admin/welcome')
      setBackupCodes(done.backupCodes)
      setStep('codes')
      void refresh()
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Something went wrong.'
      setCode('')
      if (e instanceof AdminApiError && (e.status === 404 || e.status === 409)) setDead(message)
      else if (e instanceof AdminApiError && e.status === 400 && !/code/i.test(message)) {
        setStep('password') // the server didn't accept the password
        setError(message)
      } else setError(message)
    } finally {
      setBusy(false)
    }
  }

  const expires = invite ? new Date(invite.expiresAt).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : ''

  return (
    <Center mih="100vh" p="md">
      <Box w="100%" maw={440}>
        <Stack gap="lg">
          <Stack gap={4}>
            <Text className="tb-eyebrow">Toniebee Admin</Text>
            <Title order={1} fz={28}>
              {step === 'codes' ? 'You’re in' : 'Welcome'}
            </Title>
          </Stack>

          {dead ? (
            <Stack gap="md">
              <Alert color="red" variant="light" role="alert">
                {dead}
              </Alert>
              <Anchor component={Link} to="/admin/sign-in" size="sm">
                Already set up? Sign in
              </Anchor>
            </Stack>
          ) : !invite ? (
            <Center py={60}>
              <Loader color="navy" />
            </Center>
          ) : (
            <>
              {step !== 'codes' && (
                <Stack gap={6}>
                  <Text>
                    {invite.invitedBy ? `${invite.invitedBy} invited you` : 'You’re invited'} to help run the
                    Toniebee website. Your admin sign-in email is{' '}
                    <Text span fw={600}>
                      {invite.email}
                    </Text>
                    .
                  </Text>
                  <Text size="sm" c="dimmed">
                    Three short steps. This link works once, until {expires}.
                  </Text>
                  {session.state === 'signedIn' && session.email !== invite.email && (
                    <Alert color="navy" variant="light">
                      <Text size="sm">
                        {session.email} is signed in on this browser. Finishing here signs them out and signs in{' '}
                        {invite.email}.
                      </Text>
                    </Alert>
                  )}
                </Stack>
              )}

              {step === 'password' && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault()
                    setTried(true)
                    if (!problem) {
                      setError(null)
                      setStep('app')
                    }
                  }}
                >
                  <Stack gap="md">
                    <Text fw={600}>1 of 3 · Choose your password</Text>
                    <PasswordInput
                      label="New password"
                      description={PASSWORD_HINT}
                      autoComplete="new-password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.currentTarget.value)}
                    />
                    <PasswordInput
                      label="Type it again"
                      autoComplete="new-password"
                      required
                      value={again}
                      onChange={(e) => setAgain(e.currentTarget.value)}
                      error={tried ? problem : undefined}
                    />
                    <Button type="submit" fullWidth>
                      Next
                    </Button>
                  </Stack>
                </form>
              )}

              {step === 'app' && (
                <Stack gap="md">
                  <Text fw={600}>2 of 3 · Add Toniebee to your authenticator app</Text>
                  <Text size="sm" c="dimmed">
                    Every sign-in asks for your password and a 6-digit code from this app, so nobody can get in with
                    the password alone.
                  </Text>
                  <AddToAuthenticator setup={invite.authenticator} />
                  <Text fw={600} mt="sm">
                    Then type the 6-digit code the app shows for Toniebee
                  </Text>
                  <CodeBoxes
                    value={code}
                    onChange={setCode}
                    onComplete={(value) => void finish(value)}
                    disabled={busy}
                    label="6-digit code from your authenticator app"
                  />
                  {busy && (
                    <Center>
                      <Loader color="navy" size="sm" />
                    </Center>
                  )}
                  <Anchor component="button" type="button" size="sm" onClick={() => setStep('password')}>
                    Back to the password
                  </Anchor>
                </Stack>
              )}

              {step === 'codes' && backupCodes && (
                <Stack gap="md">
                  <Text>
                    Your admin account is set up and you’re signed in as{' '}
                    <Text span fw={600}>
                      {invite.email}
                    </Text>
                    .
                  </Text>
                  <Text fw={600}>3 of 3 · Save your backup codes</Text>
                  <BackupCodesSaver
                    codes={backupCodes}
                    email={invite.email}
                    doneLabel="Open the dashboard"
                    onDone={() => navigate('/admin', { replace: true })}
                  />
                </Stack>
              )}

              {error && (
                <Alert color="red" variant="light" role="alert">
                  {error}
                </Alert>
              )}
            </>
          )}
        </Stack>
      </Box>
    </Center>
  )
}
