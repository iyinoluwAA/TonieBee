// "Your account" (/admin/account): change your password, move your authenticator to a
// new phone, get new backup codes — and "Admins": who can run the website, and invites.
// No command line needed. Each change asks for the password and a code again; the
// server checks everything (backend/src/modules/accounts/admin_account.rs, invites.rs).

import { useEffect, useState, type ReactNode } from 'react'
import {
  Alert,
  Badge,
  Box,
  Button,
  Group,
  Loader,
  Modal,
  Paper,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconUserPlus } from '@tabler/icons-react'
import { adminApi, type AuthenticatorSetup, type Confirm, type Team } from './api'
import {
  AddToAuthenticator,
  BackupCodesSaver,
  CodeBoxes,
  ConfirmFields,
  PASSWORD_HINT,
  passwordProblem,
} from './AccountParts'
import { useAdminSession } from './session'

type Dialog = 'password' | 'phone' | 'codes' | 'invite' | null
const NO_CONFIRM: Confirm = { password: '', code: '' }

const message = (e: unknown) => (e instanceof Error ? e.message : 'Something went wrong.')
const when = (iso: string) => new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })
const signedOut = (n: number) => (n ? ` ${n} other device${n === 1 ? ' was' : 's were'} signed out.` : '')

export function Account() {
  const { session } = useAdminSession()
  const email = session.state === 'signedIn' ? session.email : ''
  const [left, setLeft] = useState<number | null>(null)
  const [team, setTeam] = useState<Team | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dialog, setDialog] = useState<Dialog>(null)

  const load = async () => {
    try {
      const [account, admins] = await Promise.all([adminApi.account(), adminApi.team()])
      setLeft(account.backupCodesLeft)
      setTeam(admins)
      setError(null)
    } catch (e) {
      setError(message(e))
    }
  }

  useEffect(() => {
    void load()
  }, [])

  const close = () => {
    setDialog(null)
    void load()
  }

  const cancel = async (id: string, invitee: string) => {
    try {
      await adminApi.cancelInvite(id)
      notifications.show({ message: `The invite for ${invitee} is cancelled; its link no longer works.` })
    } catch (e) {
      notifications.show({ color: 'red', message: message(e) })
    }
    void load()
  }

  return (
    <Stack gap="xl">
      <Stack gap="md">
        <Stack gap={0}>
          <Title order={1} fz={26}>
            Your account
          </Title>
          <Text c="dimmed" size="sm">
            {email}
          </Text>
        </Stack>
        {error && (
          <Alert color="red" variant="light">
            {error}
          </Alert>
        )}
        <Paper withBorder>
          <Setting
            title="Password"
            text="Change it any time. Your other devices are signed out."
            action="Change password"
            onClick={() => setDialog('password')}
          />
          <Setting
            title="Authenticator app"
            text="New phone, or lost this one? Move your Toniebee codes to another phone."
            action="Set up a new phone"
            onClick={() => setDialog('phone')}
          />
          <Setting
            title="Backup codes"
            text={left == null ? '…' : `${left} of 10 left. Each signs you in once without your phone.`}
            warn={left != null && left <= 3}
            action="Get new codes"
            onClick={() => setDialog('codes')}
          />
        </Paper>
      </Stack>

      <Stack gap="md">
        <Stack gap={0}>
          <Title order={2} fz={22}>
            Admins
          </Title>
          <Text c="dimmed" size="sm">
            Everyone who can open the dashboard. Each has their own sign-in, so Activity shows who did what.
          </Text>
        </Stack>
        {!team ? (
          <Group justify="center" py="md">
            <Loader color="navy" size="sm" />
          </Group>
        ) : (
          <Paper withBorder>
            {team.admins.map((a) => (
              <Box key={a.email} p="md" className="tb-admin__setting">
                <Group gap="xs" wrap="nowrap">
                  <Text size="sm" fw={600} truncate>
                    {a.email}
                  </Text>
                  {a.you && (
                    <Badge size="xs" variant="light" color="navy">
                      You
                    </Badge>
                  )}
                </Group>
                <Text size="xs" c="dimmed">
                  {a.lastSignInAt ? `Last signed in ${when(a.lastSignInAt)}` : 'Hasn’t signed in yet'}
                </Text>
              </Box>
            ))}
            {team.invites.map((i) => (
              <Group key={i.id} p="md" justify="space-between" wrap="nowrap" gap="sm" className="tb-admin__setting">
                <Box miw={0}>
                  <Group gap="xs" wrap="nowrap">
                    <Text size="sm" fw={600} truncate>
                      {i.email}
                    </Text>
                    <Badge size="xs" variant="outline" color="gray">
                      Invited
                    </Badge>
                  </Group>
                  <Text size="xs" c="dimmed">
                    {i.invitedBy ? `By ${i.invitedBy} · ` : ''}link works until {when(i.expiresAt)}
                  </Text>
                </Box>
                <Button variant="subtle" color="red" size="xs" onClick={() => void cancel(i.id, i.email)}>
                  Cancel invite
                </Button>
              </Group>
            ))}
          </Paper>
        )}
        <Button
          leftSection={<IconUserPlus size={18} />}
          onClick={() => setDialog('invite')}
          style={{ alignSelf: 'flex-start' }}
        >
          Invite an admin
        </Button>
      </Stack>

      {dialog === 'password' && <PasswordDialog email={email} onClose={close} />}
      {dialog === 'phone' && <NewPhoneDialog onClose={close} />}
      {dialog === 'codes' && <BackupCodesDialog email={email} onClose={close} />}
      {dialog === 'invite' && <InviteDialog onClose={close} />}
    </Stack>
  )
}

function Setting({
  title,
  text,
  action,
  onClick,
  warn,
}: {
  title: string
  text: string
  action: string
  onClick: () => void
  warn?: boolean
}) {
  return (
    <Group p="md" justify="space-between" gap="sm" className="tb-admin__setting">
      <Box miw={0} style={{ flex: '1 1 240px' }}>
        <Text size="sm" fw={600}>
          {title}
        </Text>
        <Text size="xs" c={warn ? 'red.4' : 'dimmed'}>
          {text}
        </Text>
      </Box>
      <Button variant="default" size="sm" onClick={onClick}>
        {action}
      </Button>
    </Group>
  )
}

/** A dialog's form: its fields, an error, Cancel and the main button. */
function DialogForm({
  children,
  error,
  busy,
  submitLabel,
  onSubmit,
  onCancel,
}: {
  children: ReactNode
  error: string | null
  busy: boolean
  submitLabel: string
  onSubmit: () => void
  onCancel: () => void
}) {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit()
      }}
    >
      <Stack gap="md">
        {children}
        {error && (
          <Alert color="red" variant="light" role="alert">
            {error}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit" loading={busy}>
            {submitLabel}
          </Button>
        </Group>
      </Stack>
    </form>
  )
}

function PasswordDialog({ email, onClose }: { email: string; onClose: () => void }) {
  const [confirm, setConfirm] = useState(NO_CONFIRM)
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    const problem = passwordProblem(next, email) ?? (again !== next ? 'The new passwords don’t match.' : null)
    if (problem) return setError(problem)
    setBusy(true)
    setError(null)
    try {
      const done = await adminApi.changePassword(confirm, next)
      notifications.show({ color: 'green', message: `Password changed.${signedOut(done.otherSessionsEnded)}` })
      onClose()
    } catch (e) {
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal opened onClose={onClose} title="Change your password" centered>
      <DialogForm error={error} busy={busy} submitLabel="Change password" onSubmit={() => void submit()} onCancel={onClose}>
        <ConfirmFields value={confirm} onChange={setConfirm} passwordLabel="Current password">
          <PasswordInput
            label="New password"
            description={PASSWORD_HINT}
            autoComplete="new-password"
            required
            value={next}
            onChange={(e) => setNext(e.currentTarget.value)}
          />
          <PasswordInput
            label="Type the new one again"
            autoComplete="new-password"
            required
            value={again}
            onChange={(e) => setAgain(e.currentTarget.value)}
          />
        </ConfirmFields>
      </DialogForm>
    </Modal>
  )
}

function NewPhoneDialog({ onClose }: { onClose: () => void }) {
  const [confirm, setConfirm] = useState(NO_CONFIRM)
  const [setup, setSetup] = useState<AuthenticatorSetup | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const start = async () => {
    setBusy(true)
    setError(null)
    try {
      setSetup(await adminApi.startNewPhone(confirm))
    } catch (e) {
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }

  const finish = async (typed: string) => {
    if (busy) return
    setBusy(true)
    setError(null)
    try {
      const done = await adminApi.finishNewPhone(typed)
      notifications.show({
        color: 'green',
        message: `Your new phone is set up; the old phone’s codes no longer work.${signedOut(done.otherSessionsEnded)}`,
        autoClose: 8000,
      })
      onClose()
    } catch (e) {
      setCode('')
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal opened onClose={onClose} title="Set up a new phone" centered>
      {!setup ? (
        <DialogForm error={error} busy={busy} submitLabel="Continue" onSubmit={() => void start()} onCancel={onClose}>
          <Text size="sm" c="dimmed">
            First, confirm it’s you. Old phone lost? Use one of your backup codes as the code.
          </Text>
          <ConfirmFields value={confirm} onChange={setConfirm} />
        </DialogForm>
      ) : (
        <Stack gap="md">
          <Text size="sm">On the new phone:</Text>
          <AddToAuthenticator setup={setup} />
          <Text fw={600}>Then type the code the new phone shows for Toniebee</Text>
          <CodeBoxes
            value={code}
            onChange={setCode}
            onComplete={(value) => void finish(value)}
            disabled={busy}
            label="6-digit code from the new phone"
          />
          <Text size="xs" c="dimmed">
            Until then, the old phone’s codes keep working. This new key waits 15 minutes.
          </Text>
          {error && (
            <Alert color="red" variant="light" role="alert">
              {error}
            </Alert>
          )}
        </Stack>
      )}
    </Modal>
  )
}

function BackupCodesDialog({ email, onClose }: { email: string; onClose: () => void }) {
  const [confirm, setConfirm] = useState(NO_CONFIRM)
  const [codes, setCodes] = useState<string[] | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      setCodes((await adminApi.newBackupCodes(confirm)).backupCodes)
    } catch (e) {
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal opened onClose={onClose} title="New backup codes" centered>
      {!codes ? (
        <DialogForm error={error} busy={busy} submitLabel="Get new codes" onSubmit={() => void submit()} onCancel={onClose}>
          <Text size="sm" c="dimmed">
            Your current backup codes stop working once the new ones are made.
          </Text>
          <ConfirmFields value={confirm} onChange={setConfirm} />
        </DialogForm>
      ) : (
        <BackupCodesSaver codes={codes} email={email} doneLabel="Done" onDone={onClose} />
      )}
    </Modal>
  )
}

function InviteDialog({ onClose }: { onClose: () => void }) {
  const [invitee, setInvitee] = useState('')
  const [confirm, setConfirm] = useState(NO_CONFIRM)
  const [sent, setSent] = useState<{ email: string; expiresAt: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      setSent(await adminApi.invite(invitee, confirm))
    } catch (e) {
      setError(message(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal opened onClose={onClose} title={sent ? 'Invite sent' : 'Invite an admin'} centered>
      {!sent ? (
        <DialogForm error={error} busy={busy} submitLabel="Email the invite" onSubmit={() => void submit()} onCancel={onClose}>
          <Text size="sm" c="dimmed">
            We email them a one-time link to choose their own password and set up their own authenticator app, on
            their phone. The link goes only to that address, so only someone who can read that inbox can use it.
          </Text>
          <TextInput
            label="Their email"
            description="What they’ll sign in with."
            type="email"
            required
            data-autofocus
            value={invitee}
            onChange={(e) => setInvitee(e.currentTarget.value)}
          />
          <Text size="sm" fw={600}>
            Confirm it’s you
          </Text>
          <ConfirmFields value={confirm} onChange={setConfirm} />
        </DialogForm>
      ) : (
        <Stack gap="md">
          <Text size="sm">
            We emailed a one-time link to{' '}
            <Text span fw={600}>
              {sent.email}
            </Text>
            . It works once, until {when(sent.expiresAt)}. Ask them to check their spam folder if it doesn’t arrive.
          </Text>
          <Alert color="navy" variant="light">
            <Text size="sm">
              When they’ve finished, call to check it was them: Activity → Sign-ins &amp; security shows it, with the
              IP. Not right? Cancel the invite below, or invite them again (the old link stops working).
            </Text>
          </Alert>
          <Button variant="default" onClick={onClose}>
            Done
          </Button>
        </Stack>
      )}
    </Modal>
  )
}
