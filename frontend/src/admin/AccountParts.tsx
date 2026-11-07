// Pieces shared by the invite page (Welcome.tsx) and "Your account" (Account.tsx):
// password rules, "confirm it's you", adding Toniebee to an authenticator app, and
// saving backup codes.

import { useState, type ReactNode } from 'react'
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Code,
  CopyButton,
  Group,
  PasswordInput,
  PinInput,
  SimpleGrid,
  Stack,
  Text,
  TextInput,
} from '@mantine/core'
import { IconCopy, IconDeviceMobile, IconDownload } from '@tabler/icons-react'
import type { AuthenticatorSetup, Confirm } from './api'

/** The server's password rules (backend/src/modules/accounts/password.rs), checked here
 *  too so a problem shows before anything is sent. The server still decides. */
export function passwordProblem(password: string, email: string): string | null {
  if ([...password].length < 12) return 'Use at least 12 characters.'
  if (new TextEncoder().encode(password).length > 128) return 'Use at most 128 characters.'
  const lower = password.toLowerCase()
  const squashed = lower.replace(/[^\p{L}\p{N}]/gu, '')
  const local = email.toLowerCase().split('@')[0] ?? ''
  if (squashed.includes('toniebee') || squashed.includes('password') || (local.length >= 4 && lower.includes(local)))
    return 'Don’t use the business name, “password” or your email in it.'
  if (new Set(password).size < 5) return 'Use more different characters.'
  // The server also refuses passwords from lists of common ones (it has the list).
  return null
}

export const PASSWORD_HINT = 'At least 12 characters. A few words you’ll remember works well — like a short sentence.'

/** "Confirm it's you": the password and a code from the authenticator app, or a backup
 *  code. Other fields (`children`) go between them: the code goes last, because it
 *  changes every 30 seconds. */
export function ConfirmFields({
  value,
  onChange,
  passwordLabel = 'Your password',
  children,
}: {
  value: Confirm
  onChange: (value: Confirm) => void
  passwordLabel?: string
  children?: ReactNode
}) {
  return (
    <Stack gap="sm">
      <PasswordInput
        label={passwordLabel}
        autoComplete="current-password"
        required
        value={value.password}
        onChange={(e) => onChange({ ...value, password: e.currentTarget.value })}
      />
      {children}
      <TextInput
        label="Code"
        description="The 6-digit code from your authenticator app — or, if you’ve lost your phone, a backup code."
        autoComplete="one-time-code"
        autoCapitalize="characters"
        required
        value={value.code}
        onChange={(e) => onChange({ ...value, code: e.currentTarget.value })}
      />
    </Stack>
  )
}

/** Adds Toniebee to an authenticator app: a button that opens the app (on the phone
 *  itself), the key to type in, and a QR code for when the page is open on a computer. */
export function AddToAuthenticator({ setup }: { setup: AuthenticatorSetup }) {
  return (
    <Stack gap="sm">
      <Button component="a" href={setup.otpauthUrl} leftSection={<IconDeviceMobile size={18} />} fullWidth>
        Add to my authenticator app
      </Button>
      <Text size="xs" c="dimmed">
        Opens Google Authenticator (or the authenticator app you use) to add Toniebee. No app yet? Install Google
        Authenticator from the Play Store or App Store first.
      </Text>
      <Box>
        <Text size="sm" fw={600}>
          Nothing opened? Type this key into the app
        </Text>
        <Text size="xs" c="dimmed" mb={6}>
          In the app: + → “Enter a setup key”. Any name (say “Toniebee”), this key, “Time based”.
        </Text>
        <Group gap="xs" wrap="nowrap" align="center">
          <Code fz="sm" p="xs" className="tb-admin__key" style={{ flex: 1, minWidth: 0 }}>
            {setup.key}
          </Code>
          <CopyButton value={setup.key.replace(/ /g, '')}>
            {({ copied, copy }) => (
              <Button
                variant="default"
                size="xs"
                leftSection={<IconCopy size={14} />}
                onClick={copy}
                style={{ flexShrink: 0 }}
              >
                {copied ? 'Copied' : 'Copy'}
              </Button>
            )}
          </CopyButton>
        </Group>
      </Box>
      <Box visibleFrom="sm">
        <Text size="sm" fw={600} mb={6}>
          On a computer? Scan this with the phone’s authenticator app
        </Text>
        <img
          src={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(setup.qrSvg)}`}
          width={180}
          height={180}
          alt="QR code for your authenticator app"
          className="tb-admin__qr"
        />
      </Box>
    </Stack>
  )
}

/** The 6-digit code from the app, typed in boxes; sends itself when all 6 are filled.
 *  Sent from onChange, not PinInput's onComplete: that fires only once until the
 *  person deletes a digit themselves, so after a wrong code is cleared, a right code
 *  pasted in (copied from the app) was never sent (found 2026-10-29). */
export function CodeBoxes({
  value,
  onChange,
  onComplete,
  disabled,
  label,
}: {
  value: string
  onChange: (value: string) => void
  onComplete: (value: string) => void
  disabled?: boolean
  label: string
}) {
  return (
    <Group justify="center">
      <PinInput
        length={6}
        type="number"
        oneTimeCode
        value={value}
        onChange={(next) => {
          onChange(next)
          if (next.length === 6) onComplete(next)
        }}
        disabled={disabled}
        aria-label={label}
      />
    </Group>
  )
}

/** Backup codes, shown once: copy or download them, and say they're saved to go on. */
export function BackupCodesSaver({
  codes,
  email,
  doneLabel,
  onDone,
}: {
  codes: string[]
  email: string
  doneLabel: string
  onDone: () => void
}) {
  const [saved, setSaved] = useState(false)
  const text = `Toniebee admin backup codes — ${email}\nEach works once, in place of the authenticator code (for a lost phone).\n\n${codes.join('\n')}\n`
  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const link = document.createElement('a')
    link.href = url
    link.download = 'toniebee-backup-codes.txt'
    link.click()
    URL.revokeObjectURL(url)
  }
  return (
    <Stack gap="md">
      <Alert color="navy" variant="light">
        <Text size="sm">
          These are shown only now. If you lose your phone, each code signs you in once instead of the app’s
          code. Write them down or keep them in a password manager — not only on this phone.
        </Text>
      </Alert>
      <SimpleGrid cols={2} spacing="xs" className="tb-admin__codes">
        {codes.map((code) => (
          <Code key={code} fz="md" ta="center" p={6} block>
            {code}
          </Code>
        ))}
      </SimpleGrid>
      <Group grow>
        <CopyButton value={text}>
          {({ copied, copy }) => (
            <Button variant="default" leftSection={<IconCopy size={16} />} onClick={copy}>
              {copied ? 'Copied' : 'Copy all'}
            </Button>
          )}
        </CopyButton>
        <Button variant="default" leftSection={<IconDownload size={16} />} onClick={download}>
          Download
        </Button>
      </Group>
      <Checkbox
        label="I’ve saved them somewhere safe"
        checked={saved}
        onChange={(e) => setSaved(e.currentTarget.checked)}
      />
      <Button disabled={!saved} onClick={onDone}>
        {doneLabel}
      </Button>
    </Stack>
  )
}
