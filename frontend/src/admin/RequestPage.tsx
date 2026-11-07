// One consultation request: who, how to reach them, what about — plus the owner's own
// status and private notes. Saves carry the version the page was opened at, so two
// admins can't overwrite each other.

import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  Alert,
  Anchor,
  Badge,
  Button,
  Group,
  Loader,
  Modal,
  Paper,
  SegmentedControl,
  Stack,
  Text,
  Textarea,
  Title,
} from '@mantine/core'
import { notifications } from '@mantine/notifications'
import { IconArrowLeft, IconMail, IconPhone, IconTrash } from '@tabler/icons-react'
import {
  adminApi,
  AdminApiError,
  BEST_TIME_NAMES,
  INTEREST_NAMES,
  STATUS_COLORS,
  STATUS_NAMES,
  type RequestDetail,
  type RequestStatus,
} from './api'
import { ago } from './Requests'

const PROVINCES: Record<string, string> = {
  AB: 'Alberta', BC: 'British Columbia', MB: 'Manitoba', NB: 'New Brunswick', NL: 'Newfoundland and Labrador',
  NS: 'Nova Scotia', NT: 'Northwest Territories', NU: 'Nunavut', ON: 'Ontario', PE: 'Prince Edward Island',
  QC: 'Quebec', SK: 'Saskatchewan', YT: 'Yukon',
}

export function RequestPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const [request, setRequest] = useState<RequestDetail | null>(null)
  const [notes, setNotes] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  const show = (r: RequestDetail) => {
    setRequest(r)
    setNotes(r.adminNotes ?? '')
  }

  useEffect(() => {
    adminApi
      .request(id)
      .then(show)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'This request couldn’t load.'))
  }, [id])

  const save = async (change: { status?: RequestStatus; notes?: string }) => {
    if (!request) return
    setBusy(true)
    setError(null)
    try {
      show(await adminApi.updateRequest(request.id, { version: request.version, ...change }))
      notifications.show({ message: 'Saved.', autoClose: 2500 })
    } catch (e) {
      setError(
        e instanceof AdminApiError && e.status === 409
          ? `${e.message} (Your unsaved notes are still in the box — copy them before reloading.)`
          : e instanceof Error
            ? e.message
            : 'Not saved.',
      )
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    if (!request) return
    setBusy(true)
    try {
      await adminApi.deleteRequest(request.id, request.version)
      notifications.show({ message: `${request.name}’s request is deleted.` })
      navigate('/admin/requests', { replace: true })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Not deleted.')
      setDeleting(false)
    } finally {
      setBusy(false)
    }
  }

  if (!request) {
    return error ? (
      <Stack gap="md">
        <BackLink />
        <Alert color="red" variant="light">
          {error}
        </Alert>
      </Stack>
    ) : (
      <Group justify="center" py={80}>
        <Loader color="navy" />
      </Group>
    )
  }

  const notesChanged = notes.trim() !== (request.adminNotes ?? '')

  return (
    <Stack gap="md">
      <BackLink />
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <Stack gap={2} style={{ minWidth: 0 }}>
          <Title order={1} fz={26} style={{ overflowWrap: 'anywhere' }}>
            {request.name}
          </Title>
          <Text size="sm" c="dimmed">
            Sent {ago(request.createdAt)} · {new Date(request.createdAt).toLocaleString()}
          </Text>
        </Stack>
        <Badge color={STATUS_COLORS[request.status]} variant="light" size="lg" style={{ flexShrink: 0 }}>
          {STATUS_NAMES[request.status]}
        </Badge>
      </Group>

      <Paper withBorder p="md">
        <Stack gap="sm">
          <Text fw={600}>
            Prefers {request.contactBy === 'phone' ? 'a phone call' : 'email'} ·{' '}
            {BEST_TIME_NAMES[request.bestTime].toLowerCase()}
          </Text>
          <Group gap="sm">
            {request.phone && (
              <Button component="a" href={`tel:${request.phone.replace(/[^\d+]/g, '')}`} leftSection={<IconPhone size={18} />}>
                {request.phone}
              </Button>
            )}
            <Button
              component="a"
              href={`mailto:${request.email}`}
              variant={request.phone ? 'default' : 'filled'}
              leftSection={<IconMail size={18} />}
              style={{ maxWidth: '100%' }}
            >
              <Text span truncate>
                {request.email}
              </Text>
            </Button>
          </Group>
          <Text size="sm">
            <b>About:</b> {request.interests.map((i) => INTEREST_NAMES[i]).join(', ')}
          </Text>
          <Text size="sm">
            <b>Lives in:</b> {PROVINCES[request.province] ?? request.province}
          </Text>
          {request.message && (
            <Paper bg="var(--mantine-color-gray-0)" p="sm">
              <Text size="sm" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
                {request.message}
              </Text>
            </Paper>
          )}
          <Text size="xs" c="dimmed">
            Agreed to be contacted about this request on {new Date(request.consentAt).toLocaleString()} (wording of{' '}
            {request.consentVersion}).{request.signedIn ? ' Sent while signed in to their client account.' : ''}
          </Text>
        </Stack>
      </Paper>

      <Paper withBorder p="md">
        <Stack gap="sm">
          <Text fw={600}>Where it’s at</Text>
          <SegmentedControl
            fullWidth
            disabled={busy}
            aria-label="Status"
            data={(['new', 'contacted', 'closed'] as RequestStatus[]).map((s) => ({ value: s, label: STATUS_NAMES[s] }))}
            value={request.status}
            onChange={(value) => void save({ status: value as RequestStatus })}
          />
          <Textarea
            label="Your notes"
            description="Private — never shown to the client. Avoid writing health details here."
            autosize
            minRows={3}
            maxRows={12}
            maxLength={4000}
            value={notes}
            onChange={(e) => setNotes(e.currentTarget.value)}
          />
          <Group justify="flex-end">
            <Button disabled={!notesChanged} loading={busy} onClick={() => void save({ notes: notes.trim() })}>
              Save notes
            </Button>
          </Group>
          {error && (
            <Alert color="red" variant="light">
              {error}
            </Alert>
          )}
        </Stack>
      </Paper>

      <Group justify="space-between">
        <Text size="xs" c="dimmed">
          {request.status === 'closed' && request.closedAt
            ? `Closed ${ago(request.closedAt)}. Closed requests are deleted automatically after 2 years.`
            : 'Close it when it’s done; closed requests are deleted automatically after 2 years.'}
        </Text>
        <Button variant="subtle" color="red" leftSection={<IconTrash size={16} />} onClick={() => setDeleting(true)}>
          Delete now
        </Button>
      </Group>

      <Modal opened={deleting} onClose={() => setDeleting(false)} title="Delete this request?" centered>
        <Stack gap="md">
          <Text size="sm">
            {request.name}’s request and your notes are deleted for good. Do this when someone asks you to forget their
            information.
          </Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setDeleting(false)}>
              Keep it
            </Button>
            <Button color="red" loading={busy} onClick={() => void remove()}>
              Delete
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  )
}

function BackLink() {
  return (
    <Anchor component={Link} to="/admin/requests" size="sm">
      <Group gap={4}>
        <IconArrowLeft size={16} /> All requests
      </Group>
    </Anchor>
  )
}
