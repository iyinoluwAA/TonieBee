// The inbox: consultation requests, newest first, by status. The list shows no contact
// details — they're on each request's own page (and opening it is logged).

import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { Alert, Badge, Box, Button, Group, Loader, Paper, Stack, Text, Title } from '@mantine/core'
import { IconMessage } from '@tabler/icons-react'
import {
  adminApi,
  BEST_TIME_NAMES,
  INTEREST_NAMES,
  STATUS_COLORS,
  STATUS_NAMES,
  type RequestFilter,
  type RequestPage,
  type RequestRow,
} from './api'

const FILTERS: { value: RequestFilter; label: string }[] = [
  { value: 'open', label: 'To do' },
  { value: 'new', label: 'New' },
  { value: 'contacted', label: 'Contacted' },
  { value: 'closed', label: 'Closed' },
]

export function Requests() {
  const [params, setParams] = useSearchParams()
  const filter = (FILTERS.find((f) => f.value === params.get('show'))?.value ?? 'open') as RequestFilter
  const [rows, setRows] = useState<RequestRow[] | null>(null)
  const [page, setPage] = useState<RequestPage | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const latest = useRef(0)

  const load = async (before?: string) => {
    const request = ++latest.current
    setBusy(true)
    try {
      const next = await adminApi.requests(filter, before)
      if (request !== latest.current) return
      setPage(next)
      setRows((current) => [...(before ? (current ?? []) : []), ...next.requests])
      setError(null)
    } catch (e) {
      if (request === latest.current) setError(e instanceof Error ? e.message : 'The requests couldn’t load.')
    } finally {
      if (request === latest.current) setBusy(false)
    }
  }

  useEffect(() => {
    setRows(null)
    void load()
  }, [filter])

  const counts = page?.counts
  const label = (f: { value: RequestFilter; label: string }) => {
    if (!counts) return f.label
    const n = f.value === 'open' ? counts.new + counts.contacted : f.value === 'all' ? 0 : counts[f.value]
    return n ? `${f.label} (${n})` : f.label
  }

  return (
    <Stack gap="md">
      <Stack gap={0}>
        <Title order={1} fz={26}>
          Requests
        </Title>
        <Text c="dimmed" size="sm">
          People who asked for a consultation on the website.
        </Text>
      </Stack>
      {/* Buttons that wrap, so every filter fits a phone screen. */}
      <Group gap={6} role="group" aria-label="Which requests">
        {FILTERS.map((f) => (
          <Button
            key={f.value}
            size="compact-sm"
            radius="xl"
            variant={filter === f.value ? 'filled' : 'default'}
            aria-pressed={filter === f.value}
            onClick={() => setParams(f.value === 'open' ? {} : { show: f.value }, { replace: true })}
          >
            {label(f)}
          </Button>
        ))}
      </Group>
      {error && (
        <Alert color="red" variant="light">
          {error}
        </Alert>
      )}
      {!rows ? (
        <Group justify="center" py={80}>
          <Loader color="navy" />
        </Group>
      ) : rows.length === 0 ? (
        <Paper withBorder p="xl">
          <Text c="dimmed" ta="center">
            {filter === 'open' ? 'Nothing to do — no new or open requests.' : 'None here.'}
          </Text>
        </Paper>
      ) : (
        <Stack gap="xs">
          {rows.map((r) => (
            <Paper key={r.id} withBorder p="sm" component={Link} to={`/admin/requests/${r.id}`} className="tb-admin__row">
              <Group justify="space-between" align="flex-start" wrap="nowrap" gap="sm">
                <Box style={{ minWidth: 0 }}>
                  <Group gap={6} wrap="nowrap">
                    <Text fw={600} truncate>
                      {r.name}
                    </Text>
                    {r.hasMessage && <IconMessage size={16} aria-label="Left a message" style={{ flexShrink: 0 }} />}
                  </Group>
                  <Text size="sm" c="dimmed">
                    {r.interests.map((i) => INTEREST_NAMES[i]).join(' · ')} · {r.province}
                  </Text>
                  <Text size="xs" c="dimmed">
                    Prefers {r.contactBy === 'phone' ? 'a call' : 'email'} · {BEST_TIME_NAMES[r.bestTime].toLowerCase()} ·{' '}
                    {ago(r.createdAt)}
                  </Text>
                </Box>
                <Badge color={STATUS_COLORS[r.status]} variant="light" style={{ flexShrink: 0 }}>
                  {STATUS_NAMES[r.status]}
                </Badge>
              </Group>
            </Paper>
          ))}
          {page?.nextCursor && (
            <Button variant="default" onClick={() => void load(page.nextCursor ?? undefined)} loading={busy}>
              Older
            </Button>
          )}
        </Stack>
      )}
    </Stack>
  )
}

/** "just now", "3 h ago", "2 days ago", then the date. */
export function ago(iso: string): string {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`
  const days = Math.floor(seconds / 86_400)
  if (days < 14) return `${days} day${days === 1 ? '' : 's'} ago`
  return new Date(iso).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' })
}
