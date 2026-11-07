// The dashboard's first screen: what needs attention today.

import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Alert, Button, Group, Loader, Paper, SimpleGrid, Stack, Text, Title } from '@mantine/core'
import { IconInbox } from '@tabler/icons-react'
import { adminApi, type Overview as OverviewData } from './api'
import { useAdminSession } from './session'

export function Overview() {
  const { session } = useAdminSession()
  const [data, setData] = useState<OverviewData | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    adminApi
      .overview()
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'The overview couldn’t load.'))
  }, [])

  const hello = session.state === 'signedIn' ? session.email.split('@')[0] : ''

  return (
    <Stack gap="lg">
      <Stack gap={2}>
        <Title order={1} fz={26}>
          Hello{hello ? `, ${hello}` : ''}
        </Title>
        <Text c="dimmed" size="sm">
          Consultation requests from the website land here.
        </Text>
      </Stack>
      {error && (
        <Alert color="red" variant="light">
          {error}
        </Alert>
      )}
      {!data && !error ? (
        <Group justify="center" py={60}>
          <Loader color="navy" />
        </Group>
      ) : data ? (
        <>
          {data.email === 'off' && (
            <Alert color="orange" variant="light" title="Email isn’t switched on yet">
              <Text size="sm">
                New requests are saved here, but no email tells you about them until email is set up.
              </Text>
            </Alert>
          )}
          <SimpleGrid cols={{ base: 1, xs: 3 }} spacing="sm">
            <Stat label="New — waiting for you" value={data.requests.new} highlight={data.requests.new > 0} />
            <Stat label="Contacted — in progress" value={data.requests.contacted} />
            <Stat label="Received in the last 7 days" value={data.requests.last7Days} />
          </SimpleGrid>
          <Button component={Link} to="/admin/requests" leftSection={<IconInbox size={18} />} size="md" maw={320}>
            Open the requests
          </Button>
          <Text size="sm" c="dimmed">
            {data.clientAccounts === 0
              ? 'No one has made a client account yet.'
              : `${data.clientAccounts} ${data.clientAccounts === 1 ? 'person has' : 'people have'} a client account.`}
          </Text>
        </>
      ) : null}
    </Stack>
  )
}

function Stat({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <Paper withBorder p="md" style={highlight ? { borderColor: 'var(--mantine-color-orange-6)' } : undefined}>
      <Text fz={30} fw={700} lh={1.1}>
        {value}
      </Text>
      <Text size="sm" c="dimmed">
        {label}
      </Text>
    </Paper>
  )
}
