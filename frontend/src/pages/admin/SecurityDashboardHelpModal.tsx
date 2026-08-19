import { Modal, Stack, Text, Title, List, Divider, Code } from '@mantine/core';

type Props = {
  opened: boolean;
  onClose: () => void;
};

/**
 * Explains how Security overview metrics relate to each other so admins do not confuse
 * "total in range" with "rolling 24h live" or expect charts to ignore filters.
 */
export function SecurityDashboardHelpModal({ opened, onClose }: Props) {
  return (
    <Modal opened={opened} onClose={onClose} title={<Title order={4}>How to read this dashboard</Title>} size="lg">
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Audit data comes from the <Code>audit_logs</Code> table. Numbers only match when you know
          which time window each card uses.
        </Text>

        <Title order={5}>Why numbers change when you refresh or come back</Title>
        <Text size="sm">
          Each refresh asks the server for <strong>current</strong> data. The database can have new
          rows (logins, audits). The <strong>rolling 24h</strong> window also moves with server time,
          so its count is supposed to change over minutes and hours — that is not a bug. Fixed date
          ranges (your pickers) only change when you change the dates or when new events appear inside
          that window. The header shows a <strong>statistics snapshot time (UTC)</strong> so you know
          exactly what moment the numbers describe.
        </Text>

        <Title order={5}>Two different clocks</Title>
        <List size="sm" spacing="xs">
          <List.Item>
            <strong>Total Events, Critical, Failed logins, Rate limits, …</strong> — When you set a{' '}
            <strong>start / end date</strong> on the Events tab (or use a card preset), these counts
            include only rows whose timestamp falls <em>inside that range</em> (sent to the API as
            UTC ISO strings).
          </List.Item>
          <List.Item>
            <strong>Rolling 24h (orange card)</strong> — Always counts rows from the last 24 hours
            using the <strong>server&apos;s current UTC time</strong>. It does <strong>not</strong>{' '}
            follow your date pickers. Use it to see &quot;what happened recently on the server&quot;
            even while you have a wider or different range selected for investigation.
          </List.Item>
        </List>

        <Title order={5}>Why clicking &quot;Last 24 Hours&quot; changes everything</Title>
        <Text size="sm">
          That preset sets <strong>start = now − 24 hours</strong> and <strong>end = now</strong>{' '}
          (exactly 24 hours, not &quot;yesterday this time&quot;). Then Total, Critical, charts, and
          pie all use <strong>that same window</strong>, so they line up. The orange{' '}
          <strong>Rolling 24h</strong> number may still differ slightly because it uses the
          server&apos;s &quot;now&quot; at request time, not your browser clock.
        </Text>

        <Title order={5}>Charts</Title>
        <Text size="sm">
          The <strong>timeline</strong> and <strong>events by type</strong> use the same rule: if a
          date range is active, they show that range; if not, the timeline defaults to the last 24h
          of server time.
        </Text>

        <Title order={5}>Clicking a card</Title>
        <List size="sm" spacing="xs">
          <List.Item>
            <strong>Total</strong> — Clears date filters (all time) and opens the Events list.
          </List.Item>
          <List.Item>
            <strong>Critical</strong> — Events tab, only &quot;critical&quot; action types.
          </List.Item>
          <List.Item>
            <strong>Last 24h preset</strong> — Sets the 24h range (see above), stays on Overview.
          </List.Item>
          <List.Item>
            <strong>Failed logins / rate limits / …</strong> — Events tab with that action filter.
          </List.Item>
        </List>

        <Divider />

        <Text size="xs" c="dimmed">
          Next steps for the standalone auth extraction: open{' '}
          <Code>docs/STANDALONE_AUTH_LADDER.md</Code> in the repository (not served by the dev
          server).
        </Text>
      </Stack>
    </Modal>
  );
}
