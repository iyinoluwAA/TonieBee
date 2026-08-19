import { useEffect, useState, useCallback } from 'react';
import {
  Table,
  Text,
  Paper,
  Group,
  Badge,
  Select,
  TextInput,
  Button,
  Pagination,
  Title,
  Loader,
  Center,
  Stack,
  Card,
  Grid,
  Modal,
  Alert,
  Tabs,
  ActionIcon,
  Tooltip,
  Divider,
  RingProgress,
  Progress,
  Box,
  Code,
  CopyButton,
  Menu,
  ScrollArea,
  SimpleGrid,
} from '@mantine/core';
import {
  IconShield,
  IconAlertTriangle,
  IconLock,
  IconBan,
  IconClock,
  IconSearch,
  IconFilter,
  IconDownload,
  IconRefresh,
  IconEye,
  IconX,
  IconCopy,
  IconCheck,
  IconMapPin,
  IconUser,
  IconServer,
  IconChartLine,
  IconFileExport,
  IconHelpCircle,
} from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';
import { BarChart, PieChart } from '@mantine/charts';
import { DatePickerInput } from '@mantine/dates';
import dayjs from 'dayjs';
import { SecurityDashboardHelpModal } from './SecurityDashboardHelpModal';

interface SecurityEvent {
  id: string;
  user_id: string | null;
  action: string;
  resource: string;
  ip_address: string | null;
  user_agent: string | null;
  timestamp: string;
}

interface SecurityEventsResponse {
  events: SecurityEvent[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

interface SecurityStatistics {
  total_events: number;
  critical_events: number;
  /** Live rolling count from server UTC; ignores date pickers */
  rolling_24h: number;
  last_24h: number;
  failed_logins: number;
  rate_limits: number;
  suspicious_activity: number;
  account_lockouts: number;
  top_ips: TopIp[];
  events_by_type: EventTypeCount[];
  timeline_data: TimelinePoint[];
}

interface TopIp {
  ip_address: string;
  event_count: number;
  last_seen: string;
  critical_events: number;
}

interface EventTypeCount {
  action: string;
  count: number;
}

interface TimelinePoint {
  hour: string;
  count: number;
  critical_count: number;
}

type StatCardFilter = 'all' | 'critical' | 'last24h' | 'failed_logins' | 'rate_limits' | 'suspicious' | 'lockouts';

/** Mantine theme tokens — PieChart needs these, not bare names like "red". */
const PIE_SLICE_COLORS = ['blue.6', 'red.6', 'orange.6', 'grape.6', 'cyan.6', 'teal.6'] as const;

function dateFromPickerValue(v: string | Date | null): Date | null {
  if (v == null) return null;
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function AdminSecurityPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [statistics, setStatistics] = useState<SecurityStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [actionFilter, setActionFilter] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [ipFilter, setIpFilter] = useState<string | null>(null);
  const [startDate, setStartDate] = useState<Date | null>(null);
  const [endDate, setEndDate] = useState<Date | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [eventModalOpen, setEventModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<string | null>('overview');
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  /** When the last successful `/statistics` response was applied (for honest “snapshot” UX). */
  const [statsSnapshotAt, setStatsSnapshotAt] = useState<Date | null>(null);
  /** Server-side filter: only audit rows whose action is in the critical set (matches overview "Critical Events"). */
  const [criticalOnly, setCriticalOnly] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  const hasDateRange = Boolean(startDate && endDate);

  const fetchStatistics = useCallback(async () => {
    setStatsLoading(true);
    try {
      const params = new URLSearchParams();
      if (startDate) {
        params.append('start_date', startDate.toISOString());
      }
      if (endDate) {
        params.append('end_date', endDate.toISOString());
      }

      const response = await fetch(`/api/security/statistics?${params.toString()}`, {
        credentials: 'include',
        cache: 'no-store',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch statistics');
      }

      const data: SecurityStatistics = await response.json();
      setStatistics(data);
      setStatsSnapshotAt(new Date());
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to load security statistics',
        color: 'red',
      });
    } finally {
      setStatsLoading(false);
    }
  }, [startDate, endDate]);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: '50',
      });

      if (actionFilter) {
        params.append('action', actionFilter);
      }
      if (startDate) {
        params.append('start_date', startDate.toISOString());
      }
      if (endDate) {
        params.append('end_date', endDate.toISOString());
      }
      if (criticalOnly) {
        params.append('critical_only', 'true');
      }

      const response = await fetch(`/api/security/events?${params.toString()}`, {
        credentials: 'include',
        cache: 'no-store',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch security events');
      }

      const data: SecurityEventsResponse = await response.json();
      setEvents(data.events);
      setTotal(data.total);
      setTotalPages(data.total_pages);
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to load security events',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }, [page, actionFilter, startDate, endDate, criticalOnly]);

  const handleRefresh = () => {
    setLastRefresh(new Date());
    fetchStatistics();
    fetchEvents();
    notifications.show({
      title: 'Refreshed',
      message: 'Security data updated',
      color: 'green',
    });
  };

  useEffect(() => {
    fetchStatistics();
  }, [fetchStatistics]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  const handleStatCardClick = (filter: StatCardFilter) => {
    setCriticalOnly(false);
    switch (filter) {
      case 'critical':
        setActionFilter(null);
        setCriticalOnly(true);
        setActiveTab('events');
        break;
      case 'last24h': {
        const end = new Date();
        const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
        setStartDate(start);
        setEndDate(end);
        setActiveTab('overview');
        notifications.show({
          title: 'Preset: last 24 hours',
          message:
            'Start/end set to exactly 24 hours apart (UTC via ISO). Totals and charts match this window. The orange card still shows the live rolling count from the server.',
          color: 'blue',
          autoClose: 9000,
        });
        break;
      }
      case 'failed_logins':
        setActionFilter('FAILED_LOGIN');
        setActiveTab('events');
        break;
      case 'rate_limits':
        setActionFilter('RATE_LIMIT_EXCEEDED');
        setActiveTab('events');
        break;
      case 'suspicious':
        setActionFilter('SUSPICIOUS_ACTIVITY');
        setActiveTab('events');
        break;
      case 'lockouts':
        setActionFilter('ACCOUNT_LOCKOUT');
        setActiveTab('events');
        break;
      default:
        setActionFilter(null);
        setStartDate(null);
        setEndDate(null);
    }
    setPage(1);
  };

  const handleEventClick = async (event: SecurityEvent) => {
    try {
      const response = await fetch(`/api/security/events/${event.id}`, {
        credentials: 'include',
        cache: 'no-store',
      });
      if (response.ok) {
        const eventDetails: SecurityEvent = await response.json();
        setSelectedEvent(eventDetails);
        setEventModalOpen(true);
      }
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to load event details',
        color: 'red',
      });
    }
  };

  const exportToCSV = () => {
    const headers = ['Time', 'Action', 'Resource', 'IP Address', 'User Agent', 'User ID'];
    const rows = events.map((e) => [
      new Date(e.timestamp).toISOString(),
      e.action,
      e.resource,
      e.ip_address || 'N/A',
      e.user_agent || 'N/A',
      e.user_id || 'N/A',
    ]);

    const csv = [headers.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-events-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    notifications.show({
      title: 'Exported',
      message: 'Security events exported to CSV',
      color: 'green',
    });
  };

  const exportToJSON = () => {
    const json = JSON.stringify(events, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-events-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    notifications.show({
      title: 'Exported',
      message: 'Security events exported to JSON',
      color: 'green',
    });
  };

  const getActionBadgeColor = (action: string) => {
    if (action.includes('FAILED') || action.includes('LOCKOUT')) {
      return 'red';
    }
    if (action.includes('RATE_LIMIT') || action.includes('SUSPICIOUS')) {
      return 'orange';
    }
    if (action.includes('ADMIN')) {
      return 'blue';
    }
    return 'gray';
  };

  const getActionIcon = (action: string) => {
    if (action.includes('LOCKOUT')) {
      return <IconLock size={16} />;
    }
    if (action.includes('FAILED')) {
      return <IconBan size={16} />;
    }
    if (action.includes('RATE_LIMIT')) {
      return <IconAlertTriangle size={16} />;
    }
    return <IconClock size={16} />;
  };

  const filteredEvents = events.filter((event) => {
    if (searchTerm) {
      const search = searchTerm.toLowerCase();
      if (
        !event.action.toLowerCase().includes(search) &&
        !event.resource.toLowerCase().includes(search) &&
        !event.ip_address?.toLowerCase().includes(search) &&
        !event.user_agent?.toLowerCase().includes(search)
      ) {
        return false;
      }
    }
    if (ipFilter && event.ip_address !== ipFilter) {
      return false;
    }
    return true;
  });

  const stats = statistics || {
    total_events: 0,
    critical_events: 0,
    rolling_24h: 0,
    last_24h: 0,
    failed_logins: 0,
    rate_limits: 0,
    suspicious_activity: 0,
    account_lockouts: 0,
    top_ips: [],
    events_by_type: [],
    timeline_data: [],
  };

  const rollingLive = stats.rolling_24h ?? stats.last_24h;

  if (loading && events.length === 0 && !statistics) {
    return (
      <Center h={400}>
        <Loader size="lg" />
      </Center>
    );
  }

  return (
    <Stack gap="md">
      <SecurityDashboardHelpModal opened={helpOpen} onClose={() => setHelpOpen(false)} />

      {/* Header */}
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <Stack gap={4}>
          <Title order={2}>
            <Group gap="xs">
              <IconShield size={28} />
              Security Dashboard
            </Group>
          </Title>
          {statsSnapshotAt && (
            <Text size="xs" c="dimmed">
              Statistics snapshot:{' '}
              <Text span fw={600} c="dimmed">
                {statsSnapshotAt.toLocaleString('en-US', { timeZone: 'UTC' })} UTC
              </Text>
              {' · '}
              Refresh loads current DB counts; &quot;Rolling 24h&quot; moves with server time
            </Text>
          )}
        </Stack>
        <Group>
          <Button
            variant="light"
            leftSection={<IconHelpCircle size={18} />}
            onClick={() => setHelpOpen(true)}
          >
            How this works
          </Button>
          <Tooltip label={`Last refreshed: ${lastRefresh.toLocaleTimeString()}`}>
            <ActionIcon variant="light" onClick={handleRefresh} loading={loading || statsLoading}>
              <IconRefresh size={18} />
            </ActionIcon>
          </Tooltip>
          <Menu shadow="md" width={200}>
            <Menu.Target>
              <Button leftSection={<IconFileExport size={16} />} variant="light">
                Export
              </Button>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item leftSection={<IconDownload size={16} />} onClick={exportToCSV}>
                Export as CSV
              </Menu.Item>
              <Menu.Item leftSection={<IconDownload size={16} />} onClick={exportToJSON}>
                Export as JSON
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Group>
      </Group>

      <Tabs value={activeTab} onChange={setActiveTab}>
        <Tabs.List>
          <Tabs.Tab value="overview" leftSection={<IconChartLine size={16} />}>
            Overview
          </Tabs.Tab>
          <Tabs.Tab value="events" leftSection={<IconShield size={16} />}>
            Events
          </Tabs.Tab>
          <Tabs.Tab value="ips" leftSection={<IconMapPin size={16} />}>
            IP Analysis
          </Tabs.Tab>
        </Tabs.List>

        {/* Overview Tab */}
        <Tabs.Panel value="overview" pt="md">
          <Stack gap="md">
            {hasDateRange && (
              <Alert variant="light" color="blue" title="Date range active">
                Totals, critical counts, charts, and pie use the start/end dates from the Events tab
                (UTC). The <strong>Rolling 24h (live)</strong> card is independent — it always uses
                the server clock — so it may differ from Total. Open &quot;How this works&quot; for
                detail.
              </Alert>
            )}

            {/* Statistics Cards - Clickable */}
            <Grid>
              <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
                <Card
                  withBorder
                  padding="md"
                  radius="md"
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleStatCardClick('all')}
                  onMouseEnter={(e) => (e.currentTarget.style.transform = 'scale(1.02)')}
                  onMouseLeave={(e) => (e.currentTarget.style.transform = 'scale(1)')}
                >
                  <Group justify="space-between">
                    <div>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
                        Total Events
                      </Text>
                      <Text size="xl" fw={700}>
                        {stats.total_events.toLocaleString()}
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        {startDate || endDate ? 'Selected date range' : 'All time (database)'}
                      </Text>
                    </div>
                    <IconShield size={32} color="gray" />
                  </Group>
                </Card>
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
                <Card
                  withBorder
                  padding="md"
                  radius="md"
                  style={{ cursor: 'pointer', borderColor: 'var(--mantine-color-red-6)' }}
                  onClick={() => handleStatCardClick('critical')}
                  onMouseEnter={(e) => (e.currentTarget.style.transform = 'scale(1.02)')}
                  onMouseLeave={(e) => (e.currentTarget.style.transform = 'scale(1)')}
                >
                  <Group justify="space-between">
                    <div>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
                        Critical Events
                      </Text>
                      <Text size="xl" fw={700} c="red">
                        {stats.critical_events.toLocaleString()}
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        Failed login, rate limit, lockout, etc.
                      </Text>
                    </div>
                    <IconAlertTriangle size={32} color="red" />
                  </Group>
                </Card>
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
                <Card
                  withBorder
                  padding="md"
                  radius="md"
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleStatCardClick('last24h')}
                  onMouseEnter={(e) => (e.currentTarget.style.transform = 'scale(1.02)')}
                  onMouseLeave={(e) => (e.currentTarget.style.transform = 'scale(1)')}
                >
                  <Group justify="space-between">
                    <div>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
                        Rolling 24h (live)
                      </Text>
                      <Text size="xl" fw={700} c="orange">
                        {rollingLive.toLocaleString()}
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        Server UTC clock — not filtered by date pickers
                      </Text>
                    </div>
                    <IconClock size={32} color="orange" />
                  </Group>
                </Card>
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
                <Card withBorder padding="md" radius="md">
                  <Group justify="space-between">
                    <div>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
                        Failed Logins
                      </Text>
                      <Text size="xl" fw={700} c="red">
                        {stats.failed_logins.toLocaleString()}
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        {startDate || endDate ? 'In selected range' : 'All time'}
                      </Text>
                    </div>
                    <IconBan size={32} color="red" />
                  </Group>
                </Card>
              </Grid.Col>
            </Grid>

            {/* Secondary metrics — equal-width row (no awkward empty grid slot) */}
            <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
              <Card withBorder padding="md" radius="md" style={{ minHeight: 100 }}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700} mb="xs">
                  Rate Limits
                </Text>
                <Text size="lg" fw={700} c="orange">
                  {stats.rate_limits.toLocaleString()}
                </Text>
              </Card>
              <Card withBorder padding="md" radius="md" style={{ minHeight: 100 }}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700} mb="xs">
                  Suspicious Activity
                </Text>
                <Text size="lg" fw={700} c="orange">
                  {stats.suspicious_activity.toLocaleString()}
                </Text>
              </Card>
              <Card withBorder padding="md" radius="md" style={{ minHeight: 100 }}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700} mb="xs">
                  Account Lockouts
                </Text>
                <Text size="lg" fw={700} c="red">
                  {stats.account_lockouts.toLocaleString()}
                </Text>
              </Card>
            </SimpleGrid>

            {/* Charts: equal height columns, room for pie labels */}
            <Grid gutter="md" align="stretch">
              <Grid.Col span={{ base: 12, lg: 8 }}>
                <Paper
                  withBorder
                  p="md"
                  style={{ minHeight: 440, display: 'flex', flexDirection: 'column', height: '100%' }}
                >
                  <Text fw={700} mb="xs">
                    Event timeline
                    {hasDateRange ? ' (selected date range)' : ' (rolling 24h, UTC)'}
                  </Text>
                  {stats.timeline_data.length > 0 ? (
                    <Box style={{ flex: 1, width: '100%', minWidth: 0, minHeight: 360 }}>
                      <Text size="xs" c="dimmed" mb="sm">
                        Hourly buckets (UTC). Stacked: red = critical-type actions; blue = other audited
                        events in that hour (same total height as total events for that hour).
                      </Text>
                      <BarChart
                        h={340}
                        data={stats.timeline_data.map((d) => {
                          const total = Number(d.count);
                          const critical = Number(d.critical_count);
                          return {
                            bucket: d.hour,
                            other: Math.max(0, total - critical),
                            critical,
                          };
                        })}
                        dataKey="bucket"
                        series={[
                          { name: 'other', label: 'Non-critical', color: 'blue.5' },
                          { name: 'critical', label: 'Critical', color: 'red.6' },
                        ]}
                        type="stacked"
                        gridAxis="xy"
                        tickLine="xy"
                        withLegend
                        legendProps={{ verticalAlign: 'bottom', layout: 'horizontal', align: 'center' }}
                        barProps={() => ({ maxBarSize: 56 })}
                        xAxisProps={{
                          tickFormatter: (val: string) => {
                            const s = String(val);
                            const parsed = dayjs(s.replace(' ', 'T'));
                            return parsed.isValid() ? parsed.format('MMM D HH:mm') : s;
                          },
                          angle: stats.timeline_data.length > 3 ? -35 : 0,
                          textAnchor: 'end',
                          height: stats.timeline_data.length > 3 ? 64 : 36,
                          interval: 0,
                        }}
                      />
                    </Box>
                  ) : (
                    <Center style={{ flex: 1 }} mih={300}>
                      <Text c="dimmed">No timeline data for this window</Text>
                    </Center>
                  )}
                </Paper>
              </Grid.Col>
              <Grid.Col span={{ base: 12, lg: 4 }}>
                <Paper
                  withBorder
                  p="md"
                  style={{
                    minHeight: 440,
                    display: 'flex',
                    flexDirection: 'column',
                    height: '100%',
                    overflow: 'visible',
                  }}
                >
                  <Text fw={700} mb="xs">
                    Events by type
                  </Text>
                  <Text size="xs" c="dimmed" mb="sm">
                    Share of actions in the same range as the summary cards (UTC).
                  </Text>
                  {stats.events_by_type.length > 0 ? (
                    <Box
                      style={{
                        flex: 1,
                        width: '100%',
                        minWidth: 0,
                        display: 'flex',
                        justifyContent: 'center',
                        alignItems: 'center',
                        paddingBottom: 48,
                        paddingTop: 8,
                        overflow: 'visible',
                      }}
                    >
                      <PieChart
                        data={stats.events_by_type.slice(0, 8).map((e, i) => ({
                          name: e.action.replace(/_/g, ' '),
                          value: Number(e.count),
                          color: PIE_SLICE_COLORS[i % PIE_SLICE_COLORS.length],
                        }))}
                        withTooltip
                        withLabels
                        withLabelsLine
                        labelsPosition="outside"
                        labelsType="percent"
                        size={170}
                      />
                    </Box>
                  ) : (
                    <Center style={{ flex: 1 }} mih={260}>
                      <Text c="dimmed">No event type data for this window</Text>
                    </Center>
                  )}
                </Paper>
              </Grid.Col>
            </Grid>
          </Stack>
        </Tabs.Panel>

        {/* Events Tab */}
        <Tabs.Panel value="events" pt="md">
          <Stack gap="md">
            {criticalOnly && (
              <Group>
                <Badge color="red" variant="light" size="lg">
                  Critical events only — failed login, rate limit, lockout, suspicious, token checks
                </Badge>
                <Button size="xs" variant="subtle" onClick={() => setCriticalOnly(false)}>
                  Clear
                </Button>
              </Group>
            )}
            {/* Advanced Filters */}
            <Paper withBorder p="md">
              <Stack gap="md">
                <Group grow>
                  <TextInput
                    placeholder="Search events..."
                    leftSection={<IconSearch size={16} />}
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.currentTarget.value)}
                  />
                  <Select
                    placeholder="Filter by action"
                    leftSection={<IconFilter size={16} />}
                    data={[
                      { value: 'FAILED_LOGIN', label: 'Failed Logins' },
                      { value: 'RATE_LIMIT_EXCEEDED', label: 'Rate Limit Exceeded' },
                      { value: 'ACCOUNT_LOCKOUT', label: 'Account Lockouts' },
                      { value: 'SUSPICIOUS_ACTIVITY', label: 'Suspicious Activity' },
                      { value: 'MULTIPLE_FAILED_ATTEMPTS', label: 'Multiple Failed Attempts' },
                      { value: 'ADMIN_ACTION', label: 'Admin Actions' },
                    ]}
                    value={actionFilter}
                    onChange={(v) => {
                      setActionFilter(v);
                      if (v) setCriticalOnly(false);
                    }}
                    clearable
                  />
                  <Select
                    placeholder="Filter by IP"
                    leftSection={<IconMapPin size={16} />}
                    data={Array.from(new Set(events.map((e) => e.ip_address).filter(Boolean))).map((ip) => ({
                      value: ip!,
                      label: ip!,
                    }))}
                    value={ipFilter}
                    onChange={setIpFilter}
                    clearable
                    searchable
                  />
                </Group>
                <Group grow>
                  <DatePickerInput
                    label="Start Date"
                    placeholder="Pick start date"
                    value={startDate}
                    onChange={(v) => setStartDate(dateFromPickerValue(v))}
                    clearable
                  />
                  <DatePickerInput
                    label="End Date"
                    placeholder="Pick end date"
                    value={endDate}
                    onChange={(v) => setEndDate(dateFromPickerValue(v))}
                    clearable
                  />
                  <Group align="flex-end">
                    <Button
                      variant="light"
                      onClick={() => {
                        setStartDate(null);
                        setEndDate(null);
                        setActionFilter(null);
                        setCriticalOnly(false);
                        setIpFilter(null);
                        setSearchTerm('');
                      }}
                    >
                      Clear Filters
                    </Button>
                  </Group>
                </Group>
              </Stack>
            </Paper>

            {/* Events Table */}
            <Paper withBorder>
              <ScrollArea>
                <Table.ScrollContainer minWidth={800}>
                  <Table highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Time</Table.Th>
                      <Table.Th>Action</Table.Th>
                      <Table.Th>Resource</Table.Th>
                      <Table.Th>IP Address</Table.Th>
                      <Table.Th>User Agent</Table.Th>
                      <Table.Th>Actions</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {filteredEvents.length === 0 ? (
                      <Table.Tr>
                        <Table.Td colSpan={6}>
                          <Center p="xl">
                            <Text c="dimmed">No security events found</Text>
                          </Center>
                        </Table.Td>
                      </Table.Tr>
                    ) : (
                      filteredEvents.map((event) => (
                        <Table.Tr
                          key={event.id}
                          style={{ cursor: 'pointer' }}
                          onClick={() => handleEventClick(event)}
                        >
                          <Table.Td>
                            <Text size="sm">
                              {new Date(event.timestamp).toLocaleString('en-US', {
                                month: 'short',
                                day: '2-digit',
                                year: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                                hour12: false,
                              })}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Badge
                              color={getActionBadgeColor(event.action)}
                              leftSection={getActionIcon(event.action)}
                              variant="light"
                            >
                              {event.action}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm" c="dimmed">
                              {event.resource}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm" ff="monospace">
                              {event.ip_address || 'N/A'}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Text size="xs" c="dimmed" lineClamp={1} style={{ maxWidth: 200 }}>
                              {event.user_agent || 'N/A'}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <ActionIcon variant="subtle" onClick={(e) => {
                              e.stopPropagation();
                              handleEventClick(event);
                            }}>
                              <IconEye size={16} />
                            </ActionIcon>
                          </Table.Td>
                        </Table.Tr>
                      ))
                    )}
                  </Table.Tbody>
                </Table>
                </Table.ScrollContainer>
              </ScrollArea>

              {totalPages > 1 && (
                <Group justify="center" p="md">
                  <Pagination value={page} onChange={setPage} total={totalPages} siblings={1} />
                </Group>
              )}
            </Paper>
          </Stack>
        </Tabs.Panel>

        {/* IP Analysis Tab */}
        <Tabs.Panel value="ips" pt="md">
          <Stack gap="md">
            <Paper withBorder p="md">
              <Text fw={700} mb="md">
                Top IP Addresses
              </Text>
              {stats.top_ips.length > 0 ? (
                <Table>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>IP Address</Table.Th>
                      <Table.Th>Total Events</Table.Th>
                      <Table.Th>Critical Events</Table.Th>
                      <Table.Th>Last Seen</Table.Th>
                      <Table.Th>Risk Level</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {stats.top_ips.map((ip) => {
                      const riskLevel = ip.critical_events > 10 ? 'high' : ip.critical_events > 5 ? 'medium' : 'low';
                      return (
                        <Table.Tr
                          key={ip.ip_address}
                          style={{ cursor: 'pointer' }}
                          onClick={() => {
                            setIpFilter(ip.ip_address);
                            setActiveTab('events');
                          }}
                        >
                          <Table.Td>
                            <Text ff="monospace" fw={500}>
                              {ip.ip_address}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Text>{ip.event_count.toLocaleString()}</Text>
                          </Table.Td>
                          <Table.Td>
                            <Badge color={ip.critical_events > 0 ? 'red' : 'gray'} variant="light">
                              {ip.critical_events}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm">
                              {new Date(ip.last_seen).toLocaleString()}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Badge
                              color={riskLevel === 'high' ? 'red' : riskLevel === 'medium' ? 'orange' : 'green'}
                              variant="light"
                            >
                              {riskLevel.toUpperCase()}
                            </Badge>
                          </Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              ) : (
                <Center p="xl">
                  <Text c="dimmed">No IP data available</Text>
                </Center>
              )}
            </Paper>
          </Stack>
        </Tabs.Panel>
      </Tabs>

      {/* Event Detail Modal */}
      <Modal
        opened={eventModalOpen}
        onClose={() => setEventModalOpen(false)}
        title="Event Details"
        size="lg"
      >
        {selectedEvent && (
          <Stack gap="md">
            <Group>
              <Badge
                color={getActionBadgeColor(selectedEvent.action)}
                leftSection={getActionIcon(selectedEvent.action)}
                size="lg"
              >
                {selectedEvent.action}
              </Badge>
            </Group>

            <Divider />

            <Stack gap="xs">
              <Group>
                <IconClock size={16} />
                <Text fw={500}>Timestamp:</Text>
                <Text>{new Date(selectedEvent.timestamp).toLocaleString()}</Text>
              </Group>
              <Group>
                <IconServer size={16} />
                <Text fw={500}>Resource:</Text>
                <Text>{selectedEvent.resource}</Text>
              </Group>
              <Group>
                <IconMapPin size={16} />
                <Text fw={500}>IP Address:</Text>
                <Code>{selectedEvent.ip_address || 'N/A'}</Code>
                {selectedEvent.ip_address && (
                  <CopyButton value={selectedEvent.ip_address}>
                    {({ copied, copy }) => (
                      <ActionIcon variant="subtle" onClick={copy}>
                        {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                      </ActionIcon>
                    )}
                  </CopyButton>
                )}
              </Group>
              {selectedEvent.user_id && (
                <Group>
                  <IconUser size={16} />
                  <Text fw={500}>User ID:</Text>
                  <Code>{selectedEvent.user_id}</Code>
                  <CopyButton value={selectedEvent.user_id}>
                    {({ copied, copy }) => (
                      <ActionIcon variant="subtle" onClick={copy}>
                        {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                      </ActionIcon>
                    )}
                  </CopyButton>
                </Group>
              )}
            </Stack>

            <Divider />

            <Stack gap="xs">
              <Text fw={500}>User Agent:</Text>
              <Code block>{selectedEvent.user_agent || 'N/A'}</Code>
            </Stack>

            <Group justify="flex-end">
              <Button variant="light" onClick={() => setEventModalOpen(false)}>
                Close
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}
