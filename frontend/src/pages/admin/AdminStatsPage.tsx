import { useEffect, useState } from 'react';
import {
  Group,
  Paper,
  Text,
  Title,
  SimpleGrid,
  Badge,
  Progress,
  RingProgress,
  Stack,
} from '@mantine/core';
import { IconUsers, IconUserCheck, IconShield, IconAlertCircle } from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';

interface Stats {
  totalUsers: number;
  verifiedUsers: number;
  adminUsers: number;
  usersWith2FA: number;
}

export function AdminStatsPage() {
  const [stats, setStats] = useState<Stats>({
    totalUsers: 0,
    verifiedUsers: 0,
    adminUsers: 0,
    usersWith2FA: 0,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStats();
  }, []);

  async function fetchStats() {
    setLoading(true);
    try {
      // Fetch all users by making multiple requests (limit is max 50)
      let allUsers: any[] = [];
      let page = 1;
      const limit = 50;
      let totalUsers = 0;
      let hasMore = true;

      while (hasMore) {
        const resp = await fetch(`/api/users/users?page=${page}&limit=${limit}`, {
          credentials: 'include',
        });

        if (resp.ok) {
          const data = await resp.json();
          allUsers = [...allUsers, ...(data.users || [])];
          totalUsers = data.results || 0;
          
          // Check if we've fetched all users
          if (data.users.length < limit || allUsers.length >= totalUsers) {
            hasMore = false;
          } else {
            page++;
          }
        } else {
          const errorData = await resp.json().catch(() => ({}));
          notifications.show({
            title: 'Error',
            message: errorData.message || 'Failed to fetch statistics',
            color: 'red',
          });
          hasMore = false;
        }
      }
      
      const calculatedStats: Stats = {
        totalUsers: totalUsers || allUsers.length,
        verifiedUsers: allUsers.filter((u: any) => u.verified).length,
        adminUsers: allUsers.filter((u: any) => u.role === 'admin').length,
        usersWith2FA: allUsers.filter((u: any) => u.twoFactorEnabled).length,
      };
      
      setStats(calculatedStats);
    } catch (err) {
      console.error('Error fetching stats:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to fetch statistics',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }

  const verificationRate = stats.totalUsers > 0 
    ? (stats.verifiedUsers / stats.totalUsers) * 100 
    : 0;
  
  const twoFARate = stats.totalUsers > 0 
    ? (stats.usersWith2FA / stats.totalUsers) * 100 
    : 0;

  const statCards = [
    {
      title: 'Total Users',
      value: stats.totalUsers,
      icon: IconUsers,
      color: 'blue',
    },
    {
      title: 'Verified Users',
      value: stats.verifiedUsers,
      icon: IconUserCheck,
      color: 'green',
    },
    {
      title: 'Admin Users',
      value: stats.adminUsers,
      icon: IconShield,
      color: 'red',
    },
    {
      title: '2FA Enabled',
      value: stats.usersWith2FA,
      icon: IconAlertCircle,
      color: 'purple',
    },
  ];

  return (
    <div>
      <Title order={2} mb="lg">
        Dashboard Overview
      </Title>

      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing="md" mb="xl">
        {statCards.map((stat) => (
          <Paper key={stat.title} withBorder p="md" radius="md">
            <Group justify="space-between">
              <div>
                <Text c="dimmed" size="xs" tt="uppercase" fw={700}>
                  {stat.title}
                </Text>
                <Text fw={700} size="xl">
                  {loading ? '...' : stat.value}
                </Text>
              </div>
              <stat.icon size={32} stroke={1.5} color="var(--mantine-color-blue-6)" />
            </Group>
          </Paper>
        ))}
      </SimpleGrid>

      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
        <Paper withBorder p="md" radius="md">
          <Text fw={700} mb="md">
            Verification Status
          </Text>
          <Stack gap="xs">
            <Group justify="space-between">
              <Text size="sm">Verified</Text>
              <Text size="sm" fw={500}>
                {verificationRate.toFixed(1)}%
              </Text>
            </Group>
            <Progress value={verificationRate} color="green" size="lg" radius="xl" />
            <Text size="xs" c="dimmed">
              {stats.verifiedUsers} of {stats.totalUsers} users verified
            </Text>
          </Stack>
        </Paper>

        <Paper withBorder p="md" radius="md">
          <Text fw={700} mb="md">
            2FA Adoption
          </Text>
          <Stack gap="xs">
            <Group justify="space-between">
              <Text size="sm">Enabled</Text>
              <Text size="sm" fw={500}>
                {twoFARate.toFixed(1)}%
              </Text>
            </Group>
            <Progress value={twoFARate} color="purple" size="lg" radius="xl" />
            <Text size="xs" c="dimmed">
              {stats.usersWith2FA} of {stats.totalUsers} users have 2FA enabled
            </Text>
          </Stack>
        </Paper>
      </SimpleGrid>
    </div>
  );
}

