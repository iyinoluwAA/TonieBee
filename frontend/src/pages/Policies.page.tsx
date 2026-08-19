import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Title,
  Text,
  Stack,
  Card,
  Group,
  Badge,
  Button,
  Loader,
  Center,
  SimpleGrid,
  Box,
  rem,
  Paper,
} from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { IconShield, IconPlus, IconFileText } from '@tabler/icons-react';
import { DarkLayout } from '../components/DarkLayout';
import { notifications } from '@mantine/notifications';

interface Policy {
  id: string;
  policy_number: string;
  policy_type: string;
  status: string;
  premium_amount: number;
  coverage_amount: number;
  start_date: string;
  end_date: string | null;
}

export function PoliciesPage() {
  const navigate = useNavigate();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    fetchUser();
    fetchPolicies();
  }, []);

  async function fetchUser() {
    try {
      const resp = await fetch('/api/users/me', {
        credentials: 'include',
      });
      if (resp.status === 200) {
        const data = await resp.json();
        setUser(data.data.user);
      } else if (resp.status === 401) {
        navigate('/login');
      }
    } catch (error) {
      console.error('Error fetching user:', error);
    }
  }

  async function fetchPolicies() {
    try {
      const resp = await fetch('/api/policies', {
        credentials: 'include',
      });
      if (resp.status === 200) {
        const data = await resp.json();
        setPolicies(data.data || []);
      } else if (resp.status === 401) {
        navigate('/login');
      } else {
        notifications.show({
          title: 'Error',
          message: 'Failed to load policies',
          color: 'red',
        });
      }
    } catch (error) {
      console.error('Error fetching policies:', error);
      notifications.show({
        title: 'Error',
        message: 'Failed to connect to server',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-CA', {
      style: 'currency',
      currency: 'CAD',
    }).format(amount);
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-CA', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  if (loading) {
    return (
      <DarkLayout user={user} title="My Policies">
        <Center h="60vh">
          <Loader size="lg" />
        </Center>
      </DarkLayout>
    );
  }

  return (
    <DarkLayout user={user} title="My Policies">
      <Container size="xl" py="xl">
        <Stack gap="xl">
          {/* Header */}
          <Group justify="space-between" align="flex-start">
            <Box>
              <Title order={1} size={isMobile ? rem(28) : rem(36)} mb="xs" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
                My Policies
              </Title>
              <Text size="lg" c="gray.2" style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
                View and manage your active insurance policies
              </Text>
            </Box>
            <Button
              size={isMobile ? 'md' : 'lg'}
              leftSection={<IconPlus size={18} />}
              onClick={() => navigate('/quote')}
              style={{
                background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                border: 'none',
              }}
            >
              Get New Policy
            </Button>
          </Group>

          {/* Policies List */}
          {policies.length === 0 ? (
            <Paper
              p="xl"
              radius="lg"
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                borderColor: 'rgba(255, 255, 255, 0.1)',
                backdropFilter: 'blur(10px)',
              }}
              withBorder
            >
              <Stack align="center" gap="md">
                <IconShield size={48} style={{ color: 'var(--mantine-color-gray-5)' }} />
                <Text size="lg" fw={500} c="white" ta="center">
                  No active policies
                </Text>
                <Text size="sm" c="gray.3" ta="center">
                  Get started by requesting a quote for insurance coverage
                </Text>
                <Button
                  leftSection={<IconPlus size={18} />}
                  onClick={() => navigate('/quote')}
                  style={{
                    background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                    border: 'none',
                  }}
                >
                  Request a Quote
                </Button>
              </Stack>
            </Paper>
          ) : (
            <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
              {policies.map((policy) => (
                <Card
                  key={policy.id}
                  padding="lg"
                  radius="md"
                  withBorder
                  style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    backdropFilter: 'blur(10px)',
                    cursor: 'pointer',
                    transition: 'all 0.3s ease',
                  }}
                  onClick={() => navigate(`/policies/${policy.id}`)}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = 'translateY(-4px)';
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = 'translateY(0)';
                    e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
                  }}
                >
                  <Stack gap="md">
                    <Group justify="space-between" align="flex-start">
                      <Box>
                        <Text fw={700} size="lg" c="white" mb={4} style={{ textShadow: '0 1px 3px rgba(0, 0, 0, 0.3)' }}>
                          {policy.policy_type.charAt(0).toUpperCase() + policy.policy_type.slice(1).replace('_', ' ')} Insurance
                        </Text>
                        <Text size="xs" c="gray.3" mb={4}>
                          Policy #{policy.policy_number}
                        </Text>
                        <Text size="xl" fw={700} c="white" mb={4}>
                          {formatCurrency(policy.coverage_amount)}
                        </Text>
                        <Text size="sm" c="gray.3">
                          Premium: {formatCurrency(policy.premium_amount)}/month
                        </Text>
                      </Box>
                      <Badge
                        color={policy.status === 'active' ? 'green' : 'gray'}
                        variant="light"
                      >
                        {policy.status.charAt(0).toUpperCase() + policy.status.slice(1)}
                      </Badge>
                    </Group>

                    <Group gap="md" c="gray.3">
                      <Text size="sm">
                        Started: {formatDate(policy.start_date)}
                      </Text>
                      {policy.end_date && (
                        <Text size="sm">
                          Ends: {formatDate(policy.end_date)}
                        </Text>
                      )}
                    </Group>
                  </Stack>
                </Card>
              ))}
            </SimpleGrid>
          )}
        </Stack>
      </Container>
    </DarkLayout>
  );
}



