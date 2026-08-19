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
  ActionIcon,
} from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { IconFileText, IconPlus, IconChevronRight, IconCalendar, IconCheck, IconX, IconClock } from '@tabler/icons-react';
import { DarkLayout } from '../components/DarkLayout';
import { notifications } from '@mantine/notifications';

interface Quote {
  id: string;
  service_type: string;
  coverage_amount: number;
  coverage_term: number | null;
  status: string;
  created_at: string;
  updated_at: string;
}

export function QuotesPage() {
  const navigate = useNavigate();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [quotes, setQuotes] = useState<Quote[]>([]);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    fetchUser();
    fetchQuotes();
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

  async function fetchQuotes() {
    try {
      const resp = await fetch('/api/quotes', {
        credentials: 'include',
      });
      if (resp.status === 200) {
        const data = await resp.json();
        setQuotes(data.data || []);
      } else if (resp.status === 401) {
        notifications.show({
          title: 'Authentication Required',
          message: 'Please log in to view your quotes',
          color: 'orange',
        });
        navigate('/login');
      } else {
        const errorData = await resp.json().catch(() => ({ message: 'Failed to load quotes' }));
        notifications.show({
          title: 'Error',
          message: errorData.message || 'Failed to load quotes',
          color: 'red',
        });
      }
    } catch (error) {
      console.error('Error fetching quotes:', error);
      notifications.show({
        title: 'Connection Error',
        message: 'Failed to connect to server. Please check your connection.',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'approved':
        return 'green';
      case 'rejected':
        return 'red';
      case 'pending':
        return 'yellow';
      case 'under_review':
        return 'blue';
      default:
        return 'gray';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'approved':
        return <IconCheck size={16} />;
      case 'rejected':
        return <IconX size={16} />;
      case 'pending':
        return <IconClock size={16} />;
      default:
        return <IconClock size={16} />;
    }
  };

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
      <DarkLayout user={user} title="My Quotes">
        <Center h="60vh">
          <Loader size="lg" />
        </Center>
      </DarkLayout>
    );
  }

  return (
    <DarkLayout user={user} title="My Quotes">
      <Container size="xl" py="xl">
        <Stack gap="xl">
          {/* Header */}
          <Group justify="space-between" align="flex-start">
            <Box>
              <Title order={1} size={isMobile ? rem(28) : rem(36)} mb="xs" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
                My Quotes
              </Title>
              <Text size="lg" c="gray.2" style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
                Track and manage your insurance quote requests
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
              New Quote
            </Button>
          </Group>

          {/* Quotes List */}
          {quotes.length === 0 ? (
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
                <IconFileText size={48} style={{ color: 'var(--mantine-color-gray-5)' }} />
                <Text size="lg" fw={500} c="white" ta="center">
                  No quotes yet
                </Text>
                <Text size="sm" c="gray.3" ta="center">
                  Get started by requesting your first insurance quote
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
              {quotes.map((quote) => (
                <Card
                  key={quote.id}
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
                  onClick={() => navigate(`/quotes/${quote.id}`)}
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
                          {quote.service_type.charAt(0).toUpperCase() + quote.service_type.slice(1).replace('_', ' ')} Insurance
                        </Text>
                        <Text size="xl" fw={700} c="white" mb={4}>
                          {formatCurrency(quote.coverage_amount)}
                        </Text>
                        {quote.coverage_term && (
                          <Text size="sm" c="gray.3">
                            Term: {quote.coverage_term} years
                          </Text>
                        )}
                      </Box>
                      <Badge
                        color={getStatusColor(quote.status)}
                        variant="light"
                        leftSection={getStatusIcon(quote.status)}
                      >
                        {quote.status.replace('_', ' ').charAt(0).toUpperCase() + quote.status.slice(1).replace('_', ' ')}
                      </Badge>
                    </Group>

                    <Group gap="xs" c="gray.3">
                      <IconCalendar size={14} />
                      <Text size="sm">
                        Requested: {formatDate(quote.created_at)}
                      </Text>
                    </Group>

                    <Group justify="flex-end" mt="md">
                      <ActionIcon
                        variant="subtle"
                        color="gray"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/quotes/${quote.id}`);
                        }}
                      >
                        <IconChevronRight size={18} />
                      </ActionIcon>
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


