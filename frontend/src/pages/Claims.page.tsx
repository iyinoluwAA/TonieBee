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
import { IconAlertCircle, IconPlus, IconClock, IconCheck, IconX, IconChevronRight } from '@tabler/icons-react';
import { DarkLayout } from '../components/DarkLayout';
import { notifications } from '@mantine/notifications';

interface Claim {
  id: string;
  claim_type: string;
  claim_amount: number;
  status: string;
  incident_date: string;
  submitted_date: string;
  description: string | null;
}

export function ClaimsPage() {
  const navigate = useNavigate();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [claims, setClaims] = useState<Claim[]>([]);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    fetchUser();
    fetchClaims();
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

  async function fetchClaims() {
    try {
      const resp = await fetch('/api/claims', {
        credentials: 'include',
      });
      if (resp.status === 200) {
        const data = await resp.json();
        setClaims(data.data || []);
      } else if (resp.status === 401) {
        navigate('/login');
      } else {
        notifications.show({
          title: 'Error',
          message: 'Failed to load claims',
          color: 'red',
        });
      }
    } catch (error) {
      console.error('Error fetching claims:', error);
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

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'approved':
        return 'green';
      case 'rejected':
        return 'red';
      case 'under_review':
        return 'blue';
      case 'pending':
        return 'yellow';
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
      default:
        return <IconClock size={16} />;
    }
  };

  if (loading) {
    return (
      <DarkLayout user={user} title="Claims">
        <Center h="60vh">
          <Loader size="lg" />
        </Center>
      </DarkLayout>
    );
  }

  return (
    <DarkLayout user={user} title="Claims">
      <Container size="xl" py="xl">
        <Stack gap="xl">
          {/* Header */}
          <Group justify="space-between" align="flex-start">
            <Box>
              <Title order={1} size={isMobile ? rem(28) : rem(36)} mb="xs" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
                My Claims
              </Title>
              <Text size="lg" c="gray.2" style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
                Submit and track your insurance claims
              </Text>
            </Box>
            <Button
              size={isMobile ? 'md' : 'lg'}
              leftSection={<IconPlus size={18} />}
              onClick={() => navigate('/claims/new')}
              style={{
                background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                border: 'none',
              }}
            >
              Submit Claim
            </Button>
          </Group>

          {/* Claims List */}
          {claims.length === 0 ? (
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
                <IconAlertCircle size={48} style={{ color: 'var(--mantine-color-gray-5)' }} />
                <Text size="lg" fw={500} c="white" ta="center">
                  No claims submitted
                </Text>
                <Text size="sm" c="gray.3" ta="center">
                  Submit a claim to get started with the claims process
                </Text>
                <Button
                  leftSection={<IconPlus size={18} />}
                  onClick={() => navigate('/claims/new')}
                  style={{
                    background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                    border: 'none',
                  }}
                >
                  Submit Claim
                </Button>
              </Stack>
            </Paper>
          ) : (
            <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
              {claims.map((claim) => (
                <Card
                  key={claim.id}
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
                  onClick={() => navigate(`/claims/${claim.id}`)}
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
                          {claim.claim_type.charAt(0).toUpperCase() + claim.claim_type.slice(1).replace('_', ' ')} Claim
                        </Text>
                        <Text size="xl" fw={700} c="white" mb={4}>
                          {formatCurrency(claim.claim_amount)}
                        </Text>
                        <Text size="sm" c="gray.3">
                          Incident: {formatDate(claim.incident_date)}
                        </Text>
                        <Text size="sm" c="gray.3">
                          Submitted: {formatDate(claim.submitted_date)}
                        </Text>
                      </Box>
                      <Badge
                        color={getStatusColor(claim.status)}
                        variant="light"
                        leftSection={getStatusIcon(claim.status)}
                      >
                        {claim.status.replace('_', ' ').charAt(0).toUpperCase() + claim.status.slice(1).replace('_', ' ')}
                      </Badge>
                    </Group>

                    {claim.description && (
                      <Text size="sm" c="gray.3" lineClamp={2}>
                        {claim.description}
                      </Text>
                    )}

                    <Group justify="flex-end" mt="md">
                      <ActionIcon
                        variant="subtle"
                        color="gray"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/claims/${claim.id}`);
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


