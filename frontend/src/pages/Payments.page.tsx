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
  Table,
} from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { IconCreditCard, IconCheck, IconX, IconClock, IconPlus } from '@tabler/icons-react';
import { DarkLayout } from '../components/DarkLayout';
import { notifications } from '@mantine/notifications';

interface Payment {
  id: string;
  payment_type: string;
  amount: number;
  status: string;
  payment_date: string;
  due_date: string | null;
  payment_method: string | null;
  transaction_id: string | null;
}

export function PaymentsPage() {
  const navigate = useNavigate();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [payments, setPayments] = useState<Payment[]>([]);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    fetchUser();
    fetchPayments();
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

  async function fetchPayments() {
    try {
      const resp = await fetch('/api/payments', {
        credentials: 'include',
      });
      if (resp.status === 200) {
        const data = await resp.json();
        setPayments(data.data || []);
      } else if (resp.status === 401) {
        navigate('/login');
      } else {
        notifications.show({
          title: 'Error',
          message: 'Failed to load payments',
          color: 'red',
        });
      }
    } catch (error) {
      console.error('Error fetching payments:', error);
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
      case 'completed':
        return 'green';
      case 'failed':
        return 'red';
      case 'pending':
        return 'yellow';
      default:
        return 'gray';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <IconCheck size={16} />;
      case 'failed':
        return <IconX size={16} />;
      default:
        return <IconClock size={16} />;
    }
  };

  const totalPaid = payments
    .filter(p => p.status === 'completed')
    .reduce((sum, p) => sum + p.amount, 0);

  const pendingAmount = payments
    .filter(p => p.status === 'pending')
    .reduce((sum, p) => sum + p.amount, 0);

  if (loading) {
    return (
      <DarkLayout user={user} title="Payments">
        <Center h="60vh">
          <Loader size="lg" />
        </Center>
      </DarkLayout>
    );
  }

  return (
    <DarkLayout user={user} title="Payments">
      <Container size="xl" py="xl">
        <Stack gap="xl">
          {/* Header */}
          <Group justify="space-between" align="flex-start">
            <Box>
              <Title order={1} size={isMobile ? rem(28) : rem(36)} mb="xs" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
                Payment History
              </Title>
              <Text size="lg" c="gray.2" style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
                View and manage your insurance payments
              </Text>
            </Box>
            <Button
              size={isMobile ? 'md' : 'lg'}
              leftSection={<IconPlus size={18} />}
              onClick={() => navigate('/payments/new')}
              style={{
                background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                border: 'none',
              }}
            >
              Make Payment
            </Button>
          </Group>

          {/* Summary Cards */}
          <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
            <Card
              padding="lg"
              radius="md"
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                borderColor: 'rgba(255, 255, 255, 0.1)',
                backdropFilter: 'blur(10px)',
              }}
              withBorder
            >
              <Text size="sm" c="gray.3" mb={4}>
                Total Paid
              </Text>
              <Text size="xl" fw={700} c="white">
                {formatCurrency(totalPaid)}
              </Text>
            </Card>
            <Card
              padding="lg"
              radius="md"
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                borderColor: 'rgba(255, 255, 255, 0.1)',
                backdropFilter: 'blur(10px)',
              }}
              withBorder
            >
              <Text size="sm" c="gray.3" mb={4}>
                Pending Payments
              </Text>
              <Text size="xl" fw={700} c="white">
                {formatCurrency(pendingAmount)}
              </Text>
            </Card>
          </SimpleGrid>

          {/* Payments List */}
          {payments.length === 0 ? (
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
                <IconCreditCard size={48} style={{ color: 'var(--mantine-color-gray-5)' }} />
                <Text size="lg" fw={500} c="white" ta="center">
                  No payment history
                </Text>
                <Text size="sm" c="gray.3" ta="center">
                  Your payment history will appear here
                </Text>
              </Stack>
            </Paper>
          ) : (
            <Card
              padding="lg"
              radius="md"
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                borderColor: 'rgba(255, 255, 255, 0.1)',
                backdropFilter: 'blur(10px)',
              }}
              withBorder
            >
              {isMobile ? (
                <Stack gap="md">
                  {payments.map((payment) => (
                    <Card
                      key={payment.id}
                      padding="md"
                      radius="md"
                      style={{
                        background: 'rgba(255, 255, 255, 0.03)',
                        borderColor: 'rgba(255, 255, 255, 0.1)',
                      }}
                      withBorder
                    >
                      <Stack gap="sm">
                        <Group justify="space-between">
                          <Text fw={600} c="white">
                            {formatCurrency(payment.amount)}
                          </Text>
                          <Badge
                            color={getStatusColor(payment.status)}
                            variant="light"
                            leftSection={getStatusIcon(payment.status)}
                          >
                            {payment.status.charAt(0).toUpperCase() + payment.status.slice(1)}
                          </Badge>
                        </Group>
                        <Text size="sm" c="gray.3">
                          {payment.payment_type.replace('_', ' ').charAt(0).toUpperCase() + payment.payment_type.slice(1).replace('_', ' ')}
                        </Text>
                        <Text size="xs" c="gray.4">
                          {formatDate(payment.payment_date)}
                        </Text>
                      </Stack>
                    </Card>
                  ))}
                </Stack>
              ) : (
                <Table>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th c="gray.3">Date</Table.Th>
                      <Table.Th c="gray.3">Type</Table.Th>
                      <Table.Th c="gray.3">Amount</Table.Th>
                      <Table.Th c="gray.3">Method</Table.Th>
                      <Table.Th c="gray.3">Status</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {payments.map((payment) => (
                      <Table.Tr key={payment.id}>
                        <Table.Td c="white">{formatDate(payment.payment_date)}</Table.Td>
                        <Table.Td c="gray.2">
                          {payment.payment_type.replace('_', ' ').charAt(0).toUpperCase() + payment.payment_type.slice(1).replace('_', ' ')}
                        </Table.Td>
                        <Table.Td c="white" fw={600}>{formatCurrency(payment.amount)}</Table.Td>
                        <Table.Td c="gray.2">{payment.payment_method || 'N/A'}</Table.Td>
                        <Table.Td>
                          <Badge
                            color={getStatusColor(payment.status)}
                            variant="light"
                            leftSection={getStatusIcon(payment.status)}
                          >
                            {payment.status.charAt(0).toUpperCase() + payment.status.slice(1)}
                          </Badge>
                        </Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              )}
            </Card>
          )}
        </Stack>
      </Container>
    </DarkLayout>
  );
}


