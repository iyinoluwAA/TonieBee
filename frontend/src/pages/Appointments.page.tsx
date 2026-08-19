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
import { IconCalendar, IconPlus, IconClock, IconCheck, IconX, IconChevronRight } from '@tabler/icons-react';
import { DarkLayout } from '../components/DarkLayout';
import { notifications } from '@mantine/notifications';

interface Appointment {
  id: string;
  appointment_type: string;
  scheduled_date: string;
  scheduled_time: string;
  status: string;
  notes: string | null;
  created_at: string;
}

export function AppointmentsPage() {
  const navigate = useNavigate();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [appointments, setAppointments] = useState<Appointment[]>([]);
  const [loading, setLoading] = useState(true);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    fetchUser();
    fetchAppointments();
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

  async function fetchAppointments() {
    try {
      const resp = await fetch('/api/appointments', {
        credentials: 'include',
      });
      if (resp.status === 200) {
        const data = await resp.json();
        setAppointments(data.data || []);
      } else if (resp.status === 401) {
        navigate('/login');
      } else {
        notifications.show({
          title: 'Error',
          message: 'Failed to load appointments',
          color: 'red',
        });
      }
    } catch (error) {
      console.error('Error fetching appointments:', error);
      notifications.show({
        title: 'Error',
        message: 'Failed to connect to server',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'confirmed':
        return 'green';
      case 'cancelled':
        return 'red';
      case 'scheduled':
        return 'blue';
      case 'completed':
        return 'gray';
      default:
        return 'yellow';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'confirmed':
        return <IconCheck size={16} />;
      case 'cancelled':
        return <IconX size={16} />;
      case 'completed':
        return <IconCheck size={16} />;
      default:
        return <IconClock size={16} />;
    }
  };

  const formatDateTime = (dateString: string, timeString: string) => {
    const date = new Date(dateString);
    return {
      date: date.toLocaleDateString('en-CA', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      }),
      time: timeString || 'TBD',
    };
  };

  if (loading) {
    return (
      <DarkLayout user={user} title="Appointments">
        <Center h="60vh">
          <Loader size="lg" />
        </Center>
      </DarkLayout>
    );
  }

  return (
    <DarkLayout user={user} title="Appointments">
      <Container size="xl" py="xl">
        <Stack gap="xl">
          {/* Header */}
          <Group justify="space-between" align="flex-start">
            <Box>
              <Title order={1} size={isMobile ? rem(28) : rem(36)} mb="xs" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
                My Appointments
              </Title>
              <Text size="lg" c="gray.2" style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
                Schedule and manage your consultations
              </Text>
            </Box>
            <Button
              size={isMobile ? 'md' : 'lg'}
              leftSection={<IconPlus size={18} />}
              onClick={() => navigate('/appointments/new')}
              style={{
                background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                border: 'none',
              }}
            >
              Schedule Appointment
            </Button>
          </Group>

          {/* Appointments List */}
          {appointments.length === 0 ? (
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
                <IconCalendar size={48} style={{ color: 'var(--mantine-color-gray-5)' }} />
                <Text size="lg" fw={500} c="white" ta="center">
                  No appointments scheduled
                </Text>
                <Text size="sm" c="gray.3" ta="center">
                  Schedule a consultation to discuss your insurance needs
                </Text>
                <Button
                  leftSection={<IconPlus size={18} />}
                  onClick={() => navigate('/appointments/new')}
                  style={{
                    background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                    border: 'none',
                  }}
                >
                  Schedule Appointment
                </Button>
              </Stack>
            </Paper>
          ) : (
            <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
              {appointments.map((appointment) => {
                const { date, time } = formatDateTime(appointment.scheduled_date, appointment.scheduled_time);
                return (
                  <Card
                    key={appointment.id}
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
                    onClick={() => navigate(`/appointments/${appointment.id}`)}
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
                            {appointment.appointment_type.charAt(0).toUpperCase() + appointment.appointment_type.slice(1).replace('_', ' ')}
                          </Text>
                          <Group gap="xs" mt={4}>
                            <IconCalendar size={14} style={{ color: 'var(--mantine-color-gray-4)' }} />
                            <Text size="sm" c="gray.2">
                              {date}
                            </Text>
                          </Group>
                          <Group gap="xs" mt={4}>
                            <IconClock size={14} style={{ color: 'var(--mantine-color-gray-4)' }} />
                            <Text size="sm" c="gray.2">
                              {time}
                            </Text>
                          </Group>
                        </Box>
                        <Badge
                          color={getStatusColor(appointment.status)}
                          variant="light"
                          leftSection={getStatusIcon(appointment.status)}
                        >
                          {appointment.status.charAt(0).toUpperCase() + appointment.status.slice(1)}
                        </Badge>
                      </Group>

                      {appointment.notes && (
                        <Text size="sm" c="gray.3" lineClamp={2}>
                          {appointment.notes}
                        </Text>
                      )}

                      <Group justify="flex-end" mt="md">
                        <ActionIcon
                          variant="subtle"
                          color="gray"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/appointments/${appointment.id}`);
                          }}
                        >
                          <IconChevronRight size={18} />
                        </ActionIcon>
                      </Group>
                    </Stack>
                  </Card>
                );
              })}
            </SimpleGrid>
          )}
        </Stack>
      </Container>
    </DarkLayout>
  );
}


