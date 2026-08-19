import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom'; 
import {
  AppShell,
  Text,
  Group,
  Button,
  UnstyledButton,
  Avatar,
  Menu,
  Badge,
  Burger,
  Container,
  Loader,
  Center,
  Stack,
  ActionIcon,
  Box,
  SimpleGrid,
  Card,
  Title,
  rem,
  useMantineTheme,
  Modal,
  Alert,
} from '@mantine/core';
import { useDisclosure, useMediaQuery } from '@mantine/hooks';
import {
  IconLogout,
  IconUser,
  IconPalette,
  IconFileText,
  IconShield,
  IconCalendar,
  IconFileInvoice,
  IconCreditCard,
  IconAlertCircle,
  IconPlus,
  IconChevronRight,
} from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';
import { useColorTheme } from '@/contexts/ColorThemeContext';

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  verified: boolean;
  twoFactorEnabled?: boolean;
  createdAt: string;
}

interface QuickStats {
  activePolicies: number;
  pendingQuotes: number;
  upcomingAppointments: number;
  recentClaims: number;
}

export function ClientPortalPage() {
  const navigate = useNavigate();
  const theme = useMantineTheme();
  const { gradient, toggleTheme, theme: colorTheme } = useColorTheme();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [logoutLoading, setLogoutLoading] = useState(false);
  const [opened, { toggle }] = useDisclosure();
  const [logoutModalOpened, { open: openLogoutModal, close: closeLogoutModal }] = useDisclosure(false);
  const [stats, setStats] = useState<QuickStats>({
    activePolicies: 0,
    pendingQuotes: 0,
    upcomingAppointments: 0,
    recentClaims: 0,
  });
  const [gracePeriodDays, setGracePeriodDays] = useState<number | null>(null);
  const isMobile = useMediaQuery('(max-width: 768px)');

  useEffect(() => {
    // Check for grace period deadline first
    const storedDeadline = localStorage.getItem('recovery_setup_deadline');
    const recoveryCodeUsed = sessionStorage.getItem('recovery_code_used');
    const userNavigatedToDashboard = sessionStorage.getItem('user_navigated_to_dashboard');
    
    if (storedDeadline) {
      const deadline = new Date(storedDeadline);
      const now = new Date();
      const diff = Math.ceil((deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      if (diff > 0) {
        setGracePeriodDays(diff);
      } else {
        // Deadline passed, clear it
        localStorage.removeItem('recovery_setup_deadline');
      }
    }

    // If user intentionally navigated to dashboard (clicked "I'll do it later"), 
    // don't redirect them back - just show the grace period alert
    if (userNavigatedToDashboard === 'true') {
      // Clear the flag so it doesn't interfere with future checks
      sessionStorage.removeItem('user_navigated_to_dashboard');
      // Show grace period alert and continue normally
      fetchUser();
      fetchStats();
      return;
    }

    // Check if user needs to be redirected to recovery-setup
    // Case 1: recovery_code_used flag exists (just used recovery code)
    // Case 2: deadline exists but no recovery_code_used (logged in again after using recovery code)
    if (recoveryCodeUsed === 'true') {
      if (!storedDeadline) {
        // First time - redirect to setup page immediately
        navigate('/recovery-setup', { replace: true });
        return;
      } else {
        // They have a deadline - check if 2FA is set up
        check2FAAndRedirect();
        return;
      }
    } else if (storedDeadline) {
      // No recovery_code_used flag but deadline exists - they logged in again
      // Check if 2FA is set up - if not, redirect to recovery-setup
      check2FAAndRedirect();
      return;
    }

    // Normal flow - no recovery code issues
    fetchUser();
    fetchStats();
  }, [navigate]);

  async function check2FAAndRedirect() {
    try {
      const resp = await fetch('/api/users/me', {
        credentials: 'include',
      });
      if (resp.ok) {
        const data = await resp.json();
        const user = data.data.user;
        // If 2FA is not set up and they have a deadline, redirect to setup
        if (!user.twoFactorEnabled) {
          // Set the recovery_code_used flag so RecoverySetup knows why they're there
          sessionStorage.setItem('recovery_code_used', 'true');
          navigate('/recovery-setup', { replace: true });
        } else {
          // 2FA is set up, clear the flags and continue to dashboard
          sessionStorage.removeItem('recovery_code_used');
          localStorage.removeItem('recovery_setup_deadline');
          setGracePeriodDays(null);
          fetchUser();
          fetchStats();
        }
      } else {
        // Error fetching user, continue normally
        fetchUser();
        fetchStats();
      }
    } catch (err) {
      console.error('Error checking 2FA status:', err);
      fetchUser();
      fetchStats();
    }
  }

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
      } else {
        console.error('Failed to fetch user:', await resp.text());
        notifications.show({
          title: 'Error',
          message: 'Failed to load user data',
          color: 'red',
        });
      }
    } catch (error) {
      console.error('Error fetching user:', error);
      notifications.show({
        title: 'Error',
        message: 'Failed to connect to server',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }

  async function fetchStats() {
    try {
      // Fetch quotes
      const quotesResp = await fetch('/api/quotes', {
        credentials: 'include',
      });
      if (quotesResp.status === 200) {
        const quotesData = await quotesResp.json();
        const pendingQuotes = quotesData.data?.filter((q: any) => q.status === 'pending').length || 0;
        setStats(prev => ({ ...prev, pendingQuotes }));
      }

      // Fetch policies
      const policiesResp = await fetch('/api/policies', {
        credentials: 'include',
      });
      if (policiesResp.status === 200) {
        const policiesData = await policiesResp.json();
        const activePolicies = policiesData.data?.filter((p: any) => p.status === 'active').length || 0;
        setStats(prev => ({ ...prev, activePolicies }));
      }

      // Fetch appointments
      const appointmentsResp = await fetch('/api/appointments', {
        credentials: 'include',
      });
      if (appointmentsResp.status === 200) {
        const appointmentsData = await appointmentsResp.json();
        const upcoming = appointmentsData.data?.filter((a: any) => 
          a.status === 'scheduled' || a.status === 'confirmed'
        ).length || 0;
        setStats(prev => ({ ...prev, upcomingAppointments: upcoming }));
      }

      // Fetch claims
      const claimsResp = await fetch('/api/claims', {
        credentials: 'include',
      });
      if (claimsResp.status === 200) {
        const claimsData = await claimsResp.json();
        const recentClaims = claimsData.data?.filter((c: any) => 
          c.status === 'pending' || c.status === 'under_review'
        ).length || 0;
        setStats(prev => ({ ...prev, recentClaims }));
      }
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  }

  function getCsrfToken(): string | null {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrf_token') {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  function handleLogoutClick() {
    openLogoutModal();
  }

  async function handleLogoutConfirm() {
    closeLogoutModal();
    setLogoutLoading(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      const resp = await fetch('/api/auth/logout', {
        method: 'POST',
        headers,
        credentials: 'include',
      });

      if (resp.status === 200) {
        notifications.show({
          title: 'Logged Out',
          message: 'You have been successfully logged out',
          color: 'green',
        });
        navigate('/login');
      } else {
        notifications.show({
          title: 'Error',
          message: 'Failed to logout',
          color: 'red',
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
      notifications.show({
        title: 'Error',
        message: 'Failed to connect to server',
        color: 'red',
      });
    } finally {
      setLogoutLoading(false);
    }
  }

  const quickActions = [
    {
      title: 'Get a Quote',
      description: 'Request a personalized insurance quote',
      icon: IconFileText,
      color: 'trustBlue',
      link: '/quote',
      action: 'new',
    },
    {
      title: 'My Policies',
      description: 'View and manage your insurance policies',
      icon: IconShield,
      color: 'successGreen',
      link: '/policies',
      count: stats.activePolicies,
    },
    {
      title: 'My Quotes',
      description: 'Track your quote requests',
      icon: IconFileInvoice,
      color: 'calmingTeal',
      link: '/quotes',
      count: stats.pendingQuotes,
    },
    {
      title: 'Appointments',
      description: 'Schedule or view consultations',
      icon: IconCalendar,
      color: 'warmOrange',
      link: '/appointments',
      count: stats.upcomingAppointments,
    },
    {
      title: 'Documents',
      description: 'Access your policy documents',
      icon: IconFileText,
      color: 'trustBlue',
      link: '/documents',
    },
    {
      title: 'Payments',
      description: 'View payment history and make payments',
      icon: IconCreditCard,
      color: 'successGreen',
      link: '/payments',
    },
    {
      title: 'Claims',
      description: 'Submit or track insurance claims',
      icon: IconAlertCircle,
      color: 'warmOrange',
      link: '/claims',
      count: stats.recentClaims,
    },
  ];

  if (loading) {
    return (
      <Center h="100vh">
        <Loader size="lg" />
      </Center>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <>
    <AppShell
      header={{ height: 60 }}
      padding="md"
      style={{
        minHeight: '100vh',
        background: 'linear-gradient(180deg, #0F172A 0%, #1E293B 100%)',
      }}
    >
      {/* Header */}
      <AppShell.Header
        style={{
          background: 'rgba(15, 23, 42, 0.8)',
          backdropFilter: 'blur(10px)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
        }}
      >
        <Group h="100%" px="md" justify="space-between">
          <Group gap="sm">
            <Burger
              opened={opened}
              onClick={toggle}
              hiddenFrom="sm"
              size="sm"
              color="white"
            />
            <Text
              fw={800}
              size={isMobile ? 'lg' : 'xl'}
              style={{
                background: gradient,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text',
              }}
            >
              Toniebee
            </Text>
            <Text fw={500} size="sm" c="gray.3" visibleFrom="sm">
              Client Portal
            </Text>
          </Group>

          <Group gap="sm">
            <ActionIcon
              variant="subtle"
              onClick={toggleTheme}
              aria-label="Toggle color theme"
              style={{
                background: gradient,
                border: 'none',
                color: 'white',
              }}
            >
              <IconPalette size={18} />
            </ActionIcon>

            <Menu shadow="md" width={200} position="bottom-end">
              <Menu.Target>
                <UnstyledButton>
                  <Group gap="sm">
                    <Avatar
                      color="trustBlue"
                      radius="xl"
                      size={isMobile ? 'sm' : 'md'}
                    >
                      {user.name
                        .split(' ')
                        .map((n) => n[0])
                        .join('')
                        .toUpperCase()
                        .slice(0, 2)}
                    </Avatar>
                    {!isMobile && (
                      <Box>
                        <Text size="sm" fw={500}>
                          {user.name}
                        </Text>
                        <Text size="xs" c="dimmed">
                          {user.email}
                        </Text>
                      </Box>
                    )}
                  </Group>
                </UnstyledButton>
              </Menu.Target>

              <Menu.Dropdown>
                <Menu.Label>Account</Menu.Label>
                <Menu.Item
                  leftSection={<IconUser size={14} />}
                  onClick={() => navigate('/profile')}
                >
                  My Profile
                </Menu.Item>
                <Menu.Divider />
                <Menu.Item
                  leftSection={<IconLogout size={14} />}
                  color="red"
                  onClick={handleLogoutClick}
                  disabled={logoutLoading}
                >
                  Logout
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </Group>
      </AppShell.Header>

      {/* Main Content */}
      <AppShell.Main>
        <Container size="xl" py="xl">
          <Stack gap="xl">
            {/* Grace Period Alert */}
            {gracePeriodDays !== null && gracePeriodDays > 0 && (
              <Alert
                icon={<IconAlertCircle size={16} />}
                color={gracePeriodDays > 3 ? 'yellow' : 'orange'}
                variant="light"
                title="2FA Setup Required"
                onClose={() => setGracePeriodDays(null)}
                withCloseButton
              >
                <Group gap="xs" wrap="nowrap" align="center">
                  <Text size="sm">
                    You have <strong>{gracePeriodDays} day{gracePeriodDays !== 1 ? 's' : ''}</strong> remaining to set up 2FA after using a recovery code.
                  </Text>
                  <Button
                    variant="subtle"
                    size="xs"
                    onClick={() => navigate('/recovery-setup', { replace: true })}
                    style={{ textDecoration: 'underline', flexShrink: 0 }}
                  >
                    Set up now
                  </Button>
                </Group>
              </Alert>
            )}

            {/* Welcome Section */}
            <Box>
              <Title order={1} size={isMobile ? rem(28) : rem(36)} mb="xs" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
                Welcome back, {user.name.split(' ')[0]}! 👋
              </Title>
              <Text size="lg" c="gray.2" style={{ textShadow: '0 1px 5px rgba(0, 0, 0, 0.2)' }}>
                Manage your insurance policies, quotes, and more from your dashboard.
              </Text>
            </Box>

            {/* Quick Stats */}
            <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
              <Card
                padding="md"
                radius="md"
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  borderColor: 'rgba(255, 255, 255, 0.1)',
                  backdropFilter: 'blur(10px)',
                }}
                withBorder
              >
                <Text size="xs" tt="uppercase" fw={700} c="gray.3" mb={4}>
                  Active Policies
                </Text>
                <Text size="xl" fw={700} c="white">
                  {stats.activePolicies}
                </Text>
              </Card>
              <Card
                padding="md"
                radius="md"
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  borderColor: 'rgba(255, 255, 255, 0.1)',
                  backdropFilter: 'blur(10px)',
                }}
                withBorder
              >
                <Text size="xs" tt="uppercase" fw={700} c="gray.3" mb={4}>
                  Pending Quotes
                </Text>
                <Text size="xl" fw={700} c="white">
                  {stats.pendingQuotes}
                </Text>
              </Card>
              <Card
                padding="md"
                radius="md"
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  borderColor: 'rgba(255, 255, 255, 0.1)',
                  backdropFilter: 'blur(10px)',
                }}
                withBorder
              >
                <Text size="xs" tt="uppercase" fw={700} c="gray.3" mb={4}>
                  Appointments
                </Text>
                <Text size="xl" fw={700} c="white">
                  {stats.upcomingAppointments}
                </Text>
              </Card>
              <Card
                padding="md"
                radius="md"
                style={{
                  background: 'rgba(255, 255, 255, 0.05)',
                  borderColor: 'rgba(255, 255, 255, 0.1)',
                  backdropFilter: 'blur(10px)',
                }}
                withBorder
              >
                <Text size="xs" tt="uppercase" fw={700} c="gray.3" mb={4}>
                  Active Claims
                </Text>
                <Text size="xl" fw={700} c="white">
                  {stats.recentClaims}
                </Text>
              </Card>
            </SimpleGrid>

            {/* Quick Actions */}
            <Box>
              <Group justify="space-between" mb="md">
                <Title order={2} size="h3" c="white" fw={800} style={{ textShadow: '0 2px 10px rgba(0, 0, 0, 0.3)' }}>
                  Quick Actions
                </Title>
              </Group>
              <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} spacing="md">
                {quickActions.map((action) => (
                  <Card
                    key={action.title}
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
                    onClick={() => navigate(action.link)}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.transform = 'translateY(-8px)';
                      e.currentTarget.style.background = 'rgba(255, 255, 255, 0.08)';
                      e.currentTarget.style.boxShadow = '0 20px 40px rgba(0, 0, 0, 0.3)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.transform = 'translateY(0)';
                      e.currentTarget.style.background = 'rgba(255, 255, 255, 0.05)';
                      e.currentTarget.style.boxShadow = 'none';
                    }}
                  >
                    <Group justify="space-between" mb="xs">
                      <Group gap="sm">
                        <action.icon
                          size={24}
                          style={{ color: `var(--mantine-color-${action.color}-4)` }}
                        />
                        <Text fw={700} size="lg" c="white" style={{ textShadow: '0 1px 3px rgba(0, 0, 0, 0.3)' }}>
                          {action.title}
                        </Text>
                      </Group>
                      {action.count !== undefined && action.count > 0 && (
                        <Badge color={action.color} variant="light">
                          {action.count}
                        </Badge>
                      )}
                      {action.action === 'new' && (
                        <Badge color={action.color} variant="light" leftSection={<IconPlus size={12} />}>
                          New
                        </Badge>
                      )}
                    </Group>
                    <Text size="sm" c="gray.2" mb="md" style={{ textShadow: '0 1px 2px rgba(0, 0, 0, 0.2)' }}>
                      {action.description}
                    </Text>
                    <Group gap={4} fw={600}>
                      <Text
                        key={colorTheme} // Force re-render when theme changes
                        size="sm"
                        style={{
                          background: gradient,
                          WebkitBackgroundClip: 'text',
                          WebkitTextFillColor: 'transparent',
                          backgroundClip: 'text',
                          transition: 'background 0.3s ease',
                        }}
                      >
                        View Details
                      </Text>
                      <IconChevronRight size={16} style={{ color: `var(--mantine-color-${action.color}-4)` }} />
                    </Group>
                  </Card>
                ))}
              </SimpleGrid>
            </Box>
          </Stack>
        </Container>
      </AppShell.Main>
    </AppShell>

      <Modal
        opened={logoutModalOpened}
        onClose={closeLogoutModal}
        title="Confirm Logout"
        centered
      >
        <Stack>
          <Text>
            Are you sure you want to logout? You'll need to sign in again to access your account.
          </Text>
          <Group justify="flex-end" mt="md">
            <Button variant="subtle" onClick={closeLogoutModal} disabled={logoutLoading}>
              Cancel
            </Button>
            <Button
              color="red"
              onClick={handleLogoutConfirm}
              loading={logoutLoading}
            >
              Yes, Logout
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

