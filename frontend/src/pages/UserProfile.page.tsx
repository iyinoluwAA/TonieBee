import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Container, Paper, Text, Stack, Title, Group, Badge, Loader, Center, Modal, Switch, ActionIcon, Divider, SimpleGrid, Card, Timeline, Anchor } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useDisclosure } from '@mantine/hooks';
import { useMantineColorScheme, useComputedColorScheme } from '@mantine/core';
import { IconSun, IconMoon, IconUser, IconShield, IconMail, IconCalendar, IconKey, IconDeviceDesktop } from '@tabler/icons-react';
import { TwoFactorSetupModal } from '@/components/TwoFactorSetupModal';
import { RecoveryCodesSection } from '@/components/RecoveryCodesSection';

interface User {
  id: string;
  name: string;
  email: string;
  verified: boolean;
  role: string;
  twoFactorEnabled?: boolean;
  createdAt: string;
  updatedAt: string;
}

export function UserProfilePage() {
  const navigate = useNavigate();
  const { setColorScheme } = useMantineColorScheme();
  const computedColorScheme = useComputedColorScheme('light', { getInitialValueInEffect: true });
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [logoutLoading, setLogoutLoading] = useState(false);
  const [opened, { open, close }] = useDisclosure(false);
  const [twoFactorModalOpened, { open: open2FA, close: close2FA }] = useDisclosure(false);
  const [twoFactorLoading, setTwoFactorLoading] = useState(false);

  useEffect(() => {
    fetchUser();
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
        // Not authenticated, redirect to login
        navigate('/login');
      } else {
        console.error('Failed to fetch user:', await resp.text());
      }
    } catch (err) {
      console.error('Error fetching user:', err);
    } finally {
      setLoading(false);
    }
  }

  function getCsrfToken(): string | null {
    // Get CSRF token from cookie
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
    open(); // Open confirmation modal
  }

  async function handleDisable2FA() {
    setTwoFactorLoading(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      const resp = await fetch('/api/2fa/disable', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({}),
      });

      if (resp.ok) {
        notifications.show({
          title: '2FA Disabled',
          message: 'Two-factor authentication has been disabled for your account.',
          color: 'green',
          autoClose: 5000,
        });
        fetchUser();
      } else {
        const error = await resp.json();
        notifications.show({
          title: 'Failed to Disable',
          message: error.message || 'Failed to disable 2FA. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      notifications.show({
        title: 'Network Error',
        message: 'Unable to disable 2FA. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setTwoFactorLoading(false);
    }
  }

  async function handleLogoutConfirm() {
    close(); // Close modal first
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

      if (resp.ok || resp.status === 200) {
        // Redirect to login
        navigate('/login');
      } else {
        console.error('Logout failed:', await resp.text());
        // Still redirect even if logout API call fails
        navigate('/login');
      }
    } catch (err) {
      console.error('Logout error:', err);
      // Still redirect on error
      navigate('/login');
    } finally {
      setLogoutLoading(false);
    }
  }

  if (loading) {
    return (
      <Container size="sm" mt="xl">
        <Center>
          <Loader size="lg" />
        </Center>
      </Container>
    );
  }

  if (!user) {
    return (
      <Container size="sm" mt="xl">
        <Paper p="xl" withBorder>
          <Text>Failed to load user data. Please try again.</Text>
          <Button mt="md" onClick={() => navigate('/login')}>
            Go to Login
          </Button>
        </Paper>
      </Container>
    );
  }

  return (
    <>
      <Modal
        opened={opened}
        onClose={close}
        title="Confirm Logout"
        centered
        overlayProps={{
          backgroundOpacity: 0.55,
          blur: 3,
        }}
      >
        <Stack gap="md">
          <Text>
            Are you sure you want to logout? You'll need to sign in again to access your account.
          </Text>
          <Group justify="flex-end" mt="md">
            <Button variant="subtle" onClick={close} disabled={logoutLoading}>
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

      <TwoFactorSetupModal
        opened={twoFactorModalOpened}
        onClose={close2FA}
        onComplete={() => {
          fetchUser();
          close2FA();
        }}
      />

      <Container size="md" mt="xl">
        <Paper p="xl" withBorder radius="md">
          <Stack gap="lg">
            <Group justify="space-between" align="flex-start">
              <div>
                <Title order={2}>Profile</Title>
                <Text c="dimmed" size="sm" mt={4}>
                  {user.name} • {user.email}
                </Text>
              </div>
              <ActionIcon
                onClick={() => setColorScheme(computedColorScheme === 'light' ? 'dark' : 'light')}
                variant="default"
                size="lg"
                radius="md"
                aria-label="Toggle color scheme"
              >
                {computedColorScheme === 'light' ? (
                  <IconMoon size={20} stroke={1.5} />
                ) : (
                  <IconSun size={20} stroke={1.5} />
                )}
              </ActionIcon>
            </Group>

            <Group gap="xs">
              <Badge color={user.verified ? 'green' : 'yellow'} variant="light">
                {user.verified ? 'Verified' : 'Not Verified'}
              </Badge>
              <Badge color="blue" variant="light">
                {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
              </Badge>
              {user.twoFactorEnabled && (
                <Badge color="green" variant="light">
                  2FA Enabled
                </Badge>
              )}
            </Group>

            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md" mt="md">
              <Paper p="md" withBorder>
                <Stack gap="sm">
                  <Group justify="space-between">
                    <div>
                      <Text fw={500} size="sm">
                        Two-Factor Authentication
                      </Text>
                      <Text size="xs" c="dimmed">
                        Add an extra layer of security
                      </Text>
                    </div>
                    <Switch
                      checked={user.twoFactorEnabled || false}
                      onChange={async (e) => {
                        if (e.currentTarget.checked) {
                          open2FA();
                        } else {
                          await handleDisable2FA();
                        }
                      }}
                      disabled={twoFactorLoading}
                    />
                  </Group>
                </Stack>
              </Paper>

              <Paper p="md" withBorder>
                <Stack gap="sm">
                  <Group justify="space-between">
                    <div>
                      <Text fw={500} size="sm">
                        Email Verification
                      </Text>
                      <Text size="xs" c="dimmed">
                        {user.verified ? 'Your email is verified' : 'Verify your email address'}
                      </Text>
                    </div>
                    <Badge color={user.verified ? 'green' : 'yellow'} variant="light">
                      {user.verified ? 'Verified' : 'Pending'}
                    </Badge>
                  </Group>
                </Stack>
              </Paper>
            </SimpleGrid>

            {user.twoFactorEnabled && (
              <Paper p="md" withBorder mt="md">
                <RecoveryCodesSection />
              </Paper>
            )}

            <Divider label="Account Information" labelPosition="center" mt="xl" />

            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
              <Card withBorder p="md">
                <Group>
                  <IconUser size={24} />
                  <div>
                    <Text size="xs" c="dimmed">Member Since</Text>
                    <Text fw={500}>{new Date(user.createdAt).toLocaleDateString()}</Text>
                  </div>
                </Group>
              </Card>
              <Card withBorder p="md">
                <Group>
                  <IconCalendar size={24} />
                  <div>
                    <Text size="xs" c="dimmed">Last Updated</Text>
                    <Text fw={500}>{new Date(user.updatedAt).toLocaleDateString()}</Text>
                  </div>
                </Group>
              </Card>
            </SimpleGrid>

            <Group mt="md">
              {user.role === 'admin' && (
                <Button
                  variant="light"
                  onClick={() => navigate('/admin')}
                >
                  Admin Dashboard
                </Button>
              )}
              <Button
                color="red"
                variant="light"
                onClick={handleLogoutClick}
                loading={logoutLoading}
              >
                Logout
              </Button>
            </Group>
          </Stack>
        </Paper>
      </Container>
    </>
  );
}
