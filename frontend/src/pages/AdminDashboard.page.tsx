import { useEffect, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
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
  NavLink,
  Container,
  Loader,
  Center,
  ScrollArea,
  Stack,
  ActionIcon,
  Box,
  rem,
  useMantineColorScheme,
  useComputedColorScheme,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import {
  IconDashboard,
  IconUsers,
  IconDatabase,
  IconSettings,
  IconLogout,
  IconUser,
  IconChevronRight,
  IconSun,
  IconMoonStars,
  IconShield,
} from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';
import { AdminUsersPage } from './admin/AdminUsersPage';
import { AdminStatsPage } from './admin/AdminStatsPage';
import { AdminSecurityPage } from './admin/AdminSecurityPage';

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  verified: boolean;
  twoFactorEnabled?: boolean;
  createdAt: string;
}

export function AdminDashboardPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { setColorScheme } = useMantineColorScheme();
  const computedColorScheme = useComputedColorScheme('light', { getInitialValueInEffect: true });
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [logoutLoading, setLogoutLoading] = useState(false);
  const [opened, { toggle }] = useDisclosure();
  const [activePage, setActivePage] = useState<'dashboard' | 'users' | 'data' | 'security'>('dashboard');

  useEffect(() => {
    fetchUser();
  }, []);

  useEffect(() => {
    // Set active page based on path
    if (location.pathname.includes('/admin/users')) {
      setActivePage('users');
    } else if (location.pathname.includes('/admin/data')) {
      setActivePage('data');
    } else if (location.pathname.includes('/admin/security')) {
      setActivePage('security');
    } else {
      setActivePage('dashboard');
    }
  }, [location]);

  async function fetchUser() {
    try {
      const resp = await fetch('/api/users/me', {
        credentials: 'include',
      });

      if (resp.status === 200) {
        const data = await resp.json();
        const userData = data.data.user;
        
        // Check if user is admin
        if (userData.role !== 'admin') {
          notifications.show({
            title: 'Access Denied',
            message: 'You do not have permission to access this page.',
            color: 'red',
          });
          navigate('/dashboard');
          return;
        }
        
        setUser(userData);
      } else if (resp.status === 401) {
        navigate('/admin/login');
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
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrf_token') {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  async function handleLogout() {
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

      if (resp.ok) {
        notifications.show({
          title: 'Logged Out',
          message: 'You have been successfully logged out.',
          color: 'green',
        });
        navigate('/login');
      }
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      setLogoutLoading(false);
    }
  }

  if (loading) {
    return (
      <Center h="100vh">
        <Loader size="lg" />
      </Center>
    );
  }

  if (!user || user.role !== 'admin') {
    return null;
  }

  const navItems = [
    { icon: IconDashboard, label: 'Dashboard', page: 'dashboard' as const },
    { icon: IconUsers, label: 'User Management', page: 'users' as const },
    { icon: IconShield, label: 'Security', page: 'security' as const },
    { icon: IconDatabase, label: 'Data Management', page: 'data' as const },
  ];

  return (
    <AppShell
      header={{ height: { base: 56, sm: 60 } }}
      navbar={{
        width: { base: 280, sm: 300 },
        breakpoint: 'sm',
        collapsed: { mobile: !opened },
      }}
      padding={{ base: 'sm', sm: 'md' }}
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between" wrap="nowrap">
          <Group gap="md" wrap="nowrap">
            <Burger 
              opened={opened} 
              onClick={toggle} 
              hiddenFrom="sm" 
              size="sm" 
              aria-label="Toggle navigation"
            />
            <Text fw={700} size="lg" style={{ whiteSpace: 'nowrap' }}>
              Toniebee Admin
            </Text>
          </Group>
          <Group gap="md" wrap="nowrap">
            <ActionIcon
              variant="default"
              onClick={() => setColorScheme(computedColorScheme === 'light' ? 'dark' : 'light')}
              size="lg"
              aria-label="Toggle color scheme"
            >
              {computedColorScheme === 'dark' ? (
                <IconSun style={{ width: rem(18), height: rem(18) }} stroke={1.5} />
              ) : (
                <IconMoonStars style={{ width: rem(18), height: rem(18) }} stroke={1.5} />
              )}
            </ActionIcon>
            <Menu shadow="md" width={200} position="bottom-end">
              <Menu.Target>
                <UnstyledButton style={{ cursor: 'pointer' }}>
                  <Group gap={8} wrap="nowrap">
                    <Avatar color="blue" radius="xl" size="md">
                      {user.name.charAt(0).toUpperCase()}
                    </Avatar>
                    <Box
                      style={{ 
                        flex: 1, 
                        minWidth: 0, 
                        display: 'flex', 
                        flexDirection: 'column',
                      }}
                      visibleFrom="sm"
                    >
                      <Text 
                        size="sm" 
                        fw={500}
                        truncate
                        style={{ maxWidth: '120px' }}
                      >
                        {user.name}
                      </Text>
                      <Text 
                        size="xs" 
                        c="dimmed"
                        truncate
                        style={{ maxWidth: '120px' }}
                      >
                        {user.email}
                      </Text>
                    </Box>
                  </Group>
                </UnstyledButton>
              </Menu.Target>

              <Menu.Dropdown>
                <Menu.Label>Account</Menu.Label>
                <Menu.Item
                  leftSection={<IconUser size={14} />}
                  onClick={() => {
                    navigate('/dashboard');
                    // Close sidebar on mobile when navigating
                    if (window.innerWidth < 768) {
                      toggle();
                    }
                  }}
                >
                  User Profile
                </Menu.Item>
                <Menu.Divider />
                <Menu.Item
                  color="red"
                  leftSection={<IconLogout size={14} />}
                  onClick={handleLogout}
                  disabled={logoutLoading}
                >
                  {logoutLoading ? 'Logging out...' : 'Logout'}
                </Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="md">
        <ScrollArea type="scroll" offsetScrollbars>
          <Stack gap="xs" mt="md">
            {navItems.map((item) => (
              <NavLink
                key={item.page}
                leftSection={<item.icon size={18} />}
                label={item.label}
                active={activePage === item.page}
                onClick={() => {
                  setActivePage(item.page);
                  navigate(`/admin/${item.page === 'dashboard' ? '' : item.page}`);
                  // Close sidebar on mobile when navigating
                  if (window.innerWidth < 768) {
                    toggle();
                  }
                }}
                rightSection={
                  activePage === item.page ? (
                    <IconChevronRight size={16} />
                  ) : null
                }
              />
            ))}
          </Stack>
        </ScrollArea>

        <div
          style={{
            borderTop: '1px solid var(--mantine-color-default-border)',
            padding: '1rem',
            marginTop: 'auto',
          }}
        >
          <Group gap="xs" wrap="wrap">
            <Badge color="green" variant="light" size="sm">
              Admin
            </Badge>
            {user.twoFactorEnabled && (
              <Badge color="blue" variant="light" size="sm">
                2FA Enabled
              </Badge>
            )}
          </Group>
        </div>
      </AppShell.Navbar>

      <AppShell.Main>
        <Container fluid px="md">
          {activePage === 'dashboard' && <AdminStatsPage />}
          {activePage === 'users' && <AdminUsersPage />}
          {activePage === 'security' && <AdminSecurityPage />}
          {activePage === 'data' && (
            <div>
              <Text size="xl" fw={700} mb="md">
                Data Management
              </Text>
              <Text c="dimmed" size="md">
                Data management features coming soon...
              </Text>
            </div>
          )}
        </Container>
      </AppShell.Main>
    </AppShell>
  );
}

