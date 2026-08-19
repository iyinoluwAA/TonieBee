import { ReactNode, useState } from 'react';
import { AppShell, Group, Text, Burger, Avatar, Menu, ActionIcon, UnstyledButton, Box, useMantineTheme } from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { useNavigate } from 'react-router-dom';
import { IconLogout, IconUser, IconSun, IconMoonStars } from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';
import { useColorTheme } from '../../contexts/ColorThemeContext';

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  verified: boolean;
  twoFactorEnabled?: boolean;
  createdAt: string;
}

interface DarkLayoutProps {
  children: ReactNode;
  title?: string;
  user?: User | null;
  onLogout?: () => void;
  showBurger?: boolean;
  burgerOpened?: boolean;
  onBurgerToggle?: () => void;
}

export function DarkLayout({
  children,
  title = 'Client Portal',
  user,
  onLogout,
  showBurger = false,
  burgerOpened = false,
  onBurgerToggle,
}: DarkLayoutProps) {
  const navigate = useNavigate();
  const theme = useMantineTheme();
  const isMobile = useMediaQuery('(max-width: 768px)');
  const [logoutLoading, setLogoutLoading] = useState(false);
  const { gradient, toggleTheme, theme: colorTheme } = useColorTheme();

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
    if (onLogout) {
      onLogout();
      return;
    }

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

  return (
    <AppShell
      header={{ height: 60 }}
      padding="md"
      style={{
        minHeight: '100vh',
        background: 'linear-gradient(180deg, #0F172A 0%, #1E293B 100%)',
      }}
    >
      <AppShell.Header
        style={{
          background: 'rgba(15, 23, 42, 0.8)',
          backdropFilter: 'blur(10px)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
        }}
      >
        <Group h="100%" px="md" justify="space-between">
          <Group gap="sm">
            {showBurger && (
              <Burger
                opened={burgerOpened}
                onClick={onBurgerToggle}
                hiddenFrom="sm"
                size="sm"
                color="white"
              />
            )}
            <Text
              key={colorTheme} // Force re-render when theme changes
              fw={800}
              size={isMobile ? 'lg' : 'xl'}
              style={{
                background: gradient,
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text',
                cursor: 'pointer',
                transition: 'background 0.3s ease',
              }}
              onClick={() => navigate('/dashboard')}
            >
              Toniebee
            </Text>
            {title && (
              <Text fw={500} size="sm" c="gray.3" visibleFrom="sm">
                {title}
              </Text>
            )}
          </Group>

          <Group gap="sm">
            <ActionIcon
              variant="subtle"
              onClick={toggleTheme}
              aria-label="Toggle gradient style"
              color="gray"
              c="white"
              title={colorTheme === 'gradient' ? 'Switch to grey gradient' : 'Switch to colorful gradient'}
            >
              {colorTheme === 'gradient' ? <IconSun size={18} /> : <IconMoonStars size={18} />}
            </ActionIcon>

            {user && (
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
                          <Text size="sm" fw={500} c="white">
                            {user.name}
                          </Text>
                          <Text size="xs" c="gray.3">
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
                  <Menu.Item
                    leftSection={<IconUser size={14} />}
                    onClick={() => navigate('/dashboard')}
                  >
                    Dashboard
                  </Menu.Item>
                  <Menu.Divider />
                  <Menu.Item
                    leftSection={<IconLogout size={14} />}
                    color="red"
                    onClick={handleLogout}
                    disabled={logoutLoading}
                  >
                    {logoutLoading ? 'Logging out...' : 'Logout'}
                  </Menu.Item>
                </Menu.Dropdown>
              </Menu>
            )}
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Main>
        {children}
      </AppShell.Main>
    </AppShell>
  );
}

