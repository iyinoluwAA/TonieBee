import { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Group,
  Button,
  Burger,
  Drawer,
  Stack,
  Text,
  UnstyledButton,
  Box,
  Container,
  ActionIcon,
  Menu,
  Avatar,
  Divider,
} from '@mantine/core';
import { useDisclosure, useMediaQuery } from '@mantine/hooks';
import {
  IconUser,
  IconLogout,
  IconChevronDown,
} from '@tabler/icons-react';
import { useMantineColorScheme } from '@mantine/core';

interface NavItem {
  label: string;
  href: string;
}

const navItems: NavItem[] = [
  { label: 'Home', href: '/' },
  { label: 'Services', href: '/services' },
  { label: 'About Us', href: '/about' },
  { label: 'Resources', href: '/resources' },
  { label: 'Contact', href: '/contact' },
];

export function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const [opened, { toggle, close }] = useDisclosure(false);
  const [scrolled, setScrolled] = useState(false);
  const [isOverHero, setIsOverHero] = useState(true);
  const isMobile = useMediaQuery('(max-width: 768px)');
  const { colorScheme } = useMantineColorScheme();

  useEffect(() => {
    const handleScroll = () => {
      const scrollY = window.scrollY;
      setScrolled(scrollY > 20);
      // Hero section is approximately 90vh, so check if we're still in hero
      setIsOverHero(scrollY < window.innerHeight * 0.8);
    };
    window.addEventListener('scroll', handleScroll);
    handleScroll(); // Check initial state
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const isActive = (href: string) => location.pathname === href;

  return (
    <Box
      component="nav"
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 1000,
        transition: 'all 0.3s ease',
        backgroundColor: scrolled 
          ? (colorScheme === 'dark' ? 'rgba(30, 41, 59, 0.95)' : 'rgba(255, 255, 255, 0.95)')
          : (isOverHero ? 'transparent' : 'rgba(255, 255, 255, 0.95)'),
        backdropFilter: (scrolled || !isOverHero) ? 'blur(10px)' : 'none',
        boxShadow: (scrolled || !isOverHero) ? '0 2px 20px rgba(0, 0, 0, 0.1)' : 'none',
        borderBottom: (scrolled || !isOverHero) ? '1px solid rgba(0, 0, 0, 0.1)' : 'none',
      }}
    >
      <Container size="xl" py={{ base: 'sm', sm: 'md' }}>
        <Group justify="space-between" wrap="nowrap">
          {/* Logo */}
          <UnstyledButton
            onClick={() => navigate('/')}
            style={{ cursor: 'pointer' }}
          >
            <Text
              fw={800}
              size={isMobile ? 'lg' : 'xl'}
              style={{
                background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                backgroundClip: 'text',
              }}
            >
              Toniebee
            </Text>
          </UnstyledButton>

          {/* Desktop Navigation */}
          <Group gap="xl" visibleFrom="md" wrap="nowrap">
            {navItems.map((item) => (
              <UnstyledButton
                key={item.href}
                onClick={() => {
                  navigate(item.href);
                }}
                style={{
                  position: 'relative',
                  cursor: 'pointer',
                }}
              >
                <Text
                  fw={isActive(item.href) ? 600 : 500}
                  size="sm"
                  c={
                    isActive(item.href) 
                      ? 'trustBlue' 
                      : (isOverHero && !scrolled ? 'white' : 'dark.9')
                  }
                  style={{
                    transition: 'color 0.2s ease',
                    textShadow: (isOverHero && !scrolled) ? '0 2px 4px rgba(0, 0, 0, 0.2)' : 'none',
                  }}
                  onMouseEnter={(e) => {
                    if (!isActive(item.href)) {
                      if (isOverHero && !scrolled) {
                        e.currentTarget.style.color = 'rgba(255, 255, 255, 0.8)';
                      } else {
                        e.currentTarget.style.color = 'var(--mantine-color-trustBlue-6)';
                      }
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!isActive(item.href)) {
                      e.currentTarget.style.color = '';
                    }
                  }}
                >
                  {item.label}
                </Text>
                {isActive(item.href) && (
                  <Box
                    style={{
                      position: 'absolute',
                      bottom: -8,
                      left: 0,
                      right: 0,
                      height: 2,
                      background: 'linear-gradient(90deg, #1E40AF 0%, #0D9488 100%)',
                      borderRadius: 2,
                    }}
                  />
                )}
              </UnstyledButton>
            ))}
          </Group>

          {/* Actions */}
          <Group gap="sm" wrap="nowrap">
            <Button
              variant="subtle"
              size={isMobile ? 'sm' : 'md'}
              onClick={() => navigate('/login')}
              visibleFrom="sm"
            >
              <Text
                style={{
                  background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  backgroundClip: 'text',
                }}
              >
                Sign In
              </Text>
            </Button>
            <Button
              size={isMobile ? 'sm' : 'md'}
              radius="xl"
              onClick={() => navigate('/register')}
              visibleFrom="sm"
              style={{
                background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                border: 'none',
              }}
            >
              Sign Up Free
            </Button>
            
            {/* Mobile Menu Button */}
            <Burger
              opened={opened}
              onClick={toggle}
              hiddenFrom="md"
              size="sm"
              aria-label="Toggle navigation"
              color={isOverHero && !scrolled ? 'white' : undefined}
            />
          </Group>
        </Group>
      </Container>

      {/* Mobile Drawer */}
      <Drawer
        opened={opened}
        onClose={close}
        padding="xl"
        size="xs"
        position="right"
        hiddenFrom="md"
        withCloseButton={true}
        closeButtonProps={{ 'aria-label': 'Close navigation' }}
      >
        <Text fw={700} size="lg" c="trustBlue" mb="md">
          Menu
        </Text>
        <Stack gap="md">
          {navItems.map((item) => (
            <UnstyledButton
              key={item.href}
              onClick={() => {
                navigate(item.href);
                close();
              }}
              style={{
                padding: '0.75rem',
                borderRadius: '0.5rem',
                backgroundColor: isActive(item.href) 
                  ? 'var(--mantine-color-trustBlue-0)' 
                  : 'transparent',
                transition: 'background-color 0.2s ease',
              }}
            >
              <Text
                fw={isActive(item.href) ? 600 : 500}
                c={isActive(item.href) ? 'trustBlue' : 'dark.9'}
              >
                {item.label}
              </Text>
            </UnstyledButton>
          ))}
          
          <Divider my="md" />
          
          <Stack gap="sm">
            <Button
              variant="subtle"
              fullWidth
              onClick={() => {
                navigate('/login');
                close();
              }}
            >
              <Text
                style={{
                  background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  backgroundClip: 'text',
                }}
              >
                Sign In
              </Text>
            </Button>
            <Button
              fullWidth
              radius="xl"
              onClick={() => {
                navigate('/register');
                close();
              }}
              style={{
                background: 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)',
                border: 'none',
              }}
            >
              Sign Up Free
            </Button>
          </Stack>
        </Stack>
      </Drawer>
    </Box>
  );
}

