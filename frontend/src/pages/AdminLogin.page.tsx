import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Title,
  TextInput,
  PasswordInput,
  Button,
  Stack,
  Text,
  Alert,
  Center,
  Loader,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle, IconShield } from '@tabler/icons-react';
import { TwoFactorVerifyStep } from '@/components/TwoFactorVerifyStep';

export function AdminLoginPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [show2FA, setShow2FA] = useState(false);
  const [pendingEmail, setPendingEmail] = useState<string>('');

  const form = useForm({
    initialValues: {
      email: '',
      password: '',
    },
    validate: {
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
      password: (val) => (val.length < 6 ? 'Password must be at least 6 characters' : null),
    },
  });

  async function handleSubmit(values: typeof form.values) {
    setLoading(true);
    try {
      const resp = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: values.email, password: values.password }),
        credentials: 'include',
      });

      if (resp.status === 200) {
        // Check if 2FA is required
        try {
          const body = await resp.json();
          if (body.status === '2fa_required') {
            // Show 2FA verification step
            setPendingEmail(values.email);
            setShow2FA(true);
            setLoading(false);
            return;
          }
        } catch (e) {
          // Not JSON, continue
        }

        // Check if user is admin
        const userResp = await fetch('/api/users/me', {
          credentials: 'include',
        });

        if (userResp.status === 200) {
          const userData = await userResp.json();
          const user = userData.data.user;

          if (user.role !== 'admin') {
            notifications.show({
              title: 'Access Denied',
              message: 'This account does not have admin privileges.',
              color: 'red',
              autoClose: 5000,
            });
            setLoading(false);
            return;
          }

          // Admin login successful
          notifications.show({
            title: 'Admin Login Successful!',
            message: 'Redirecting to admin dashboard...',
            color: 'green',
            autoClose: 2000,
          });
          setTimeout(() => navigate('/admin'), 500);
        } else {
          notifications.show({
            title: 'Error',
            message: 'Failed to verify admin status.',
            color: 'red',
            autoClose: 5000,
          });
        }
      } else if (resp.status === 401) {
        let msg: string = 'Login failed';
        try {
          const body = await resp.json();
          if (body && typeof body === 'object' && 'message' in body) {
            msg = String(body.message);
          }
        } catch (e) {
          msg = await resp.text().catch(() => 'Login failed');
        }

        notifications.show({
          title: 'Login Failed',
          message: msg,
          color: 'red',
          autoClose: 5000,
        });
      } else {
        const text = await resp.text();
        notifications.show({
          title: 'Login Failed',
          message: text || 'Something went wrong. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      console.error('Admin login error:', err);
      notifications.show({
        title: 'Network Error',
        message: 'Unable to connect to server. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  if (show2FA) {
    return (
      <TwoFactorVerifyStep
        email={pendingEmail}
        onSuccess={() => {
          // After 2FA verification, check if user is admin
          fetch('/api/users/me', {
            credentials: 'include',
          })
            .then((resp) => {
              if (resp.status === 200) {
                return resp.json();
              }
              throw new Error('Failed to verify admin status');
            })
            .then((data) => {
              const user = data.data.user;
              if (user.role !== 'admin') {
                notifications.show({
                  title: 'Access Denied',
                  message: 'This account does not have admin privileges.',
                  color: 'red',
                  autoClose: 5000,
                });
                navigate('/admin/login');
              } else {
                notifications.show({
                  title: 'Admin Login Successful!',
                  message: 'Redirecting to admin dashboard...',
                  color: 'green',
                  autoClose: 2000,
                });
                setTimeout(() => navigate('/admin'), 500);
              }
            })
            .catch((err) => {
              console.error('Error verifying admin status:', err);
              notifications.show({
                title: 'Error',
                message: 'Failed to verify admin status.',
                color: 'red',
                autoClose: 5000,
              });
              navigate('/admin/login');
            });
        }}
        onCancel={() => {
          setShow2FA(false);
          setPendingEmail('');
        }}
      />
    );
  }

  return (
    <Container size={420} my={40}>
      <Center>
        <Paper withBorder shadow="md" p={30} radius="md" w="100%">
          <Stack gap="md" align="center" mb="xl">
            <IconShield size={48} stroke={1.5} />
            <Title ta="center" order={2}>
              Admin Login
            </Title>
            <Text c="dimmed" size="sm" ta="center">
              Sign in to access the admin dashboard
            </Text>
          </Stack>

          <Alert icon={<IconAlertCircle size={16} />} color="blue" variant="light" mb="md">
            <Text size="xs">
              This page is for administrators only. If you're a regular user, please use the{' '}
              <a href="/login" style={{ textDecoration: 'underline' }}>
                regular login page
              </a>
              .
            </Text>
          </Alert>

          <form onSubmit={form.onSubmit((values) => void handleSubmit(values))}>
            <Stack>
              <TextInput
                required
                label="Email"
                placeholder="admin@example.com"
                value={form.values.email}
                onChange={(event) => form.setFieldValue('email', event.currentTarget.value)}
                error={form.errors.email}
                radius="md"
              />

              <PasswordInput
                required
                label="Password"
                placeholder="Your password"
                value={form.values.password}
                onChange={(event) => form.setFieldValue('password', event.currentTarget.value)}
                error={form.errors.password}
                radius="md"
              />

              <Button type="submit" radius="xl" fullWidth loading={loading} mt="md">
                Sign In as Admin
              </Button>
            </Stack>
          </form>

          <Text ta="center" size="sm" c="dimmed" mt="md">
            <a href="/login" style={{ textDecoration: 'underline' }}>
              Regular user login
            </a>
          </Text>
        </Paper>
      </Center>
    </Container>
  );
}

