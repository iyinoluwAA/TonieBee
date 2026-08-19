import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Title,
  TextInput,
  Button,
  Stack,
  Text,
  Anchor,
  Center,
  Alert,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle } from '@tabler/icons-react';
import { ActionToggle } from '@/components/ColorSchemeToggle/ActionToggle';

export function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [requires2FA, setRequires2FA] = useState(false);
  const [email, setEmail] = useState('');
  const [twoFACode, setTwoFACode] = useState('');

  const form = useForm({
    initialValues: {
      email: '',
    },
    validate: {
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
    },
  });

  async function handleSubmit(values: typeof form.values) {
    setLoading(true);
    try {
      const resp = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(values),
      });

      const data = await resp.json();

      if (resp.ok) {
        // Check if 2FA is required
        if (data.requires_2fa) {
          setRequires2FA(true);
          setEmail(values.email);
          notifications.show({
            title: '2FA Required',
            message: 'Please enter your 2FA code to continue',
            color: 'blue',
            autoClose: 5000,
          });
        } else {
          // No 2FA required - reset link sent
          notifications.show({
            title: 'Success',
            message: data.message || 'Password reset link has been sent to your email',
            color: 'green',
            autoClose: 5000,
          });
          // Redirect to login after a short delay
          setTimeout(() => {
            navigate('/login');
          }, 2000);
        }
      } else {
        notifications.show({
          title: 'Error',
          message: data.message || 'Failed to send password reset email',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      console.error('Forgot password error:', err);
      notifications.show({
        title: 'Error',
        message: 'An unexpected error occurred. Please try again.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  async function handle2FAVerify() {
    if (twoFACode.length !== 6) {
      notifications.show({
        title: 'Invalid Code',
        message: 'Please enter a 6-digit code from your authenticator app',
        color: 'red',
        autoClose: 3000,
      });
      return;
    }

    setLoading(true);
    try {
      const resp = await fetch('/api/auth/forgot-password-verify-2fa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          email,
          code: twoFACode,
        }),
      });

      const data = await resp.json();

      if (resp.ok) {
        notifications.show({
          title: 'Success',
          message: data.message || 'Password reset link has been sent to your email',
          color: 'green',
          autoClose: 5000,
        });
        // Redirect to login after a short delay
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      } else {
        notifications.show({
          title: 'Error',
          message: data.message || 'Invalid 2FA code. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      console.error('2FA verification error:', err);
      notifications.show({
        title: 'Error',
        message: 'An unexpected error occurred. Please try again.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Container size={420} my={40}>
        <Center>
          <Paper withBorder shadow="md" p={30} radius="md" w="100%">
            <Title ta="center" order={2}>
              Forgot Password?
            </Title>
            <Text c="dimmed" size="sm" ta="center" mt={5}>
              Enter your email address and we'll send you a link to reset your password.
            </Text>

            {requires2FA ? (
              <Stack mt="xl">
                <Alert
                  icon={<IconAlertCircle size="1rem" />}
                  title="2FA Verification Required"
                  color="blue"
                >
                  Your account has 2FA enabled. Please enter the 6-digit code from your authenticator app to continue.
                </Alert>
                <TextInput
                  label="2FA Code"
                  placeholder="000000"
                  required
                  maxLength={6}
                  value={twoFACode}
                  onChange={(e) => setTwoFACode(e.currentTarget.value.replace(/\D/g, ''))}
                />
                <Button
                  fullWidth
                  loading={loading}
                  onClick={handle2FAVerify}
                  disabled={twoFACode.length !== 6}
                >
                  Verify 2FA Code
                </Button>
                <Button
                  variant="subtle"
                  fullWidth
                  onClick={() => {
                    setRequires2FA(false);
                    setTwoFACode('');
                  }}
                >
                  Back
                </Button>
                <Text ta="center" size="sm">
                  Remember your password?{' '}
                  <Anchor
                    component="button"
                    type="button"
                    onClick={() => navigate('/login')}
                  >
                    Back to Login
                  </Anchor>
                </Text>
              </Stack>
            ) : (
              <form onSubmit={form.onSubmit(handleSubmit)}>
                <Stack mt="xl">
                  <TextInput
                    label="Email"
                    placeholder="your.email@example.com"
                    required
                    {...form.getInputProps('email')}
                  />

                  <Button type="submit" fullWidth loading={loading}>
                    Continue
                  </Button>

                  <Text ta="center" size="sm">
                    Remember your password?{' '}
                    <Anchor
                      component="button"
                      type="button"
                      onClick={() => navigate('/login')}
                    >
                      Back to Login
                    </Anchor>
                  </Text>
                </Stack>
              </form>
            )}
          </Paper>
        </Center>
      </Container>
      <ActionToggle />
    </>
  );
}

