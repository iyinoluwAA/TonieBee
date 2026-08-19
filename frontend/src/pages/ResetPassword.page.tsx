import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Container,
  Paper,
  Title,
  TextInput,
  PasswordInput,
  Button,
  Stack,
  Text,
  Anchor,
  Center,
  Alert,
  Loader,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle } from '@tabler/icons-react';
import { ActionToggle } from '@/components/ColorSchemeToggle/ActionToggle';
import { PasswordStrengthMeter } from '@/components/PasswordStrengthMeter';

export function ResetPasswordPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [validating, setValidating] = useState(true);
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const tokenParam = searchParams.get('token');
    if (!tokenParam) {
      setError('Invalid reset link. Please request a new password reset.');
      setValidating(false);
      return;
    }

    setToken(tokenParam);
    
    // Validate token immediately when page loads
    async function validateToken() {
      try {
        const resp = await fetch(`/api/auth/validate-reset-token?token=${encodeURIComponent(tokenParam)}`, {
          method: 'GET',
          credentials: 'include',
        });

        if (!resp.ok) {
          const data = await resp.json().catch(() => ({ message: 'Invalid or expired token. Please request a new password reset.' }));
          // Use generic error message (security: don't reveal specific token state)
          setError(data.message || 'Invalid or expired token. Please request a new password reset.');
        }
        // If OK, token is valid - allow form to be shown
      } catch (err) {
        console.error('Token validation error:', err);
        setError('Failed to validate token. Please try again or request a new password reset.');
      } finally {
        setValidating(false);
      }
    }

    validateToken();
  }, [searchParams]);

  const form = useForm({
    initialValues: {
      newPassword: '',
      confirmPassword: '',
    },
    validate: {
      newPassword: (val) => {
        if (val.length < 14) return 'Password must be at least 14 characters (recommended: 16+)';
        if (val.length > 128) return 'Password must not exceed 128 characters';
        
        if (!/[a-z]/.test(val)) return 'Password must contain at least one lowercase letter';
        if (!/[A-Z]/.test(val)) return 'Password must contain at least one uppercase letter';
        if (!/[0-9]/.test(val)) return 'Password must contain at least one number';
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(val)) {
          return 'Password must contain at least one special character';
        }
        
        const lowercaseCount = (val.match(/[a-z]/g) || []).length;
        const uppercaseCount = (val.match(/[A-Z]/g) || []).length;
        const numberCount = (val.match(/[0-9]/g) || []).length;
        const specialCount = (val.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length;
        
        if (lowercaseCount < 2) return 'Password must contain at least 2 lowercase letters';
        if (uppercaseCount < 2) return 'Password must contain at least 2 uppercase letters';
        if (numberCount < 2) return 'Password must contain at least 2 numbers';
        if (specialCount < 2) return 'Password must contain at least 2 special characters';
        
        return null;
      },
      confirmPassword: (val, values) =>
        val !== values.newPassword ? 'Passwords do not match' : null,
    },
  });

  async function handleSubmit(values: typeof form.values) {
    if (!token) {
      setError('Invalid reset token. Please request a new password reset.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const resp = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          token,
          new_password: values.newPassword,
          new_password_confirm: values.confirmPassword,
        }),
      });

      // Try to parse as JSON, fallback to text if it fails
      let errorMessage = 'Failed to reset password. The token may have expired.';
      let data: any = null;

      const text = await resp.text();
      if (text) {
        try {
          data = JSON.parse(text);
          errorMessage = data.message || errorMessage;
        } catch {
          // If not JSON, use the text as error message
          errorMessage = text || errorMessage;
        }
      }

      if (resp.ok && data) {
        notifications.show({
          title: 'Success',
          message: data.message || 'Password has been successfully reset',
          color: 'green',
          autoClose: 7000,
        });
        // Redirect to login after a short delay
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      } else {
        setError(errorMessage);
        notifications.show({
          title: 'Error',
          message: errorMessage,
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      console.error('Reset password error:', err);
      const errorMsg = err instanceof Error ? err.message : 'An unexpected error occurred. Please try again.';
      setError(errorMsg);
      notifications.show({
        title: 'Error',
        message: errorMsg,
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  // Show loading state while validating token
  if (validating) {
    return (
      <>
        <Container size={420} my={40}>
          <Center>
            <Paper withBorder shadow="md" p={30} radius="md" w="100%">
              <Stack align="center" gap="md">
                <Loader size="sm" />
                <Text ta="center">Validating reset token...</Text>
              </Stack>
            </Paper>
          </Center>
        </Container>
        <ActionToggle />
      </>
    );
  }

  // Show error if token is invalid or expired
  if (error && (!token || error.includes('expired') || error.includes('Invalid'))) {
    return (
      <>
        <Container size={420} my={40}>
          <Center>
            <Paper withBorder shadow="md" p={30} radius="md" w="100%">
              <Alert
                icon={<IconAlertCircle size="1rem" />}
                title="Invalid or Expired Reset Link"
                color="red"
                mb="md"
              >
                {error}
              </Alert>
              <Button
                fullWidth
                onClick={() => navigate('/forgot-password')}
                mt="md"
              >
                Request a new password reset
              </Button>
            </Paper>
          </Center>
        </Container>
        <ActionToggle />
      </>
    );
  }

  return (
    <>
      <Container size={420} my={40}>
        <Center>
          <Paper withBorder shadow="md" p={30} radius="md" w="100%">
            <Title ta="center" order={2}>
              Reset Password
            </Title>
            <Text c="dimmed" size="sm" ta="center" mt={5}>
              Enter your new password below.
            </Text>

            {error && (
              <Alert
                icon={<IconAlertCircle size="1rem" />}
                title="Error"
                color="red"
                mb="md"
                mt="md"
              >
                {error}
              </Alert>
            )}

            <form onSubmit={form.onSubmit(handleSubmit)}>
              <Stack mt="xl">
                <PasswordInput
                  label="New Password"
                  placeholder="Enter your new password"
                  required
                  {...form.getInputProps('newPassword')}
                />
                <PasswordStrengthMeter password={form.values.newPassword} />

                <PasswordInput
                  label="Confirm Password"
                  placeholder="Confirm your new password"
                  required
                  {...form.getInputProps('confirmPassword')}
                />

                <Button type="submit" fullWidth loading={loading}>
                  Reset Password
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
          </Paper>
        </Center>
      </Container>
      <ActionToggle />
    </>
  );
}

