import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Stack, Text, TextInput, Button, Group, Paper, Alert, Loader, Center, Divider } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle, IconKey } from '@tabler/icons-react';

interface TwoFactorVerifyStepProps {
  email: string;
  onSuccess: () => void;
  onCancel: () => void;
}

type VerificationMode = 'totp' | 'recovery' | 'select';

export function TwoFactorVerifyStep({ email, onSuccess, onCancel }: TwoFactorVerifyStepProps) {
  const navigate = useNavigate();
  const [mode, setMode] = useState<VerificationMode>('select');
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);

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

  async function handleVerify() {
    // Validate code length based on mode
    if (mode === 'totp' && code.length !== 6) {
      notifications.show({
        title: 'Invalid Code',
        message: 'Please enter a 6-digit code from your authenticator app.',
        color: 'red',
        autoClose: 3000,
      });
      return;
    }

    if (mode === 'recovery' && code.length !== 10) {
      notifications.show({
        title: 'Invalid Recovery Code',
        message: 'Recovery codes are 10 characters long. Please check your saved codes.',
        color: 'red',
        autoClose: 3000,
      });
      return;
    }

    setLoading(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      const resp = await fetch('/api/auth/verify-login', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          code: code,
          email: email,
        }),
      });

      if (resp.ok) {
        const data = await resp.json();
        
        // Check if recovery code was used (from backend response or mode)
        // Backend returns recoveryCodeUsed as boolean in the response
        const usedRecoveryCode = data.recoveryCodeUsed === true || data.recoveryCodeUsed === 'true' || mode === 'recovery';
        
        // If recovery code was used, redirect to recovery setup page
        if (usedRecoveryCode) {
          // Store flag that recovery code was used (sessionStorage is fine for hosting - it's client-side only)
          sessionStorage.setItem('recovery_code_used', 'true');
          console.log('Setting recovery_code_used flag and redirecting...');
          
          // Don't call onSuccess - we're redirecting instead
          notifications.show({
            title: 'Recovery Code Used',
            message: '⚠️ You used a recovery code. For security, you must set up 2FA again.',
            color: 'orange',
            autoClose: 2000,
          });
          
          // Redirect using React Router navigate (better for SPA, maintains state)
          console.log('Redirecting to /recovery-setup NOW');
          // Use navigate with replace to prevent back button issues
          navigate('/recovery-setup', { replace: true });
          return; // Exit early, don't call onSuccess
        } else {
          // Clear any stale recovery code flag
          sessionStorage.removeItem('recovery_code_used');
          
          notifications.show({
            title: 'Login Successful!',
            message: 'Redirecting to dashboard...',
            color: 'green',
            autoClose: 2000,
          });
          onSuccess();
        }
      } else {
        const error = await resp.json();
        notifications.show({
          title: 'Verification Failed',
          message: error.message || 'Invalid code. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
        setCode('');
      }
    } catch (err) {
      notifications.show({
        title: 'Network Error',
        message: 'Unable to verify code. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  // Mode selection screen
  if (mode === 'select') {
    return (
      <Paper p="xl" withBorder radius="md" w={{ base: '90%', sm: 450 }} mx="auto" mt={{ base: 20, sm: 50 }}>
        <Stack gap="md">
          <div>
            <Text size="lg" fw={500} mb={4}>
              Two-Factor Authentication Required
            </Text>
            <Text size="sm" c="dimmed">
              Choose how you want to verify your identity.
            </Text>
          </div>

          <Button
            fullWidth
            size="lg"
            onClick={() => setMode('totp')}
            leftSection={<IconKey size={20} />}
          >
            Enter 2FA Code from Authenticator App
          </Button>

          <Divider label="OR" labelPosition="center" />

          <Button
            fullWidth
            size="lg"
            variant="light"
            onClick={() => setMode('recovery')}
            leftSection={<IconKey size={20} />}
          >
            Lost 2FA App? Use Recovery Code
          </Button>

          <Alert icon={<IconAlertCircle size={16} />} color="blue" variant="light" mt="md">
            <Text size="xs">
              Recovery codes are 10-character codes you saved when setting up 2FA. 
              Each code can only be used once.
            </Text>
          </Alert>

          <Group justify="center" mt="md">
            <Button variant="subtle" onClick={onCancel} disabled={loading}>
              Cancel
            </Button>
          </Group>
        </Stack>
      </Paper>
    );
  }

  // TOTP Code Input
  if (mode === 'totp') {
    return (
      <Paper p="xl" withBorder radius="md" w={{ base: '90%', sm: 450 }} mx="auto" mt={{ base: 20, sm: 50 }}>
        <Stack gap="md">
          <div>
            <Text size="lg" fw={500} mb={4}>
              Enter 2FA Code
            </Text>
            <Text size="sm" c="dimmed">
              Enter the 6-digit code from your authenticator app.
            </Text>
          </div>

          <TextInput
            label="Verification Code"
            placeholder="000000"
            value={code}
            onChange={(e) => {
              const value = e.currentTarget.value.replace(/\D/g, '').slice(0, 6);
              setCode(value);
            }}
            maxLength={6}
            size="md"
            autoFocus
          />

          <Group justify="space-between" mt="md">
            <Button variant="subtle" onClick={() => setMode('select')} disabled={loading}>
              Back
            </Button>
            <Button onClick={handleVerify} loading={loading} disabled={code.length !== 6}>
              Verify & Login
            </Button>
          </Group>
        </Stack>
      </Paper>
    );
  }

  // Recovery Code Input
  return (
    <Paper p="xl" withBorder radius="md" w={{ base: '90%', sm: 450 }} mx="auto" mt={{ base: 20, sm: 50 }}>
      <Stack gap="md">
        <div>
          <Text size="lg" fw={500} mb={4}>
            Enter Recovery Code
          </Text>
          <Text size="sm" c="dimmed">
            Enter one of your 10-character recovery codes. Each code can only be used once.
          </Text>
        </div>

        <Alert icon={<IconAlertCircle size={16} />} color="yellow" variant="light">
          <Text size="xs" fw={500}>
            Important: After using a recovery code, you'll need to set up 2FA again with a new authenticator app.
          </Text>
        </Alert>

        <TextInput
          label="Recovery Code"
          placeholder="X3H7GFH5J2"
          value={code}
          onChange={(e) => {
            // Allow alphanumeric, uppercase, max 10 chars
            const value = e.currentTarget.value
              .toUpperCase()
              .replace(/[^A-Z0-9]/g, '')
              .slice(0, 10);
            setCode(value);
          }}
          maxLength={10}
          size="md"
          autoFocus
        />

        <Group justify="space-between" mt="md">
          <Button variant="subtle" onClick={() => setMode('select')} disabled={loading}>
            Back
          </Button>
          <Button onClick={handleVerify} loading={loading} disabled={code.length !== 10}>
            Verify & Login
          </Button>
        </Group>
      </Stack>
    </Paper>
  );
}

