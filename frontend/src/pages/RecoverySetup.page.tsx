import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Title,
  Text,
  Stack,
  Alert,
  Button,
  Group,
  Progress,
  Badge,
  Modal,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle, IconShield, IconClock } from '@tabler/icons-react';
import { TwoFactorSetupModal } from '@/components/TwoFactorSetupModal';

export function RecoverySetupPage() {
  const navigate = useNavigate();
  const [setupModalOpened, setSetupModalOpened] = useState(false);
  const [daysRemaining, setDaysRemaining] = useState(7);
  const [setupCompleted, setSetupCompleted] = useState(false);

  useEffect(() => {
    // Check if user actually used a recovery code (either from sessionStorage or if deadline exists)
    const recoveryCodeUsed = sessionStorage.getItem('recovery_code_used');
    const storedDeadline = localStorage.getItem('recovery_setup_deadline');
    
    // If no recovery code flag AND no deadline, they shouldn't be here
    if (recoveryCodeUsed !== 'true' && !storedDeadline) {
      // Not from recovery code login, redirect to dashboard
      navigate('/dashboard', { replace: true });
      return;
    }

    // If they have a deadline but no recovery_code_used flag, they're logging in again
    // Check if 2FA is set up - if yes, they don't need to be here
    if (!recoveryCodeUsed && storedDeadline) {
      check2FAStatusAndRedirect();
      return;
    }

    // Check if 2FA is already set up (user might have set it up already)
    check2FAStatus();

    // Set up countdown timer
    if (!storedDeadline) {
      // Set deadline 7 days from now (first time seeing this page)
      const deadline = new Date();
      deadline.setDate(deadline.getDate() + 7);
      localStorage.setItem('recovery_setup_deadline', deadline.toISOString());
      setDaysRemaining(7);
    } else {
      const deadline = new Date(storedDeadline);
      const now = new Date();
      const diff = Math.ceil((deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
      setDaysRemaining(Math.max(0, diff));
    }
  }, [navigate]);

  async function check2FAStatus() {
    try {
      const resp = await fetch('/api/users/me', {
        credentials: 'include',
      });

      if (resp.ok) {
        const data = await resp.json();
        const user = data.data.user;
        
        // IMPORTANT: Even if 2FA is enabled, if they used a recovery code,
        // they need to set up NEW 2FA because the old authenticator is lost.
        // Don't auto-redirect - let them set up new 2FA.
        // Only redirect if they've already completed the NEW setup after using recovery code.
        
        // We'll check this after they complete the setup in handleSetupComplete
        console.log('Recovery setup page - User 2FA status:', user.twoFactorEnabled);
        console.log('Recovery code was used, requiring new 2FA setup');
      }
    } catch (err) {
      console.error('Error checking 2FA status:', err);
    }
  }

  async function check2FAStatusAndRedirect() {
    try {
      const resp = await fetch('/api/users/me', {
        credentials: 'include',
      });

      if (resp.ok) {
        const data = await resp.json();
        const user = data.data.user;
        
        // If 2FA is already set up, they don't need to be here
        // Clear the deadline and redirect to dashboard
        if (user.twoFactorEnabled) {
          sessionStorage.removeItem('recovery_code_used');
          localStorage.removeItem('recovery_setup_deadline');
          navigate('/dashboard', { replace: true });
        }
        // If 2FA is not set up, stay on this page (they need to set it up)
      }
    } catch (err) {
      console.error('Error checking 2FA status for redirect:', err);
    }
  }

  function handleSetupComplete() {
    sessionStorage.removeItem('recovery_code_used');
    localStorage.removeItem('recovery_setup_deadline');
    setSetupCompleted(true);
    notifications.show({
      title: '2FA Setup Complete!',
      message: 'Your account is now secure. Redirecting to dashboard...',
      color: 'green',
      autoClose: 2000,
    });
    setTimeout(() => {
      navigate('/dashboard');
    }, 2000);
  }

  const [laterModalOpened, setLaterModalOpened] = useState(false);

  function handleLater() {
    if (daysRemaining <= 0) {
      notifications.show({
        title: 'Setup Required',
        message: 'You must set up 2FA to continue using your account.',
        color: 'red',
        autoClose: 5000,
      });
      return;
    }

    // Show modal before redirecting
    setLaterModalOpened(true);
  }

  function handleLaterConfirm() {
    setLaterModalOpened(false);
    // Don't clear recovery_code_used flag - we still need to track that they need to set up 2FA
    // Set a flag to indicate user intentionally navigated to dashboard (prevents redirect loop)
    sessionStorage.setItem('user_navigated_to_dashboard', 'true');
    notifications.show({
      title: 'Redirecting to Dashboard',
      message: `You have ${daysRemaining} day${daysRemaining !== 1 ? 's' : ''} remaining to set up 2FA.`,
      color: 'yellow',
      autoClose: 3000,
    });
    // Use replace to prevent back button from going back to recovery-setup
    navigate('/dashboard', { replace: true });
  }

  if (setupCompleted) {
    return (
      <Container size="sm" mt="xl">
        <Paper p="xl" withBorder radius="md" shadow="sm">
          <Stack align="center" gap="lg">
            <IconShield size={48} color="green" />
            <Title order={2} ta="center">
              2FA Setup Complete! ✅
            </Title>
            <Text c="dimmed" ta="center" size="lg">
              Your account is now secure. Redirecting to dashboard...
            </Text>
          </Stack>
        </Paper>
      </Container>
    );
  }

  const progress = ((7 - daysRemaining) / 7) * 100;

  return (
    <Container size="sm" mt="xl">
      <Paper p="xl" withBorder radius="md" shadow="sm">
        <Stack gap="lg">
          <div>
            <Title order={2} mb="xs">
              🔐 Security Setup Required
            </Title>
            <Text c="dimmed" size="sm" mb="md">
              You used a recovery code to access your account. Recovery codes are one-time use only.
            </Text>
            <Alert icon={<IconAlertCircle size={16} />} color="blue" variant="light" mb="md">
              <Text size="sm" fw={500} mb={4}>
                Why do I need to set up 2FA again?
              </Text>
              <Text size="xs">
                When you use a recovery code, it means you no longer have access to your authenticator app. 
                Setting up 2FA again ensures your account remains secure. You'll get new recovery codes to save.
              </Text>
            </Alert>
          </div>

          <Alert icon={<IconAlertCircle size={16} />} color="yellow" variant="light">
            <Text size="sm" fw={500} mb={4}>
              Important: Setup Deadline
            </Text>
            <Text size="xs">
              You have <strong>{daysRemaining} day{daysRemaining !== 1 ? 's' : ''}</strong> remaining to set up 2FA.
              After this period, your account will be locked until 2FA is configured.
            </Text>
          </Alert>

          {daysRemaining < 3 && daysRemaining > 0 && (
            <Alert icon={<IconClock size={16} />} color="orange" variant="light">
              <Text size="sm">
                <strong>Urgent:</strong> Only {daysRemaining} day{daysRemaining !== 1 ? 's' : ''} remaining!
              </Text>
            </Alert>
          )}

          {daysRemaining === 0 && (
            <Alert icon={<IconAlertCircle size={16} />} color="red" variant="light">
              <Text size="sm" fw={500}>
                Setup Required Now
              </Text>
              <Text size="xs">
                Your grace period has expired. You must set up 2FA to continue using your account.
              </Text>
            </Alert>
          )}

          <div>
            <Group justify="space-between" mb="xs">
              <Text size="sm" fw={500}>
                Time Remaining
              </Text>
              <Badge color={daysRemaining > 3 ? 'green' : daysRemaining > 0 ? 'orange' : 'red'}>
                {daysRemaining} day{daysRemaining !== 1 ? 's' : ''}
              </Badge>
            </Group>
            <Progress value={progress} color={daysRemaining > 3 ? 'green' : daysRemaining > 0 ? 'orange' : 'red'} />
          </div>

          <Stack gap="md" mt="md">
            <Button
              fullWidth
              size="lg"
              onClick={() => setSetupModalOpened(true)}
              leftSection={<IconShield size={20} />}
            >
              Set Up 2FA Now
            </Button>

            {daysRemaining > 0 && (
              <Button
                fullWidth
                variant="light"
                onClick={handleLater}
              >
                I'll Do This Later ({daysRemaining} day{daysRemaining !== 1 ? 's' : ''} remaining)
              </Button>
            )}
          </Stack>

          <Text size="xs" c="dimmed" ta="center" mt="md">
            Why is this required? Recovery codes are one-time use. Setting up 2FA ensures your account remains secure.
          </Text>
        </Stack>
      </Paper>

      <TwoFactorSetupModal
        opened={setupModalOpened}
        onClose={() => setSetupModalOpened(false)}
        onComplete={handleSetupComplete}
      />

      <Modal
        opened={laterModalOpened}
        onClose={() => setLaterModalOpened(false)}
        title="Reminder Set"
        centered
      >
        <Stack gap="md">
          <Text>
            You have <strong>{daysRemaining} day{daysRemaining !== 1 ? 's' : ''}</strong> remaining to set up 2FA.
          </Text>
          <Text size="sm" c="dimmed">
            A reminder will be shown on your dashboard. After the grace period expires, you'll need to set up 2FA to continue using your account.
          </Text>
          <Group justify="flex-end" mt="md">
            <Button variant="subtle" onClick={() => setLaterModalOpened(false)}>
              Cancel
            </Button>
            <Button onClick={handleLaterConfirm}>
              Continue to Dashboard
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Container>
  );
}

