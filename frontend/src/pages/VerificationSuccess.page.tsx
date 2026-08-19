import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Container, Paper, Stack, Text, Title, Center, Loader } from '@mantine/core';
import { notifications } from '@mantine/notifications';

export function VerificationSuccessPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [countdown, setCountdown] = useState(5);

  useEffect(() => {
    // Show success notification
    const notificationId = notifications.show({
      title: 'Email Verified! ✅',
      message: 'Your email has been successfully verified. Redirecting to dashboard...',
      color: 'green',
      autoClose: 5000,
    });

    // Countdown timer
    const interval = setInterval(() => {
      setCountdown((prev) => prev - 1);
    }, 1000);

    // Redirect after countdown
    const redirectTimer = setTimeout(() => {
      navigate('/dashboard');
    }, 5000);

    return () => {
      clearInterval(interval);
      clearTimeout(redirectTimer);
      notifications.hide(notificationId);
    };
  }, [navigate]);

  return (
    <Container size="sm" mt="xl">
      <Paper p="xl" withBorder radius="md" shadow="sm">
        <Stack align="center" gap="lg">
          <Center>
            <Loader size="lg" color="green" />
          </Center>
          <Title order={2} ta="center">
            Email Verified Successfully! 🎉
          </Title>
          <Text c="dimmed" ta="center" size="lg">
            Your account has been verified. You can now access all features.
          </Text>
          {countdown > 0 && (
            <Text size="sm" c="dimmed" ta="center">
              Redirecting to dashboard in {countdown} seconds...
            </Text>
          )}
        </Stack>
      </Paper>
    </Container>
  );
}

