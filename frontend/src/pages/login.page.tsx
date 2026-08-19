import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { AuthenticationForm } from '../AuthenticationForm/AuthenticationForm';
import { ActionToggle } from '@/components/ColorSchemeToggle/ActionToggle';
import { notifications } from '@mantine/notifications';

export function LoginPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  useEffect(() => {
    // Handle OAuth callback redirect
    if (token) {
      notifications.show({
        title: 'Login Successful!',
        message: 'Redirecting to dashboard...',
        color: 'green',
        autoClose: 2000,
      });
      setTimeout(() => navigate('/dashboard'), 500);
    }
  }, [token, navigate]);

  return (
    <>
      <AuthenticationForm />
      <ActionToggle />
    </>
  );
}