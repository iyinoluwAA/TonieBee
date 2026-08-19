import { Button, ButtonProps } from '@mantine/core';
import { useState } from 'react';
import { notifications } from '@mantine/notifications';
import { TwitterIcon } from '@mantinex/dev-icons';

export function TwitterButton(props: ButtonProps & React.ComponentPropsWithoutRef<'button'>) {
  const [loading, setLoading] = useState(false);

  async function handleOAuthLogin() {
    setLoading(true);
    try {
      const resp = await fetch('/api/oauth/twitter/initiate', {
        credentials: 'include',
      });
      
      if (resp.ok) {
        const data = await resp.json();
        // Redirect to OAuth provider
        window.location.href = data.redirect_url;
      } else {
        const error = await resp.json().catch(() => ({ message: 'Failed to initiate OAuth' }));
        notifications.show({
          title: 'OAuth Error',
          message: error.message || 'Failed to initiate Twitter login',
          color: 'red',
        });
        setLoading(false);
      }
    } catch (err) {
      notifications.show({
        title: 'Network Error',
        message: 'Unable to connect to server',
        color: 'red',
      });
      setLoading(false);
    }
  }

  return (
    <Button
      leftSection={<TwitterIcon size={16} color="#00ACEE" />}
      variant="default"
      onClick={handleOAuthLogin}
      loading={loading}
      {...props}
    >
      {props.children || 'Twitter'}
    </Button>
  );
}
