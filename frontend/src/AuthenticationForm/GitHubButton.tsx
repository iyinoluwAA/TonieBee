import { Button, ButtonProps } from '@mantine/core';
import { useState } from 'react';
import { notifications } from '@mantine/notifications';
import { IconBrandGithub } from '@tabler/icons-react';

export function GitHubButton(props: ButtonProps & React.ComponentPropsWithoutRef<'button'>) {
  const [loading, setLoading] = useState(false);

  async function handleOAuthLogin() {
    setLoading(true);
    try {
      const resp = await fetch('/api/oauth/github/initiate', {
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
          message: error.message || 'Failed to initiate GitHub login',
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
      leftSection={<IconBrandGithub size={16} />}
      variant="default"
      onClick={handleOAuthLogin}
      loading={loading}
      {...props}
    >
      {props.children || 'GitHub'}
    </Button>
  );
}

