import { useState, useEffect } from 'react';
import {
  Stack,
  Text,
  Group,
  Button,
  Badge,
  Alert,
  Modal,
  Code,
  CopyButton,
  Tooltip,
  ActionIcon,
  Loader,
  Center,
  Paper,
  SimpleGrid,
  Checkbox,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconCheck, IconCopy, IconAlertCircle, IconDownload, IconRefresh } from '@tabler/icons-react';
import { useDisclosure } from '@mantine/hooks';

interface RecoveryCodesStatus {
  total: number;
  unused: number;
  used: number;
  expires_at: string | null;
  days_until_expiration: number | null;
}

export function RecoveryCodesSection() {
  const [status, setStatus] = useState<RecoveryCodesStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);
  const [regenerateModalOpened, { open: openRegenerateModal, close: closeRegenerateModal }] = useDisclosure(false);
  const [newCodes, setNewCodes] = useState<string[]>([]);
  const [codesSaved, setCodesSaved] = useState(false);
  const [downloadStatus, setDownloadStatus] = useState<'idle' | 'downloading' | 'downloaded'>('idle');

  useEffect(() => {
    fetchStatus();
  }, []);

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

  async function fetchStatus() {
    setLoading(true);
    try {
      const resp = await fetch('/api/2fa/recovery-codes', {
        credentials: 'include',
      });

      if (resp.ok) {
        const data = await resp.json();
        setStatus(data);
      } else {
        console.error('Failed to fetch recovery codes status');
      }
    } catch (err) {
      console.error('Error fetching recovery codes status:', err);
    } finally {
      setLoading(false);
    }
  }

  async function handleRegenerate() {
    setRegenerating(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      const resp = await fetch('/api/2fa/recovery-codes/regenerate', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({}),
      });

      if (resp.ok) {
        const data = await resp.json();
        setNewCodes(data.backup_codes);
        openRegenerateModal();
        fetchStatus(); // Refresh status
      } else {
        const error = await resp.json();
        notifications.show({
          title: 'Error',
          message: error.message || 'Failed to regenerate recovery codes',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      notifications.show({
        title: 'Network Error',
        message: 'Unable to regenerate codes. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setRegenerating(false);
    }
  }

  function handleCopyCodes() {
    const codesText = newCodes.join('\n');
    navigator.clipboard.writeText(codesText);
    notifications.show({
      title: 'Copied!',
      message: 'Recovery codes copied to clipboard',
      color: 'green',
      autoClose: 2000,
    });
  }

  function handleDownloadCodes() {
    // Set downloading state immediately
    setDownloadStatus('downloading');
    
    // Show notification that download started
    notifications.show({
      title: 'Download Started',
      message: 'Recovery codes download initiated',
      color: 'blue',
      autoClose: 2000,
    });
    
    const codesText = newCodes.join('\n');
    const blob = new Blob([codesText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `toniebee-recovery-codes-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    // Update button to show "Downloaded" after short delay
    setTimeout(() => {
      setDownloadStatus('downloaded');
    }, 1000); // 1 second - enough time for download to start
    
    // Reset button state after 3 seconds
    setTimeout(() => {
      setDownloadStatus('idle');
    }, 3000);
  }

  if (loading) {
    return (
      <Center py="md">
        <Loader size="sm" />
      </Center>
    );
  }

  if (!status) {
    return null;
  }

  const expirationText = status.days_until_expiration !== null
    ? status.days_until_expiration > 0
      ? `Expires in ${status.days_until_expiration} day${status.days_until_expiration !== 1 ? 's' : ''}`
      : status.days_until_expiration === 0
      ? 'Expires today'
      : 'Expired'
    : 'No expiration date';

  const expirationColor = status.days_until_expiration !== null
    ? status.days_until_expiration > 30
      ? 'green'
      : status.days_until_expiration > 7
      ? 'yellow'
      : 'red'
    : 'gray';

  return (
    <>
      <Stack gap="sm">
        <Group justify="space-between">
          <div>
            <Text fw={500} size="sm">
              Recovery Codes
            </Text>
            <Text size="xs" c="dimmed">
              Backup codes for account recovery
            </Text>
          </div>
          <Badge color={expirationColor} variant="light">
            {expirationText}
          </Badge>
        </Group>

        <Group gap="xs">
          <Text size="sm" c="dimmed">
            Total: <strong>{status.total}</strong> | Unused: <strong>{status.unused}</strong> | Used: <strong>{status.used}</strong>
          </Text>
        </Group>

        {status.unused < 3 && status.unused > 0 && (
          <Alert icon={<IconAlertCircle size={16} />} color="orange" variant="light">
            <Text size="xs">
              <strong>Warning:</strong> You have {status.unused} recovery code{status.unused !== 1 ? 's' : ''} remaining. Consider regenerating new codes.
            </Text>
          </Alert>
        )}

        {status.unused === 0 && (
          <Alert icon={<IconAlertCircle size={16} />} color="red" variant="light">
            <Text size="xs">
              <strong>Critical:</strong> You have no unused recovery codes. Please regenerate new codes immediately.
            </Text>
          </Alert>
        )}

        <Button
          variant="light"
          size="sm"
          leftSection={<IconRefresh size={16} />}
          onClick={handleRegenerate}
          loading={regenerating}
        >
          Regenerate Codes
        </Button>

        <Text size="xs" c="dimmed">
          Regenerating codes will invalidate all unused codes. Make sure to save the new codes securely.
        </Text>
      </Stack>

      <Modal
        opened={regenerateModalOpened}
        onClose={codesSaved ? closeRegenerateModal : undefined}
        closeOnClickOutside={codesSaved}
        closeOnEscape={codesSaved}
        title="New Recovery Codes Generated"
        size="lg"
        centered
      >
        <Stack>
          <Alert icon={<IconAlertCircle size={16} />} color="yellow" variant="light">
            <Text size="sm" fw={500} mb={4}>
              Important: Save These Codes
            </Text>
            <Text size="xs">
              These codes can only be viewed once. Save them in a secure location like a password manager.
            </Text>
          </Alert>

          <Paper p="md" withBorder style={{ backgroundColor: 'var(--mantine-color-dark-7)' }}>
            <SimpleGrid cols={2} spacing="xs">
              {newCodes.map((code, index) => (
                <Code key={index} block style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                  {code}
                </Code>
              ))}
            </SimpleGrid>
          </Paper>

          <Group>
            <CopyButton value={newCodes.join('\n')}>
              {({ copied, copy }) => (
                <Tooltip label={copied ? 'Copied!' : 'Copy to clipboard'}>
                  <ActionIcon color={copied ? 'teal' : 'gray'} onClick={copy}>
                    {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                  </ActionIcon>
                </Tooltip>
              )}
            </CopyButton>
            <Button
              variant="light"
              leftSection={<IconDownload size={16} />}
              onClick={handleDownloadCodes}
              disabled={downloadStatus === 'downloading'}
            >
              {downloadStatus === 'downloading' 
                ? 'Downloading...' 
                : downloadStatus === 'downloaded' 
                ? 'Downloaded' 
                : 'Download'}
            </Button>
          </Group>

          <Checkbox
            label="I've saved my recovery codes in a secure location"
            checked={codesSaved}
            onChange={(e) => setCodesSaved(e.currentTarget.checked)}
          />

          <Group justify="flex-end" mt="md">
            <Button
              onClick={closeRegenerateModal}
              disabled={!codesSaved}
            >
              I've Saved Them
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}

