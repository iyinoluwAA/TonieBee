import { useState } from 'react';
import {
  Modal,
  Stack,
  Text,
  TextInput,
  Button,
  Group,
  Paper,
  Alert,
  Code,
  CopyButton,
  Tooltip,
  ActionIcon,
  Loader,
  Center,
  Checkbox,
  Box,
  Anchor,
  Divider,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconCheck, IconCopy, IconAlertCircle, IconDownload } from '@tabler/icons-react';
import { QRCodeSVG } from 'qrcode.react';

interface TwoFactorSetupModalProps {
  opened: boolean;
  onClose: () => void;
  onComplete: () => void;
}

export function TwoFactorSetupModal({ opened, onClose, onComplete }: TwoFactorSetupModalProps) {
  const [loading, setLoading] = useState(false);
  const [setupLoading, setSetupLoading] = useState(false);
  const [step, setStep] = useState<'setup' | 'verify' | 'recovery'>('setup');
  const [secret, setSecret] = useState<string>('');
  const [qrCodeUrl, setQrCodeUrl] = useState<string>('');
  const [verificationCode, setVerificationCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [email, setEmail] = useState<string>('');
  const [codesSaved, setCodesSaved] = useState(false);
  const [downloadStatus, setDownloadStatus] = useState<'idle' | 'downloading' | 'downloaded'>('idle');

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

  async function handleSetup() {
    setSetupLoading(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      const resp = await fetch('/api/2fa/setup', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({}),
      });

      if (resp.ok) {
        const data = await resp.json();
        console.log('2FA Setup Response: secret=', data.secret, 'secret_length=', data.secret?.length);
        console.log('2FA Setup: QR URL length=', data.qr_code_url?.length);
        console.log('2FA Setup: Full QR URL:', data.qr_code_url);
        
        // Extract secret from QR URL to verify it matches
        const secretMatch = data.qr_code_url.match(/secret=([^&]+)/);
        if (secretMatch) {
          const secretFromUrl = secretMatch[1];
          console.log('2FA Setup: Secret from QR URL:', secretFromUrl);
          console.log('2FA Setup: Secret from response:', data.secret);
          console.log('2FA Setup: Secrets match?', secretFromUrl === data.secret);
        }
        
        setSecret(data.secret);
        setQrCodeUrl(data.qr_code_url);
        
        // Extract email from QR code URL for display (format: otpauth://totp/Toniebee:email@example.com?secret=...)
        try {
          // Try URL-decoded first, then plain
          const urlMatch = data.qr_code_url.match(/Toniebee%3A([^%&?]+)/) || 
                          data.qr_code_url.match(/Toniebee:([^?&]+)/);
          if (urlMatch) {
            const emailExtracted = decodeURIComponent(urlMatch[1]);
            setEmail(emailExtracted);
            console.log('2FA Setup: Secret=', data.secret, 'Email=', emailExtracted);
          }
        } catch (e) {
          console.error('Failed to extract email from QR URL:', e);
        }
        setStep('verify');
      } else {
        const error = await resp.json();
        notifications.show({
          title: 'Setup Failed',
          message: error.message || 'Failed to setup 2FA. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      notifications.show({
        title: 'Network Error',
        message: 'Unable to setup 2FA. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setSetupLoading(false);
    }
  }

  async function handleVerify() {
    if (verificationCode.length !== 6) {
      notifications.show({
        title: 'Invalid Code',
        message: 'Please enter a 6-digit code from your authenticator app.',
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

      console.log('2FA Verify: Sending code=', verificationCode, 'secret=', secret, 'secret_length=', secret?.length);
      
      const resp = await fetch('/api/2fa/verify', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          code: verificationCode,
          secret: secret, // Make sure we're sending the exact secret from setup
        }),
      });

      if (resp.ok) {
        const data = await resp.json();
        setBackupCodes(data.backup_codes);
        setStep('recovery'); // Move to recovery codes step
      } else {
        let errorMessage = 'Invalid verification code. Please try again.';
        try {
          const error = await resp.json();
          errorMessage = error.message || errorMessage;
          console.error('2FA Verification error:', error, 'Status:', resp.status);
        } catch (e) {
          console.error('Failed to parse error response:', e);
          errorMessage = `Verification failed (${resp.status}). Please check your CSRF token and try again.`;
        }
        notifications.show({
          title: 'Verification Failed',
          message: errorMessage,
          color: 'red',
          autoClose: 5000,
        });
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

  function handleClose() {
    setStep('setup');
    setSecret('');
    setQrCodeUrl('');
    setVerificationCode('');
    setBackupCodes([]);
    setCodesSaved(false);
    onClose();
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
    
    const content = backupCodes.join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
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

  function handleComplete() {
    if (!codesSaved) {
      notifications.show({
        title: 'Please Confirm',
        message: 'Please confirm that you have saved your recovery codes',
        color: 'orange',
        autoClose: 3000,
      });
      return;
    }
    notifications.show({
      title: '2FA Enabled!',
      message: 'Two-factor authentication has been successfully enabled for your account.',
      color: 'green',
      autoClose: 5000,
    });
    onComplete();
    handleClose();
  }

  // Prevent closing modal during critical recovery code step
  const canClose = step !== 'recovery' || codesSaved;
  
  function handleModalClose() {
    if (!canClose) {
      notifications.show({
        title: 'Please Save Your Codes',
        message: 'You must save your recovery codes before closing. Please copy or download them first.',
        color: 'orange',
        autoClose: 3000,
      });
      return;
    }
    handleClose();
  }

  return (
    <Modal
      opened={opened}
      onClose={canClose ? handleModalClose : undefined}
      closeOnClickOutside={canClose}
      closeOnEscape={canClose}
      title={
        step === 'setup'
          ? 'Multi-factor Authentication'
          : step === 'verify'
          ? 'Verify Setup'
          : 'Recovery codes'
      }
      centered
      size={step === 'recovery' ? 'lg' : 'md'}
      overlayProps={{
        backgroundOpacity: 0.55,
        blur: 3,
      }}
    >
      <Stack gap="md">
        {step === 'setup' ? (
          <>
            <Text size="sm" c="dimmed">
              Use an authenticator app like{' '}
              <Anchor href="https://1password.com/" target="_blank" size="sm">
                1Password
              </Anchor>
              ,{' '}
              <Anchor href="https://www.google.com/authenticator" target="_blank" size="sm">
                Google Authenticator
              </Anchor>
              , or{' '}
              <Anchor href="https://www.microsoft.com/en-us/security/mobile-authenticator-app" target="_blank" size="sm">
                Microsoft Authenticator
              </Anchor>{' '}
              to generate one-time passwords that are used as a second factor when you sign in to Toniebee.
            </Text>

            <Text size="xs" c="dimmed">
              Enable or disable MFA at any time in the User Settings page.
            </Text>

            <Group justify="flex-end" mt="md">
              <Button variant="subtle" onClick={handleClose}>
                Skip
              </Button>
              <Button onClick={handleSetup} loading={setupLoading}>
                Next
              </Button>
            </Group>
          </>
        ) : step === 'verify' ? (
          <>
            <Text size="sm" c="dimmed" mb="xs">
              Scan the QR code using your authenticator app
            </Text>

            <Center>
              <Paper p="md" withBorder style={{ backgroundColor: 'white' }}>
                {qrCodeUrl ? (
                  <QRCodeSVG 
                    value={qrCodeUrl} 
                    size={256} 
                    level="M"
                    includeMargin={true}
                  />
                ) : (
                  <Loader size="md" />
                )}
              </Paper>
            </Center>

            <Divider label="OR" labelPosition="center" my="md" />

            <Text size="sm" c="dimmed" mb="xs">
              Or enter the code below into the authenticator app
            </Text>

            <Box>
              <Group gap="xs" wrap="nowrap" align="center">
                <Code 
                  style={{ 
                    fontSize: '18px', 
                    fontFamily: 'monospace', 
                    fontWeight: 600,
                    letterSpacing: '2px',
                    flex: 1,
                    textAlign: 'center',
                    padding: '12px',
                  }}
                >
                  {secret}
                </Code>
                <CopyButton value={secret} timeout={2000}>
                  {({ copied, copy }) => (
                    <Tooltip label={copied ? 'Copied!' : 'Copy to clipboard'} withArrow>
                      <ActionIcon 
                        color={copied ? 'teal' : 'gray'} 
                        variant="subtle" 
                        onClick={copy}
                        size="lg"
                      >
                        {copied ? <IconCheck size={20} /> : <IconCopy size={20} />}
                      </ActionIcon>
                    </Tooltip>
                  )}
                </CopyButton>
              </Group>
            </Box>

            <TextInput
              label="Enter verification code"
              placeholder="000000"
              value={verificationCode}
              onChange={(e) => {
                const value = e.currentTarget.value.replace(/\D/g, '').slice(0, 6);
                setVerificationCode(value);
              }}
              maxLength={6}
              size="md"
              mt="xl"
            />

            <Group justify="flex-end" mt="md">
              <Button variant="subtle" onClick={() => setStep('setup')}>
                Back
              </Button>
              <Button onClick={handleVerify} loading={loading} disabled={verificationCode.length !== 6}>
                Verify & Enable
              </Button>
            </Group>
          </>
        ) : (
          // Recovery Codes Step
          <>
            <Text size="sm" c="dimmed">
              The below codes are used to recover your account in case you lose access to your MFA authenticator.
            </Text>

            <Text size="sm" c="dimmed">
              Save these recovery codes as securely as a password. We recommend using a password manager such as{' '}
              <Anchor href="https://1password.com/" target="_blank" size="sm">
                1Password
              </Anchor>
              ,{' '}
              <Anchor href="https://keepassxc.org/" target="_blank" size="sm">
                KeePassXC
              </Anchor>
              , or{' '}
              <Anchor href="https://bitwarden.com/" target="_blank" size="sm">
                bitwarden
              </Anchor>
              .
            </Text>

            <Alert icon={<IconAlertCircle size={16} />} color="red" variant="light">
              <Text size="sm" fw={500}>
                If you cannot find these codes, you will lose access to your account.
              </Text>
            </Alert>

            <Paper p="md" withBorder style={{ backgroundColor: 'var(--mantine-color-dark-7)' }}>
              <Group gap="md" align="flex-start">
                <Stack gap="xs" style={{ flex: 1 }}>
                  {backupCodes.slice(0, 5).map((code, index) => (
                    <Code
                      key={index}
                      style={{
                        fontSize: '14px',
                        fontFamily: 'monospace',
                        fontWeight: 500,
                        padding: '8px 12px',
                        width: '100%',
                        textAlign: 'center',
                      }}
                    >
                      {code}
                    </Code>
                  ))}
                </Stack>
                <Stack gap="xs" style={{ flex: 1 }}>
                  {backupCodes.slice(5, 10).map((code, index) => (
                    <Code
                      key={index + 5}
                      style={{
                        fontSize: '14px',
                        fontFamily: 'monospace',
                        fontWeight: 500,
                        padding: '8px 12px',
                        width: '100%',
                        textAlign: 'center',
                      }}
                    >
                      {code}
                    </Code>
                  ))}
                </Stack>
              </Group>
            </Paper>

            <Group gap="sm">
              <CopyButton value={backupCodes.join('\n')} timeout={2000}>
                {({ copied, copy }) => (
                  <Button
                    variant="light"
                    leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                    onClick={copy}
                    style={{ flex: 1 }}
                  >
                    {copied ? 'Copied!' : 'Copy to clipboard'}
                  </Button>
                )}
              </CopyButton>
              <Button
                variant="light"
                leftSection={<IconDownload size={16} />}
                onClick={handleDownloadCodes}
                disabled={downloadStatus === 'downloading'}
                style={{ flex: 1 }}
              >
                {downloadStatus === 'downloading' 
                  ? 'Downloading...' 
                  : downloadStatus === 'downloaded' 
                  ? 'Downloaded' 
                  : 'Download'}
              </Button>
            </Group>

            <Checkbox
              checked={codesSaved}
              onChange={(e) => setCodesSaved(e.currentTarget.checked)}
              label="I've saved my recovery codes"
              mt="md"
            />

            <Group justify="flex-end" mt="xl">
              <Button onClick={handleComplete} disabled={!codesSaved}>
                Continue
              </Button>
            </Group>
          </>
        )}
      </Stack>
    </Modal>
  );
}

