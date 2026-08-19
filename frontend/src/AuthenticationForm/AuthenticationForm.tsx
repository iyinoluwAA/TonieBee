import React, { useState } from 'react';
import {
  Anchor,
  Button,
  Checkbox,
  Divider,
  Group,
  Paper,
  PaperProps,
  PasswordInput,
  Stack,
  Text,
  TextInput,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { upperFirst, useToggle } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { GoogleButton } from './GoogleButton';
import { useNavigate } from 'react-router-dom';
import { TwitterButton } from './TwitterButton';
import { GitHubButton } from './GitHubButton';
import { PasswordStrengthMeter } from '@/components/PasswordStrengthMeter';
import { TwoFactorVerifyStep } from '@/components/TwoFactorVerifyStep';

type FormValues = {
  email: string;
  name: string;
  password: string;
  passwordConfirm: string;
  terms: boolean;
};

export function AuthenticationForm(props: PaperProps) {
  const navigate = useNavigate();
  const [type, toggle] = useToggle(['login', 'register']);
  const [showResend, setShowResend] = useState(false);
  const [show2FA, setShow2FA] = useState(false);
  const [pendingEmail, setPendingEmail] = useState<string>('');
  const form = useForm<FormValues>({
    initialValues: {
      email: '',
      name: '',
      password: '',
      passwordConfirm: '',
      terms: false, // Terms must be explicitly accepted
    },

    validate: {
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
      password: (val) => {
        if (type === 'register') {
          // Stricter password requirements
          if (val.length < 14) return 'Password must be at least 14 characters (recommended: 16+)';
          if (val.length > 128) return 'Password must not exceed 128 characters';
          
          // Character requirements
          if (!/[a-z]/.test(val)) return 'Password must contain at least one lowercase letter';
          if (!/[A-Z]/.test(val)) return 'Password must contain at least one uppercase letter';
          if (!/[0-9]/.test(val)) return 'Password must contain at least one number';
          if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(val)) {
            return 'Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:\'",.<>?)';
          }
          
          // Require at least 2 of each character type for stronger passwords
          const lowercaseCount = (val.match(/[a-z]/g) || []).length;
          const uppercaseCount = (val.match(/[A-Z]/g) || []).length;
          const numberCount = (val.match(/[0-9]/g) || []).length;
          const specialCount = (val.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length;
          
          if (lowercaseCount < 2) return 'Password must contain at least 2 lowercase letters';
          if (uppercaseCount < 2) return 'Password must contain at least 2 uppercase letters';
          if (numberCount < 2) return 'Password must contain at least 2 numbers';
          if (specialCount < 2) return 'Password must contain at least 2 special characters';
          
          // Pattern checks - sequential characters
          if (/(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(val)) {
            return 'Avoid sequential characters (abc, 123, etc.)';
          }
          
          // Repeating characters
          if (/(.)\1{3,}/.test(val)) {
            return 'Avoid repeating the same character 4+ times (aaaa, 1111)';
          }
          
          // Keyboard patterns
          if (/(qwerty|asdf|zxcv|qaz|wsx|edc)/i.test(val)) {
            return 'Avoid keyboard patterns (qwerty, asdf)';
          }
          
          // Common passwords (case-insensitive)
          const commonPasswords = [
            'password', 'password123', 'password1', 'password12',
            '12345678', '123456789', '1234567890', '12345678901',
            'qwerty', 'qwerty123', 'qwertyuiop',
            'admin', 'admin123', 'administrator',
            'letmein', 'welcome', 'welcome123',
            'monkey', 'iloveyou', 'princess',
            'abc123', '123qwe', 'qwe123',
            'password!', 'P@ssw0rd', 'P@ssw0rd123'
          ];
          
          if (commonPasswords.some(common => val.toLowerCase().includes(common.toLowerCase()))) {
            return 'Password is too common. Please choose a more unique password.';
          }
          
          // Check if password contains email (if email is entered)
          if (form.values.email && val.toLowerCase().includes(form.values.email.toLowerCase().split('@')[0])) {
            return 'Password should not contain your email address';
          }
          
          // Check if password contains name (if name is entered)
          if (form.values.name && val.toLowerCase().includes(form.values.name.toLowerCase())) {
            return 'Password should not contain your name';
          }
          
          return null; // All checks passed
        } else {
          // Login mode - just check minimum length
          if (val.length < 6) return 'Password must be at least 6 characters';
          return null;
        }
      },
      passwordConfirm: (val, values) => {
        // Only validate in register mode
        if (type === 'register' && val) {
          return values.password !== val ? 'Passwords do not match' : null;
        }
        return null;
      },
      terms: (val) => {
        // Only validate in register mode
        if (type === 'register') {
          return val ? null : 'You must accept the Terms and Conditions to register';
        }
        return null;
      },
    },
  });

  async function submit(values: FormValues) {
    setShowResend(false);

    console.log('Form submitted:', { type, email: values.email });

    try {
      if (type === 'register') {
        const resp = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: values.name,
            email: values.email,
            password: values.password,
            passwordconfirm: values.passwordConfirm, // backend expects this key
            termsAccepted: values.terms, // Terms and Conditions acceptance
          }),
          credentials: 'include',
        });

        if (resp.status === 201) {
          notifications.show({
            title: 'Registration Successful!',
            message: 'Please check your email to verify your account.',
            color: 'green',
            autoClose: 5000,
          });
          form.reset();
        } else {
          const text = await resp.text();
          notifications.show({
            title: 'Registration Failed',
            message: text || 'Something went wrong. Please try again.',
            color: 'red',
            autoClose: 5000,
          });
        }
      } else {
        // login
        const resp = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: values.email, password: values.password }),
          credentials: 'include',
        });

        if (resp.status === 200) {
          // Check if 2FA is required
          try {
            const body = await resp.json();
            if (body.status === '2fa_required') {
              setPendingEmail(values.email);
              setShow2FA(true);
              return;
            }
          } catch (e) {
            // Not JSON, continue with normal flow
          }
          
          // Normal login success
          notifications.show({
            title: 'Login Successful!',
            message: 'Redirecting to dashboard...',
            color: 'green',
            autoClose: 2000,
          });
          setShowResend(false);
          setTimeout(() => navigate('/dashboard'), 500);
        } else if (resp.status === 401) {
          let msg: string = 'Login failed';
          
          try {
            const body = await resp.json();
            // Extract message from response - backend returns {status: "fail", message: "..."}
            if (body && typeof body === 'object' && 'message' in body) {
              msg = String(body.message);
            }
          } catch (e) {
            // If JSON parsing fails, try text
            msg = await resp.text().catch(() => 'Login failed');
          }
          
          // Clean message - remove any JSON artifacts or brackets
          msg = msg.trim().replace(/^[{"']+|["'}]+$/g, '');
          
          // Check for specific error types - order matters!
          if (/email not registered|not registered/i.test(msg)) {
            notifications.show({
              title: 'Email Not Registered',
              message: 'This email address is not registered. Please register first.',
              color: 'red',
              autoClose: 6000,
            });
            setShowResend(false);
          } else if (/verified|not verified/i.test(msg)) {
            notifications.show({
              title: 'Email Not Verified',
              message: 'Please check your inbox or resend verification email.',
              color: 'yellow',
              autoClose: 6000,
            });
            setShowResend(true);
          } else if (/locked/i.test(msg)) {
            notifications.show({
              title: 'Account Locked',
              message: msg,
              color: 'red',
              autoClose: 8000,
            });
            setShowResend(false);
          } else {
            // Default error - show clean message
            notifications.show({
              title: 'Login Failed',
              message: msg,
              color: 'red',
              autoClose: 5000,
            });
            setShowResend(false);
          }
        } else {
          const text = await resp.text();
          notifications.show({
            title: 'Login Failed',
            message: text || 'Something went wrong. Please try again.',
            color: 'red',
            autoClose: 5000,
          });
          setShowResend(false);
        }
      }
    } catch (err) {
      console.error('Login/Register error:', err);
      notifications.show({
        title: 'Network Error',
        message: 'Unable to connect to server. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
      setShowResend(false);
    }
  }

  async function resendVerification(email?: string) {
    const targetEmail = email ?? form.values.email;
    if (!targetEmail) {
      notifications.show({
        title: 'Email Required',
        message: 'Please enter an email to resend verification to.',
        color: 'red',
        autoClose: 4000,
      });
      return;
    }

    try {
      const resp = await fetch('/api/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: targetEmail }),
        credentials: 'include',
      });

      if (resp.ok) {
        notifications.show({
          title: 'Verification Email Sent!',
          message: 'Check your inbox (or MailHog in dev) for the verification link.',
          color: 'green',
          autoClose: 5000,
        });
        setShowResend(false);
      } else {
        const text = await resp.text();
        notifications.show({
          title: 'Failed to Resend',
          message: text || 'Something went wrong. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      notifications.show({
        title: 'Network Error',
        message: 'Unable to send verification email. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
    }
  }

  if (show2FA) {
    return (
      <TwoFactorVerifyStep
        email={pendingEmail}
        onSuccess={() => {
          // Check if recovery code was used - if so, don't navigate (redirect will happen in TwoFactorVerifyStep)
          const recoveryCodeUsed = sessionStorage.getItem('recovery_code_used');
          if (recoveryCodeUsed !== 'true') {
            setShow2FA(false);
            setTimeout(() => navigate('/dashboard'), 500);
          }
          // If recovery code was used, TwoFactorVerifyStep will handle the redirect
        }}
        onCancel={() => {
          setShow2FA(false);
          setPendingEmail('');
        }}
      />
    );
  }

  return (
    <Paper w={{ base: '90%', sm: 450 }} mt={{ base: 20, sm: 50 }} mx="auto" radius="md" p="lg" withBorder {...props}>
      <Text size="lg" fw={500}>
        Welcome to Toniebee, {type} with
      </Text>

      <Group grow mb="md" mt="md">
        <GoogleButton radius="xl">Google</GoogleButton>
        <GitHubButton radius="xl">GitHub</GitHubButton>
        {/* Twitter OAuth - Commented out until production (Twitter doesn't accept localhost URLs) */}
        {/* <TwitterButton radius="xl">Twitter</TwitterButton> */}
      </Group>

      <Divider label="Or continue with email" labelPosition="center" my="lg" />

      <form onSubmit={form.onSubmit((values) => void submit(values))}>
        <Stack>
          {type === 'register' && (
            <TextInput
              label="Name"
              placeholder="Your name"
              value={form.values.name}
              onChange={(event) => form.setFieldValue('name', event.currentTarget.value)}
              radius="md"
            />
          )}

          <TextInput
            required
            label="Email"
            placeholder="example@gmail.com"
            value={form.values.email}
            onChange={(event) => form.setFieldValue('email', event.currentTarget.value)}
            error={form.errors.email}
            radius="md"
          />

          <PasswordInput
            required
            label="Password"
            placeholder="Your password"
            value={form.values.password}
            onChange={(event) => form.setFieldValue('password', event.currentTarget.value)}
            error={form.errors.password}
            radius="md"
          />
          {type === 'login' && (
            <Anchor
              component="button"
              type="button"
              onClick={() => navigate('/forgot-password')}
              size="xs"
              ta="right"
              style={{ display: 'block', textAlign: 'right' }}
            >
              Forgot password?
            </Anchor>
          )}
          {type === 'register' && <PasswordStrengthMeter password={form.values.password} />}

          {type === 'register' && (
            <PasswordInput
              required
              label="Confirm password"
              placeholder="Confirm password"
              value={form.values.passwordConfirm}
              onChange={(event) => form.setFieldValue('passwordConfirm', event.currentTarget.value)}
              error={form.errors.passwordConfirm}
              radius="md"
            />
          )}

          {type === 'register' && (
            <Checkbox
              label={
                <span>
                  I accept the{' '}
                  <Anchor href="/terms" target="_blank" onClick={(e) => e.stopPropagation()}>
                    Terms and Conditions
                  </Anchor>
                </span>
              }
              checked={form.values.terms}
              onChange={(event) => form.setFieldValue('terms', event.currentTarget.checked)}
              error={form.errors.terms}
            />
          )}
        </Stack>

        <Group justify="space-between" mt="xl">
          <Anchor component="button" type="button" c="dimmed" onClick={() => toggle()} size="xs">
            {type === 'register' ? 'Already have an account? Login' : "Don't have an account? Register"}
          </Anchor>
          <Button type="submit" radius="xl">
            {upperFirst(type)}
          </Button>
        </Group>
      </form>

      {/* resend button (shown when email not verified) */}
      {showResend && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 12 }}>
          <Button size="xs" variant="outline" onClick={() => void resendVerification()}>
            Resend verification
          </Button>
        </div>
      )}
    </Paper>
  );
}
