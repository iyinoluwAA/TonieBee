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
import { GoogleButton } from './GoogleButton';
import { useNavigate } from 'react-router-dom';
import { TwitterButton } from './TwitterButton';

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
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [statusColor, setStatusColor] = useState<'green' | 'red' | 'yellow'>('green');
  const [showResend, setShowResend] = useState(false);
  const form = useForm<FormValues>({
    initialValues: {
      email: '',
      name: '',
      password: '',
      passwordConfirm: '',
      terms: true,
    },

    validate: {
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
      password: (val) => (val.length <= 6 ? 'Password should include at least 6 characters' : null),
      passwordConfirm: (val, values) => (values.password !== val ? 'Passwords do not match' : null),
    },
  });

  async function submit(values: FormValues) {
    setStatusMsg(null);
    setShowResend(false);

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
          }),
          credentials: 'include', // keep if using cookies or cross-origin
        });

        if (resp.status === 201) {
          setStatusMsg('Registration successful — check your email for verification.');
          setStatusColor('green');
          form.reset(); // optional: clear form on success
        } else {
          // Try parse JSON, otherwise show text
          const text = await resp.text();
          setStatusMsg(text || 'Registration failed');
          setStatusColor('red');
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
          setStatusMsg('Login successful — redirecting...');
          setStatusColor('green');
          setShowResend(false);
          setTimeout(() => navigate('/dashboard'), 300);
        } else if (resp.status === 401) {
          // usually returns JSON like { status:"fail", message:"email not verified" }
          const body = await resp.json().catch(() => ({}));
          const msg: string = (body && (body.message || body.error)) || 'Login failed';
          if (/verified/i.test(String(msg))) {
            setStatusMsg('Email not verified — please check your inbox or resend verification.');
            setStatusColor('yellow');
            setShowResend(true);
          } else {
            setStatusMsg(msg);
            setStatusColor('red');
            setShowResend(false);
          }
        } else {
          const text = await resp.text();
          setStatusMsg(text || 'Login failed');
          setStatusColor('red');
          setShowResend(false);
        }
      }
    } catch (err) {
      setStatusMsg('Network or server error');
      setStatusColor('red');
      setShowResend(false);
      // optional: console.error(err)
    }
  }

  async function resendVerification(email?: string) {
    const targetEmail = email ?? form.values.email;
    if (!targetEmail) {
      setStatusMsg('Please enter an email to resend verification to.');
      setStatusColor('red');
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
        setStatusMsg('Verification email resent. Check your inbox (or MailHog in dev).');
        setStatusColor('green');
        setShowResend(false);
      } else {
        const text = await resp.text();
        setStatusMsg(text || 'Failed to resend verification');
        setStatusColor('red');
      }
    } catch (err) {
      setStatusMsg('Network error');
      setStatusColor('red');
    }
  }

  return (
    <Paper w={{ base: '90%', sm: 450 }} mt={{ base: 20, sm: 50 }} mx="auto" radius="md" p="lg" withBorder {...props}>
      <Text size="lg" fw={500}>
        Welcome to Toniebee, {type} with
      </Text>

      <Group grow mb="md" mt="md">
        <GoogleButton radius="xl">Google</GoogleButton>
        <TwitterButton radius="xl">Twitter</TwitterButton>
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
            error={form.errors.email && 'Invalid email'}
            radius="md"
          />

          <PasswordInput
            required
            label="Password"
            placeholder="Your password"
            value={form.values.password}
            onChange={(event) => form.setFieldValue('password', event.currentTarget.value)}
            error={form.errors.password && 'Password should include at least 6 characters'}
            radius="md"
          />

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
              label="I accept terms and conditions"
              checked={form.values.terms}
              onChange={(event) => form.setFieldValue('terms', event.currentTarget.checked)}
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

      {/* status message */}
      {statusMsg && (
        <Text mt="md" color={statusColor === 'green' ? 'teal' : statusColor === 'red' ? 'red' : 'yellow'}>
          {statusMsg}
        </Text>
      )}

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
