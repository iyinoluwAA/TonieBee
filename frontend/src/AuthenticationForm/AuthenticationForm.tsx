// frontend/src/AuthenticationForm/AuthenticationForm.tsx
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
import { TwitterButton } from './TwitterButton';
import { useState } from 'react';

export function AuthenticationForm(props: PaperProps) {
  const [type, toggle] = useToggle(['login', 'register']);
  const [serverMessage, setServerMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const form = useForm({
    initialValues: {
      email: '',
      name: '',
      password: '',
      passwordConfirm: '',
      terms: true,
    },

    validate: {
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
      password: (val) =>
        val.length <= 6 ? 'Password should include at least 6 characters' : null,
    },
  });

  async function handleRegister() {
    setServerMessage(null);
    form.clearErrors();

    // client-side checks
    if (form.values.password !== form.values.passwordConfirm) {
      form.setFieldError('password', 'Passwords do not match');
      return;
    }
    if (!form.values.terms) {
      setServerMessage('You must accept the terms and conditions.');
      return;
    }

    setLoading(true);
    try {
      const payload = {
        name: form.values.name,
        email: form.values.email,
        password: form.values.password,
        passwordconfirm: form.values.passwordConfirm,
      };

      const resp = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // important: allow cookies (token/refresh/csrf)
        body: JSON.stringify(payload),
      });

      if (resp.status === 201) {
        setServerMessage('Registration successful. Please check your email to verify your account.');
        // keep the user on the same page; they may verify email — or navigate to login:
        toggle(); // switch to "login" view after success
      } else {
        // try to show backend message if present
        const body = await resp.json().catch(() => null);
        setServerMessage(body?.message || `Registration failed (status ${resp.status})`);
      }
    } catch (err: any) {
      setServerMessage(err?.message || 'Network error');
    } finally {
      setLoading(false);
    }
  }

  async function handleLogin() {
    setServerMessage(null);
    form.clearErrors();

    setLoading(true);
    try {
      const payload = {
        email: form.values.email,
        password: form.values.password,
      };

      const resp = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // important to receive cookies
        body: JSON.stringify(payload),
      });

      if (resp.status === 200) {
        // login success — you may read the response or simply navigate
        // read body for token if needed
        // const body = await resp.json();
        // redirect to dashboard
        window.location.href = '/dashboard';
      } else {
        const body = await resp.json().catch(() => null);
        setServerMessage(body?.message || `Login failed (status ${resp.status})`);
      }
    } catch (err: any) {
      setServerMessage(err?.message || 'Network error');
    } finally {
      setLoading(false);
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

      <form
        onSubmit={form.onSubmit(() => {
          // route submit to register or login handlers
          if (type === 'register') {
            handleRegister();
          } else {
            handleLogin();
          }
        })}
      >
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
            <>
              <PasswordInput
                required
                label="Confirm password"
                placeholder="Confirm password"
                value={form.values.passwordConfirm}
                onChange={(event) => form.setFieldValue('passwordConfirm', event.currentTarget.value)}
                radius="md"
              />

              <Checkbox
                label="I accept terms and conditions"
                checked={form.values.terms}
                onChange={(event) => form.setFieldValue('terms', event.currentTarget.checked)}
              />
            </>
          )}
        </Stack>

        {/* server / submit messages (non-intrusive) */}
        {serverMessage && (
          <Text mt="sm" color="red" size="sm" role="alert">
            {serverMessage}
          </Text>
        )}

        <Group justify="space-between" mt="xl">
          <Anchor component="button" type="button" c="dimmed" onClick={() => toggle()} size="xs">
            {type === 'register' ? 'Already have an account? Login' : "Don't have an account? Register"}
          </Anchor>
          <Button type="submit" radius="xl" loading={loading}>
            {upperFirst(type)}
          </Button>
        </Group>
      </form>
    </Paper>
  );
}
