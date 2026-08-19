# Toniebee Auth / 2FA / Email UI Digest

## Files

```txt
frontend/package.json
frontend/src/App.tsx
frontend/src/Router.tsx
frontend/src/theme.ts
frontend/src/AuthenticationForm/AuthenticationForm.tsx
frontend/src/AuthenticationForm/GoogleButton.tsx
frontend/src/AuthenticationForm/GitHubButton.tsx
frontend/src/AuthenticationForm/TwitterButton.tsx
frontend/src/components/TwoFactorSetupModal.tsx
frontend/src/components/TwoFactorVerifyStep.tsx
frontend/src/components/RecoveryCodesSection.tsx
frontend/src/components/PasswordStrengthMeter.tsx
frontend/src/pages/login.page.tsx
frontend/src/pages/ForgotPassword.page.tsx
frontend/src/pages/ResetPassword.page.tsx
frontend/src/pages/RecoverySetup.page.tsx
frontend/src/pages/UserProfile.page.tsx
frontend/src/pages/AdminLogin.page.tsx
frontend/src/pages/admin/AdminSecurityPage.tsx
frontend/src/pages/admin/AdminUsersPage.tsx
frontend/src/pages/admin/SecurityDashboardHelpModal.tsx
backend/src/mail/templates/RecoveryCodeWarning-email.html
backend/src/mail/templates/RestPassword-email.html
backend/src/mail/templates/Verification-email.html
backend/src/mail/templates/Welcome-email.html
backend/src/mail/mod.rs
backend/src/mail/mails.rs
backend/src/mail/sendmail.rs
```



---

## FILE: `frontend/package.json`

```json
{
  "name": "Toniebee Frontend",
  "private": true,
  "type": "module",
  "version": "0.0.0",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "typecheck": "tsc --noEmit",
    "lint": "npm run eslint && npm run stylelint",
    "eslint": "eslint . --cache",
    "stylelint": "stylelint '**/*.css' --cache",
    "prettier": "prettier --check \"**/*.{ts,tsx}\"",
    "prettier:write": "prettier --write \"**/*.{ts,tsx}\"",
    "vitest": "vitest run",
    "vitest:watch": "vitest",
    "test": "npm run typecheck && npm run prettier && npm run lint && npm run vitest && npm run build",
    "storybook": "storybook dev -p 6006",
    "storybook:build": "storybook build"
  },
  "dependencies": {
    "@mantine/carousel": "^8.1.3",
    "@mantine/charts": "^8.1.3",
    "@mantine/code-highlight": "^8.1.3",
    "@mantine/core": "^8.1.3",
    "@mantine/dates": "^8.1.3",
    "@mantine/dropzone": "^8.1.3",
    "@mantine/form": "^8.1.3",
    "@mantine/hooks": "^8.1.3",
    "@mantine/modals": "^8.1.3",
    "@mantine/notifications": "^8.1.3",
    "@mantine/nprogress": "^8.1.3",
    "@mantine/spotlight": "^8.1.3",
    "@mantine/tiptap": "^8.1.3",
    "@mantinex/dev-icons": "^2.0.0",
    "@tabler/icons-react": "^3.34.1",
    "@tiptap/extension-link": "^3.0.7",
    "@tiptap/pm": "^3.0.7",
    "@tiptap/react": "^3.0.7",
    "@tiptap/starter-kit": "^3.0.7",
    "dayjs": "^1.11.13",
    "embla-carousel": "^8.5.2",
    "embla-carousel-react": "^8.5.2",
    "qrcode.react": "^4.2.0",
    "react": "^19.1.0",
    "react-dom": "^19.1.0",
    "react-router-dom": "^7.6.2",
    "recharts": "2"
  },
  "devDependencies": {
    "@eslint/js": "^9.29.0",
    "@ianvs/prettier-plugin-sort-imports": "^4.4.2",
    "@storybook/react": "^8.6.12",
    "@storybook/react-vite": "^8.6.12",
    "@testing-library/dom": "^10.4.0",
    "@testing-library/jest-dom": "^6.6.3",
    "@testing-library/react": "^16.3.0",
    "@testing-library/user-event": "^14.6.1",
    "@types/node": "^22.15.11",
    "@types/react": "^19.1.8",
    "@types/react-dom": "^19.1.6",
    "@vitejs/plugin-react": "^4.5.2",
    "eslint": "^9.29.0",
    "eslint-config-mantine": "^4.0.3",
    "eslint-plugin-jsx-a11y": "^6.10.2",
    "eslint-plugin-react": "^7.37.5",
    "identity-obj-proxy": "^3.0.0",
    "jsdom": "^26.1.0",
    "postcss": "^8.5.6",
    "postcss-preset-mantine": "^1.17.0",
    "postcss-simple-vars": "^7.0.1",
    "prettier": "^3.5.3",
    "prop-types": "^15.8.1",
    "storybook": "^8.6.12",
    "storybook-dark-mode": "^4.0.2",
    "stylelint": "^16.20.0",
    "stylelint-config-standard-scss": "^15.0.1",
    "typescript": "^5.8.3",
    "typescript-eslint": "^8.34.0",
    "vite": "^6.3.5",
    "vite-tsconfig-paths": "^5.1.4",
    "vitest": "^3.2.3"
  },
  "packageManager": "yarn@4.9.2"
}

```


---

## FILE: `frontend/src/App.tsx`

```tsx
import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { Router } from './Router';
import { theme } from './theme';
import { ColorThemeProvider } from './contexts/ColorThemeContext';

export default function App() {
  return (
    <MantineProvider theme={theme}>
      <ColorThemeProvider>
        <Notifications position="top-right" zIndex={1000} />
        <Router />
      </ColorThemeProvider>
    </MantineProvider>
  );
}

```


---

## FILE: `frontend/src/Router.tsx`

```tsx
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom';
import { LoginPage } from './pages/login.page';
import { UserProfilePage } from './pages/UserProfile.page';
import { ClientPortalPage } from './pages/ClientPortal.page';
import { VerificationSuccessPage } from './pages/VerificationSuccess.page';
import { ForgotPasswordPage } from './pages/ForgotPassword.page';
import { ResetPasswordPage } from './pages/ResetPassword.page';
import { AdminDashboardPage } from './pages/AdminDashboard.page';
import { AdminLoginPage } from './pages/AdminLogin.page';
import { RecoverySetupPage } from './pages/RecoverySetup.page';
import { HomePage } from './pages/Home.page';
import { QuotePage } from './pages/Quote.page';
import { QuotesPage } from './pages/Quotes.page';
import { PoliciesPage } from './pages/Policies.page';
import { AppointmentsPage } from './pages/Appointments.page';
import { DocumentsPage } from './pages/Documents.page';
import { PaymentsPage } from './pages/Payments.page';
import { ClaimsPage } from './pages/Claims.page';

const router = createBrowserRouter([
  {
    path: '/',
    element: <HomePage />,
  },
  {
    path: '/home',
    element: <HomePage />,
  },
  {
    path: '/login',
    element: <LoginPage />,
  },
  {
    path: '/dashboard',
    element: <ClientPortalPage />,
  },
  {
    path: '/profile',
    element: <UserProfilePage />,
  },
  {
    path: '/verify-success',
    element: <VerificationSuccessPage />,
  },
  {
    path: '/forgot-password',
    element: <ForgotPasswordPage />,
  },
  {
    path: '/reset-password',
    element: <ResetPasswordPage />,
  },
  {
    path: '/admin/login',
    element: <AdminLoginPage />,
  },
  {
    path: '/recovery-setup',
    element: <RecoverySetupPage />,
  },
  {
    path: '/admin',
    element: <AdminDashboardPage />,
  },
  {
    path: '/admin/users',
    element: <AdminDashboardPage />,
  },
  {
    path: '/admin/data',
    element: <AdminDashboardPage />,
  },
  {
    path: '/admin/security',
    element: <AdminDashboardPage />,
  },
  {
    path: '/quote',
    element: <QuotePage />,
  },
  {
    path: '/quotes',
    element: <QuotesPage />,
  },
  {
    path: '/policies',
    element: <PoliciesPage />,
  },
  {
    path: '/appointments',
    element: <AppointmentsPage />,
  },
  {
    path: '/documents',
    element: <DocumentsPage />,
  },
  {
    path: '/payments',
    element: <PaymentsPage />,
  },
  {
    path: '/claims',
    element: <ClaimsPage />,
  },
  {
    path: '*',
    element: <Navigate to="/login" replace />,
  },
]);

export function Router() {
  return <RouterProvider router={router} />;
}

```


---

## FILE: `frontend/src/theme.ts`

```ts
import { createTheme, MantineColorsTuple } from '@mantine/core';

// Custom color tuples for our insurance platform
const trustBlue: MantineColorsTuple = [
  '#EFF6FF',
  '#DBEAFE',
  '#BFDBFE',
  '#93C5FD',
  '#60A5FA',
  '#3B82F6',
  '#2563EB',
  '#1D4ED8',
  '#1E40AF', // Primary
  '#1E3A8A',
];

const calmingTeal: MantineColorsTuple = [
  '#F0FDFA',
  '#CCFBF1',
  '#99F6E4',
  '#5EEAD4',
  '#2DD4BF',
  '#14B8A6',
  '#0D9488', // Primary
  '#0F766E',
  '#115E59',
  '#134E4A',
];

const warmOrange: MantineColorsTuple = [
  '#FFF7ED',
  '#FFEDD5',
  '#FED7AA',
  '#FDBA74',
  '#FB923C',
  '#F97316', // Primary (CTAs)
  '#EA580C',
  '#C2410C',
  '#9A3412',
  '#7C2D12',
];

const successGreen: MantineColorsTuple = [
  '#F0FDF4',
  '#DCFCE7',
  '#BBF7D0',
  '#86EFAC',
  '#4ADE80',
  '#22C55E',
  '#16A34A',
  '#15803D',
  '#166534',
  '#14532D',
];

export const theme = createTheme({
  /** Primary color - Trust Blue */
  primaryColor: 'trustBlue',
  
  /** Custom colors */
  colors: {
    trustBlue,
    calmingTeal,
    warmOrange,
    successGreen,
  },

  /** Typography */
  fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  fontFamilyMonospace: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  
  headings: {
    fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontWeight: '600',
    sizes: {
      h1: { fontSize: 'clamp(2rem, 5vw, 3.5rem)', lineHeight: '1.2' },
      h2: { fontSize: 'clamp(1.75rem, 4vw, 2.75rem)', lineHeight: '1.3' },
      h3: { fontSize: 'clamp(1.5rem, 3vw, 2.25rem)', lineHeight: '1.4' },
      h4: { fontSize: 'clamp(1.25rem, 2.5vw, 1.75rem)', lineHeight: '1.4' },
      h5: { fontSize: 'clamp(1.125rem, 2vw, 1.5rem)', lineHeight: '1.5' },
      h6: { fontSize: 'clamp(1rem, 1.5vw, 1.25rem)', lineHeight: '1.5' },
    },
  },

  /** Spacing */
  spacing: {
    xs: '0.5rem',   // 8px
    sm: '0.75rem',  // 12px
    md: '1rem',     // 16px
    lg: '1.5rem',   // 24px
    xl: '2rem',     // 32px
  },

  /** Shadows - Subtle and elegant */
  shadows: {
    xs: '0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.1)',
    sm: '0 1px 3px rgba(0, 0, 0, 0.05), 0 2px 4px rgba(0, 0, 0, 0.1)',
    md: '0 4px 6px rgba(0, 0, 0, 0.07), 0 2px 4px rgba(0, 0, 0, 0.06)',
    lg: '0 10px 15px rgba(0, 0, 0, 0.1), 0 4px 6px rgba(0, 0, 0, 0.05)',
    xl: '0 20px 25px rgba(0, 0, 0, 0.1), 0 10px 10px rgba(0, 0, 0, 0.04)',
  },

  /** Radius - Soft, friendly corners */
  radius: {
    xs: '0.25rem',  // 4px
    sm: '0.5rem',   // 8px
    md: '0.75rem',  // 12px
    lg: '1rem',     // 16px
    xl: '1.5rem',   // 24px
  },

  /** Default props */
  defaultProps: {
    Button: {
      radius: 'md',
    },
    Card: {
      radius: 'lg',
      shadow: 'sm',
      withBorder: true,
    },
    TextInput: {
      radius: 'md',
    },
    Paper: {
      radius: 'lg',
      shadow: 'sm',
    },
  },

  /** Other theme properties */
  respectReducedMotion: true,
  cursorType: 'pointer',
  focusRing: 'auto',
});

```


---

## FILE: `frontend/src/AuthenticationForm/AuthenticationForm.tsx`

```tsx
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

```


---

## FILE: `frontend/src/AuthenticationForm/GoogleButton.tsx`

```tsx
import { Button, ButtonProps } from '@mantine/core';
import { useState } from 'react';
import { notifications } from '@mantine/notifications';

function GoogleIcon(props: React.ComponentPropsWithoutRef<'svg'>) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      preserveAspectRatio="xMidYMid"
      viewBox="0 0 256 262"
      style={{ width: 14, height: 14 }}
      {...props}
    >
      <path
        fill="#4285F4"
        d="M255.878 133.451c0-10.734-.871-18.567-2.756-26.69H130.55v48.448h71.947c-1.45 12.04-9.283 30.172-26.69 42.356l-.244 1.622 38.755 30.023 2.685.268c24.659-22.774 38.875-56.282 38.875-96.027"
      />
      <path
        fill="#34A853"
        d="M130.55 261.1c35.248 0 64.839-11.605 86.453-31.622l-41.196-31.913c-11.024 7.688-25.82 13.055-45.257 13.055-34.523 0-63.824-22.773-74.269-54.25l-1.531.13-40.298 31.187-.527 1.465C35.393 231.798 79.49 261.1 130.55 261.1"
      />
      <path
        fill="#FBBC05"
        d="M56.281 156.37c-2.756-8.123-4.351-16.827-4.351-25.82 0-8.994 1.595-17.697 4.206-25.82l-.073-1.73L15.26 71.312l-1.335.635C5.077 89.644 0 109.517 0 130.55s5.077 40.905 13.925 58.602l42.356-32.782"
      />
      <path
        fill="#EB4335"
        d="M130.55 50.479c24.514 0 41.05 10.589 50.479 19.438l36.844-35.974C195.245 12.91 165.798 0 130.55 0 79.49 0 35.393 29.301 13.925 71.947l42.211 32.783c10.59-31.477 39.891-54.251 74.414-54.251"
      />
    </svg>
  );
}

export function GoogleButton(props: ButtonProps & React.ComponentPropsWithoutRef<'button'>) {
  const [loading, setLoading] = useState(false);

  async function handleOAuthLogin() {
    setLoading(true);
    try {
      const resp = await fetch('/api/oauth/google/initiate', {
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
          message: error.message || 'Failed to initiate Google login',
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
      leftSection={<GoogleIcon />}
      variant="default"
      onClick={handleOAuthLogin}
      loading={loading}
      {...props}
    >
      {props.children || 'Google'}
    </Button>
  );
}

```


---

## FILE: `frontend/src/AuthenticationForm/GitHubButton.tsx`

```tsx
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


```


---

## FILE: `frontend/src/AuthenticationForm/TwitterButton.tsx`

```tsx
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

```


---

## FILE: `frontend/src/components/TwoFactorSetupModal.tsx`

```tsx
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


```


---

## FILE: `frontend/src/components/TwoFactorVerifyStep.tsx`

```tsx
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Stack, Text, TextInput, Button, Group, Paper, Alert, Loader, Center, Divider } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle, IconKey } from '@tabler/icons-react';

interface TwoFactorVerifyStepProps {
  email: string;
  onSuccess: () => void;
  onCancel: () => void;
}

type VerificationMode = 'totp' | 'recovery' | 'select';

export function TwoFactorVerifyStep({ email, onSuccess, onCancel }: TwoFactorVerifyStepProps) {
  const navigate = useNavigate();
  const [mode, setMode] = useState<VerificationMode>('select');
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);

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

  async function handleVerify() {
    // Validate code length based on mode
    if (mode === 'totp' && code.length !== 6) {
      notifications.show({
        title: 'Invalid Code',
        message: 'Please enter a 6-digit code from your authenticator app.',
        color: 'red',
        autoClose: 3000,
      });
      return;
    }

    if (mode === 'recovery' && code.length !== 10) {
      notifications.show({
        title: 'Invalid Recovery Code',
        message: 'Recovery codes are 10 characters long. Please check your saved codes.',
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

      const resp = await fetch('/api/auth/verify-login', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          code: code,
          email: email,
        }),
      });

      if (resp.ok) {
        const data = await resp.json();
        
        // Check if recovery code was used (from backend response or mode)
        // Backend returns recoveryCodeUsed as boolean in the response
        const usedRecoveryCode = data.recoveryCodeUsed === true || data.recoveryCodeUsed === 'true' || mode === 'recovery';
        
        // If recovery code was used, redirect to recovery setup page
        if (usedRecoveryCode) {
          // Store flag that recovery code was used (sessionStorage is fine for hosting - it's client-side only)
          sessionStorage.setItem('recovery_code_used', 'true');
          console.log('Setting recovery_code_used flag and redirecting...');
          
          // Don't call onSuccess - we're redirecting instead
          notifications.show({
            title: 'Recovery Code Used',
            message: '⚠️ You used a recovery code. For security, you must set up 2FA again.',
            color: 'orange',
            autoClose: 2000,
          });
          
          // Redirect using React Router navigate (better for SPA, maintains state)
          console.log('Redirecting to /recovery-setup NOW');
          // Use navigate with replace to prevent back button issues
          navigate('/recovery-setup', { replace: true });
          return; // Exit early, don't call onSuccess
        } else {
          // Clear any stale recovery code flag
          sessionStorage.removeItem('recovery_code_used');
          
          notifications.show({
            title: 'Login Successful!',
            message: 'Redirecting to dashboard...',
            color: 'green',
            autoClose: 2000,
          });
          onSuccess();
        }
      } else {
        const error = await resp.json();
        notifications.show({
          title: 'Verification Failed',
          message: error.message || 'Invalid code. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
        setCode('');
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

  // Mode selection screen
  if (mode === 'select') {
    return (
      <Paper p="xl" withBorder radius="md" w={{ base: '90%', sm: 450 }} mx="auto" mt={{ base: 20, sm: 50 }}>
        <Stack gap="md">
          <div>
            <Text size="lg" fw={500} mb={4}>
              Two-Factor Authentication Required
            </Text>
            <Text size="sm" c="dimmed">
              Choose how you want to verify your identity.
            </Text>
          </div>

          <Button
            fullWidth
            size="lg"
            onClick={() => setMode('totp')}
            leftSection={<IconKey size={20} />}
          >
            Enter 2FA Code from Authenticator App
          </Button>

          <Divider label="OR" labelPosition="center" />

          <Button
            fullWidth
            size="lg"
            variant="light"
            onClick={() => setMode('recovery')}
            leftSection={<IconKey size={20} />}
          >
            Lost 2FA App? Use Recovery Code
          </Button>

          <Alert icon={<IconAlertCircle size={16} />} color="blue" variant="light" mt="md">
            <Text size="xs">
              Recovery codes are 10-character codes you saved when setting up 2FA. 
              Each code can only be used once.
            </Text>
          </Alert>

          <Group justify="center" mt="md">
            <Button variant="subtle" onClick={onCancel} disabled={loading}>
              Cancel
            </Button>
          </Group>
        </Stack>
      </Paper>
    );
  }

  // TOTP Code Input
  if (mode === 'totp') {
    return (
      <Paper p="xl" withBorder radius="md" w={{ base: '90%', sm: 450 }} mx="auto" mt={{ base: 20, sm: 50 }}>
        <Stack gap="md">
          <div>
            <Text size="lg" fw={500} mb={4}>
              Enter 2FA Code
            </Text>
            <Text size="sm" c="dimmed">
              Enter the 6-digit code from your authenticator app.
            </Text>
          </div>

          <TextInput
            label="Verification Code"
            placeholder="000000"
            value={code}
            onChange={(e) => {
              const value = e.currentTarget.value.replace(/\D/g, '').slice(0, 6);
              setCode(value);
            }}
            maxLength={6}
            size="md"
            autoFocus
          />

          <Group justify="space-between" mt="md">
            <Button variant="subtle" onClick={() => setMode('select')} disabled={loading}>
              Back
            </Button>
            <Button onClick={handleVerify} loading={loading} disabled={code.length !== 6}>
              Verify & Login
            </Button>
          </Group>
        </Stack>
      </Paper>
    );
  }

  // Recovery Code Input
  return (
    <Paper p="xl" withBorder radius="md" w={{ base: '90%', sm: 450 }} mx="auto" mt={{ base: 20, sm: 50 }}>
      <Stack gap="md">
        <div>
          <Text size="lg" fw={500} mb={4}>
            Enter Recovery Code
          </Text>
          <Text size="sm" c="dimmed">
            Enter one of your 10-character recovery codes. Each code can only be used once.
          </Text>
        </div>

        <Alert icon={<IconAlertCircle size={16} />} color="yellow" variant="light">
          <Text size="xs" fw={500}>
            Important: After using a recovery code, you'll need to set up 2FA again with a new authenticator app.
          </Text>
        </Alert>

        <TextInput
          label="Recovery Code"
          placeholder="X3H7GFH5J2"
          value={code}
          onChange={(e) => {
            // Allow alphanumeric, uppercase, max 10 chars
            const value = e.currentTarget.value
              .toUpperCase()
              .replace(/[^A-Z0-9]/g, '')
              .slice(0, 10);
            setCode(value);
          }}
          maxLength={10}
          size="md"
          autoFocus
        />

        <Group justify="space-between" mt="md">
          <Button variant="subtle" onClick={() => setMode('select')} disabled={loading}>
            Back
          </Button>
          <Button onClick={handleVerify} loading={loading} disabled={code.length !== 10}>
            Verify & Login
          </Button>
        </Group>
      </Stack>
    </Paper>
  );
}


```


---

## FILE: `frontend/src/components/RecoveryCodesSection.tsx`

```tsx
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


```


---

## FILE: `frontend/src/components/PasswordStrengthMeter.tsx`

```tsx
import { Progress, Text, Box } from '@mantine/core';

interface PasswordStrengthMeterProps {
  password: string;
}

export function PasswordStrengthMeter({ password }: PasswordStrengthMeterProps) {
  if (!password) return null;

  function calculateStrength(password: string): { value: number; color: string; label: string; feedback: string[] } {
    let strength = 0;
    const feedback: string[] = [];
    
    const checks = {
      length12: password.length >= 12, // Minimum required
      length14: password.length >= 14, // Recommended
      length16: password.length >= 16, // Excellent
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /[0-9]/.test(password),
      special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password),
      noSequential: !/(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password),
      noRepeating: !/(.)\1{2,}/.test(password), // No 3+ repeating characters
      noCommon: !['password', '12345678', '123456789', '1234567890', 'qwerty', 'qwerty123', 'admin', 'letmein', 'welcome', 'monkey', 'password123', 'iloveyou', 'princess', 'rockyou', '123qwe', 'abc123', 'password1', 'admin123'].some(common => password.toLowerCase().includes(common)),
    };

    // Calculate strength (0-100) with weighted scoring
    if (checks.length12) strength += 15; // Base requirement
    if (checks.length14) strength += 10; // Bonus for longer
    if (checks.length16) strength += 5;  // Extra bonus
    if (checks.lowercase) strength += 12;
    if (checks.uppercase) strength += 12;
    if (checks.numbers) strength += 12;
    if (checks.special) strength += 12;
    if (checks.noSequential) strength += 11; // Bonus for avoiding patterns
    if (checks.noRepeating) strength += 11; // Bonus for avoiding repetition
    if (checks.noCommon) strength += 10; // Bonus for avoiding common passwords

    // Build feedback
    if (!checks.length12) feedback.push('• Use at least 12 characters');
    if (checks.length12 && !checks.length14) feedback.push('• Use 14+ characters for better security');
    if (!checks.lowercase) feedback.push('• Add lowercase letters');
    if (!checks.uppercase) feedback.push('• Add uppercase letters');
    if (!checks.numbers) feedback.push('• Add numbers');
    if (!checks.special) feedback.push('• Add special characters (!@#$%^&*)');
    if (!checks.noSequential) feedback.push('• Avoid sequential characters (abc, 123)');
    if (!checks.noRepeating) feedback.push('• Avoid repeating characters (aaa, 111)');
    if (!checks.noCommon) feedback.push('• Avoid common words (password, qwerty)');

    // Determine color and label
    let color = 'red';
    let label = 'Weak';
    
    if (strength >= 85) {
      color = 'green';
      label = 'Very Strong';
    } else if (strength >= 70) {
      color = 'green';
      label = 'Strong';
    } else if (strength >= 50) {
      color = 'yellow';
      label = 'Medium';
    } else if (strength >= 30) {
      color = 'orange';
      label = 'Fair';
    } else {
      color = 'red';
      label = 'Weak';
    }

    return { value: strength, color, label, feedback };
  }

  const { value, color, label, feedback } = calculateStrength(password);

  return (
    <Box mt="xs">
      <Progress value={value} color={color} size="sm" radius="xl" />
      <Text size="xs" c={color} mt={4} fw={500}>
        Password strength: {label}
      </Text>
      {value < 85 && feedback.length > 0 && (
        <Box mt={4}>
          {feedback.map((item, index) => (
            <Text key={index} size="xs" c="dimmed" mt={2}>
              {item}
            </Text>
          ))}
        </Box>
      )}
    </Box>
  );
}


```


---

## FILE: `frontend/src/pages/login.page.tsx`

```tsx
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
```


---

## FILE: `frontend/src/pages/ForgotPassword.page.tsx`

```tsx
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Title,
  TextInput,
  Button,
  Stack,
  Text,
  Anchor,
  Center,
  Alert,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle } from '@tabler/icons-react';
import { ActionToggle } from '@/components/ColorSchemeToggle/ActionToggle';

export function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [requires2FA, setRequires2FA] = useState(false);
  const [email, setEmail] = useState('');
  const [twoFACode, setTwoFACode] = useState('');

  const form = useForm({
    initialValues: {
      email: '',
    },
    validate: {
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
    },
  });

  async function handleSubmit(values: typeof form.values) {
    setLoading(true);
    try {
      const resp = await fetch('/api/auth/forgot-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(values),
      });

      const data = await resp.json();

      if (resp.ok) {
        // Check if 2FA is required
        if (data.requires_2fa) {
          setRequires2FA(true);
          setEmail(values.email);
          notifications.show({
            title: '2FA Required',
            message: 'Please enter your 2FA code to continue',
            color: 'blue',
            autoClose: 5000,
          });
        } else {
          // No 2FA required - reset link sent
          notifications.show({
            title: 'Success',
            message: data.message || 'Password reset link has been sent to your email',
            color: 'green',
            autoClose: 5000,
          });
          // Redirect to login after a short delay
          setTimeout(() => {
            navigate('/login');
          }, 2000);
        }
      } else {
        notifications.show({
          title: 'Error',
          message: data.message || 'Failed to send password reset email',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      console.error('Forgot password error:', err);
      notifications.show({
        title: 'Error',
        message: 'An unexpected error occurred. Please try again.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  async function handle2FAVerify() {
    if (twoFACode.length !== 6) {
      notifications.show({
        title: 'Invalid Code',
        message: 'Please enter a 6-digit code from your authenticator app',
        color: 'red',
        autoClose: 3000,
      });
      return;
    }

    setLoading(true);
    try {
      const resp = await fetch('/api/auth/forgot-password-verify-2fa', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          email,
          code: twoFACode,
        }),
      });

      const data = await resp.json();

      if (resp.ok) {
        notifications.show({
          title: 'Success',
          message: data.message || 'Password reset link has been sent to your email',
          color: 'green',
          autoClose: 5000,
        });
        // Redirect to login after a short delay
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      } else {
        notifications.show({
          title: 'Error',
          message: data.message || 'Invalid 2FA code. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      console.error('2FA verification error:', err);
      notifications.show({
        title: 'Error',
        message: 'An unexpected error occurred. Please try again.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <Container size={420} my={40}>
        <Center>
          <Paper withBorder shadow="md" p={30} radius="md" w="100%">
            <Title ta="center" order={2}>
              Forgot Password?
            </Title>
            <Text c="dimmed" size="sm" ta="center" mt={5}>
              Enter your email address and we'll send you a link to reset your password.
            </Text>

            {requires2FA ? (
              <Stack mt="xl">
                <Alert
                  icon={<IconAlertCircle size="1rem" />}
                  title="2FA Verification Required"
                  color="blue"
                >
                  Your account has 2FA enabled. Please enter the 6-digit code from your authenticator app to continue.
                </Alert>
                <TextInput
                  label="2FA Code"
                  placeholder="000000"
                  required
                  maxLength={6}
                  value={twoFACode}
                  onChange={(e) => setTwoFACode(e.currentTarget.value.replace(/\D/g, ''))}
                />
                <Button
                  fullWidth
                  loading={loading}
                  onClick={handle2FAVerify}
                  disabled={twoFACode.length !== 6}
                >
                  Verify 2FA Code
                </Button>
                <Button
                  variant="subtle"
                  fullWidth
                  onClick={() => {
                    setRequires2FA(false);
                    setTwoFACode('');
                  }}
                >
                  Back
                </Button>
                <Text ta="center" size="sm">
                  Remember your password?{' '}
                  <Anchor
                    component="button"
                    type="button"
                    onClick={() => navigate('/login')}
                  >
                    Back to Login
                  </Anchor>
                </Text>
              </Stack>
            ) : (
              <form onSubmit={form.onSubmit(handleSubmit)}>
                <Stack mt="xl">
                  <TextInput
                    label="Email"
                    placeholder="your.email@example.com"
                    required
                    {...form.getInputProps('email')}
                  />

                  <Button type="submit" fullWidth loading={loading}>
                    Continue
                  </Button>

                  <Text ta="center" size="sm">
                    Remember your password?{' '}
                    <Anchor
                      component="button"
                      type="button"
                      onClick={() => navigate('/login')}
                    >
                      Back to Login
                    </Anchor>
                  </Text>
                </Stack>
              </form>
            )}
          </Paper>
        </Center>
      </Container>
      <ActionToggle />
    </>
  );
}


```


---

## FILE: `frontend/src/pages/ResetPassword.page.tsx`

```tsx
import { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Container,
  Paper,
  Title,
  TextInput,
  PasswordInput,
  Button,
  Stack,
  Text,
  Anchor,
  Center,
  Alert,
  Loader,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle } from '@tabler/icons-react';
import { ActionToggle } from '@/components/ColorSchemeToggle/ActionToggle';
import { PasswordStrengthMeter } from '@/components/PasswordStrengthMeter';

export function ResetPasswordPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [loading, setLoading] = useState(false);
  const [validating, setValidating] = useState(true);
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const tokenParam = searchParams.get('token');
    if (!tokenParam) {
      setError('Invalid reset link. Please request a new password reset.');
      setValidating(false);
      return;
    }

    setToken(tokenParam);
    
    // Validate token immediately when page loads
    async function validateToken() {
      try {
        const resp = await fetch(`/api/auth/validate-reset-token?token=${encodeURIComponent(tokenParam)}`, {
          method: 'GET',
          credentials: 'include',
        });

        if (!resp.ok) {
          const data = await resp.json().catch(() => ({ message: 'Invalid or expired token. Please request a new password reset.' }));
          // Use generic error message (security: don't reveal specific token state)
          setError(data.message || 'Invalid or expired token. Please request a new password reset.');
        }
        // If OK, token is valid - allow form to be shown
      } catch (err) {
        console.error('Token validation error:', err);
        setError('Failed to validate token. Please try again or request a new password reset.');
      } finally {
        setValidating(false);
      }
    }

    validateToken();
  }, [searchParams]);

  const form = useForm({
    initialValues: {
      newPassword: '',
      confirmPassword: '',
    },
    validate: {
      newPassword: (val) => {
        if (val.length < 14) return 'Password must be at least 14 characters (recommended: 16+)';
        if (val.length > 128) return 'Password must not exceed 128 characters';
        
        if (!/[a-z]/.test(val)) return 'Password must contain at least one lowercase letter';
        if (!/[A-Z]/.test(val)) return 'Password must contain at least one uppercase letter';
        if (!/[0-9]/.test(val)) return 'Password must contain at least one number';
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(val)) {
          return 'Password must contain at least one special character';
        }
        
        const lowercaseCount = (val.match(/[a-z]/g) || []).length;
        const uppercaseCount = (val.match(/[A-Z]/g) || []).length;
        const numberCount = (val.match(/[0-9]/g) || []).length;
        const specialCount = (val.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/g) || []).length;
        
        if (lowercaseCount < 2) return 'Password must contain at least 2 lowercase letters';
        if (uppercaseCount < 2) return 'Password must contain at least 2 uppercase letters';
        if (numberCount < 2) return 'Password must contain at least 2 numbers';
        if (specialCount < 2) return 'Password must contain at least 2 special characters';
        
        return null;
      },
      confirmPassword: (val, values) =>
        val !== values.newPassword ? 'Passwords do not match' : null,
    },
  });

  async function handleSubmit(values: typeof form.values) {
    if (!token) {
      setError('Invalid reset token. Please request a new password reset.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const resp = await fetch('/api/auth/reset-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          token,
          new_password: values.newPassword,
          new_password_confirm: values.confirmPassword,
        }),
      });

      // Try to parse as JSON, fallback to text if it fails
      let errorMessage = 'Failed to reset password. The token may have expired.';
      let data: any = null;

      const text = await resp.text();
      if (text) {
        try {
          data = JSON.parse(text);
          errorMessage = data.message || errorMessage;
        } catch {
          // If not JSON, use the text as error message
          errorMessage = text || errorMessage;
        }
      }

      if (resp.ok && data) {
        notifications.show({
          title: 'Success',
          message: data.message || 'Password has been successfully reset',
          color: 'green',
          autoClose: 7000,
        });
        // Redirect to login after a short delay
        setTimeout(() => {
          navigate('/login');
        }, 2000);
      } else {
        setError(errorMessage);
        notifications.show({
          title: 'Error',
          message: errorMessage,
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      console.error('Reset password error:', err);
      const errorMsg = err instanceof Error ? err.message : 'An unexpected error occurred. Please try again.';
      setError(errorMsg);
      notifications.show({
        title: 'Error',
        message: errorMsg,
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  // Show loading state while validating token
  if (validating) {
    return (
      <>
        <Container size={420} my={40}>
          <Center>
            <Paper withBorder shadow="md" p={30} radius="md" w="100%">
              <Stack align="center" gap="md">
                <Loader size="sm" />
                <Text ta="center">Validating reset token...</Text>
              </Stack>
            </Paper>
          </Center>
        </Container>
        <ActionToggle />
      </>
    );
  }

  // Show error if token is invalid or expired
  if (error && (!token || error.includes('expired') || error.includes('Invalid'))) {
    return (
      <>
        <Container size={420} my={40}>
          <Center>
            <Paper withBorder shadow="md" p={30} radius="md" w="100%">
              <Alert
                icon={<IconAlertCircle size="1rem" />}
                title="Invalid or Expired Reset Link"
                color="red"
                mb="md"
              >
                {error}
              </Alert>
              <Button
                fullWidth
                onClick={() => navigate('/forgot-password')}
                mt="md"
              >
                Request a new password reset
              </Button>
            </Paper>
          </Center>
        </Container>
        <ActionToggle />
      </>
    );
  }

  return (
    <>
      <Container size={420} my={40}>
        <Center>
          <Paper withBorder shadow="md" p={30} radius="md" w="100%">
            <Title ta="center" order={2}>
              Reset Password
            </Title>
            <Text c="dimmed" size="sm" ta="center" mt={5}>
              Enter your new password below.
            </Text>

            {error && (
              <Alert
                icon={<IconAlertCircle size="1rem" />}
                title="Error"
                color="red"
                mb="md"
                mt="md"
              >
                {error}
              </Alert>
            )}

            <form onSubmit={form.onSubmit(handleSubmit)}>
              <Stack mt="xl">
                <PasswordInput
                  label="New Password"
                  placeholder="Enter your new password"
                  required
                  {...form.getInputProps('newPassword')}
                />
                <PasswordStrengthMeter password={form.values.newPassword} />

                <PasswordInput
                  label="Confirm Password"
                  placeholder="Confirm your new password"
                  required
                  {...form.getInputProps('confirmPassword')}
                />

                <Button type="submit" fullWidth loading={loading}>
                  Reset Password
                </Button>

                <Text ta="center" size="sm">
                  Remember your password?{' '}
                  <Anchor
                    component="button"
                    type="button"
                    onClick={() => navigate('/login')}
                  >
                    Back to Login
                  </Anchor>
                </Text>
              </Stack>
            </form>
          </Paper>
        </Center>
      </Container>
      <ActionToggle />
    </>
  );
}


```


---

## FILE: `frontend/src/pages/RecoverySetup.page.tsx`

```tsx
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


```


---

## FILE: `frontend/src/pages/UserProfile.page.tsx`

```tsx
import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, Container, Paper, Text, Stack, Title, Group, Badge, Loader, Center, Modal, Switch, ActionIcon, Divider, SimpleGrid, Card, Timeline, Anchor } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useDisclosure } from '@mantine/hooks';
import { useMantineColorScheme, useComputedColorScheme } from '@mantine/core';
import { IconSun, IconMoon, IconUser, IconShield, IconMail, IconCalendar, IconKey, IconDeviceDesktop } from '@tabler/icons-react';
import { TwoFactorSetupModal } from '@/components/TwoFactorSetupModal';
import { RecoveryCodesSection } from '@/components/RecoveryCodesSection';

interface User {
  id: string;
  name: string;
  email: string;
  verified: boolean;
  role: string;
  twoFactorEnabled?: boolean;
  createdAt: string;
  updatedAt: string;
}

export function UserProfilePage() {
  const navigate = useNavigate();
  const { setColorScheme } = useMantineColorScheme();
  const computedColorScheme = useComputedColorScheme('light', { getInitialValueInEffect: true });
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [logoutLoading, setLogoutLoading] = useState(false);
  const [opened, { open, close }] = useDisclosure(false);
  const [twoFactorModalOpened, { open: open2FA, close: close2FA }] = useDisclosure(false);
  const [twoFactorLoading, setTwoFactorLoading] = useState(false);

  useEffect(() => {
    fetchUser();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function fetchUser() {
    try {
      const resp = await fetch('/api/users/me', {
        credentials: 'include',
      });

      if (resp.status === 200) {
        const data = await resp.json();
        setUser(data.data.user);
      } else if (resp.status === 401) {
        // Not authenticated, redirect to login
        navigate('/login');
      } else {
        console.error('Failed to fetch user:', await resp.text());
      }
    } catch (err) {
      console.error('Error fetching user:', err);
    } finally {
      setLoading(false);
    }
  }

  function getCsrfToken(): string | null {
    // Get CSRF token from cookie
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrf_token') {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  function handleLogoutClick() {
    open(); // Open confirmation modal
  }

  async function handleDisable2FA() {
    setTwoFactorLoading(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      const resp = await fetch('/api/2fa/disable', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({}),
      });

      if (resp.ok) {
        notifications.show({
          title: '2FA Disabled',
          message: 'Two-factor authentication has been disabled for your account.',
          color: 'green',
          autoClose: 5000,
        });
        fetchUser();
      } else {
        const error = await resp.json();
        notifications.show({
          title: 'Failed to Disable',
          message: error.message || 'Failed to disable 2FA. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      notifications.show({
        title: 'Network Error',
        message: 'Unable to disable 2FA. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setTwoFactorLoading(false);
    }
  }

  async function handleLogoutConfirm() {
    close(); // Close modal first
    setLogoutLoading(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      const resp = await fetch('/api/auth/logout', {
        method: 'POST',
        headers,
        credentials: 'include',
      });

      if (resp.ok || resp.status === 200) {
        // Redirect to login
        navigate('/login');
      } else {
        console.error('Logout failed:', await resp.text());
        // Still redirect even if logout API call fails
        navigate('/login');
      }
    } catch (err) {
      console.error('Logout error:', err);
      // Still redirect on error
      navigate('/login');
    } finally {
      setLogoutLoading(false);
    }
  }

  if (loading) {
    return (
      <Container size="sm" mt="xl">
        <Center>
          <Loader size="lg" />
        </Center>
      </Container>
    );
  }

  if (!user) {
    return (
      <Container size="sm" mt="xl">
        <Paper p="xl" withBorder>
          <Text>Failed to load user data. Please try again.</Text>
          <Button mt="md" onClick={() => navigate('/login')}>
            Go to Login
          </Button>
        </Paper>
      </Container>
    );
  }

  return (
    <>
      <Modal
        opened={opened}
        onClose={close}
        title="Confirm Logout"
        centered
        overlayProps={{
          backgroundOpacity: 0.55,
          blur: 3,
        }}
      >
        <Stack gap="md">
          <Text>
            Are you sure you want to logout? You'll need to sign in again to access your account.
          </Text>
          <Group justify="flex-end" mt="md">
            <Button variant="subtle" onClick={close} disabled={logoutLoading}>
              Cancel
            </Button>
            <Button
              color="red"
              onClick={handleLogoutConfirm}
              loading={logoutLoading}
            >
              Yes, Logout
            </Button>
          </Group>
        </Stack>
      </Modal>

      <TwoFactorSetupModal
        opened={twoFactorModalOpened}
        onClose={close2FA}
        onComplete={() => {
          fetchUser();
          close2FA();
        }}
      />

      <Container size="md" mt="xl">
        <Paper p="xl" withBorder radius="md">
          <Stack gap="lg">
            <Group justify="space-between" align="flex-start">
              <div>
                <Title order={2}>Profile</Title>
                <Text c="dimmed" size="sm" mt={4}>
                  {user.name} • {user.email}
                </Text>
              </div>
              <ActionIcon
                onClick={() => setColorScheme(computedColorScheme === 'light' ? 'dark' : 'light')}
                variant="default"
                size="lg"
                radius="md"
                aria-label="Toggle color scheme"
              >
                {computedColorScheme === 'light' ? (
                  <IconMoon size={20} stroke={1.5} />
                ) : (
                  <IconSun size={20} stroke={1.5} />
                )}
              </ActionIcon>
            </Group>

            <Group gap="xs">
              <Badge color={user.verified ? 'green' : 'yellow'} variant="light">
                {user.verified ? 'Verified' : 'Not Verified'}
              </Badge>
              <Badge color="blue" variant="light">
                {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
              </Badge>
              {user.twoFactorEnabled && (
                <Badge color="green" variant="light">
                  2FA Enabled
                </Badge>
              )}
            </Group>

            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md" mt="md">
              <Paper p="md" withBorder>
                <Stack gap="sm">
                  <Group justify="space-between">
                    <div>
                      <Text fw={500} size="sm">
                        Two-Factor Authentication
                      </Text>
                      <Text size="xs" c="dimmed">
                        Add an extra layer of security
                      </Text>
                    </div>
                    <Switch
                      checked={user.twoFactorEnabled || false}
                      onChange={async (e) => {
                        if (e.currentTarget.checked) {
                          open2FA();
                        } else {
                          await handleDisable2FA();
                        }
                      }}
                      disabled={twoFactorLoading}
                    />
                  </Group>
                </Stack>
              </Paper>

              <Paper p="md" withBorder>
                <Stack gap="sm">
                  <Group justify="space-between">
                    <div>
                      <Text fw={500} size="sm">
                        Email Verification
                      </Text>
                      <Text size="xs" c="dimmed">
                        {user.verified ? 'Your email is verified' : 'Verify your email address'}
                      </Text>
                    </div>
                    <Badge color={user.verified ? 'green' : 'yellow'} variant="light">
                      {user.verified ? 'Verified' : 'Pending'}
                    </Badge>
                  </Group>
                </Stack>
              </Paper>
            </SimpleGrid>

            {user.twoFactorEnabled && (
              <Paper p="md" withBorder mt="md">
                <RecoveryCodesSection />
              </Paper>
            )}

            <Divider label="Account Information" labelPosition="center" mt="xl" />

            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="md">
              <Card withBorder p="md">
                <Group>
                  <IconUser size={24} />
                  <div>
                    <Text size="xs" c="dimmed">Member Since</Text>
                    <Text fw={500}>{new Date(user.createdAt).toLocaleDateString()}</Text>
                  </div>
                </Group>
              </Card>
              <Card withBorder p="md">
                <Group>
                  <IconCalendar size={24} />
                  <div>
                    <Text size="xs" c="dimmed">Last Updated</Text>
                    <Text fw={500}>{new Date(user.updatedAt).toLocaleDateString()}</Text>
                  </div>
                </Group>
              </Card>
            </SimpleGrid>

            <Group mt="md">
              {user.role === 'admin' && (
                <Button
                  variant="light"
                  onClick={() => navigate('/admin')}
                >
                  Admin Dashboard
                </Button>
              )}
              <Button
                color="red"
                variant="light"
                onClick={handleLogoutClick}
                loading={logoutLoading}
              >
                Logout
              </Button>
            </Group>
          </Stack>
        </Paper>
      </Container>
    </>
  );
}

```


---

## FILE: `frontend/src/pages/AdminLogin.page.tsx`

```tsx
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Container,
  Paper,
  Title,
  TextInput,
  PasswordInput,
  Button,
  Stack,
  Text,
  Alert,
  Center,
  Loader,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconAlertCircle, IconShield } from '@tabler/icons-react';
import { TwoFactorVerifyStep } from '@/components/TwoFactorVerifyStep';

export function AdminLoginPage() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [show2FA, setShow2FA] = useState(false);
  const [pendingEmail, setPendingEmail] = useState<string>('');

  const form = useForm({
    initialValues: {
      email: '',
      password: '',
    },
    validate: {
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
      password: (val) => (val.length < 6 ? 'Password must be at least 6 characters' : null),
    },
  });

  async function handleSubmit(values: typeof form.values) {
    setLoading(true);
    try {
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
            // Show 2FA verification step
            setPendingEmail(values.email);
            setShow2FA(true);
            setLoading(false);
            return;
          }
        } catch (e) {
          // Not JSON, continue
        }

        // Check if user is admin
        const userResp = await fetch('/api/users/me', {
          credentials: 'include',
        });

        if (userResp.status === 200) {
          const userData = await userResp.json();
          const user = userData.data.user;

          if (user.role !== 'admin') {
            notifications.show({
              title: 'Access Denied',
              message: 'This account does not have admin privileges.',
              color: 'red',
              autoClose: 5000,
            });
            setLoading(false);
            return;
          }

          // Admin login successful
          notifications.show({
            title: 'Admin Login Successful!',
            message: 'Redirecting to admin dashboard...',
            color: 'green',
            autoClose: 2000,
          });
          setTimeout(() => navigate('/admin'), 500);
        } else {
          notifications.show({
            title: 'Error',
            message: 'Failed to verify admin status.',
            color: 'red',
            autoClose: 5000,
          });
        }
      } else if (resp.status === 401) {
        let msg: string = 'Login failed';
        try {
          const body = await resp.json();
          if (body && typeof body === 'object' && 'message' in body) {
            msg = String(body.message);
          }
        } catch (e) {
          msg = await resp.text().catch(() => 'Login failed');
        }

        notifications.show({
          title: 'Login Failed',
          message: msg,
          color: 'red',
          autoClose: 5000,
        });
      } else {
        const text = await resp.text();
        notifications.show({
          title: 'Login Failed',
          message: text || 'Something went wrong. Please try again.',
          color: 'red',
          autoClose: 5000,
        });
      }
    } catch (err) {
      console.error('Admin login error:', err);
      notifications.show({
        title: 'Network Error',
        message: 'Unable to connect to server. Please check your connection.',
        color: 'red',
        autoClose: 5000,
      });
    } finally {
      setLoading(false);
    }
  }

  if (show2FA) {
    return (
      <TwoFactorVerifyStep
        email={pendingEmail}
        onSuccess={() => {
          // After 2FA verification, check if user is admin
          fetch('/api/users/me', {
            credentials: 'include',
          })
            .then((resp) => {
              if (resp.status === 200) {
                return resp.json();
              }
              throw new Error('Failed to verify admin status');
            })
            .then((data) => {
              const user = data.data.user;
              if (user.role !== 'admin') {
                notifications.show({
                  title: 'Access Denied',
                  message: 'This account does not have admin privileges.',
                  color: 'red',
                  autoClose: 5000,
                });
                navigate('/admin/login');
              } else {
                notifications.show({
                  title: 'Admin Login Successful!',
                  message: 'Redirecting to admin dashboard...',
                  color: 'green',
                  autoClose: 2000,
                });
                setTimeout(() => navigate('/admin'), 500);
              }
            })
            .catch((err) => {
              console.error('Error verifying admin status:', err);
              notifications.show({
                title: 'Error',
                message: 'Failed to verify admin status.',
                color: 'red',
                autoClose: 5000,
              });
              navigate('/admin/login');
            });
        }}
        onCancel={() => {
          setShow2FA(false);
          setPendingEmail('');
        }}
      />
    );
  }

  return (
    <Container size={420} my={40}>
      <Center>
        <Paper withBorder shadow="md" p={30} radius="md" w="100%">
          <Stack gap="md" align="center" mb="xl">
            <IconShield size={48} stroke={1.5} />
            <Title ta="center" order={2}>
              Admin Login
            </Title>
            <Text c="dimmed" size="sm" ta="center">
              Sign in to access the admin dashboard
            </Text>
          </Stack>

          <Alert icon={<IconAlertCircle size={16} />} color="blue" variant="light" mb="md">
            <Text size="xs">
              This page is for administrators only. If you're a regular user, please use the{' '}
              <a href="/login" style={{ textDecoration: 'underline' }}>
                regular login page
              </a>
              .
            </Text>
          </Alert>

          <form onSubmit={form.onSubmit((values) => void handleSubmit(values))}>
            <Stack>
              <TextInput
                required
                label="Email"
                placeholder="admin@example.com"
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

              <Button type="submit" radius="xl" fullWidth loading={loading} mt="md">
                Sign In as Admin
              </Button>
            </Stack>
          </form>

          <Text ta="center" size="sm" c="dimmed" mt="md">
            <a href="/login" style={{ textDecoration: 'underline' }}>
              Regular user login
            </a>
          </Text>
        </Paper>
      </Center>
    </Container>
  );
}


```


---

## FILE: `frontend/src/pages/admin/AdminSecurityPage.tsx`

```tsx
import { useEffect, useState, useCallback } from 'react';
import {
  Table,
  Text,
  Paper,
  Group,
  Badge,
  Select,
  TextInput,
  Button,
  Pagination,
  Title,
  Loader,
  Center,
  Stack,
  Card,
  Grid,
  Modal,
  Alert,
  Tabs,
  ActionIcon,
  Tooltip,
  Divider,
  RingProgress,
  Progress,
  Box,
  Code,
  CopyButton,
  Menu,
  ScrollArea,
  SimpleGrid,
} from '@mantine/core';
import {
  IconShield,
  IconAlertTriangle,
  IconLock,
  IconBan,
  IconClock,
  IconSearch,
  IconFilter,
  IconDownload,
  IconRefresh,
  IconEye,
  IconX,
  IconCopy,
  IconCheck,
  IconMapPin,
  IconUser,
  IconServer,
  IconChartLine,
  IconFileExport,
  IconHelpCircle,
} from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';
import { BarChart, PieChart } from '@mantine/charts';
import { DatePickerInput } from '@mantine/dates';
import dayjs from 'dayjs';
import { SecurityDashboardHelpModal } from './SecurityDashboardHelpModal';

interface SecurityEvent {
  id: string;
  user_id: string | null;
  action: string;
  resource: string;
  ip_address: string | null;
  user_agent: string | null;
  timestamp: string;
}

interface SecurityEventsResponse {
  events: SecurityEvent[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

interface SecurityStatistics {
  total_events: number;
  critical_events: number;
  /** Live rolling count from server UTC; ignores date pickers */
  rolling_24h: number;
  last_24h: number;
  failed_logins: number;
  rate_limits: number;
  suspicious_activity: number;
  account_lockouts: number;
  top_ips: TopIp[];
  events_by_type: EventTypeCount[];
  timeline_data: TimelinePoint[];
}

interface TopIp {
  ip_address: string;
  event_count: number;
  last_seen: string;
  critical_events: number;
}

interface EventTypeCount {
  action: string;
  count: number;
}

interface TimelinePoint {
  hour: string;
  count: number;
  critical_count: number;
}

type StatCardFilter = 'all' | 'critical' | 'last24h' | 'failed_logins' | 'rate_limits' | 'suspicious' | 'lockouts';

/** Mantine theme tokens — PieChart needs these, not bare names like "red". */
const PIE_SLICE_COLORS = ['blue.6', 'red.6', 'orange.6', 'grape.6', 'cyan.6', 'teal.6'] as const;

function dateFromPickerValue(v: string | Date | null): Date | null {
  if (v == null) return null;
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function AdminSecurityPage() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [statistics, setStatistics] = useState<SecurityStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [actionFilter, setActionFilter] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [ipFilter, setIpFilter] = useState<string | null>(null);
  const [startDate, setStartDate] = useState<Date | null>(null);
  const [endDate, setEndDate] = useState<Date | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [eventModalOpen, setEventModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<string | null>('overview');
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());
  /** When the last successful `/statistics` response was applied (for honest “snapshot” UX). */
  const [statsSnapshotAt, setStatsSnapshotAt] = useState<Date | null>(null);
  /** Server-side filter: only audit rows whose action is in the critical set (matches overview "Critical Events"). */
  const [criticalOnly, setCriticalOnly] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  const hasDateRange = Boolean(startDate && endDate);

  const fetchStatistics = useCallback(async () => {
    setStatsLoading(true);
    try {
      const params = new URLSearchParams();
      if (startDate) {
        params.append('start_date', startDate.toISOString());
      }
      if (endDate) {
        params.append('end_date', endDate.toISOString());
      }

      const response = await fetch(`/api/security/statistics?${params.toString()}`, {
        credentials: 'include',
        cache: 'no-store',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch statistics');
      }

      const data: SecurityStatistics = await response.json();
      setStatistics(data);
      setStatsSnapshotAt(new Date());
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to load security statistics',
        color: 'red',
      });
    } finally {
      setStatsLoading(false);
    }
  }, [startDate, endDate]);

  const fetchEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: '50',
      });

      if (actionFilter) {
        params.append('action', actionFilter);
      }
      if (startDate) {
        params.append('start_date', startDate.toISOString());
      }
      if (endDate) {
        params.append('end_date', endDate.toISOString());
      }
      if (criticalOnly) {
        params.append('critical_only', 'true');
      }

      const response = await fetch(`/api/security/events?${params.toString()}`, {
        credentials: 'include',
        cache: 'no-store',
      });

      if (!response.ok) {
        throw new Error('Failed to fetch security events');
      }

      const data: SecurityEventsResponse = await response.json();
      setEvents(data.events);
      setTotal(data.total);
      setTotalPages(data.total_pages);
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to load security events',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }, [page, actionFilter, startDate, endDate, criticalOnly]);

  const handleRefresh = () => {
    setLastRefresh(new Date());
    fetchStatistics();
    fetchEvents();
    notifications.show({
      title: 'Refreshed',
      message: 'Security data updated',
      color: 'green',
    });
  };

  useEffect(() => {
    fetchStatistics();
  }, [fetchStatistics]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  const handleStatCardClick = (filter: StatCardFilter) => {
    setCriticalOnly(false);
    switch (filter) {
      case 'critical':
        setActionFilter(null);
        setCriticalOnly(true);
        setActiveTab('events');
        break;
      case 'last24h': {
        const end = new Date();
        const start = new Date(end.getTime() - 24 * 60 * 60 * 1000);
        setStartDate(start);
        setEndDate(end);
        setActiveTab('overview');
        notifications.show({
          title: 'Preset: last 24 hours',
          message:
            'Start/end set to exactly 24 hours apart (UTC via ISO). Totals and charts match this window. The orange card still shows the live rolling count from the server.',
          color: 'blue',
          autoClose: 9000,
        });
        break;
      }
      case 'failed_logins':
        setActionFilter('FAILED_LOGIN');
        setActiveTab('events');
        break;
      case 'rate_limits':
        setActionFilter('RATE_LIMIT_EXCEEDED');
        setActiveTab('events');
        break;
      case 'suspicious':
        setActionFilter('SUSPICIOUS_ACTIVITY');
        setActiveTab('events');
        break;
      case 'lockouts':
        setActionFilter('ACCOUNT_LOCKOUT');
        setActiveTab('events');
        break;
      default:
        setActionFilter(null);
        setStartDate(null);
        setEndDate(null);
    }
    setPage(1);
  };

  const handleEventClick = async (event: SecurityEvent) => {
    try {
      const response = await fetch(`/api/security/events/${event.id}`, {
        credentials: 'include',
        cache: 'no-store',
      });
      if (response.ok) {
        const eventDetails: SecurityEvent = await response.json();
        setSelectedEvent(eventDetails);
        setEventModalOpen(true);
      }
    } catch (error) {
      notifications.show({
        title: 'Error',
        message: 'Failed to load event details',
        color: 'red',
      });
    }
  };

  const exportToCSV = () => {
    const headers = ['Time', 'Action', 'Resource', 'IP Address', 'User Agent', 'User ID'];
    const rows = events.map((e) => [
      new Date(e.timestamp).toISOString(),
      e.action,
      e.resource,
      e.ip_address || 'N/A',
      e.user_agent || 'N/A',
      e.user_id || 'N/A',
    ]);

    const csv = [headers.join(','), ...rows.map((r) => r.map((c) => `"${c}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-events-${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    notifications.show({
      title: 'Exported',
      message: 'Security events exported to CSV',
      color: 'green',
    });
  };

  const exportToJSON = () => {
    const json = JSON.stringify(events, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-events-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    notifications.show({
      title: 'Exported',
      message: 'Security events exported to JSON',
      color: 'green',
    });
  };

  const getActionBadgeColor = (action: string) => {
    if (action.includes('FAILED') || action.includes('LOCKOUT')) {
      return 'red';
    }
    if (action.includes('RATE_LIMIT') || action.includes('SUSPICIOUS')) {
      return 'orange';
    }
    if (action.includes('ADMIN')) {
      return 'blue';
    }
    return 'gray';
  };

  const getActionIcon = (action: string) => {
    if (action.includes('LOCKOUT')) {
      return <IconLock size={16} />;
    }
    if (action.includes('FAILED')) {
      return <IconBan size={16} />;
    }
    if (action.includes('RATE_LIMIT')) {
      return <IconAlertTriangle size={16} />;
    }
    return <IconClock size={16} />;
  };

  const filteredEvents = events.filter((event) => {
    if (searchTerm) {
      const search = searchTerm.toLowerCase();
      if (
        !event.action.toLowerCase().includes(search) &&
        !event.resource.toLowerCase().includes(search) &&
        !event.ip_address?.toLowerCase().includes(search) &&
        !event.user_agent?.toLowerCase().includes(search)
      ) {
        return false;
      }
    }
    if (ipFilter && event.ip_address !== ipFilter) {
      return false;
    }
    return true;
  });

  const stats = statistics || {
    total_events: 0,
    critical_events: 0,
    rolling_24h: 0,
    last_24h: 0,
    failed_logins: 0,
    rate_limits: 0,
    suspicious_activity: 0,
    account_lockouts: 0,
    top_ips: [],
    events_by_type: [],
    timeline_data: [],
  };

  const rollingLive = stats.rolling_24h ?? stats.last_24h;

  if (loading && events.length === 0 && !statistics) {
    return (
      <Center h={400}>
        <Loader size="lg" />
      </Center>
    );
  }

  return (
    <Stack gap="md">
      <SecurityDashboardHelpModal opened={helpOpen} onClose={() => setHelpOpen(false)} />

      {/* Header */}
      <Group justify="space-between" align="flex-start" wrap="wrap">
        <Stack gap={4}>
          <Title order={2}>
            <Group gap="xs">
              <IconShield size={28} />
              Security Dashboard
            </Group>
          </Title>
          {statsSnapshotAt && (
            <Text size="xs" c="dimmed">
              Statistics snapshot:{' '}
              <Text span fw={600} c="dimmed">
                {statsSnapshotAt.toLocaleString('en-US', { timeZone: 'UTC' })} UTC
              </Text>
              {' · '}
              Refresh loads current DB counts; &quot;Rolling 24h&quot; moves with server time
            </Text>
          )}
        </Stack>
        <Group>
          <Button
            variant="light"
            leftSection={<IconHelpCircle size={18} />}
            onClick={() => setHelpOpen(true)}
          >
            How this works
          </Button>
          <Tooltip label={`Last refreshed: ${lastRefresh.toLocaleTimeString()}`}>
            <ActionIcon variant="light" onClick={handleRefresh} loading={loading || statsLoading}>
              <IconRefresh size={18} />
            </ActionIcon>
          </Tooltip>
          <Menu shadow="md" width={200}>
            <Menu.Target>
              <Button leftSection={<IconFileExport size={16} />} variant="light">
                Export
              </Button>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item leftSection={<IconDownload size={16} />} onClick={exportToCSV}>
                Export as CSV
              </Menu.Item>
              <Menu.Item leftSection={<IconDownload size={16} />} onClick={exportToJSON}>
                Export as JSON
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        </Group>
      </Group>

      <Tabs value={activeTab} onChange={setActiveTab}>
        <Tabs.List>
          <Tabs.Tab value="overview" leftSection={<IconChartLine size={16} />}>
            Overview
          </Tabs.Tab>
          <Tabs.Tab value="events" leftSection={<IconShield size={16} />}>
            Events
          </Tabs.Tab>
          <Tabs.Tab value="ips" leftSection={<IconMapPin size={16} />}>
            IP Analysis
          </Tabs.Tab>
        </Tabs.List>

        {/* Overview Tab */}
        <Tabs.Panel value="overview" pt="md">
          <Stack gap="md">
            {hasDateRange && (
              <Alert variant="light" color="blue" title="Date range active">
                Totals, critical counts, charts, and pie use the start/end dates from the Events tab
                (UTC). The <strong>Rolling 24h (live)</strong> card is independent — it always uses
                the server clock — so it may differ from Total. Open &quot;How this works&quot; for
                detail.
              </Alert>
            )}

            {/* Statistics Cards - Clickable */}
            <Grid>
              <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
                <Card
                  withBorder
                  padding="md"
                  radius="md"
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleStatCardClick('all')}
                  onMouseEnter={(e) => (e.currentTarget.style.transform = 'scale(1.02)')}
                  onMouseLeave={(e) => (e.currentTarget.style.transform = 'scale(1)')}
                >
                  <Group justify="space-between">
                    <div>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
                        Total Events
                      </Text>
                      <Text size="xl" fw={700}>
                        {stats.total_events.toLocaleString()}
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        {startDate || endDate ? 'Selected date range' : 'All time (database)'}
                      </Text>
                    </div>
                    <IconShield size={32} color="gray" />
                  </Group>
                </Card>
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
                <Card
                  withBorder
                  padding="md"
                  radius="md"
                  style={{ cursor: 'pointer', borderColor: 'var(--mantine-color-red-6)' }}
                  onClick={() => handleStatCardClick('critical')}
                  onMouseEnter={(e) => (e.currentTarget.style.transform = 'scale(1.02)')}
                  onMouseLeave={(e) => (e.currentTarget.style.transform = 'scale(1)')}
                >
                  <Group justify="space-between">
                    <div>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
                        Critical Events
                      </Text>
                      <Text size="xl" fw={700} c="red">
                        {stats.critical_events.toLocaleString()}
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        Failed login, rate limit, lockout, etc.
                      </Text>
                    </div>
                    <IconAlertTriangle size={32} color="red" />
                  </Group>
                </Card>
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
                <Card
                  withBorder
                  padding="md"
                  radius="md"
                  style={{ cursor: 'pointer' }}
                  onClick={() => handleStatCardClick('last24h')}
                  onMouseEnter={(e) => (e.currentTarget.style.transform = 'scale(1.02)')}
                  onMouseLeave={(e) => (e.currentTarget.style.transform = 'scale(1)')}
                >
                  <Group justify="space-between">
                    <div>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
                        Rolling 24h (live)
                      </Text>
                      <Text size="xl" fw={700} c="orange">
                        {rollingLive.toLocaleString()}
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        Server UTC clock — not filtered by date pickers
                      </Text>
                    </div>
                    <IconClock size={32} color="orange" />
                  </Group>
                </Card>
              </Grid.Col>
              <Grid.Col span={{ base: 12, sm: 6, md: 3 }}>
                <Card withBorder padding="md" radius="md">
                  <Group justify="space-between">
                    <div>
                      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>
                        Failed Logins
                      </Text>
                      <Text size="xl" fw={700} c="red">
                        {stats.failed_logins.toLocaleString()}
                      </Text>
                      <Text size="xs" c="dimmed" mt={4}>
                        {startDate || endDate ? 'In selected range' : 'All time'}
                      </Text>
                    </div>
                    <IconBan size={32} color="red" />
                  </Group>
                </Card>
              </Grid.Col>
            </Grid>

            {/* Secondary metrics — equal-width row (no awkward empty grid slot) */}
            <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="md">
              <Card withBorder padding="md" radius="md" style={{ minHeight: 100 }}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700} mb="xs">
                  Rate Limits
                </Text>
                <Text size="lg" fw={700} c="orange">
                  {stats.rate_limits.toLocaleString()}
                </Text>
              </Card>
              <Card withBorder padding="md" radius="md" style={{ minHeight: 100 }}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700} mb="xs">
                  Suspicious Activity
                </Text>
                <Text size="lg" fw={700} c="orange">
                  {stats.suspicious_activity.toLocaleString()}
                </Text>
              </Card>
              <Card withBorder padding="md" radius="md" style={{ minHeight: 100 }}>
                <Text size="xs" c="dimmed" tt="uppercase" fw={700} mb="xs">
                  Account Lockouts
                </Text>
                <Text size="lg" fw={700} c="red">
                  {stats.account_lockouts.toLocaleString()}
                </Text>
              </Card>
            </SimpleGrid>

            {/* Charts: equal height columns, room for pie labels */}
            <Grid gutter="md" align="stretch">
              <Grid.Col span={{ base: 12, lg: 8 }}>
                <Paper
                  withBorder
                  p="md"
                  style={{ minHeight: 440, display: 'flex', flexDirection: 'column', height: '100%' }}
                >
                  <Text fw={700} mb="xs">
                    Event timeline
                    {hasDateRange ? ' (selected date range)' : ' (rolling 24h, UTC)'}
                  </Text>
                  {stats.timeline_data.length > 0 ? (
                    <Box style={{ flex: 1, width: '100%', minWidth: 0, minHeight: 360 }}>
                      <Text size="xs" c="dimmed" mb="sm">
                        Hourly buckets (UTC). Stacked: red = critical-type actions; blue = other audited
                        events in that hour (same total height as total events for that hour).
                      </Text>
                      <BarChart
                        h={340}
                        data={stats.timeline_data.map((d) => {
                          const total = Number(d.count);
                          const critical = Number(d.critical_count);
                          return {
                            bucket: d.hour,
                            other: Math.max(0, total - critical),
                            critical,
                          };
                        })}
                        dataKey="bucket"
                        series={[
                          { name: 'other', label: 'Non-critical', color: 'blue.5' },
                          { name: 'critical', label: 'Critical', color: 'red.6' },
                        ]}
                        type="stacked"
                        gridAxis="xy"
                        tickLine="xy"
                        withLegend
                        legendProps={{ verticalAlign: 'bottom', layout: 'horizontal', align: 'center' }}
                        barProps={() => ({ maxBarSize: 56 })}
                        xAxisProps={{
                          tickFormatter: (val: string) => {
                            const s = String(val);
                            const parsed = dayjs(s.replace(' ', 'T'));
                            return parsed.isValid() ? parsed.format('MMM D HH:mm') : s;
                          },
                          angle: stats.timeline_data.length > 3 ? -35 : 0,
                          textAnchor: 'end',
                          height: stats.timeline_data.length > 3 ? 64 : 36,
                          interval: 0,
                        }}
                      />
                    </Box>
                  ) : (
                    <Center style={{ flex: 1 }} mih={300}>
                      <Text c="dimmed">No timeline data for this window</Text>
                    </Center>
                  )}
                </Paper>
              </Grid.Col>
              <Grid.Col span={{ base: 12, lg: 4 }}>
                <Paper
                  withBorder
                  p="md"
                  style={{
                    minHeight: 440,
                    display: 'flex',
                    flexDirection: 'column',
                    height: '100%',
                    overflow: 'visible',
                  }}
                >
                  <Text fw={700} mb="xs">
                    Events by type
                  </Text>
                  <Text size="xs" c="dimmed" mb="sm">
                    Share of actions in the same range as the summary cards (UTC).
                  </Text>
                  {stats.events_by_type.length > 0 ? (
                    <Box
                      style={{
                        flex: 1,
                        width: '100%',
                        minWidth: 0,
                        display: 'flex',
                        justifyContent: 'center',
                        alignItems: 'center',
                        paddingBottom: 48,
                        paddingTop: 8,
                        overflow: 'visible',
                      }}
                    >
                      <PieChart
                        data={stats.events_by_type.slice(0, 8).map((e, i) => ({
                          name: e.action.replace(/_/g, ' '),
                          value: Number(e.count),
                          color: PIE_SLICE_COLORS[i % PIE_SLICE_COLORS.length],
                        }))}
                        withTooltip
                        withLabels
                        withLabelsLine
                        labelsPosition="outside"
                        labelsType="percent"
                        size={170}
                      />
                    </Box>
                  ) : (
                    <Center style={{ flex: 1 }} mih={260}>
                      <Text c="dimmed">No event type data for this window</Text>
                    </Center>
                  )}
                </Paper>
              </Grid.Col>
            </Grid>
          </Stack>
        </Tabs.Panel>

        {/* Events Tab */}
        <Tabs.Panel value="events" pt="md">
          <Stack gap="md">
            {criticalOnly && (
              <Group>
                <Badge color="red" variant="light" size="lg">
                  Critical events only — failed login, rate limit, lockout, suspicious, token checks
                </Badge>
                <Button size="xs" variant="subtle" onClick={() => setCriticalOnly(false)}>
                  Clear
                </Button>
              </Group>
            )}
            {/* Advanced Filters */}
            <Paper withBorder p="md">
              <Stack gap="md">
                <Group grow>
                  <TextInput
                    placeholder="Search events..."
                    leftSection={<IconSearch size={16} />}
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.currentTarget.value)}
                  />
                  <Select
                    placeholder="Filter by action"
                    leftSection={<IconFilter size={16} />}
                    data={[
                      { value: 'FAILED_LOGIN', label: 'Failed Logins' },
                      { value: 'RATE_LIMIT_EXCEEDED', label: 'Rate Limit Exceeded' },
                      { value: 'ACCOUNT_LOCKOUT', label: 'Account Lockouts' },
                      { value: 'SUSPICIOUS_ACTIVITY', label: 'Suspicious Activity' },
                      { value: 'MULTIPLE_FAILED_ATTEMPTS', label: 'Multiple Failed Attempts' },
                      { value: 'ADMIN_ACTION', label: 'Admin Actions' },
                    ]}
                    value={actionFilter}
                    onChange={(v) => {
                      setActionFilter(v);
                      if (v) setCriticalOnly(false);
                    }}
                    clearable
                  />
                  <Select
                    placeholder="Filter by IP"
                    leftSection={<IconMapPin size={16} />}
                    data={Array.from(new Set(events.map((e) => e.ip_address).filter(Boolean))).map((ip) => ({
                      value: ip!,
                      label: ip!,
                    }))}
                    value={ipFilter}
                    onChange={setIpFilter}
                    clearable
                    searchable
                  />
                </Group>
                <Group grow>
                  <DatePickerInput
                    label="Start Date"
                    placeholder="Pick start date"
                    value={startDate}
                    onChange={(v) => setStartDate(dateFromPickerValue(v))}
                    clearable
                  />
                  <DatePickerInput
                    label="End Date"
                    placeholder="Pick end date"
                    value={endDate}
                    onChange={(v) => setEndDate(dateFromPickerValue(v))}
                    clearable
                  />
                  <Group align="flex-end">
                    <Button
                      variant="light"
                      onClick={() => {
                        setStartDate(null);
                        setEndDate(null);
                        setActionFilter(null);
                        setCriticalOnly(false);
                        setIpFilter(null);
                        setSearchTerm('');
                      }}
                    >
                      Clear Filters
                    </Button>
                  </Group>
                </Group>
              </Stack>
            </Paper>

            {/* Events Table */}
            <Paper withBorder>
              <ScrollArea>
                <Table.ScrollContainer minWidth={800}>
                  <Table highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Time</Table.Th>
                      <Table.Th>Action</Table.Th>
                      <Table.Th>Resource</Table.Th>
                      <Table.Th>IP Address</Table.Th>
                      <Table.Th>User Agent</Table.Th>
                      <Table.Th>Actions</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {filteredEvents.length === 0 ? (
                      <Table.Tr>
                        <Table.Td colSpan={6}>
                          <Center p="xl">
                            <Text c="dimmed">No security events found</Text>
                          </Center>
                        </Table.Td>
                      </Table.Tr>
                    ) : (
                      filteredEvents.map((event) => (
                        <Table.Tr
                          key={event.id}
                          style={{ cursor: 'pointer' }}
                          onClick={() => handleEventClick(event)}
                        >
                          <Table.Td>
                            <Text size="sm">
                              {new Date(event.timestamp).toLocaleString('en-US', {
                                month: 'short',
                                day: '2-digit',
                                year: 'numeric',
                                hour: '2-digit',
                                minute: '2-digit',
                                second: '2-digit',
                                hour12: false,
                              })}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Badge
                              color={getActionBadgeColor(event.action)}
                              leftSection={getActionIcon(event.action)}
                              variant="light"
                            >
                              {event.action}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm" c="dimmed">
                              {event.resource}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm" ff="monospace">
                              {event.ip_address || 'N/A'}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Text size="xs" c="dimmed" lineClamp={1} style={{ maxWidth: 200 }}>
                              {event.user_agent || 'N/A'}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <ActionIcon variant="subtle" onClick={(e) => {
                              e.stopPropagation();
                              handleEventClick(event);
                            }}>
                              <IconEye size={16} />
                            </ActionIcon>
                          </Table.Td>
                        </Table.Tr>
                      ))
                    )}
                  </Table.Tbody>
                </Table>
                </Table.ScrollContainer>
              </ScrollArea>

              {totalPages > 1 && (
                <Group justify="center" p="md">
                  <Pagination value={page} onChange={setPage} total={totalPages} siblings={1} />
                </Group>
              )}
            </Paper>
          </Stack>
        </Tabs.Panel>

        {/* IP Analysis Tab */}
        <Tabs.Panel value="ips" pt="md">
          <Stack gap="md">
            <Paper withBorder p="md">
              <Text fw={700} mb="md">
                Top IP Addresses
              </Text>
              {stats.top_ips.length > 0 ? (
                <Table>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>IP Address</Table.Th>
                      <Table.Th>Total Events</Table.Th>
                      <Table.Th>Critical Events</Table.Th>
                      <Table.Th>Last Seen</Table.Th>
                      <Table.Th>Risk Level</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {stats.top_ips.map((ip) => {
                      const riskLevel = ip.critical_events > 10 ? 'high' : ip.critical_events > 5 ? 'medium' : 'low';
                      return (
                        <Table.Tr
                          key={ip.ip_address}
                          style={{ cursor: 'pointer' }}
                          onClick={() => {
                            setIpFilter(ip.ip_address);
                            setActiveTab('events');
                          }}
                        >
                          <Table.Td>
                            <Text ff="monospace" fw={500}>
                              {ip.ip_address}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Text>{ip.event_count.toLocaleString()}</Text>
                          </Table.Td>
                          <Table.Td>
                            <Badge color={ip.critical_events > 0 ? 'red' : 'gray'} variant="light">
                              {ip.critical_events}
                            </Badge>
                          </Table.Td>
                          <Table.Td>
                            <Text size="sm">
                              {new Date(ip.last_seen).toLocaleString()}
                            </Text>
                          </Table.Td>
                          <Table.Td>
                            <Badge
                              color={riskLevel === 'high' ? 'red' : riskLevel === 'medium' ? 'orange' : 'green'}
                              variant="light"
                            >
                              {riskLevel.toUpperCase()}
                            </Badge>
                          </Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              ) : (
                <Center p="xl">
                  <Text c="dimmed">No IP data available</Text>
                </Center>
              )}
            </Paper>
          </Stack>
        </Tabs.Panel>
      </Tabs>

      {/* Event Detail Modal */}
      <Modal
        opened={eventModalOpen}
        onClose={() => setEventModalOpen(false)}
        title="Event Details"
        size="lg"
      >
        {selectedEvent && (
          <Stack gap="md">
            <Group>
              <Badge
                color={getActionBadgeColor(selectedEvent.action)}
                leftSection={getActionIcon(selectedEvent.action)}
                size="lg"
              >
                {selectedEvent.action}
              </Badge>
            </Group>

            <Divider />

            <Stack gap="xs">
              <Group>
                <IconClock size={16} />
                <Text fw={500}>Timestamp:</Text>
                <Text>{new Date(selectedEvent.timestamp).toLocaleString()}</Text>
              </Group>
              <Group>
                <IconServer size={16} />
                <Text fw={500}>Resource:</Text>
                <Text>{selectedEvent.resource}</Text>
              </Group>
              <Group>
                <IconMapPin size={16} />
                <Text fw={500}>IP Address:</Text>
                <Code>{selectedEvent.ip_address || 'N/A'}</Code>
                {selectedEvent.ip_address && (
                  <CopyButton value={selectedEvent.ip_address}>
                    {({ copied, copy }) => (
                      <ActionIcon variant="subtle" onClick={copy}>
                        {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                      </ActionIcon>
                    )}
                  </CopyButton>
                )}
              </Group>
              {selectedEvent.user_id && (
                <Group>
                  <IconUser size={16} />
                  <Text fw={500}>User ID:</Text>
                  <Code>{selectedEvent.user_id}</Code>
                  <CopyButton value={selectedEvent.user_id}>
                    {({ copied, copy }) => (
                      <ActionIcon variant="subtle" onClick={copy}>
                        {copied ? <IconCheck size={16} /> : <IconCopy size={16} />}
                      </ActionIcon>
                    )}
                  </CopyButton>
                </Group>
              )}
            </Stack>

            <Divider />

            <Stack gap="xs">
              <Text fw={500}>User Agent:</Text>
              <Code block>{selectedEvent.user_agent || 'N/A'}</Code>
            </Stack>

            <Group justify="flex-end">
              <Button variant="light" onClick={() => setEventModalOpen(false)}>
                Close
              </Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Stack>
  );
}

```


---

## FILE: `frontend/src/pages/admin/AdminUsersPage.tsx`

```tsx
import { useEffect, useState } from 'react';
import {
  Table,
  Text,
  Paper,
  Group,
  Badge,
  ActionIcon,
  Select,
  TextInput,
  Button,
  Pagination,
  Modal,
  Stack,
  Title,
  Loader,
  Center,
  Alert,
  Divider,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconEdit, IconTrash, IconSearch, IconAlertCircle, IconPlus, IconShield, IconInfoCircle } from '@tabler/icons-react';
import { notifications } from '@mantine/notifications';

interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  verified: boolean;
  twoFactorEnabled?: boolean;
  createdAt: string;
  updatedAt: string;
}

export function AdminUsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalUsers, setTotalUsers] = useState(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [roleModalOpened, { open: openRoleModal, close: closeRoleModal }] = useDisclosure(false);
  const [createModalOpened, { open: openCreateModal, close: closeCreateModal }] = useDisclosure(false);
  const [deleteModalOpened, { open: openDeleteModal, close: closeDeleteModal }] = useDisclosure(false);
  const [twoFAModalOpened, { open: open2FAModal, close: close2FAModal }] = useDisclosure(false);
  const [newRole, setNewRole] = useState<string>('user');
  const [updating, setUpdating] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [creating, setCreating] = useState(false);
  const [recoveryStatus, setRecoveryStatus] = useState<any>(null);
  const [loading2FA, setLoading2FA] = useState(false);
  const [resetting2FA, setResetting2FA] = useState(false);
  const limit = 10;
  
  const createForm = useForm({
    initialValues: {
      name: '',
      email: '',
      password: '',
      role: 'user' as string,
    },
    validate: {
      name: (val) => (val.length < 1 ? 'Name is required' : null),
      email: (val) => (/^\S+@\S+$/.test(val) ? null : 'Invalid email'),
      password: (val) => (val.length < 6 ? 'Password must be at least 6 characters' : null),
    },
  });

  useEffect(() => {
    fetchUsers();
  }, [page]);

  async function fetchUsers() {
    setLoading(true);
    try {
      const resp = await fetch(`/api/users/users?page=${page}&limit=${limit}`, {
        credentials: 'include',
      });

      if (resp.ok) {
        const data = await resp.json();
        setUsers(data.users || []);
        setTotalUsers(data.results || 0);
      } else {
        notifications.show({
          title: 'Error',
          message: 'Failed to fetch users',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error fetching users:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to fetch users',
        color: 'red',
      });
    } finally {
      setLoading(false);
    }
  }

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

  async function handleRoleUpdate() {
    if (!selectedUser) return;

    setUpdating(true);
    try {
      const csrfToken = getCsrfToken();
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
      };

      if (csrfToken) {
        headers['X-CSRF-Token'] = csrfToken;
      }

      console.log('Updating role:', { user_id: selectedUser.id, role: newRole });
      
      const resp = await fetch('/api/users/role', {
        method: 'PUT',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          user_id: selectedUser.id,
          role: newRole.toLowerCase(), // Ensure lowercase to match enum
        }),
      });
      
      console.log('Role update response status:', resp.status);

      if (resp.ok) {
        notifications.show({
          title: 'Success',
          message: `User role updated to ${newRole}`,
          color: 'green',
        });
        closeRoleModal();
        fetchUsers();
      } else {
        let errorMessage = 'Failed to update user role';
        try {
          const data = await resp.json();
          console.log('Error response:', data);
          errorMessage = data.message || data.error || JSON.stringify(data) || errorMessage;
        } catch (e) {
          // Response is not JSON, try to get text
          try {
            const text = await resp.text();
            console.log('Error response (text):', text);
            errorMessage = text || errorMessage;
          } catch (textErr) {
            console.error('Failed to parse error response:', textErr);
            // Ignore text parsing errors
          }
        }
        
        notifications.show({
          title: 'Error',
          message: errorMessage,
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error updating role:', err);
      notifications.show({
        title: 'Error',
        message: err instanceof Error ? err.message : 'Failed to update user role',
        color: 'red',
      });
    } finally {
      setUpdating(false);
    }
  }

  function handleEditRole(user: User) {
    setSelectedUser(user);
    setNewRole(user.role.toLowerCase()); // Ensure lowercase
    openRoleModal();
  }

  async function handleDeleteUser() {
    if (!selectedUser) return;

    setDeleting(true);
    try {
      const resp = await fetch(`/api/users/users/${selectedUser.id}`, {
        method: 'DELETE',
        credentials: 'include',
      });

      if (resp.ok) {
        notifications.show({
          title: 'Success',
          message: 'User deleted successfully',
          color: 'green',
        });
        closeDeleteModal();
        fetchUsers();
      } else {
        const data = await resp.json();
        notifications.show({
          title: 'Error',
          message: data.message || 'Failed to delete user',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error deleting user:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to delete user',
        color: 'red',
      });
    } finally {
      setDeleting(false);
    }
  }

  function handleDeleteClick(user: User) {
    setSelectedUser(user);
    openDeleteModal();
  }

  async function handleView2FAStatus(user: User) {
    setSelectedUser(user);
    setLoading2FA(true);
    setRecoveryStatus(null);
    open2FAModal();
    
    try {
      const resp = await fetch(`/api/2fa/admin/status/${user.id}`, {
        credentials: 'include',
      });

      if (resp.ok) {
        const data = await resp.json();
        setRecoveryStatus(data);
      } else {
        const errorData = await resp.json().catch(() => ({ message: 'Failed to fetch 2FA status' }));
        notifications.show({
          title: 'Error',
          message: errorData.message || 'Failed to fetch 2FA status',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error fetching 2FA status:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to fetch 2FA status',
        color: 'red',
      });
    } finally {
      setLoading2FA(false);
    }
  }

  async function handleReset2FA() {
    if (!selectedUser) return;
    
    setResetting2FA(true);
    try {
      const csrfToken = getCsrfToken();
      const resp = await fetch(`/api/2fa/admin/reset/${selectedUser.id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken || '',
        },
        credentials: 'include',
        body: JSON.stringify({}),
      });

      if (resp.ok) {
        const data = await resp.json();
        notifications.show({
          title: 'Success',
          message: data.message || '2FA has been reset for this user',
          color: 'green',
        });
        close2FAModal();
        fetchUsers(); // Refresh user list
      } else {
        const errorData = await resp.json().catch(() => ({ message: 'Failed to reset 2FA' }));
        notifications.show({
          title: 'Error',
          message: errorData.message || 'Failed to reset 2FA',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error resetting 2FA:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to reset 2FA',
        color: 'red',
      });
    } finally {
      setResetting2FA(false);
    }
  }

  async function handleCreateUser(values: typeof createForm.values) {
    setCreating(true);
    try {
      const resp = await fetch('/api/users/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          name: values.name,
          email: values.email,
          password: values.password,
          role: values.role,
        }),
      });

      if (resp.ok) {
        notifications.show({
          title: 'Success',
          message: 'User created successfully',
          color: 'green',
        });
        closeCreateModal();
        createForm.reset();
        fetchUsers();
      } else {
        const data = await resp.json();
        notifications.show({
          title: 'Error',
          message: data.message || 'Failed to create user',
          color: 'red',
        });
      }
    } catch (err) {
      console.error('Error creating user:', err);
      notifications.show({
        title: 'Error',
        message: 'Failed to create user',
        color: 'red',
      });
    } finally {
      setCreating(false);
    }
  }

  const filteredUsers = users.filter(
    (user) =>
      user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      user.email.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const rows = filteredUsers.map((user) => (
    <Table.Tr key={user.id}>
      <Table.Td>
        <Text fw={500}>{user.name}</Text>
        <Text size="xs" c="dimmed">
          {user.email}
        </Text>
      </Table.Td>
      <Table.Td>
        <Badge color={user.role === 'admin' ? 'red' : 'blue'} variant="light">
          {user.role}
        </Badge>
      </Table.Td>
      <Table.Td>
        <Group gap="xs">
          {user.verified ? (
            <Badge color="green" variant="light">
              Verified
            </Badge>
          ) : (
            <Badge color="orange" variant="light">
              Unverified
            </Badge>
          )}
          {user.twoFactorEnabled && (
            <Badge color="blue" variant="light">
              2FA
            </Badge>
          )}
        </Group>
      </Table.Td>
      <Table.Td>
        <Text size="sm" c="dimmed">
          {new Date(user.createdAt).toLocaleDateString()}
        </Text>
      </Table.Td>
      <Table.Td>
        <Group gap="xs">
          <ActionIcon
            variant="light"
            color="blue"
            onClick={() => handleEditRole(user)}
            title="Edit Role"
          >
            <IconEdit size={16} />
          </ActionIcon>
          {user.twoFactorEnabled && (
            <ActionIcon
              variant="light"
              color="purple"
              onClick={() => handleView2FAStatus(user)}
              title="View 2FA Status"
            >
              <IconShield size={16} />
            </ActionIcon>
          )}
          <ActionIcon
            variant="light"
            color="red"
            onClick={() => handleDeleteClick(user)}
            title="Delete User"
          >
            <IconTrash size={16} />
          </ActionIcon>
        </Group>
      </Table.Td>
    </Table.Tr>
  ));

  if (loading) {
    return (
      <Center h={400}>
        <Loader size="lg" />
      </Center>
    );
  }

  return (
    <div>
      <Group justify="space-between" mb="lg">
        <Title order={2}>User Management</Title>
        <Button leftSection={<IconPlus size={16} />} onClick={openCreateModal}>
          Add User
        </Button>
      </Group>

      <Paper withBorder p="md" mb="md">
        <Group justify="space-between" mb="md">
          <TextInput
            placeholder="Search users..."
            leftSection={<IconSearch size={16} />}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.currentTarget.value)}
            style={{ flex: 1, maxWidth: 400 }}
          />
          <Text size="sm" c="dimmed">
            Total: {totalUsers} users
          </Text>
        </Group>

        <Table striped highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>User</Table.Th>
              <Table.Th>Role</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Joined</Table.Th>
              <Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.length > 0 ? (
              rows
            ) : (
              <Table.Tr>
                <Table.Td colSpan={5}>
                  <Center p="xl">
                    <Text c="dimmed">No users found</Text>
                  </Center>
                </Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>

        {totalUsers > limit && (
          <Group justify="center" mt="md">
            <Pagination
              value={page}
              onChange={setPage}
              total={Math.ceil(totalUsers / limit)}
            />
          </Group>
        )}
      </Paper>

      <Modal
        opened={roleModalOpened}
        onClose={closeRoleModal}
        title="Update User Role"
      >
        <Stack>
          <Alert icon={<IconAlertCircle size={16} />} color="yellow">
            Changing a user's role will affect their access permissions immediately.
          </Alert>
          {selectedUser && (
            <>
              <Text>
                <strong>User:</strong> {selectedUser.name} ({selectedUser.email})
              </Text>
              <Select
                label="New Role"
                data={[
                  { value: 'user', label: 'User' },
                  { value: 'admin', label: 'Admin' },
                ]}
                value={newRole}
                onChange={(value) => value && setNewRole(value)}
              />
              <Group justify="flex-end" mt="md">
                <Button variant="subtle" onClick={closeRoleModal}>
                  Cancel
                </Button>
                <Button onClick={handleRoleUpdate} loading={updating}>
                  Update Role
                </Button>
              </Group>
            </>
          )}
        </Stack>
      </Modal>

      <Modal
        opened={deleteModalOpened}
        onClose={closeDeleteModal}
        title="Delete User"
      >
        <Stack>
          <Alert icon={<IconAlertCircle size={16} />} color="red">
            Are you sure you want to delete this user? This action cannot be undone.
          </Alert>
          {selectedUser && (
            <>
              <Text>
                <strong>User:</strong> {selectedUser.name} ({selectedUser.email})
              </Text>
              <Group justify="flex-end" mt="md">
                <Button variant="subtle" onClick={closeDeleteModal}>
                  Cancel
                </Button>
                <Button color="red" onClick={handleDeleteUser} loading={deleting}>
                  Delete User
                </Button>
              </Group>
            </>
          )}
        </Stack>
      </Modal>

      <Modal
        opened={createModalOpened}
        onClose={closeCreateModal}
        title="Create New User"
      >
        <form onSubmit={createForm.onSubmit(handleCreateUser)}>
          <Stack>
            <TextInput
              label="Name"
              placeholder="John Doe"
              required
              {...createForm.getInputProps('name')}
            />
            <TextInput
              label="Email"
              placeholder="user@example.com"
              required
              {...createForm.getInputProps('email')}
            />
            <TextInput
              label="Password"
              type="password"
              placeholder="Enter password"
              required
              {...createForm.getInputProps('password')}
            />
            <Select
              label="Role"
              data={[
                { value: 'user', label: 'User' },
                { value: 'admin', label: 'Admin' },
              ]}
              {...createForm.getInputProps('role')}
            />
            <Group justify="flex-end" mt="md">
              <Button variant="subtle" onClick={closeCreateModal}>
                Cancel
              </Button>
              <Button type="submit" loading={creating}>
                Create User
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <Modal
        opened={twoFAModalOpened}
        onClose={close2FAModal}
        title="2FA Management"
        size="lg"
      >
        <Stack>
          {selectedUser && (
            <>
              <Alert icon={<IconInfoCircle size={16} />} color="blue">
                <Text size="sm">
                  <strong>User:</strong> {selectedUser.name} ({selectedUser.email})
                </Text>
              </Alert>

              {loading2FA ? (
                <Center p="xl">
                  <Loader size="md" />
                </Center>
              ) : recoveryStatus ? (
                <>
                  <Paper p="md" withBorder>
                    <Stack gap="sm">
                      <Group justify="space-between">
                        <Text fw={500}>2FA Status</Text>
                        <Badge color={recoveryStatus.two_factor_enabled ? 'green' : 'gray'}>
                          {recoveryStatus.two_factor_enabled ? 'Enabled' : 'Disabled'}
                        </Badge>
                      </Group>

                      {recoveryStatus.two_factor_enabled && (
                        <>
                          <Divider />
                          <Group justify="space-between">
                            <Text size="sm">Total Recovery Codes</Text>
                            <Text fw={500}>{recoveryStatus.total_codes}</Text>
                          </Group>
                          <Group justify="space-between">
                            <Text size="sm">Unused Codes</Text>
                            <Badge color={recoveryStatus.unused_codes > 0 ? 'green' : 'red'}>
                              {recoveryStatus.unused_codes}
                            </Badge>
                          </Group>
                          <Group justify="space-between">
                            <Text size="sm">Used Codes</Text>
                            <Text>{recoveryStatus.used_codes}</Text>
                          </Group>
                          {recoveryStatus.days_until_expiration !== null && (
                            <>
                              <Divider />
                              <Group justify="space-between">
                                <Text size="sm">Days Until Expiration</Text>
                                <Badge
                                  color={
                                    recoveryStatus.days_until_expiration > 30
                                      ? 'green'
                                      : recoveryStatus.days_until_expiration > 7
                                      ? 'yellow'
                                      : 'red'
                                  }
                                >
                                  {recoveryStatus.days_until_expiration} days
                                </Badge>
                              </Group>
                            </>
                          )}
                        </>
                      )}
                    </Stack>
                  </Paper>

                  {recoveryStatus.two_factor_enabled && (
                    <Alert icon={<IconAlertCircle size={16} />} color="orange">
                      <Text size="sm">
                        <strong>Warning:</strong> Resetting 2FA will disable it and delete all recovery codes.
                        The user will need to set up 2FA again on their next login.
                      </Text>
                    </Alert>
                  )}

                  <Group justify="flex-end" mt="md">
                    <Button variant="subtle" onClick={close2FAModal}>
                      Close
                    </Button>
                    {recoveryStatus.two_factor_enabled && (
                      <Button
                        color="red"
                        onClick={handleReset2FA}
                        loading={resetting2FA}
                        leftSection={<IconShield size={16} />}
                      >
                        Reset 2FA
                      </Button>
                    )}
                  </Group>
                </>
              ) : (
                <Alert color="red">
                  <Text size="sm">Failed to load 2FA status</Text>
                </Alert>
              )}
            </>
          )}
        </Stack>
      </Modal>
    </div>
  );
}


```


---

## FILE: `frontend/src/pages/admin/SecurityDashboardHelpModal.tsx`

```tsx
import { Modal, Stack, Text, Title, List, Divider, Code } from '@mantine/core';

type Props = {
  opened: boolean;
  onClose: () => void;
};

/**
 * Explains how Security overview metrics relate to each other so admins do not confuse
 * "total in range" with "rolling 24h live" or expect charts to ignore filters.
 */
export function SecurityDashboardHelpModal({ opened, onClose }: Props) {
  return (
    <Modal opened={opened} onClose={onClose} title={<Title order={4}>How to read this dashboard</Title>} size="lg">
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Audit data comes from the <Code>audit_logs</Code> table. Numbers only match when you know
          which time window each card uses.
        </Text>

        <Title order={5}>Why numbers change when you refresh or come back</Title>
        <Text size="sm">
          Each refresh asks the server for <strong>current</strong> data. The database can have new
          rows (logins, audits). The <strong>rolling 24h</strong> window also moves with server time,
          so its count is supposed to change over minutes and hours — that is not a bug. Fixed date
          ranges (your pickers) only change when you change the dates or when new events appear inside
          that window. The header shows a <strong>statistics snapshot time (UTC)</strong> so you know
          exactly what moment the numbers describe.
        </Text>

        <Title order={5}>Two different clocks</Title>
        <List size="sm" spacing="xs">
          <List.Item>
            <strong>Total Events, Critical, Failed logins, Rate limits, …</strong> — When you set a{' '}
            <strong>start / end date</strong> on the Events tab (or use a card preset), these counts
            include only rows whose timestamp falls <em>inside that range</em> (sent to the API as
            UTC ISO strings).
          </List.Item>
          <List.Item>
            <strong>Rolling 24h (orange card)</strong> — Always counts rows from the last 24 hours
            using the <strong>server&apos;s current UTC time</strong>. It does <strong>not</strong>{' '}
            follow your date pickers. Use it to see &quot;what happened recently on the server&quot;
            even while you have a wider or different range selected for investigation.
          </List.Item>
        </List>

        <Title order={5}>Why clicking &quot;Last 24 Hours&quot; changes everything</Title>
        <Text size="sm">
          That preset sets <strong>start = now − 24 hours</strong> and <strong>end = now</strong>{' '}
          (exactly 24 hours, not &quot;yesterday this time&quot;). Then Total, Critical, charts, and
          pie all use <strong>that same window</strong>, so they line up. The orange{' '}
          <strong>Rolling 24h</strong> number may still differ slightly because it uses the
          server&apos;s &quot;now&quot; at request time, not your browser clock.
        </Text>

        <Title order={5}>Charts</Title>
        <Text size="sm">
          The <strong>timeline</strong> and <strong>events by type</strong> use the same rule: if a
          date range is active, they show that range; if not, the timeline defaults to the last 24h
          of server time.
        </Text>

        <Title order={5}>Clicking a card</Title>
        <List size="sm" spacing="xs">
          <List.Item>
            <strong>Total</strong> — Clears date filters (all time) and opens the Events list.
          </List.Item>
          <List.Item>
            <strong>Critical</strong> — Events tab, only &quot;critical&quot; action types.
          </List.Item>
          <List.Item>
            <strong>Last 24h preset</strong> — Sets the 24h range (see above), stays on Overview.
          </List.Item>
          <List.Item>
            <strong>Failed logins / rate limits / …</strong> — Events tab with that action filter.
          </List.Item>
        </List>

        <Divider />

        <Text size="xs" c="dimmed">
          Next steps for the standalone auth extraction: open{' '}
          <Code>docs/STANDALONE_AUTH_LADDER.md</Code> in the repository (not served by the dev
          server).
        </Text>
      </Stack>
    </Modal>
  );
}

```


---

## FILE: `backend/src/mail/templates/RecoveryCodeWarning-email.html`

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recovery Codes Expiring Soon</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #1E40AF 0%, #0D9488 100%);
            color: white;
            padding: 30px;
            text-align: center;
            border-radius: 8px 8px 0 0;
        }
        .content {
            background: #f9f9f9;
            padding: 30px;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 8px 8px;
        }
        .warning-box {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 6px;
            padding: 20px;
            margin: 20px 0;
        }
        .warning-box h2 {
            color: #856404;
            margin-top: 0;
        }
        .button {
            display: inline-block;
            background: linear-gradient(135deg, #1E40AF 0%, #0D9488 100%);
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
            font-weight: bold;
        }
        .footer {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }
        .days-remaining {
            font-size: 32px;
            font-weight: bold;
            color: #dc3545;
            text-align: center;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Recovery Codes Expiring Soon</h1>
    </div>
    <div class="content">
        <p>Hello {{username}},</p>
        
        <div class="warning-box">
            <h2>⚠️ Important Security Notice</h2>
            <p>Your 2FA recovery codes will expire soon!</p>
            <div class="days-remaining">{{days_remaining}} Days Remaining</div>
        </div>
        
        <p>This is a reminder that your recovery codes for two-factor authentication will expire in <strong>{{days_remaining}} days</strong>.</p>
        
        <p><strong>What are recovery codes?</strong><br>
        Recovery codes are backup codes that allow you to access your account if you lose access to your authenticator app.</p>
        
        <p><strong>What should you do?</strong></p>
        <ul>
            <li>Log in to your account and go to your Profile</li>
            <li>Navigate to the "Recovery Codes" section</li>
            <li>Click "Regenerate Codes" to create new recovery codes</li>
            <li>Save the new codes in a secure location (password manager, encrypted file, etc.)</li>
        </ul>
        
        <div style="text-align: center;">
            <a href="http://localhost:5173/profile" class="button">Manage Recovery Codes</a>
        </div>
        
        <p><strong>Security Tip:</strong> Never share your recovery codes with anyone. Store them securely and only use them when you cannot access your authenticator app.</p>
        
        <p>If you have any questions or concerns, please contact our support team.</p>
        
        <p>Stay secure,<br>
        The Toniebee Team</p>
    </div>
    <div class="footer">
        <p>This is an automated security notification. Please do not reply to this email.</p>
        <p>&copy; 2024 Toniebee. All rights reserved.</p>
    </div>
</body>
</html>


```


---

## FILE: `backend/src/mail/templates/RestPassword-email.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px;">
        <h2 style="color: #333333;">Reset Your Password</h2>
        <p style="color: #555555;">Hello, {{username}}!</p>
        <p style="color: #555555;">We received a request to reset your password. Please click the link below to set a new password:</p>
        <a href="{{reset_link}}" style="display: inline-block; padding: 10px 20px; font-size: 16px; color: #ffffff; background-color: #007bff; text-decoration: none; border-radius: 5px;">Reset Password</a>
        <p style="color: #555555;">If you did not request a password reset, please ignore this email.</p>
        <p style="color: #555555;">This link will expire in 1 hour .</p>
        <p style="color: #555555;">Best regards,</p>
        <p style="color: #555555;">The Application Team</p>
    </div>
</body>
</html>
```


---

## FILE: `backend/src/mail/templates/Verification-email.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px;">
        <h2 style="color: #333333;">Email Verification</h2>
        <p style="color: #555555;">Hello, {{username}}!</p>
        <p style="color: #555555;">Thank you for registering at our application. Please click the link below to verify your email address:</p>
        <a href="{{verification_link}}" style="display: inline-block; padding: 10px 20px; font-size: 16px; color: #ffffff; background-color: #007bff; text-decoration: none; border-radius: 5px;">Verify Email</a>
        <p style="color: #555555;">If you did not register, please ignore this email.</p>
        <p style="color: #555555;">Best regards,</p>
        <p style="color: #555555;">The Application Team</p>
    </div>
</body>
</html>
```


---

## FILE: `backend/src/mail/templates/Welcome-email.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome Email</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 8px;">
        <h2 style="color: #333333;">Welcome to Our Application!</h2>
        <p style="color: #555555;">Hello, {{username}}!</p>
        <p style="color: #555555;">Thank you for registering at our application. We’re excited to have you on board.</p>
        <p style="color: #555555;">If you have any questions, feel free to reply to this email or visit our support page.</p>
        <p style="color: #555555;">Best regards,</p>
        <p style="color: #555555;">The Application Team</p>
    </div>
</body>
</html>
```


---

## FILE: `backend/src/mail/mod.rs`

```rust
pub mod mails;
pub mod sendmail;

```


---

## FILE: `backend/src/mail/mails.rs`

```rust
use super::sendmail::send_email;

pub async fn send_verification_email(
    to_email: &str,
    username: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let subject = "Email Verification";
    let template_path = "src/mail/templates/Verification-email.html";
    let base_url = "http://localhost:8000/api/auth/verify";
    let verification_link = create_verification_link(base_url, token);
    let placeholders = vec![
        ("{{username}}".to_string(), username.to_string()),
        ("{{verification_link}}".to_string(), verification_link),
    ];

    send_email(to_email, subject, template_path, &placeholders).await
}

fn create_verification_link(base_url: &str, token: &str) -> String {
    format!("{}?token={}", base_url, token)
}

pub async fn send_welcome_email(
    to_email: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let subject = "Welcome to Application";
    let template_path = "src/mail/templates/Welcome-email.html";
    let placeholders = vec![("{{username}}".to_string(), username.to_string())];

    send_email(to_email, subject, template_path, &placeholders).await
}

pub async fn send_forget_password_email(
    to_email: &str,
    reset_link: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let subject = "Reset your Password";
    let template_path = "src/mail/templates/RestPassword-email.html";
    let placeholders = vec![
        ("{{username}}".to_string(), username.to_string()),
        ("{{reset_link}}".to_string(), reset_link.to_string()),
    ];

    send_email(to_email, subject, template_path, &placeholders).await
}

```


---

## FILE: `backend/src/mail/sendmail.rs`

```rust
use lettre::{
    message::{header, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use std::{env, fs};

pub async fn send_email(
    to_email: &str,
    subject: &str,
    template_path: &str,
    placeholders: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    // In development, use MailHog (no auth, no TLS)
    // In production, use authenticated SMTP with TLS
    let is_dev = std::env::var("RUST_ENV").unwrap_or_default() != "production";
    
    // Get SMTP settings with defaults for MailHog
    let smtp_server = if is_dev {
        env::var("SMTP_SERVER").unwrap_or_else(|_| "127.0.0.1".to_string())
    } else {
        env::var("SMTP_SERVER")?
    };
    
    let smtp_port: u16 = if is_dev {
        env::var("SMTP_PORT")
            .unwrap_or_else(|_| "1025".to_string())
            .parse()
            .unwrap_or(1025)
    } else {
        env::var("SMTP_PORT")?.parse()?
    };
    
    let is_mailhog = smtp_server == "127.0.0.1" || smtp_server == "localhost";
    
    // Only require username/password for real SMTP (not MailHog)
    let smtp_username = if is_dev && is_mailhog {
        env::var("SMTP_USERNAME").unwrap_or_else(|_| "dev@localhost".to_string())
    } else {
        env::var("SMTP_USERNAME")?
    };
    
    let smtp_password = if is_dev && is_mailhog {
        env::var("SMTP_PASSWORD").unwrap_or_else(|_| "".to_string())
    } else {
        env::var("SMTP_PASSWORD")?
    };

    let mut html_template = fs::read_to_string(template_path)?;

    for (key, value) in placeholders {
        html_template = html_template.replace(key, value)
    }

    let email = Message::builder()
        .from(smtp_username.parse()?)
        .to(to_email.parse()?)
        .subject(subject)
        .header(header::ContentType::TEXT_HTML)
        .singlepart(
            SinglePart::builder()
                .header(header::ContentType::TEXT_HTML)
                .body(html_template),
        )?;
    
    let mailer = if is_dev && is_mailhog {
        // MailHog: no authentication, no TLS
        SmtpTransport::builder_dangerous(smtp_server)
            .port(smtp_port)
            .build()
    } else {
        // Production SMTP: use authentication and TLS
        let creds = Credentials::new(smtp_username.clone(), smtp_password.clone());
        SmtpTransport::starttls_relay(&smtp_server)?
            .credentials(creds)
            .port(smtp_port)
            .build()
    };

    let result = mailer.send(&email);

    match result {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => println!("Failed to send email: {:?}", e),
    }

    Ok(())
}

```
