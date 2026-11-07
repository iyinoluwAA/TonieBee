// The admin dashboard (/admin). Loaded only when someone opens /admin, so visitors never
// download it. Phone-first: the owner works through requests from her phone.

import { useEffect, useState, type ReactNode } from 'react'
import { Link, Navigate, NavLink, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { Alert, Anchor, Box, Button, Center, Group, Loader, Menu, Stack, Text, UnstyledButton } from '@mantine/core'
import { IconChevronDown, IconExternalLink, IconLogout, IconUserCircle } from '@tabler/icons-react'
import { adminApi, AdminApiError, listenForWake } from './api'
import { SessionContext, useAdminSession, type Session } from './session'
import { SignIn } from './SignIn'
import { Welcome } from './Welcome'
import { Overview } from './Overview'
import { Requests } from './Requests'
import { RequestPage } from './RequestPage'
import { Activity } from './Activity'
import { Account } from './Account'

export default function AdminApp() {
  const [session, setSession] = useState<Session>({ state: 'checking' })
  const [error, setError] = useState<string | null>(null)
  const [waking, setWaking] = useState(false)
  useAdminHead()

  const refresh = async () => {
    try {
      const me = await adminApi.me()
      setSession({ state: 'signedIn', email: me.email })
      setError(null)
    } catch (e) {
      if (e instanceof AdminApiError && (e.status === 401 || e.status === 403)) {
        setSession({ state: 'signedOut' })
        setError(null)
      } else {
        setError(e instanceof Error ? e.message : 'Something went wrong.')
      }
    }
  }

  useEffect(() => {
    listenForWake(setWaking)
    void refresh()
  }, [])

  return (
    <SessionContext.Provider value={{ session, refresh }}>
      <Box className="tb-admin" mih="100vh">
        {waking && (
          <Alert color="navy" variant="light" radius={0} p="xs" role="status">
            <Text size="sm">Waking the server — it sleeps when nobody’s used it for a while. One moment…</Text>
          </Alert>
        )}
        {error ? (
          <Center mih="60vh" p="md">
            <Stack align="center" gap="sm" maw={420}>
              <Text fw={600}>The dashboard can’t load</Text>
              <Text c="dimmed" ta="center">
                {error}
              </Text>
              <Button onClick={() => void refresh()}>Try again</Button>
            </Stack>
          </Center>
        ) : session.state === 'checking' ? (
          <Center mih="60vh">
            <Loader color="navy" />
          </Center>
        ) : (
          <Routes>
            {/* Paths are relative to /admin (this app is mounted at /admin/*). */}
            <Route path="sign-in" element={<SignIn />} />
            {/* An invite link's page: open to whoever holds the link (signed out). */}
            <Route path="welcome" element={<Welcome />} />
            <Route index element={<Guarded><Overview /></Guarded>} />
            <Route path="requests" element={<Guarded><Requests /></Guarded>} />
            <Route path="requests/:id" element={<Guarded><RequestPage /></Guarded>} />
            <Route path="activity" element={<Guarded><Activity /></Guarded>} />
            <Route path="account" element={<Guarded><Account /></Guarded>} />
            <Route path="*" element={<Navigate to="/admin" replace />} />
          </Routes>
        )}
      </Box>
    </SessionContext.Provider>
  )
}

/** Signed-in pages; anyone else goes to sign-in (and comes back after). */
function Guarded({ children }: { children: ReactNode }) {
  const { session } = useAdminSession()
  const location = useLocation()
  if (session.state !== 'signedIn') {
    const next = encodeURIComponent(location.pathname + location.search)
    return <Navigate to={`/admin/sign-in?next=${next}`} replace />
  }
  return (
    <>
      <TopBar email={session.email} />
      <Box component="main" className="tb-admin__page">
        {children}
      </Box>
    </>
  )
}

function TopBar({ email }: { email: string }) {
  const { refresh } = useAdminSession()
  const navigate = useNavigate()
  const signOut = async () => {
    try {
      await adminApi.signOut()
    } finally {
      await refresh()
      navigate('/admin/sign-in', { replace: true })
    }
  }
  return (
    <Box component="header" className="tb-admin__bar">
      <Group justify="space-between" wrap="nowrap" gap="sm">
        <Group gap="md" wrap="nowrap">
          <Anchor component={Link} to="/admin" underline="never" className="tb-admin__brand">
            Toniebee <span>Admin</span>
          </Anchor>
          <Group gap={2} component="nav" aria-label="Dashboard" wrap="nowrap">
            <NavLink to="/admin/requests" className="tb-admin__nav">
              Requests
            </NavLink>
            <NavLink to="/admin/activity" className="tb-admin__nav">
              Activity
            </NavLink>
          </Group>
        </Group>
        <Menu position="bottom-end" width={240}>
          <Menu.Target>
            <UnstyledButton className="tb-admin__account" aria-label="Your account">
              <Text size="sm" truncate maw={140} visibleFrom="xs">
                {email}
              </Text>
              <IconChevronDown size={16} />
            </UnstyledButton>
          </Menu.Target>
          <Menu.Dropdown>
            <Menu.Label>{email}</Menu.Label>
            <Menu.Item leftSection={<IconUserCircle size={16} />} component={Link} to="/admin/account">
              Your account &amp; admins
            </Menu.Item>
            <Menu.Item leftSection={<IconExternalLink size={16} />} component="a" href="/" target="_blank" rel="noreferrer">
              Open the website
            </Menu.Item>
            <Menu.Item leftSection={<IconLogout size={16} />} onClick={() => void signOut()}>
              Sign out
            </Menu.Item>
          </Menu.Dropdown>
        </Menu>
      </Group>
    </Box>
  )
}

/** Title, and keep the dashboard out of search engines. */
function useAdminHead() {
  useEffect(() => {
    const previousTitle = document.title
    document.title = 'Toniebee Admin'
    const robots = document.createElement('meta')
    robots.name = 'robots'
    robots.content = 'noindex, nofollow'
    document.head.appendChild(robots)
    return () => {
      document.title = previousTitle
      robots.remove()
    }
  }, [])
}
