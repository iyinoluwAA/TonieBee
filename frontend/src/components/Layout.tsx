import { useEffect, type ReactNode } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom'
import { Anchor, Box, Burger, Button, Divider, Drawer, Group, SimpleGrid, Stack, Text } from '@mantine/core'
import { useDisclosure } from '@mantine/hooks'
import { IconMail, IconPhone } from '@tabler/icons-react'
import { business, missingFields } from '@/content/business'
import { services } from '@/content/services'
import { useAuth } from '@/lib/AuthContext'
import { Fact } from './Fact'
import { Wordmark } from './Logo'

const NAV = [
  ...services.map((s) => ({ to: `/${s.slug}`, label: s.title.replace(' insurance', '') })),
  { to: '/about', label: 'About' },
  { to: '/faq', label: 'FAQ' },
]

export function Layout() {
  const [open, { toggle, close }] = useDisclosure(false)
  const location = useLocation()
  const { status } = useAuth()
  const missing = missingFields().length

  // A new page starts at the top, and the menu closes.
  useEffect(() => {
    if (!location.hash) window.scrollTo(0, 0)
    close()
  }, [location.pathname, location.hash, close])

  return (
    <>
      <a href="#main" className="tb-skip">
        Skip to content
      </a>
      {missing > 0 && (
        <div className="tb-preview-bar" role="note">
          Preview — {missing} {missing === 1 ? 'detail is' : 'details are'} still to be filled in (marked with a dashed
          box).
        </div>
      )}
      <header className="tb-header">
        <div className="tb-container tb-header__inner">
          <Wordmark />
          <Group gap={2} component="nav" aria-label="Main" className="tb-nav" visibleFrom="md" wrap="nowrap">
            {NAV.map((item) => (
              <NavLink key={item.to} to={item.to}>
                {item.label}
              </NavLink>
            ))}
          </Group>
          <Group gap="xs" wrap="nowrap">
            <Button component={Link} to="/account" variant="subtle" visibleFrom="sm">
              {status === 'signedIn' ? 'My account' : 'Sign in'}
            </Button>
            <Button component={Link} to="/book" color="orange" visibleFrom="xs">
              Book a consultation
            </Button>
            <Burger opened={open} onClick={toggle} hiddenFrom="md" aria-label="Open the menu" />
          </Group>
        </div>
      </header>
      <Drawer opened={open} onClose={close} position="right" size="xs" title={business.tradingName} hiddenFrom="md">
        <Stack gap={4} component="nav" aria-label="Menu" className="tb-nav">
          {NAV.map((item) => (
            <NavLink key={item.to} to={item.to}>
              {item.label}
            </NavLink>
          ))}
          <Divider my="sm" />
          <Button component={Link} to="/book" color="orange" fullWidth>
            Book a consultation
          </Button>
          <Button component={Link} to="/account" variant="default" fullWidth mt="xs">
            {status === 'signedIn' ? 'My account' : 'Sign in'}
          </Button>
        </Stack>
      </Drawer>
      <main id="main" tabIndex={-1}>
        <Outlet />
      </main>
      <Footer />
    </>
  )
}

function Footer() {
  const year = new Date().getFullYear()
  return (
    <footer className="tb-footer">
      <div className="tb-container">
        <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} spacing="xl">
          <Stack gap="xs">
            <Text fw={800} fz="lg" c="white">
              {business.tradingName}
            </Text>
            <Text size="sm">
              <Fact field="ownerName" />
              {', '}
              <Fact field="ownerTitle" />
            </Text>
            <Text size="sm">
              <Fact field="serviceArea" />
            </Text>
          </Stack>
          <Stack gap="xs">
            <Text fw={700} c="white">
              Cover
            </Text>
            {services.map((s) => (
              <Anchor key={s.slug} component={Link} to={`/${s.slug}`} size="sm">
                {s.title}
              </Anchor>
            ))}
          </Stack>
          <Stack gap="xs">
            <Text fw={700} c="white">
              Contact
            </Text>
            <FooterLine icon={<IconMail size={16} />}>
              <Anchor href={`mailto:${business.email}`} size="sm">
                {business.email}
              </Anchor>
            </FooterLine>
            <FooterLine icon={<IconPhone size={16} />}>
              <Fact field="phone">{(phone) => <Anchor href={`tel:${phone.replace(/[^\d+]/g, '')}`} size="sm">{phone}</Anchor>}</Fact>
            </FooterLine>
            <Text size="sm">
              <Fact field="hours" />
            </Text>
          </Stack>
          <Stack gap="xs">
            <Text fw={700} c="white">
              About this site
            </Text>
            <Anchor component={Link} to="/disclosure" size="sm">
              Licensing &amp; disclosure
            </Anchor>
            <Anchor component={Link} to="/privacy" size="sm">
              Privacy policy
            </Anchor>
            <Anchor component={Link} to="/terms" size="sm">
              Terms of use
            </Anchor>
            <Anchor component={Link} to="/accessibility" size="sm">
              Accessibility
            </Anchor>
          </Stack>
        </SimpleGrid>
        <Divider my="xl" color="rgba(255,255,255,0.12)" />
        <Stack gap={6}>
          <Text size="xs">
            The information on this website is general and isn’t advice for your situation. Insurance is provided by
            insurance companies; coverage depends on the policy issued.
          </Text>
          <Text size="xs">
            © {year} <Fact field="legalName" />. All rights reserved.
          </Text>
        </Stack>
      </div>
    </footer>
  )
}

function FooterLine({ icon, children }: { icon: ReactNode; children: ReactNode }) {
  return (
    <Group gap={8} wrap="nowrap" align="center">
      <Box c="#9fb3e6" style={{ display: 'flex' }}>
        {icon}
      </Box>
      {children}
    </Group>
  )
}
