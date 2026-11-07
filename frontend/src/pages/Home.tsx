import { Link } from 'react-router-dom'
import { Box, Button, Group, Paper, SimpleGrid, Stack, Text, ThemeIcon, Title } from '@mantine/core'
import { IconArrowRight, IconHeartHandshake, IconShieldHeart, IconUmbrella } from '@tabler/icons-react'
import { business } from '@/content/business'
import { services } from '@/content/services'
import { Fact } from '@/components/Fact'
import { BookBand, Section, useHead } from '@/components/Page'

const ICONS = { life: IconShieldHeart, critical_illness: IconHeartHandshake, disability: IconUmbrella }

export function Home() {
  useHead('', 'Life, critical illness and disability insurance, explained in plain language — and a consultation with a licensed advisor when you’re ready.')
  return (
    <>
      <section className="tb-hero">
        <div className="tb-container">
          <SimpleGrid cols={{ base: 1, md: 2 }} spacing={48} style={{ alignItems: 'center' }}>
            <Stack gap="lg">
              <Text className="tb-eyebrow">Life · Critical illness · Disability</Text>
              {/* The owner's own headline, from her original concept. */}
              <Title order={1}>Protect what matters most</Title>
              <Text className="tb-lead">
                Insurance that looks after the people who count on you — explained simply, chosen with you, and never
                rushed.
              </Text>
              <Group gap="sm">
                <Button component={Link} to="/book" color="orange" size="lg">
                  Book a consultation
                </Button>
                <Button component="a" href="#cover" variant="default" size="lg">
                  See the options
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                <Fact field="consultationFee" />
              </Text>
            </Stack>
            <HeroArt />
          </SimpleGrid>
        </div>
      </section>

      <Section id="cover">
        <Stack gap="xs" mb="xl" maw={680}>
          <Text className="tb-eyebrow">What we can help with</Text>
          <Title order={2}>Three ways to protect your family’s future</Title>
        </Stack>
        <SimpleGrid cols={{ base: 1, sm: 2, md: 3 }} spacing="lg">
          {services.map((s) => {
            const Icon = ICONS[s.interest]
            return (
              <Paper key={s.slug} component={Link} to={`/${s.slug}`} p="xl" className="tb-card">
                <Stack gap="md" h="100%">
                  <ThemeIcon size={48} radius="md" variant="light" color="navy">
                    <Icon size={26} />
                  </ThemeIcon>
                  <Title order={3}>{s.title}</Title>
                  <Text c="dimmed" style={{ flex: 1 }}>
                    {s.short}
                  </Text>
                  <Group gap={4} c="navy.7" fw={600}>
                    Learn more <IconArrowRight size={16} />
                  </Group>
                </Stack>
              </Paper>
            )
          })}
        </SimpleGrid>
      </Section>

      <Section soft>
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing={48}>
          <Stack gap="xs">
            <Text className="tb-eyebrow">How it works</Text>
            <Title order={2}>Simple, from the first conversation</Title>
            <Text className="tb-lead">
              You don’t need to know the jargon. Tell us about your family and your plans, and we’ll explain your
              options in plain words.
            </Text>
          </Stack>
          <Stack gap="lg">
            {[
              ['Tell us about you', 'Send a short request with the best way and time to reach you. No health questions online.'],
              ['Talk it through', 'We look at who depends on you, what you already have, and what fits your budget.'],
              ['Decide in your own time', 'You get clear options and answers to your questions. You choose when — and whether — to apply.'],
            ].map(([title, text], i) => (
              <Group key={title} align="flex-start" wrap="nowrap" gap="md">
                <span className="tb-step" aria-hidden="true">
                  {i + 1}
                </span>
                <Box>
                  <Text fw={700} fz="lg">
                    {title}
                  </Text>
                  <Text c="dimmed">{text}</Text>
                </Box>
              </Group>
            ))}
          </Stack>
        </SimpleGrid>
      </Section>

      <Section>
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing={48} style={{ alignItems: 'center' }}>
          <Stack gap="xs">
            <Text className="tb-eyebrow">Licensed and accountable</Text>
            <Title order={2}>Know who you’re talking to</Title>
            <Text className="tb-lead">
              Insurance advisors in Canada are licensed by the province they work in. You can always check a licence
              yourself, and ask which insurers an advisor represents and how they’re paid.
            </Text>
            <Button component={Link} to="/disclosure" variant="default" w="fit-content" mt="xs">
              Licensing &amp; disclosure
            </Button>
          </Stack>
          <Paper withBorder p="xl">
            <Stack gap="sm">
              <Text fw={700}>{business.tradingName}</Text>
              <Text size="sm">
                <b>Advisor:</b> <Fact field="ownerName" /> — <Fact field="ownerTitle" />
              </Text>
              <Text size="sm">
                <b>Licensed in:</b> <Fact field="provinces">{(p) => p.join(', ')}</Fact>
              </Text>
              <Text size="sm">
                <b>Works through:</b> <Fact field="agency" />
              </Text>
              <Text size="sm">
                <b>Represents:</b> <Fact field="insurers">{(list) => list.join(', ')}</Fact>
              </Text>
            </Stack>
          </Paper>
        </SimpleGrid>
      </Section>

      <BookBand />
    </>
  )
}

/** A calm illustration: a home under a shield. Decorative only. */
function HeroArt() {
  return (
    <Box className="tb-hero__art" visibleFrom="md" aria-hidden="true">
      <svg viewBox="0 0 440 380" width="100%" role="presentation">
        <defs>
          <linearGradient id="tb-sky" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#EEF3FF" />
            <stop offset="1" stopColor="#E8FBF8" />
          </linearGradient>
          <linearGradient id="tb-shield" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#2F5FD0" />
            <stop offset="1" stopColor="#14296C" />
          </linearGradient>
        </defs>
        <rect x="20" y="30" width="400" height="330" rx="36" fill="url(#tb-sky)" />
        <path d="M220 50 100 92v84c0 77 51 137 120 158 69-21 120-81 120-158V92L220 50Z" fill="url(#tb-shield)" opacity="0.95" />
        <path d="M220 86 136 116v62c0 55 36 98 84 114 48-16 84-59 84-114v-62l-84-30Z" fill="#fff" opacity="0.1" />
        <path d="M160 214l60-50 60 50v62a8 8 0 0 1-8 8h-104a8 8 0 0 1-8-8v-62Z" fill="#fff" />
        <path d="M148 222l72-60 72 60" fill="none" stroke="#0D9488" strokeWidth="10" strokeLinecap="round" strokeLinejoin="round" />
        <rect x="206" y="236" width="28" height="48" rx="4" fill="#0D9488" />
        <circle cx="120" cy="300" r="14" fill="#FE9439" />
        <rect x="108" y="316" width="24" height="30" rx="10" fill="#FE9439" />
        <circle cx="330" cy="296" r="16" fill="#0D9488" />
        <rect x="316" y="314" width="28" height="34" rx="12" fill="#0D9488" />
        <circle cx="356" cy="314" r="10" fill="#FE9439" />
        <rect x="348" y="326" width="18" height="22" rx="8" fill="#FE9439" />
      </svg>
    </Box>
  )
}
