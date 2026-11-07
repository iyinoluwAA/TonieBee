// Small building blocks shared by the pages: the page title (and the browser tab's),
// a section, and the closing "book a consultation" band.

import { useEffect, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Button, Group, Stack, Text, Title } from '@mantine/core'
import { business } from '@/content/business'

/** Sets the browser tab's title and the page's description (for search results). */
export function useHead(title: string, description?: string) {
  useEffect(() => {
    document.title = title ? `${title} — ${business.tradingName}` : `${business.tradingName} — life, critical illness and disability insurance`
    if (description) {
      document.querySelector('meta[name="description"]')?.setAttribute('content', description)
    }
  }, [title, description])
}

export function PageHeader({ eyebrow, title, lead }: { eyebrow?: string; title: string; lead?: ReactNode }) {
  return (
    <div className="tb-hero tb-hero--compact">
      <div className="tb-container">
        <Stack gap="xs" maw={760}>
          {eyebrow && <Text className="tb-eyebrow">{eyebrow}</Text>}
          <Title order={1} className="tb-page-title">
            {title}
          </Title>
          {lead && <Text className="tb-lead">{lead}</Text>}
        </Stack>
      </div>
    </div>
  )
}

export function Section({ children, soft, id }: { children: ReactNode; soft?: boolean; id?: string }) {
  return (
    <section id={id} className={soft ? 'tb-section tb-section--soft' : 'tb-section'}>
      <div className="tb-container">{children}</div>
    </section>
  )
}

export function BookBand({ title = 'Talk it through, with no pressure', text }: { title?: string; text?: string }) {
  return (
    <Section>
      <div className="tb-band">
        <Group justify="space-between" align="center" gap="lg">
          <Stack gap={6} maw={620}>
            <Title order={2} c="white">
              {title}
            </Title>
            <Text c="#dbe4fb" fz="lg">
              {text ?? 'Tell us a little about you and the best time to reach you. We’ll get back to you to set up a conversation.'}
            </Text>
          </Stack>
          <Button component={Link} to="/book" color="orange" size="lg">
            Book a consultation
          </Button>
        </Group>
      </div>
    </Section>
  )
}
