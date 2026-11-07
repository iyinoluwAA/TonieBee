import { Link } from 'react-router-dom'
import { Alert, Button, Grid, List, Paper, Stack, Text, ThemeIcon, Title } from '@mantine/core'
import { IconInfoCircle, IconQuestionMark } from '@tabler/icons-react'
import type { Service } from '@/content/services'
import { BookBand, PageHeader, Section, useHead } from '@/components/Page'

export function ServicePage({ service }: { service: Service }) {
  useHead(service.title, service.short)
  return (
    <>
      <PageHeader eyebrow="Cover" title={service.title} lead={service.intro} />
      <Section>
        <Grid gap={48}>
          <Grid.Col span={{ base: 12, md: 7 }}>
            <Stack gap="xl" className="tb-prose">
              {service.sections.map((section) => (
                <div key={section.heading}>
                  <Title order={2} fz="h3" mb="sm">
                    {section.heading}
                  </Title>
                  {section.body.map((p) => (
                    <Text key={p} mb="sm" lh={1.7}>
                      {p}
                    </Text>
                  ))}
                </div>
              ))}
              <Alert variant="light" color="navy" icon={<IconInfoCircle />}>
                This is general information. What a policy covers, costs and pays depends on the insurer and the
                policy itself — we’ll go through the details with you.
              </Alert>
            </Stack>
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 5 }}>
            <Paper withBorder p="xl" style={{ position: 'sticky', top: 96 }}>
              <Stack gap="md">
                <ThemeIcon size={40} radius="md" variant="light" color="teal">
                  <IconQuestionMark size={22} />
                </ThemeIcon>
                <Title order={2} fz="h3">
                  Good questions to ask
                </Title>
                <List spacing="sm">
                  {service.questions.map((q) => (
                    <List.Item key={q}>{q}</List.Item>
                  ))}
                </List>
                <Button component={Link} to={`/book?about=${service.interest}`} color="orange" fullWidth mt="xs">
                  Talk about {service.title.toLowerCase()}
                </Button>
              </Stack>
            </Paper>
          </Grid.Col>
        </Grid>
      </Section>
      <BookBand />
    </>
  )
}
