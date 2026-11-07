import { Link } from 'react-router-dom'
import { Anchor, Grid, Paper, Stack, Text, Title } from '@mantine/core'
import { business } from '@/content/business'
import { Fact, Pending } from '@/components/Fact'
import { BookBand, PageHeader, Section, useHead } from '@/components/Page'

export function About() {
  useHead('About', `About ${business.tradingName} and the advisor behind it.`)
  return (
    <>
      <PageHeader eyebrow="About" title={`About ${business.tradingName}`} />
      <Section>
        <Grid gap={48}>
          <Grid.Col span={{ base: 12, md: 4 }}>
            <Paper withBorder p="lg" ta="center">
              {business.photo ? (
                <img
                  src={business.photo}
                  alt={business.ownerName ?? ''}
                  style={{ borderRadius: 16, width: '100%', aspectRatio: '4 / 5', objectFit: 'cover' }}
                />
              ) : (
                <Stack gap="xs" py="xl">
                  <Pending field="photo" />
                </Stack>
              )}
              <Text fw={700} mt="md">
                <Fact field="ownerName" />
              </Text>
              <Text size="sm" c="dimmed">
                <Fact field="ownerTitle" />
              </Text>
            </Paper>
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 8 }}>
            <Stack gap="md" className="tb-prose">
              {business.bio ? (
                business.bio.map((p) => (
                  <Text key={p} lh={1.7} fz="lg">
                    {p}
                  </Text>
                ))
              ) : (
                <Text fz="lg">
                  <Pending field="bio" />
                </Text>
              )}
              <Title order={2} fz="h3" mt="lg">
                Licensing
              </Title>
              <Text>
                Licensed in: <Fact field="provinces">{(p) => p.join(', ')}</Fact>. Full details, including the insurers
                represented and how the advisor is paid, are on the{' '}
                <Anchor component={Link} to="/disclosure" inherit>
                  licensing &amp; disclosure
                </Anchor> page.
              </Text>
            </Stack>
          </Grid.Col>
        </Grid>
      </Section>
      <BookBand />
    </>
  )
}
