// Disclosure, privacy, terms and accessibility. DRAFTS written against Canadian rules
// as researched on 2026-11-06 (PIPEDA; provincial insurance regulators' disclosure
// rules; CCIR/CISRO fair treatment guidance; WCAG 2.2) — to be reviewed by the owner,
// and ideally her agency's compliance team, before launch. Every business fact comes
// from content/business.ts.

import { Link } from 'react-router-dom'
import { Alert, Anchor, List, Stack, Table, Text, Title } from '@mantine/core'
import { business, PROVINCE_NAMES } from '@/content/business'
import { Fact, Pending } from '@/components/Fact'
import { PageHeader, Section, useHead } from '@/components/Page'

const UPDATED = '7 November 2026'

function Draft() {
  return (
    <Alert color="orange" variant="light">
      Draft — to be reviewed before the website goes live.
    </Alert>
  )
}

export function Disclosure() {
  useHead('Licensing & disclosure', 'Who the advisor is, where they are licensed, which insurers they represent and how they are paid.')
  return (
    <>
      <PageHeader eyebrow="Licensing & disclosure" title="Who you’re dealing with" lead="What the law says you have a right to know before you buy insurance." />
      <Section>
        <Stack gap="xl" maw={820} className="tb-prose">
          <Draft />
          <div>
            <Title order={2} fz="h3">The advisor</Title>
            <Text>
              <Fact field="ownerName" />, <Fact field="ownerTitle" />, trading as {business.tradingName} (
              <Fact field="legalName" />).
            </Text>
          </div>
          <div>
            <Title order={2} fz="h3">Licences</Title>
            {business.licences ? (
              <Table withTableBorder striped>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Province</Table.Th>
                    <Table.Th>Licence</Table.Th>
                    <Table.Th>Number</Table.Th>
                    <Table.Th>Check it</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {business.licences.map((l) => (
                    <Table.Tr key={l.number}>
                      <Table.Td>{PROVINCE_NAMES[l.province] ?? l.province}</Table.Td>
                      <Table.Td>{l.kind}</Table.Td>
                      <Table.Td>{l.number}</Table.Td>
                      <Table.Td>
                        <Anchor href={l.checkUrl} target="_blank" rel="noopener noreferrer">
                          {l.regulator}
                        </Anchor>
                      </Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            ) : (
              <Text>
                <Pending field="licences" />
              </Text>
            )}
            <Text size="sm" c="dimmed" mt="xs">
              Insurance advisors in Canada are licensed by each province. You can check any licence on the provincial
              regulator’s public website.
            </Text>
          </div>
          <div>
            <Title order={2} fz="h3">Agency and insurers represented</Title>
            <Text>
              Works through: <Fact field="agency" />.
            </Text>
            <Text>Represents these insurance companies:</Text>
            {business.insurers ? (
              <List>{business.insurers.map((i) => <List.Item key={i}>{i}</List.Item>)}</List>
            ) : (
              <Text>
                <Pending field="insurers" />
              </Text>
            )}
          </div>
          <div>
            <Title order={2} fz="h3">How the advisor is paid</Title>
            <Text>
              <Fact field="compensation" />
            </Text>
          </div>
          <div>
            <Title order={2} fz="h3">Conflicts of interest</Title>
            <Text>
              <Fact field="conflicts" />
            </Text>
            <Text>Any conflict that affects a recommendation to you will be explained to you in writing before you decide.</Text>
          </div>
          <div>
            <Title order={2} fz="h3">If you have a complaint</Title>
            <Text>
              <Fact field="complaints" />
            </Text>
          </div>
        </Stack>
      </Section>
    </>
  )
}

export function Privacy() {
  useHead('Privacy policy', `How ${business.tradingName} collects, uses and protects your personal information.`)
  const name = business.tradingName
  return (
    <>
      <PageHeader eyebrow="Privacy" title="Privacy policy" lead={`How ${name} collects, uses and protects your personal information. Last updated ${UPDATED}.`} />
      <Section>
        <Stack gap="lg" maw={820} className="tb-prose">
          <Draft />
          <Text>
            {name} follows Canada’s private-sector privacy law, the Personal Information Protection and Electronic
            Documents Act (PIPEDA), and any provincial privacy law that applies.
          </Text>

          <Title order={2} fz="h3">Who is responsible</Title>
          <Text>
            The person accountable for privacy at {name} is <Fact field="ownerName" />. Contact:{' '}
            <Anchor href={`mailto:${business.email}`}>{business.email}</Anchor>.
          </Text>

          <Title order={2} fz="h3">What we collect, and why</Title>
          <List spacing="xs">
            <List.Item>
              <b>When you book a consultation:</b> your name, email, phone number (if you give it), province, what you’d
              like to talk about, the best time to reach you and any message you add — only so we can reply to your
              request. We record that you agreed, and when.
            </List.Item>
            <List.Item>
              <b>If you make an account:</b> your email address (and a name, if you add one), so you can sign in and see
              your requests.
            </List.Item>
            <List.Item>
              <b>To keep accounts safe:</b> the kind of browser you signed in with (for example “Chrome on Windows”) and,
              for staff sign-ins, the network (IP) address used.
            </List.Item>
          </List>
          <Text>
            The website never asks for health information, and we ask you not to put any in your message. If you decide
            to apply for insurance, the insurer collects what it needs through its own application.
          </Text>

          <Title order={2} fz="h3">What we don’t do</Title>
          <List spacing="xs">
            <List.Item>We don’t sell or rent your information, or share it for anyone else’s marketing.</List.Item>
            <List.Item>We don’t use advertising or tracking cookies, and no outside analytics service sees your visit.</List.Item>
            <List.Item>We don’t send newsletters or offers unless you separately ask for them.</List.Item>
          </List>

          <Title order={2} fz="h3">Cookies</Title>
          <Text>
            The website uses only the cookies it needs to work: one that keeps you signed in, one that remembers a
            browser you’ve signed in from (so strangers can’t lock you out), and short-lived ones during sign-in. They
            can’t be read by other websites.
          </Text>

          <Title order={2} fz="h3">Who else handles it</Title>
          <Text>
            To run the website, we use service providers for hosting, the database and sending email. They may only use
            your information to provide that service to us. Your information is stored in <Fact field="dataLocation" />,
            and may be subject to the laws of that country, including lawful access by its authorities.
          </Text>

          <Title order={2} fz="h3">How long we keep it</Title>
          <Text>
            <Fact field="retention" /> Sign-in records are deleted within a day; security records after about 13
            months. If you delete your account, the requests you sent while signed in are deleted with it.
          </Text>

          <Title order={2} fz="h3">How it’s protected</Title>
          <Text>
            Connections are encrypted. Staff sign in with a password and a code from their phone, and every time a
            request is opened is recorded. Account sign-in uses emailed links instead of passwords.
          </Text>

          <Title order={2} fz="h3">Your choices and rights</Title>
          <Text>
            You can ask to see the personal information we hold about you, ask us to correct it, or withdraw your consent
            and ask us to delete it — email <Anchor href={`mailto:${business.email}`}>{business.email}</Anchor>. You can
            delete your account yourself from <Anchor component={Link} to="/account">your account page</Anchor>. If
            something goes wrong with your information, we will tell you and, where the law requires, the Privacy
            Commissioner of Canada.
          </Text>
          <Text>
            If you’re not satisfied with our answer, you can complain to the{' '}
            <Anchor href="https://www.priv.gc.ca/en/report-a-concern/" target="_blank" rel="noopener noreferrer">
              Office of the Privacy Commissioner of Canada
            </Anchor>
            .
          </Text>
        </Stack>
      </Section>
    </>
  )
}

export function Terms() {
  useHead('Terms of use', `The terms for using the ${business.tradingName} website.`)
  return (
    <>
      <PageHeader eyebrow="Terms" title="Terms of use" lead={`Last updated ${UPDATED}.`} />
      <Section>
        <Stack gap="lg" maw={820} className="tb-prose">
          <Draft />
          <Title order={2} fz="h3">Information, not advice</Title>
          <Text>
            The articles and explanations on this website are general information about insurance in Canada. They aren’t
            advice for your situation, and they aren’t an offer of insurance. Advice comes from a conversation with a
            licensed advisor who knows your circumstances.
          </Text>
          <Title order={2} fz="h3">Insurance comes from insurers</Title>
          <Text>
            Insurance is provided by insurance companies. You’re only covered once an insurer accepts your application
            and issues a policy, and what you’re covered for is set out in that policy.
          </Text>
          <Title order={2} fz="h3">Where we can help</Title>
          <Text>
            We can only advise residents of the provinces where we’re licensed: <Fact field="provinces">{(p) => p.map((c) => PROVINCE_NAMES[c] ?? c).join(', ')}</Fact>.
          </Text>
          <Title order={2} fz="h3">Your account</Title>
          <Text>
            Keep access to your email safe: signing in uses links sent there. We’ll never ask for your sign-in code by
            phone, text or email.
          </Text>
          <Title order={2} fz="h3">Contact</Title>
          <Text>
            Questions about these terms: <Anchor href={`mailto:${business.email}`}>{business.email}</Anchor>.
          </Text>
        </Stack>
      </Section>
    </>
  )
}

export function Accessibility() {
  useHead('Accessibility', `Accessibility of the ${business.tradingName} website.`)
  return (
    <>
      <PageHeader eyebrow="Accessibility" title="Accessibility" lead="Everyone should be able to use this website." />
      <Section>
        <Stack gap="lg" maw={820} className="tb-prose">
          <Text>
            This website aims to meet the Web Content Accessibility Guidelines (WCAG) 2.2 at level AA: it works with a
            keyboard and screen readers, text can be zoomed, colours have enough contrast, and nothing relies on colour
            alone.
          </Text>
          <Text>
            If something doesn’t work for you, or you’d like information in another format, please tell us at{' '}
            <Anchor href={`mailto:${business.email}`}>{business.email}</Anchor>
            {business.phone ? ` or ${business.phone}` : ''} and we’ll help.
          </Text>
        </Stack>
      </Section>
    </>
  )
}

export function NotFound() {
  useHead('Page not found')
  return (
    <Section>
      <Stack gap="md" maw={560} mx="auto" ta="center" py="xl">
        <Title order={1}>We can’t find that page</Title>
        <Text c="dimmed">It may have moved. Try the home page, or book a consultation.</Text>
        <Text>
          <Anchor component={Link} to="/">
            Go to the home page
          </Anchor>
        </Text>
      </Stack>
    </Section>
  )
}
