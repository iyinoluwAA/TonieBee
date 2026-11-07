// "Book a consultation" — the one form on the site. It asks only what's needed to get
// back to someone (PIPEDA: limit collection), and never health details.

import { useEffect, useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  Alert,
  Anchor,
  Box,
  Button,
  Checkbox,
  Grid,
  Paper,
  Radio,
  Select,
  Stack,
  Text,
  Textarea,
  TextInput,
  Title,
} from '@mantine/core'
import { IconCircleCheck, IconLock } from '@tabler/icons-react'
import { business, PROVINCE_NAMES } from '@/content/business'
import { CONSENT_VERSION, consentText } from '@/content/consent'
import { Fact } from '@/components/Fact'
import { PageHeader, Section, useHead } from '@/components/Page'
import { requestsApi, problem, type Interest } from '@/lib/api'
import { useAuth } from '@/lib/AuthContext'
import { validate, type FormErrors, type FormValues } from '@/lib/requestForm'

const INTERESTS: { value: Interest; label: string }[] = [
  { value: 'life', label: 'Life insurance' },
  { value: 'critical_illness', label: 'Critical illness insurance' },
  { value: 'disability', label: 'Disability insurance' },
  { value: 'not_sure', label: 'I’m not sure yet' },
]

type BestTime = 'morning' | 'afternoon' | 'evening' | 'any'

export function Book() {
  useHead('Book a consultation', 'Ask for a conversation about life, critical illness or disability insurance.')
  const [params] = useSearchParams()
  const { user } = useAuth()
  const about = INTERESTS.find((i) => i.value === params.get('about'))?.value
  const [values, setValues] = useState<FormValues>({
    name: '',
    email: '',
    phone: '',
    province: business.provinces?.length === 1 ? business.provinces[0] : '',
    interests: about ? [about] : [],
    contactBy: 'phone',
    message: '',
    consent: false,
  })
  const [bestTime, setBestTime] = useState<BestTime>('any')
  const [website, setWebsite] = useState('') // the hidden field only bots fill in
  const [errors, setErrors] = useState<FormErrors>({})
  const [busy, setBusy] = useState(false)
  const [failure, setFailure] = useState<string | null>(null)
  const [sent, setSent] = useState(false)

  // Signed in: start from the account's details.
  useEffect(() => {
    if (user?.role === 'customer')
      setValues((v) => ({ ...v, email: v.email || user.email, name: v.name || user.name || '' }))
  }, [user])

  const provinces = useMemo(
    () =>
      (business.provinces ?? Object.keys(PROVINCE_NAMES)).map((code) => ({ value: code, label: PROVINCE_NAMES[code] ?? code })),
    [],
  )
  const set = <K extends keyof FormValues>(key: K, value: FormValues[K]) => {
    setValues((v) => ({ ...v, [key]: value }))
    if (errors[key]) setErrors((e) => ({ ...e, [key]: undefined }))
  }

  const submit = async () => {
    const found = validate(values, business.provinces)
    setErrors(found)
    setFailure(null)
    if (Object.keys(found).length > 0) {
      document.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus()
      return
    }
    setBusy(true)
    try {
      await requestsApi.send({
        ...values,
        interests: values.interests as Interest[],
        name: values.name.trim(),
        email: values.email.trim(),
        phone: values.phone.trim(),
        message: values.message.trim(),
        bestTime,
        consentVersion: CONSENT_VERSION,
        website,
      })
      setSent(true)
      window.scrollTo(0, 0)
    } catch (e) {
      setFailure(problem(e))
    } finally {
      setBusy(false)
    }
  }

  if (sent) {
    return (
      <Section>
        <Paper withBorder p="xl" maw={620} mx="auto" ta="center" role="status">
          <Stack gap="md" align="center">
            <IconCircleCheck size={56} color="var(--tb-teal)" aria-hidden="true" />
            <Title order={1} fz="h2">
              Thank you — your request is in
            </Title>
            <Text className="tb-lead">
              We’ll contact you by {values.contactBy === 'phone' ? 'phone' : 'email'} to find a time to talk.
            </Text>
            <Text size="sm" c="dimmed">
              Want to follow your request?{' '}
              <Anchor component={Link} to="/account">
                {user ? 'See it in your account' : 'Sign in with the same email'}
              </Anchor>
              .
            </Text>
            <Button component={Link} to="/" variant="default">
              Back to the home page
            </Button>
          </Stack>
        </Paper>
      </Section>
    )
  }

  return (
    <>
      <PageHeader
        eyebrow="Book a consultation"
        title="Let’s talk about what you need"
        lead="Tell us how to reach you and what you’d like to talk about. It takes about a minute."
      />
      <Section>
        <Grid gap={48}>
          <Grid.Col span={{ base: 12, md: 7 }}>
            <form
              noValidate
              onSubmit={(e) => {
                e.preventDefault()
                void submit()
              }}
            >
              <Stack gap="lg">
                <TextInput
                  label="Your name"
                  autoComplete="name"
                  required
                  maxLength={100}
                  value={values.name}
                  error={errors.name}
                  onChange={(e) => set('name', e.currentTarget.value)}
                />
                <Grid gap="md">
                  <Grid.Col span={{ base: 12, sm: 6 }}>
                    <TextInput
                      label="Email"
                      type="email"
                      autoComplete="email"
                      required
                      value={values.email}
                      error={errors.email}
                      onChange={(e) => set('email', e.currentTarget.value)}
                    />
                  </Grid.Col>
                  <Grid.Col span={{ base: 12, sm: 6 }}>
                    <TextInput
                      label="Phone"
                      type="tel"
                      autoComplete="tel"
                      description={values.contactBy === 'phone' ? 'Needed so we can call you' : 'Optional'}
                      maxLength={25}
                      value={values.phone}
                      error={errors.phone}
                      onChange={(e) => set('phone', e.currentTarget.value)}
                    />
                  </Grid.Col>
                </Grid>
                <Select
                  label="Province or territory you live in"
                  description={business.provinces ? 'We can only advise residents of these provinces.' : undefined}
                  placeholder="Choose one"
                  required
                  data={provinces}
                  value={values.province || null}
                  error={errors.province}
                  onChange={(value) => set('province', value ?? '')}
                  allowDeselect={false}
                  comboboxProps={{ withinPortal: true }}
                />
                <Checkbox.Group
                  label="What would you like to talk about?"
                  required
                  value={values.interests}
                  error={errors.interests}
                  onChange={(value) => set('interests', value)}
                >
                  <Stack gap="xs" mt="xs">
                    {INTERESTS.map((i) => (
                      <Checkbox key={i.value} value={i.value} label={i.label} />
                    ))}
                  </Stack>
                </Checkbox.Group>
                <Radio.Group
                  label="How should we contact you?"
                  value={values.contactBy}
                  onChange={(value) => set('contactBy', value as FormValues['contactBy'])}
                >
                  <Stack gap="xs" mt="xs">
                    <Radio value="phone" label="Call me" />
                    <Radio value="email" label="Email me" />
                  </Stack>
                </Radio.Group>
                <Select
                  label="Best time to reach you"
                  data={[
                    { value: 'any', label: 'Any time' },
                    { value: 'morning', label: 'Mornings' },
                    { value: 'afternoon', label: 'Afternoons' },
                    { value: 'evening', label: 'Evenings' },
                  ]}
                  value={bestTime}
                  onChange={(value) => setBestTime((value as BestTime | null) ?? 'any')}
                  allowDeselect={false}
                />
                <Textarea
                  label="Anything you’d like us to know? (optional)"
                  description="Please don’t include health details — we’ll ask what’s needed, privately, later."
                  autosize
                  minRows={3}
                  maxLength={1000}
                  value={values.message}
                  error={errors.message}
                  onChange={(e) => set('message', e.currentTarget.value)}
                />
                {/* Hidden from people (and screen readers); bots fill it in. */}
                <Box aria-hidden="true" style={{ position: 'absolute', left: '-10000px', width: 1, height: 1, overflow: 'hidden' }}>
                  <label>
                    Website
                    <input tabIndex={-1} autoComplete="off" value={website} onChange={(e) => setWebsite(e.currentTarget.value)} />
                  </label>
                </Box>
                <Checkbox
                  required
                  checked={values.consent}
                  error={errors.consent}
                  onChange={(e) => set('consent', e.currentTarget.checked)}
                  label={
                    <>
                      {consentText(business.tradingName)}{' '}
                      <Anchor component={Link} to="/privacy" inherit>
                        Read the Privacy Policy
                      </Anchor>
                      .
                    </>
                  }
                />
                {failure && (
                  <Alert color="red" variant="light" role="alert">
                    {failure}
                  </Alert>
                )}
                <Button type="submit" color="orange" size="lg" loading={busy} w={{ base: '100%', sm: 'auto' }}>
                  Send my request
                </Button>
              </Stack>
            </form>
          </Grid.Col>
          <Grid.Col span={{ base: 12, md: 5 }}>
            <Stack gap="lg">
              <Paper withBorder p="xl">
                <Stack gap="sm">
                  <Title order={2} fz="h3">
                    What happens next
                  </Title>
                  <Text>We’ll contact you the way you chose, at the time you prefer, to set up a conversation.</Text>
                  <Text size="sm" c="dimmed">
                    <Fact field="consultationFee" />
                  </Text>
                </Stack>
              </Paper>
              <Paper withBorder p="xl">
                <Stack gap="sm">
                  <Title order={2} fz="h3">
                    <IconLock size={20} style={{ verticalAlign: '-3px', marginRight: 6 }} aria-hidden="true" />
                    Your details stay private
                  </Title>
                  <Text size="sm">
                    We use them only to reply to this request. They’re kept behind a protected sign-in, never sold, and
                    deleted when they’re no longer needed.{' '}
                    <Anchor component={Link} to="/privacy" inherit>
                      How we protect them
                    </Anchor>
                    .
                  </Text>
                </Stack>
              </Paper>
            </Stack>
          </Grid.Col>
        </Grid>
      </Section>
    </>
  )
}
