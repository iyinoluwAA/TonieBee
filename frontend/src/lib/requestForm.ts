// The consultation form's checks, mirrored from the API (backend/src/modules/requests)
// so problems show before anything is sent. The server still decides.
// Plain TypeScript with no imports, so `npm test` runs it directly with Node.

export interface FormValues {
  name: string
  email: string
  phone: string
  province: string
  interests: string[]
  contactBy: 'email' | 'phone'
  message: string
  consent: boolean
}

export type FormErrors = Partial<Record<keyof FormValues, string>>

/** Control characters and the invisible ones used to disguise text (bidi overrides,
 *  zero-width spaces) — matched on purpose, as the server refuses them. Tabs and line
 *  breaks are allowed. Built from code points so the source stays plain ASCII. */
const HIDDEN_RANGES: [number, number][] = [
  [0x0000, 0x0008],
  [0x000b, 0x000c],
  [0x000e, 0x001f],
  [0x007f, 0x007f],
  [0x200b, 0x200f],
  [0x202a, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
]
const isHidden = (c: string) => {
  const code = c.codePointAt(0) ?? 0
  return HIDDEN_RANGES.some(([from, to]) => code >= from && code <= to)
}
const HIDDEN = { test: (text: string) => [...text].some(isHidden) }

export function phoneDigits(phone: string): string {
  return phone.replace(/\D/g, '')
}

export function validPhone(raw: string): boolean {
  const phone = raw.trim()
  if (phone.length > 25 || !/^\+?[\d\s\-.()]+$/.test(phone)) return false
  const digits = phoneDigits(phone)
  return digits.length === 10 || (digits.length === 11 && digits.startsWith('1')) || (digits.length >= 12 && digits.length <= 15 && phone.startsWith('+'))
}

export function validEmail(raw: string): boolean {
  const email = raw.trim()
  if (email.length < 3 || email.length > 254 || /\s/.test(email) || HIDDEN.test(email)) return false
  const at = email.indexOf('@')
  if (at < 1 || at !== email.lastIndexOf('@')) return false
  const domain = email.slice(at + 1)
  return domain.includes('.') && !domain.startsWith('.') && !domain.endsWith('.') && !domain.includes('..')
}

export function validate(values: FormValues, provinces: string[] | null): FormErrors {
  const errors: FormErrors = {}
  const name = values.name.trim().replace(/\s+/g, ' ')
  if (!name) errors.name = 'Please tell us your name.'
  else if ([...name].length > 100 || HIDDEN.test(name)) errors.name = 'Please check your name (at most 100 letters).'

  if (!validEmail(values.email)) errors.email = 'Please enter a valid email address.'

  if (values.phone.trim() && !validPhone(values.phone))
    errors.phone = 'Please enter a phone number with its area code, like 416-555-0123.'
  if (values.contactBy === 'phone' && !values.phone.trim()) errors.phone = 'Please add your phone number so we can call you.'

  if (!values.province) errors.province = 'Please choose your province or territory.'
  else if (provinces && !provinces.includes(values.province))
    errors.province = 'Sorry — we can only advise residents of the provinces listed.'

  if (values.interests.length === 0) errors.interests = 'Please choose at least one.'

  const message = values.message.trim()
  if ([...message].length > 1000) errors.message = 'Please keep your message under 1,000 characters.'
  else if (HIDDEN.test(message))
    errors.message = 'Your message has characters we can’t use.'

  if (!values.consent) errors.consent = 'Please tick the box so we can contact you.'
  return errors
}
