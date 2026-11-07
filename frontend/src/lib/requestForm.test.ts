// Run with: npm test (Node's own test runner; no extra packages).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validate, validEmail, validPhone, type FormValues } from './requestForm.ts'

const good: FormValues = {
  name: 'Ada Obi',
  email: 'ada@example.com',
  phone: '416-555-0123',
  province: 'ON',
  interests: ['life'],
  contactBy: 'phone',
  message: 'Hello',
  consent: true,
}

test('a complete form has no problems', () => {
  assert.deepEqual(validate(good, null), {})
  assert.deepEqual(validate(good, ['ON']), {})
})

test('each field is checked like the server checks it', () => {
  const check = (change: Partial<FormValues>, provinces: string[] | null = null) =>
    Object.keys(validate({ ...good, ...change }, provinces))
  assert.deepEqual(check({ name: '  ' }), ['name'])
  assert.deepEqual(check({ name: 'Ada\u202E' }), ['name'])
  assert.deepEqual(check({ email: 'nope' }), ['email'])
  assert.deepEqual(check({ phone: '' }), ['phone'], 'a call needs a number')
  assert.deepEqual(check({ phone: '', contactBy: 'email' }), [])
  assert.deepEqual(check({ province: '' }), ['province'])
  assert.deepEqual(check({ province: 'BC' }, ['ON']), ['province'])
  assert.deepEqual(check({ interests: [] }), ['interests'])
  assert.deepEqual(check({ message: 'x'.repeat(1001) }), ['message'])
  assert.deepEqual(check({ message: 'hi\u200B' }), ['message'])
  assert.deepEqual(check({ consent: false }), ['consent'])
})

test('phone numbers are read like people write them', () => {
  for (const ok of ['(416) 555-0123', '416.555.0123', '1-416-555-0123', '+1 416 555 0123', '+44 20 7946 0958'])
    assert.ok(validPhone(ok), ok)
  for (const bad of ['555-0123', '416-555-01a3', '4165550123456789', '41+6555012300'])
    assert.ok(!validPhone(bad), bad)
})

test('email addresses are checked loosely, as the server does', () => {
  assert.ok(validEmail(' Ada.Obi+quotes@Gmail.com '))
  for (const bad of ['', 'a@b', '@x.com', 'a b@c.com', 'a@b@c.com', 'a@b..com']) assert.ok(!validEmail(bad), bad)
})
