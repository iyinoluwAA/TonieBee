// Click-through check of the REAL website + API, the way people use them:
//   1. a visitor sends a consultation request (after seeing the form's own errors);
//   2. they sign in by email — link opened on a "phone", code typed on the "laptop";
//   3. a request sent while signed in shows under "My requests";
//   4. the owner signs in to the dashboard (password + authenticator code), opens the
//      request, marks it contacted, saves a note, and sees it in Activity.
//
// Needs: the API (backend, port 8000, MAIL_PROVIDER=log, its log in $API_LOG), the dev
// site (frontend, port 5175) and a dev admin (python3 tools/dev_admin.py).
//   API_LOG=/path/to/api.log node tools/e2e/site.mjs
// Screens are saved to tools/shots/e2e-*.png.

import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright-core'

const here = dirname(fileURLToPath(import.meta.url))
const SITE = 'http://localhost:5175'
const SHOTS = join(here, '..', 'shots')
const API_LOG = process.env.API_LOG
if (!API_LOG) throw new Error('Set API_LOG to the API server’s log file (development emails are printed there).')
const admin = JSON.parse(readFileSync(join(here, 'out', 'dev-admin.json'), 'utf8'))
const executablePath = join(homedir(), '.cache/ms-playwright/chromium-1248/chrome-linux64/chrome')

let checks = 0
const ok = (what) => {
  checks += 1
  console.log(`  ✓ ${what}`)
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function totp(key, at = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of key.replace(/ /g, '')) bits += alphabet.indexOf(c).toString(2).padStart(5, '0')
  const bytes = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)))
  const step = Buffer.alloc(8)
  step.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)))
  const mac = createHmac('sha1', bytes).update(step).digest()
  const offset = mac[mac.length - 1] & 0x0f
  return String((mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, '0')
}

/** The newest sign-in link printed for `email` in the API's log. */
async function linkFor(email, marker = '/sign-in/link#') {
  for (let i = 0; i < 40; i++) {
    const log = readFileSync(API_LOG, 'utf8')
    const blocks = log.split('DEV EMAIL').filter((b) => b.includes(`To: ${email}`) && b.includes(marker))
    const last = blocks.at(-1)
    if (last) return last.slice(last.indexOf(marker) + marker.length).slice(0, 64)
    await sleep(250)
  }
  throw new Error(`no email with ${marker} for ${email} in the API log`)
}

const browser = await chromium.launch({ executablePath, headless: true })
const laptop = await browser.newContext({ viewport: { width: 1280, height: 610 } })
const phone = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })
const email = `e2e.${Date.now()}@example.com`
const name = 'Ada E2E Obi'

try {
  console.log('Visitor')
  const page = await laptop.newPage()
  await page.goto(`${SITE}/book`)
  await page.getByRole('button', { name: 'Send my request' }).click()
  await page.getByText('Please tell us your name.').waitFor()
  await page.getByText('Please tick the box so we can contact you.').waitFor()
  ok('an empty form shows what to fix, and sends nothing')

  await page.getByLabel('Your name').fill(name)
  await page.getByRole('textbox', { name: 'Email' }).fill(email)
  await page.getByLabel('Phone').fill('416-555-0199')
  await page.getByPlaceholder('Choose one').click()
  await page.getByRole('option', { name: 'Ontario' }).click()
  await page.getByLabel('Life insurance').check()
  await page.getByRole('checkbox', { name: /I agree that/ }).check()
  await page.getByRole('button', { name: 'Send my request' }).click()
  await page.getByText('Thank you — your request is in').waitFor()
  await page.screenshot({ path: join(SHOTS, 'e2e-sent.png') })
  ok('a filled-in request is sent and thanked')

  console.log('Client sign-in (link on the phone, code on the laptop)')
  await page.goto(`${SITE}/account`)
  await page.getByRole('textbox', { name: 'Email' }).fill(email)
  await page.getByRole('button', { name: 'Email me a sign-in link' }).click()
  await page.getByText('Check your email').waitFor()
  const token = await linkFor(email)
  const onPhone = await phone.newPage()
  await onPhone.goto(`${SITE}/sign-in/link#${token}`)
  await onPhone.getByText('Your sign-in code').waitFor()
  await onPhone.getByText(/Asked for from/).waitFor()
  const shown = (await onPhone.getByLabel(/^Sign-in code/).textContent()).replace(/\D/g, '')
  await onPhone.screenshot({ path: join(SHOTS, 'e2e-code-on-phone.png') })
  ok(`the link on another device shows the code (${shown.length} digits) and who asked`)
  if (onPhone.url().includes('#')) throw new Error('the token stayed in the address bar')
  ok('the token is cleared from the address bar')

  await page.locator('input[aria-label="6-digit sign-in code"]').first().click()
  await page.keyboard.type(shown)
  await page.getByText(/Signed in as/).waitFor()
  ok('the code typed on the laptop signs it in')

  await page.goto(`${SITE}/book`)
  await page.getByLabel('Your name').fill(name)
  if ((await page.getByRole('textbox', { name: 'Email' }).inputValue()) !== email) throw new Error('email not prefilled')
  ok('the form starts from the signed-in account')
  await page.getByPlaceholder('Choose one').click()
  await page.getByRole('option', { name: 'Ontario' }).click()
  await page.getByLabel('Disability insurance').check()
  await page.getByRole('radio', { name: 'Email me' }).check()
  await page.getByLabel('Phone').fill('')
  await page.getByRole('checkbox', { name: /I agree that/ }).check()
  await page.getByRole('button', { name: 'Send my request' }).click()
  await page.getByText('Thank you — your request is in').waitFor()
  await page.goto(`${SITE}/account`)
  await page.getByText('Disability').first().waitFor()
  await page.getByText('Received').first().waitFor()
  await page.screenshot({ path: join(SHOTS, 'e2e-my-requests.png'), fullPage: true })
  ok('"My requests" shows the request sent while signed in')

  console.log('Owner’s dashboard')
  const desk = await laptop.newPage()
  await desk.goto(`${SITE}/admin/requests`)
  await desk.waitForURL(/\/admin\/sign-in/)
  ok('the dashboard sends signed-out visitors to sign in')
  // A client session never opens the dashboard: this browser IS signed in as a client.
  await desk.getByRole('textbox', { name: 'Email' }).fill(admin.email)
  await desk.getByRole('textbox', { name: 'Password' }).fill(admin.password)
  await desk.getByRole('button', { name: 'Continue' }).click()
  await desk.getByText('One more step').waitFor()
  // Each code works once: wait for a fresh one (create-admin used the one it saw).
  await sleep((30 - (Math.floor(Date.now() / 1000) % 30) + 1) * 1000)
  await desk.locator('input[aria-label="6-digit code from your authenticator app"]').first().click()
  await desk.keyboard.type(totp(admin.key))
  await desk.waitForURL(/\/admin\/requests/)
  ok('password + authenticator code signs the owner in, back to where she was going')

  await desk.getByText(name).first().click()
  await desk.getByText(email).first().waitFor()
  ok('opening a request shows how to reach them')
  await desk.locator('label[for$="-contacted"]').click()
  await desk.getByText('Saved.').first().waitFor()
  await desk.getByLabel('Your notes').fill('Called — call back Tuesday evening.')
  await desk.getByRole('button', { name: 'Save notes' }).click()
  await desk.getByText('Saved.').first().waitFor()
  ok('status and private notes are saved')
  // The owner works from her phone: the same screens at phone width.
  await desk.setViewportSize({ width: 390, height: 844 })
  await desk.evaluate(() => window.scrollTo(0, 0))
  await sleep(400)
  await desk.screenshot({ path: join(SHOTS, 'e2e-request-phone.png') })
  await desk.goto(`${SITE}/admin/requests?show=contacted`)
  await desk.getByText(name).first().waitFor()
  await desk.screenshot({ path: join(SHOTS, 'e2e-requests-phone.png') })
  await desk.goto(`${SITE}/admin`)
  await desk.getByText('Open the requests').waitFor()
  await desk.screenshot({ path: join(SHOTS, 'e2e-overview-phone.png') })
  await desk.setViewportSize({ width: 1280, height: 610 })

  await desk.goto(`${SITE}/admin/activity`)
  await desk.getByText(/opened request/).first().waitFor()
  await desk.getByText(/updated request/).first().waitFor()
  ok('Activity shows who opened and changed the request')

  const deskPhone = await phone.newPage()
  await deskPhone.goto(`${SITE}/admin/requests`)
  await deskPhone.waitForURL(/\/admin\/sign-in/)
  ok('a different device has to sign in on its own')

  console.log(`\n✓ ${checks} checks passed`)
} catch (error) {
  console.error(`\n✗ after ${checks} checks: ${error.message}`)
  for (const context of [laptop, phone])
    for (const [i, p] of context.pages().entries())
      await p.screenshot({ path: join(SHOTS, `e2e-failure-${i}.png`), fullPage: true }).catch(() => {})
  process.exitCode = 1
} finally {
  await browser.close()
}
