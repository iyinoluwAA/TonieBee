# Changing the website's words, facts and look

Everything the owner might want changed lives in a few files. After any change, run
`npm run check` in `frontend/` (it catches mistakes), then look at the page.

## The owner's facts — `frontend/src/content/business.ts`
Name, title, licences, provinces, agency, insurers, how she's paid, conflicts, complaints,
phone, hours, area, bio, photo, whether a consultation is free, retention, data location.

- `null` means "not known yet". The site shows a dashed **"To be filled in"** note there,
  and a banner says how many are missing.
- **Never guess one.** A wrong licence number or insurer on an insurance website is a
  regulatory problem.
- `npm run launch-check` lists what's still missing. The live build (`npm run build:live`,
  and the Docker build without `PREVIEW=1`) refuses to run until nothing is.
- Example, once she answers:
  ```ts
  phone: '(416) 555-0123',          // her real number
  provinces: ['ON'],
  insurers: ['Insurer A', 'Insurer B'],
  licences: [{ province: 'ON', regulator: 'FSRA', kind: 'Life and accident & sickness insurance agent',
               number: '...', checkUrl: 'https://...' }],
  ```
- **Her title**: not "Financial Advisor" or "Financial Planner" unless she holds an
  approved credential (Ontario title protection). "Licensed Life Insurance Agent" or
  "Insurance Advisor" are the usual safe choices — check with her agency.
- **Provinces**: also set `SERVICE_PROVINCES` on the server (e.g. `ON`) so the form can't
  be sent from elsewhere.
- **Photo**: put the file in `frontend/public/images/` and set `photo: '/images/name.jpg'`
  (a portrait, ideally 800×1000 or larger).

## Words
- The three kinds of cover: `src/content/services.ts`
- Questions & answers: `src/content/faq.ts`
- Home page wording: `src/pages/Home.tsx`
- Disclosure, privacy, terms, accessibility: `src/pages/Legal.tsx`
- The consent sentence on the form: `src/content/consent.ts` — **if you change the wording,
  change `CONSENT_VERSION` there AND in `backend/src/modules/requests/mod.rs`** (the server
  records which wording each person agreed to, and refuses older pages).

All of this wording is a **draft** for the owner to review. Keep it general (no prices,
statistics or promises about a particular insurer), and never add testimonials unless
they're real and the person agreed in writing.

## Look
- Colours: `src/theme.ts` (Mantine) and the `--tb-*` variables at the top of
  `src/styles/global.css`.
- Logo: `src/components/Logo.tsx` (the shield + name) and `public/favicon.svg`.
- The business name shown everywhere: `tradingName` in `business.ts`; in emails and the
  authenticator app: `BRAND_NAME` on the server.
