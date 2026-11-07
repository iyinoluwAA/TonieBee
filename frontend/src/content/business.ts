// Every fact about the business that the website shows — in ONE place, so the owner's
// answers go here and nowhere else (see docs/EDITING.md).
//
// `null` means "not known yet". The preview shows it as a dashed "To be filled in"
// note, and `npm run build:live` (the live site's build) refuses to run until every
// `null` here has a real answer. Nothing is ever guessed: a wrong licence number or
// insurer name on an insurance website is a regulatory problem, not a typo.
//
// This file must stay plain TypeScript with no imports (scripts/launch-check.mjs
// reads it directly with Node).

export interface Licence {
  /** Two-letter province code, e.g. "ON". */
  province: string
  /** Who issued it, e.g. "Financial Services Regulatory Authority of Ontario (FSRA)". */
  regulator: string
  /** e.g. "Life and accident & sickness insurance agent". */
  kind: string
  number: string
  /** Where anyone can check it (the regulator's public licence search). */
  checkUrl: string
}

export const business = {
  /** The name used across the site (the existing brand). */
  tradingName: 'Toniebee',
  /** The business name EXACTLY as on her licence (regulators require ads to use it). */
  legalName: null as string | null,
  /** Her full name, as on her licence. */
  ownerName: null as string | null,
  /** Her title. Not "Financial Advisor"/"Financial Planner" unless she holds an approved
   *  credential (Ontario title protection) — e.g. "Licensed Life Insurance Agent". */
  ownerTitle: null as string | null,
  /** Confirmed by AJ (2026-11-07) as her address. */
  email: 'octmay71@gmail.com',
  phone: null as string | null,
  /** Where she works from, e.g. "Brampton, Ontario" (no street address needed). */
  serviceArea: null as string | null,
  /** e.g. "Monday to Friday, 9 a.m. to 6 p.m. Eastern; evenings by appointment". */
  hours: null as string | null,
  licences: null as Licence[] | null,
  /** Province codes she may advise in (must match her licences). */
  provinces: null as string[] | null,
  /** The agency / MGA she's contracted through. */
  agency: null as string | null,
  /** The insurers she represents (regulators require this in writing). */
  insurers: null as string[] | null,
  /** How she's paid, in plain words — e.g. commission from the insurer. */
  compensation: null as string | null,
  /** Any conflicts of interest, or a plain statement that there are none known. */
  conflicts: null as string | null,
  /** What to do with a complaint: her own process, then the insurer's, then the regulator. */
  complaints: null as string | null,
  /** About her, in her own words (2–4 short paragraphs). */
  bio: null as string[] | null,
  /** A photo of her (file in public/images/), or "" for none. */
  photo: null as string | null,
  /** Whether a consultation costs anything, in her words. */
  consultationFee: null as string | null,
  /** How long closed requests are kept (the API deletes them after 2 years — confirm). */
  retention: null as string | null,
  /** Where the website's data is stored (decided at deploy, e.g. "the United States"). */
  dataLocation: null as string | null,
}

export type BusinessField = keyof typeof business

/** Plain names for the "To be filled in" notes and the launch check. */
export const FIELD_LABELS: Record<BusinessField, string> = {
  tradingName: 'Business name',
  legalName: 'Business name exactly as on the licence',
  ownerName: 'Her full name (as on the licence)',
  ownerTitle: 'Her title',
  email: 'Email address',
  phone: 'Phone number',
  serviceArea: 'Where she works from',
  hours: 'Opening hours',
  licences: 'Licence details (province, type, number)',
  provinces: 'Provinces she can advise in',
  agency: 'The agency / MGA she works through',
  insurers: 'The insurers she represents',
  compensation: 'How she is paid',
  conflicts: 'Conflicts of interest',
  complaints: 'How complaints are handled',
  bio: 'About her (in her words)',
  photo: 'Her photo',
  consultationFee: 'Whether a consultation is free',
  retention: 'How long requests are kept',
  dataLocation: 'Where the website’s data is stored',
}

/** Every field still waiting for an answer. */
export function missingFields(): BusinessField[] {
  return (Object.keys(business) as BusinessField[]).filter((key) => business[key] === null)
}

export const PROVINCE_NAMES: Record<string, string> = {
  AB: 'Alberta',
  BC: 'British Columbia',
  MB: 'Manitoba',
  NB: 'New Brunswick',
  NL: 'Newfoundland and Labrador',
  NS: 'Nova Scotia',
  NT: 'Northwest Territories',
  NU: 'Nunavut',
  ON: 'Ontario',
  PE: 'Prince Edward Island',
  QC: 'Quebec',
  SK: 'Saskatchewan',
  YT: 'Yukon',
}
