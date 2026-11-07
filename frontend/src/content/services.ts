// The three kinds of cover, explained in plain language. DRAFT WORDING for the owner
// to review and change — general education only, no prices, no statistics, no promises
// about any particular insurer's policy (those differ, and she knows them).

export interface Service {
  slug: string
  /** The API's name for it (consultation form). */
  interest: 'life' | 'critical_illness' | 'disability'
  title: string
  short: string
  intro: string
  sections: { heading: string; body: string[] }[]
  /** "Good questions to ask" list. */
  questions: string[]
}

export const services: Service[] = [
  {
    slug: 'life-insurance',
    interest: 'life',
    title: 'Life insurance',
    short: 'Money for the people who depend on you, if you die — so they can stay in their home and keep their plans.',
    intro:
      'Life insurance pays a sum of money to the people you choose (your beneficiaries) when you die. It can replace your income, pay off a mortgage or other debts, and cover costs like childcare or education.',
    sections: [
      {
        heading: 'Who it’s for',
        body: [
          'Anyone whose family, partner or business would struggle without their income or the work they do at home.',
          'People with a mortgage or other debts they don’t want to leave behind.',
        ],
      },
      {
        heading: 'The two main types',
        body: [
          'Term life insurance covers you for a set number of years — often while children are young or the mortgage is being paid. It is usually the simplest and least expensive way to get a large amount of cover.',
          'Permanent life insurance (such as whole life or universal life) lasts for your whole life as long as it’s kept in force, and some policies build a cash value over time. It costs more for the same amount of cover.',
        ],
      },
      {
        heading: 'Worth knowing',
        body: [
          'In Canada, a life insurance payout to a named beneficiary is generally not taxable.',
          'How much cover you need depends on your debts, your income and the people who rely on it — there’s no single right number.',
        ],
      },
    ],
    questions: [
      'Who would need money if I died, and for how long?',
      'Do I need cover for a set time, or for life?',
      'What would happen to my mortgage and debts?',
      'Do I already have cover through work, and would it follow me if I changed jobs?',
    ],
  },
  {
    slug: 'critical-illness-insurance',
    interest: 'critical_illness',
    title: 'Critical illness insurance',
    short: 'A lump sum if you’re diagnosed with a serious illness covered by your policy — to use however you need while you recover.',
    intro:
      'Critical illness insurance pays you a one-time lump sum if you are diagnosed with a serious condition that your policy covers, such as many cancers, heart attack or stroke, and you survive the short waiting period the policy sets.',
    sections: [
      {
        heading: 'Why people choose it',
        body: [
          'Provincial health plans cover a lot of medical care, but not everything — and not the income you may lose while you recover or care for yourself.',
          'The money is yours to use as you choose: bills, treatment not covered by your plan, travel to appointments, or simply time off work.',
        ],
      },
      {
        heading: 'Worth knowing',
        body: [
          'Each policy lists exactly which conditions it covers and how each one is defined. These lists differ between insurers, so it’s worth comparing them.',
          'Some policies return part of what you paid if you never claim; that option usually costs more.',
        ],
      },
    ],
    questions: [
      'Which conditions are covered, and how are they defined?',
      'How long is the waiting period after a diagnosis?',
      'How much would I need to cover a few months or a year away from work?',
      'Do I already have some critical illness cover through work?',
    ],
  },
  {
    slug: 'disability-insurance',
    interest: 'disability',
    title: 'Disability insurance',
    short: 'A monthly income if an illness or injury stops you from working — protecting your biggest asset: your ability to earn.',
    intro:
      'Disability insurance pays you part of your income, usually every month, if an illness or injury means you can’t work. It helps you keep paying for your home, your bills and your family while you recover.',
    sections: [
      {
        heading: 'Who it’s for',
        body: [
          'Anyone who relies on their pay — especially the self-employed, business owners and people whose work plan doesn’t cover enough of their income.',
        ],
      },
      {
        heading: 'Short-term and long-term',
        body: [
          'Short-term disability insurance covers a few weeks or months. Long-term disability insurance can pay for years — sometimes until retirement — if you stay unable to work.',
          'Government programs such as Employment Insurance sickness benefits and the Canada Pension Plan disability benefit exist, but they have strict rules and limits, and may not replace enough of your income.',
        ],
      },
      {
        heading: 'Worth knowing',
        body: [
          'Policies define “disabled” differently — for example, unable to do your own job, or unable to do any job you’re reasonably suited for. This makes a big difference.',
          'There’s usually a waiting period before payments start. A longer one generally lowers the cost.',
        ],
      },
    ],
    questions: [
      'How much of my income would I need each month?',
      'How long could I manage before payments start?',
      'How does the policy define being unable to work?',
      'What does my work plan already cover, and is it enough?',
    ],
  },
]

export const serviceBySlug = (slug: string) => services.find((s) => s.slug === slug)
