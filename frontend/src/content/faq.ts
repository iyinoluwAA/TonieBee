// Frequently asked questions. DRAFT WORDING for the owner to review. Answers that
// depend on her own facts (fees, provinces, how she's paid) come from business.ts.

export interface Faq {
  question: string
  /** Plain paragraphs. Business facts are filled in by the FAQ page itself. */
  answer: string[]
  /** Which business.ts fact completes this answer, if any. */
  fact?: 'consultationFee' | 'provinces' | 'compensation'
}

export const faqs: Faq[] = [
  {
    question: 'Do I really need life insurance?',
    answer: [
      'If anyone depends on your income — a partner, children, parents you support — or you have debts like a mortgage, life insurance makes sure they aren’t left struggling. If no one relies on you financially, you may need little or none. A conversation helps you decide.',
    ],
  },
  {
    question: 'How much cover do I need?',
    answer: [
      'It depends on your income, your debts, your family and your plans. We’ll go through these together and look at what you already have, such as cover through work.',
    ],
  },
  {
    question: 'What’s the difference between term and permanent insurance?',
    answer: [
      'Term insurance covers you for a set number of years and is usually the least expensive way to get a large amount of cover. Permanent insurance lasts for life and can build cash value, but costs more. Many families use term; some situations call for permanent.',
    ],
  },
  {
    question: 'Will I need a medical exam?',
    answer: [
      'Sometimes. It depends on the insurer, your age, your health and the amount of cover. Many applications only need you to answer health questions. Any health details go to the insurer through its own application — not through this website.',
    ],
  },
  {
    question: 'What happens when I book a consultation?',
    answer: [
      'You’ll be contacted the way you asked (a call or an email) to find a time to talk. We’ll go through your situation and your options. Booking doesn’t commit you to anything.',
    ],
    fact: 'consultationFee',
  },
  {
    question: 'Where can you help?',
    answer: ['Insurance advisors in Canada are licensed province by province.'],
    fact: 'provinces',
  },
  {
    question: 'How are you paid?',
    answer: ['You have a right to know how your advisor is paid.'],
    fact: 'compensation',
  },
  {
    question: 'How is my information protected?',
    answer: [
      'The website asks only for what’s needed to get back to you, never health details. Your request is kept behind a sign-in that needs a password and a code from a phone, and every time it’s opened is recorded. The Privacy Policy explains exactly what’s kept, why, and for how long.',
    ],
  },
]
