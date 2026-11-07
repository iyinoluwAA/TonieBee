// A simple shield mark + the name. A placeholder look until the owner has a logo of her
// own (swap the SVG here; everything else picks it up).

import { Link } from 'react-router-dom'
import { business } from '@/content/business'

export function Mark({ size = 32 }: { size?: number }) {
  return (
    <svg className="tb-wordmark__mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 4 6.5v8.2C4 22.3 9.1 28.2 16 30c6.9-1.8 12-7.7 12-15.3V6.5L16 2Z" fill="#1E40AF" />
      <path d="M16 6.2 8 9.2v5.6c0 5.1 3.4 9.1 8 10.5 4.6-1.4 8-5.4 8-10.5V9.2l-8-3Z" fill="#0D9488" />
      <path d="M11.5 15.6l3.1 3.1 6-6.2" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function Wordmark() {
  return (
    <Link to="/" className="tb-wordmark" aria-label={`${business.tradingName} — home`}>
      <Mark />
      <span>{business.tradingName}</span>
    </Link>
  )
}
