// Shows one of the owner's facts from content/business.ts — or, while it's still
// unknown, a dashed "To be filled in" note. Never a made-up stand-in.

import type { ReactNode } from 'react'
import { business, FIELD_LABELS, type BusinessField } from '@/content/business'

export function Pending({ field }: { field: BusinessField }) {
  return (
    <span className="tb-pending" title="This detail is waiting for the owner">
      To be filled in: {FIELD_LABELS[field].toLowerCase()}
    </span>
  )
}

/** `children(value)` renders the fact once it's known. */
export function Fact<K extends BusinessField>({
  field,
  children,
}: {
  field: K
  children?: (value: NonNullable<(typeof business)[K]>) => ReactNode
}) {
  const value = business[field]
  if (value === null) return <Pending field={field} />
  return <>{children ? children(value as NonNullable<(typeof business)[K]>) : String(value)}</>
}
