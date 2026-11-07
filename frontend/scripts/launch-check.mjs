#!/usr/bin/env node
// The launch check: lists every fact about the business that's still missing from
// src/content/business.ts, and refuses (exit 1) while any is — so the live site can
// never be built with "To be filled in" on it. `--report` lists them without failing
// (CI uses that, so pull requests stay green while the owner's answers are pending).
//
// Run: npm run launch-check   (the live build, npm run build:live, runs it first)

const { business, FIELD_LABELS, missingFields } = await import('../src/content/business.ts')

const reportOnly = process.argv.includes('--report')
const missing = missingFields()

if (missing.length === 0) {
  console.log(`✓ Every business detail is filled in (${Object.keys(business).length} of ${Object.keys(business).length}).`)
  process.exit(0)
}

console.log(`${missing.length} business detail${missing.length === 1 ? ' is' : 's are'} still missing (src/content/business.ts):`)
for (const field of missing) console.log(`  • ${FIELD_LABELS[field]}  (${field})`)

if (reportOnly) {
  console.log('\n(Report only — the live build stays blocked until these are filled in.)')
  process.exit(0)
}
console.error('\n✋ The live site can’t be built until these are filled in. See docs/EDITING.md.')
process.exit(1)
