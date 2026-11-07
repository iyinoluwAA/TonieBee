// The consent wording on the consultation form. Its version is stored with every
// request (PIPEDA consent record). When the wording changes, change the version here
// AND `CONSENT_VERSION` in backend/src/modules/requests/mod.rs — the server refuses
// requests sent from a page with older wording.

export const CONSENT_VERSION = '2026-11-07'

export const consentText = (tradingName: string) =>
  `I agree that ${tradingName} may use the details above to contact me about this request, as the Privacy Policy describes.`
