import { createTheme, type MantineColorsTuple } from '@mantine/core'

// The colours AJ chose for TonieBee from the start: trust blue, calming teal, and a
// warm orange kept for the one thing to do on each page (book a consultation).
// Brand colours live here and in styles/global.css (--tb-*) only — see docs/EDITING.md.

const navy: MantineColorsTuple = [
  '#EEF3FF', '#DCE5FC', '#B6C9F5', '#8DAAEE', '#6A8FE8', '#5480E4', '#2F5FD0', '#1E40AF', '#1A378F', '#14296C',
]
const teal: MantineColorsTuple = [
  '#E8FBF8', '#CCF4EE', '#9BE8DC', '#64DBC9', '#38CFB8', '#1CC5AC', '#0D9488', '#0B7A70', '#0A6159', '#08463F',
]
const orange: MantineColorsTuple = [
  '#FFF4E8', '#FFE7CF', '#FFCB9D', '#FFAE66', '#FE9439', '#FE841B', '#F26B07', '#C2570A', '#9A430B', '#7A350C',
]

export const theme = createTheme({
  primaryColor: 'navy',
  primaryShade: 7,
  colors: { navy, teal, orange },
  // The system's own fonts: fast, and no third-party font service sees visitors.
  fontFamily:
    'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", "Noto Sans", Arial, sans-serif',
  headings: {
    fontFamily:
      'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", "Noto Sans", Arial, sans-serif',
    fontWeight: '700',
    sizes: {
      h1: { fontSize: 'clamp(2rem, 4.2vw, 3.1rem)', lineHeight: '1.15' },
      h2: { fontSize: 'clamp(1.6rem, 3vw, 2.25rem)', lineHeight: '1.2' },
      h3: { fontSize: '1.3rem', lineHeight: '1.3' },
    },
  },
  defaultRadius: 'md',
  black: '#14213D',
  cursorType: 'pointer',
  focusRing: 'auto',
  components: {
    Button: { defaultProps: { radius: 'xl' } },
    Paper: { defaultProps: { radius: 'lg' } },
  },
})
