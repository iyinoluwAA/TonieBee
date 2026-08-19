import { createTheme, MantineColorsTuple } from '@mantine/core';

// Custom color tuples for our insurance platform
const trustBlue: MantineColorsTuple = [
  '#EFF6FF',
  '#DBEAFE',
  '#BFDBFE',
  '#93C5FD',
  '#60A5FA',
  '#3B82F6',
  '#2563EB',
  '#1D4ED8',
  '#1E40AF', // Primary
  '#1E3A8A',
];

const calmingTeal: MantineColorsTuple = [
  '#F0FDFA',
  '#CCFBF1',
  '#99F6E4',
  '#5EEAD4',
  '#2DD4BF',
  '#14B8A6',
  '#0D9488', // Primary
  '#0F766E',
  '#115E59',
  '#134E4A',
];

const warmOrange: MantineColorsTuple = [
  '#FFF7ED',
  '#FFEDD5',
  '#FED7AA',
  '#FDBA74',
  '#FB923C',
  '#F97316', // Primary (CTAs)
  '#EA580C',
  '#C2410C',
  '#9A3412',
  '#7C2D12',
];

const successGreen: MantineColorsTuple = [
  '#F0FDF4',
  '#DCFCE7',
  '#BBF7D0',
  '#86EFAC',
  '#4ADE80',
  '#22C55E',
  '#16A34A',
  '#15803D',
  '#166534',
  '#14532D',
];

export const theme = createTheme({
  /** Primary color - Trust Blue */
  primaryColor: 'trustBlue',
  
  /** Custom colors */
  colors: {
    trustBlue,
    calmingTeal,
    warmOrange,
    successGreen,
  },

  /** Typography */
  fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  fontFamilyMonospace: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
  
  headings: {
    fontFamily: 'Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    fontWeight: '600',
    sizes: {
      h1: { fontSize: 'clamp(2rem, 5vw, 3.5rem)', lineHeight: '1.2' },
      h2: { fontSize: 'clamp(1.75rem, 4vw, 2.75rem)', lineHeight: '1.3' },
      h3: { fontSize: 'clamp(1.5rem, 3vw, 2.25rem)', lineHeight: '1.4' },
      h4: { fontSize: 'clamp(1.25rem, 2.5vw, 1.75rem)', lineHeight: '1.4' },
      h5: { fontSize: 'clamp(1.125rem, 2vw, 1.5rem)', lineHeight: '1.5' },
      h6: { fontSize: 'clamp(1rem, 1.5vw, 1.25rem)', lineHeight: '1.5' },
    },
  },

  /** Spacing */
  spacing: {
    xs: '0.5rem',   // 8px
    sm: '0.75rem',  // 12px
    md: '1rem',     // 16px
    lg: '1.5rem',   // 24px
    xl: '2rem',     // 32px
  },

  /** Shadows - Subtle and elegant */
  shadows: {
    xs: '0 1px 3px rgba(0, 0, 0, 0.05), 0 1px 2px rgba(0, 0, 0, 0.1)',
    sm: '0 1px 3px rgba(0, 0, 0, 0.05), 0 2px 4px rgba(0, 0, 0, 0.1)',
    md: '0 4px 6px rgba(0, 0, 0, 0.07), 0 2px 4px rgba(0, 0, 0, 0.06)',
    lg: '0 10px 15px rgba(0, 0, 0, 0.1), 0 4px 6px rgba(0, 0, 0, 0.05)',
    xl: '0 20px 25px rgba(0, 0, 0, 0.1), 0 10px 10px rgba(0, 0, 0, 0.04)',
  },

  /** Radius - Soft, friendly corners */
  radius: {
    xs: '0.25rem',  // 4px
    sm: '0.5rem',   // 8px
    md: '0.75rem',  // 12px
    lg: '1rem',     // 16px
    xl: '1.5rem',   // 24px
  },

  /** Default props */
  defaultProps: {
    Button: {
      radius: 'md',
    },
    Card: {
      radius: 'lg',
      shadow: 'sm',
      withBorder: true,
    },
    TextInput: {
      radius: 'md',
    },
    Paper: {
      radius: 'lg',
      shadow: 'sm',
    },
  },

  /** Other theme properties */
  respectReducedMotion: true,
  cursorType: 'pointer',
  focusRing: 'auto',
});
