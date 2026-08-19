import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';

import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { Router } from './Router';
import { theme } from './theme';
import { ColorThemeProvider } from './contexts/ColorThemeContext';

export default function App() {
  return (
    <MantineProvider theme={theme}>
      <ColorThemeProvider>
        <Notifications position="top-right" zIndex={1000} />
        <Router />
      </ColorThemeProvider>
    </MantineProvider>
  );
}
