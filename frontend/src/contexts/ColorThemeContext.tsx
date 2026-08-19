import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

type Theme = 'gradient' | 'grey';

interface ColorThemeContextType {
  theme: Theme;
  toggleTheme: () => void;
  gradient: string;
}

const ColorThemeContext = createContext<ColorThemeContextType | undefined>(undefined);

export function ColorThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>('gradient');

  useEffect(() => {
    const saved = localStorage.getItem('colorTheme');
    if (saved === 'gradient' || saved === 'grey') {
      setTheme(saved);
    }
  }, []);

  const toggleTheme = () => {
    const newTheme: Theme = theme === 'gradient' ? 'grey' : 'gradient';
    setTheme(newTheme);
    localStorage.setItem('colorTheme', newTheme);
  };

  const gradient = theme === 'gradient'
    ? 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)'
    : 'linear-gradient(135deg, #64748B 0%, #94A3B8 100%)';

  return (
    <ColorThemeContext.Provider value={{ theme, toggleTheme, gradient }}>
      {children}
    </ColorThemeContext.Provider>
  );
}

export function useColorTheme() {
  const context = useContext(ColorThemeContext);
  if (context === undefined) {
    throw new Error('useColorTheme must be used within a ColorThemeProvider');
  }
  return context;
}



