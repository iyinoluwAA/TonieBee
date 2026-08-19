import { createContext, useContext, useState, useEffect, ReactNode } from 'react';

interface GradientContextType {
  useGradient: boolean;
  toggleGradient: () => void;
  gradient: string;
}

const GradientContext = createContext<GradientContextType | undefined>(undefined);

export function GradientProvider({ children }: { children: ReactNode }) {
  const [useGradient, setUseGradient] = useState(true);

  useEffect(() => {
    const saved = localStorage.getItem('useGradient');
    if (saved !== null) {
      setUseGradient(saved === 'true');
    }
  }, []);

  const toggleGradient = () => {
    const newValue = !useGradient;
    setUseGradient(newValue);
    localStorage.setItem('useGradient', String(newValue));
  };

  const gradient = useGradient
    ? 'linear-gradient(135deg, #1E40AF 0%, #0D9488 100%)'
    : 'linear-gradient(135deg, #64748B 0%, #94A3B8 100%)';

  return (
    <GradientContext.Provider value={{ useGradient, toggleGradient, gradient }}>
      {children}
    </GradientContext.Provider>
  );
}

export function useGradient() {
  const context = useContext(GradientContext);
  if (context === undefined) {
    throw new Error('useGradient must be used within a GradientProvider');
  }
  return context;
}



