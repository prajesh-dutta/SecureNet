import { useEffect, useState } from 'react';

type Theme = 'dark' | 'light' | 'system';

export function useTheme(defaultTheme: Theme = 'dark') {
  const [theme, setTheme] = useState<Theme>(() => {
    // Check local storage first
    const storedTheme = localStorage.getItem('theme') as Theme | null;
    if (storedTheme) {
      return storedTheme;
    }
    return defaultTheme;
  });

  // Update the theme class on the document
  useEffect(() => {
    const root = window.document.documentElement;
    
    if (theme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
      
      root.classList.remove('light', 'dark');
      root.classList.add(systemTheme);
    } else {
      root.classList.remove('light', 'dark');
      root.classList.add(theme);
    }
    
    // Store the theme preference
    localStorage.setItem('theme', theme);
  }, [theme]);

  return { theme, setTheme };
}
