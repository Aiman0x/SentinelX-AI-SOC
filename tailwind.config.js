/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        sx: {
          bg: '#090909',
          side: '#0D0D0D',
          panel: '#141414',
          elev: '#1B1B1B',
          line: '#292929',
          red: '#E53935',
          reddark: '#8F1D1D',
          gold: '#D4AF37',
          ink: '#F3F3F3',
          mute: '#969696',
          ok: '#43B581',
          warn: '#F0A83C',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      boxShadow: {
        panel: '0 1px 0 rgba(255,255,255,0.02) inset, 0 8px 24px -12px rgba(0,0,0,0.7)',
        glow: '0 0 0 1px rgba(229,57,53,0.35), 0 0 18px -4px rgba(229,57,53,0.35)',
      },
    },
  },
  plugins: [],
};
