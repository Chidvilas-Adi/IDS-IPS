/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Severity levels
        severity: {
          critical: {
            DEFAULT: '#ef4444',
            bg: '#450a0a',
            border: '#991b1b',
            text: '#fca5a5',
          },
          high: {
            DEFAULT: '#f97316',
            bg: '#431407',
            border: '#9a3412',
            text: '#fdba74',
          },
          medium: {
            DEFAULT: '#eab308',
            bg: '#422006',
            border: '#92400e',
            text: '#fde047',
          },
          low: {
            DEFAULT: '#3b82f6',
            bg: '#1e1b4b',
            border: '#1d4ed8',
            text: '#93c5fd',
          },
          info: {
            DEFAULT: '#6b7280',
            bg: '#111827',
            border: '#374151',
            text: '#9ca3af',
          },
        },
        // Status colors
        status: {
          online: '#22c55e',
          warning: '#f59e0b',
          offline: '#ef4444',
          unknown: '#6b7280',
        },
        // Custom brand colors
        brand: {
          50: '#eef2ff',
          100: '#e0e7ff',
          200: '#c7d2fe',
          300: '#a5b4fc',
          400: '#818cf8',
          500: '#6366f1',
          600: '#4f46e5',
          700: '#4338ca',
          800: '#3730a3',
          900: '#312e81',
          950: '#1e1b4b',
        },
        // Background shades
        surface: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',
          850: '#172033',
          900: '#0f172a',
          950: '#020617',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.875rem' }],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 3s linear infinite',
        'fade-in': 'fadeIn 0.2s ease-in-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'ticker': 'ticker 20s linear infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
        ticker: {
          '0%': { transform: 'translateX(100%)' },
          '100%': { transform: 'translateX(-100%)' },
        },
      },
      boxShadow: {
        'glow-red': '0 0 15px rgba(239, 68, 68, 0.4)',
        'glow-orange': '0 0 15px rgba(249, 115, 22, 0.4)',
        'glow-yellow': '0 0 15px rgba(234, 179, 8, 0.4)',
        'glow-blue': '0 0 15px rgba(59, 130, 246, 0.4)',
        'glow-green': '0 0 15px rgba(34, 197, 94, 0.4)',
        'inner-glow': 'inset 0 0 20px rgba(99, 102, 241, 0.1)',
      },
      borderRadius: {
        'xl': '0.75rem',
        '2xl': '1rem',
        '3xl': '1.5rem',
      },
      screens: {
        'xs': '475px',
        '3xl': '1920px',
      },
      backdropBlur: {
        xs: '2px',
      },
      gridTemplateColumns: {
        'sidebar': '240px 1fr',
        'sidebar-collapsed': '64px 1fr',
      },
    },
  },
  plugins: [],
};
