/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        canvas: {
          DEFAULT: '#07090E',
          subtle: '#0B0F19',
        },
        surface: {
          DEFAULT: '#0E1424',
          elevated: '#131B30',
          border: '#1F2A44',
          highlight: '#2A3859',
        },
        cyber: {
          emerald: '#10B981',
          cyan: '#06B6D4',
          blue: '#3B82F6',
          violet: '#8B5CF6',
          amber: '#F59E0B',
          rose: '#F43F5E',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      animation: {
        'pulse-subtle': 'pulseSubtle 3s ease-in-out infinite',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
        'radar': 'radarSweep 4s linear infinite',
        'fade-in': 'fadeIn 0.3s cubic-bezier(0.16, 1, 0.3, 1)',
        'slide-up': 'slideUp 0.35s cubic-bezier(0.16, 1, 0.3, 1)',
      },
      keyframes: {
        pulseSubtle: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.6' },
        },
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 15px rgba(16, 185, 129, 0.2)' },
          '50%': { boxShadow: '0 0 30px rgba(16, 185, 129, 0.45)' },
        },
        radarSweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      boxShadow: {
        'cyber-emerald': '0 0 25px -5px rgba(16, 185, 129, 0.25)',
        'cyber-cyan': '0 0 25px -5px rgba(6, 182, 212, 0.25)',
        'cyber-violet': '0 0 25px -5px rgba(139, 92, 246, 0.25)',
        'cyber-rose': '0 0 25px -5px rgba(244, 63, 94, 0.25)',
      },
    },
  },
  plugins: [],
}
