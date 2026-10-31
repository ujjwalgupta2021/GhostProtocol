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
        cyber: {
          void: '#07090E',
          black: '#0A0D14',
          slate: '#0F172A',
          surface: '#131D33',
          card: '#16233E',
          border: '#1E293B',
          borderLight: '#334155',
          cyan: '#00E5FF',
          magenta: '#FF0055',
          green: '#00FF66',
          amber: '#FFB800',
          text: '#F1F5F9',
          muted: '#94A3B8',
          dim: '#64748B'
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['"Inter"', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif']
      },
      boxShadow: {
        'neon-cyan': '0 0 20px -3px rgba(0, 229, 255, 0.35), 0 0 8px -2px rgba(0, 229, 255, 0.2)',
        'neon-magenta': '0 0 20px -3px rgba(255, 0, 85, 0.35), 0 0 8px -2px rgba(255, 0, 85, 0.2)',
        'neon-green': '0 0 20px -3px rgba(0, 255, 102, 0.35)',
        'cyber-card': '0 4px 20px -2px rgba(0, 0, 0, 0.7), inset 0 1px 0 0 rgba(255, 255, 255, 0.05)',
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' }
        },
        pulseGlow: {
          '0%, 100%': { opacity: '0.4' },
          '50%': { opacity: '0.9' }
        },
        radarSweep: {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' }
        }
      },
      animation: {
        'scanline': 'scanline 8s linear infinite',
        'pulse-glow': 'pulseGlow 2.5s ease-in-out infinite',
        'radar': 'radarSweep 3s linear infinite'
      }
    },
  },
  plugins: [],
}
