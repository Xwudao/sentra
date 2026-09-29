import presetIcons from '@unocss/preset-icons'
import { defineConfig, presetWind3 } from 'unocss'

export default defineConfig({
  content: {
    pipeline: {
      include: ['./src/**/*.{ts,tsx,html}'],
    },
  },
  presets: [
    presetWind3({ preflight: false }),
    presetIcons({
      scale: 1.1,
      prefix: 'i-',
      extraProperties: {
        display: 'inline-block',
        'vertical-align': 'middle',
      },
    }),
  ],
})
