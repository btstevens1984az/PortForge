import { chromium } from 'playwright'
import { mkdirSync, existsSync, writeFileSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { execSync } from 'child_process'

const __dirname = dirname(fileURLToPath(import.meta.url))
const media = join(__dirname, '..', 'media')
mkdirSync(media, { recursive: true })

const browser = await chromium.launch({ headless: true })
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
await page.goto('http://127.0.0.1:5173', { waitUntil: 'networkidle' })
await page.waitForTimeout(800)

// Encyclopedia with selection
await page.getByPlaceholder('Search port, service, HL7, RDP, risk…').fill('RDP')
await page.waitForTimeout(400)
await page.locator('tbody tr').first().click()
await page.waitForTimeout(400)
await page.screenshot({ path: join(media, '01-encyclopedia.png') })

// Clear search, healthcare filter
await page.getByPlaceholder('Search port, service, HL7, RDP, risk…').fill('')
await page.getByRole('button', { name: 'Healthcare', exact: true }).click()
await page.waitForTimeout(300)
await page.locator('tbody tr').first().click()
await page.waitForTimeout(300)

// Load demo and capture forge
await page.getByRole('button', { name: 'Load demo' }).click()
await page.waitForTimeout(300)
await page.getByRole('button', { name: 'Rule Forge' }).click()
await page.waitForTimeout(500)
await page.screenshot({ path: join(media, '02-rule-forge.png') })

await page.getByRole('button', { name: 'Conflicts' }).click()
await page.waitForTimeout(500)
await page.screenshot({ path: join(media, '03-conflicts.png') })

await page.getByRole('button', { name: 'Export' }).click()
await page.waitForTimeout(500)
await page.screenshot({ path: join(media, '04-export.png') })

// GIF frames
const framesDir = join(media, '_frames')
mkdirSync(framesDir, { recursive: true })
const steps = [
  async () => {
    await page.getByRole('button', { name: 'Encyclopedia' }).click()
    await page.getByRole('button', { name: 'All', exact: true }).first().click()
    await page.getByPlaceholder('Search port, service, HL7, RDP, risk…').fill('')
    await page.getByRole('button', { name: 'critical' }).click()
    await page.waitForTimeout(250)
  },
  async () => {
    await page.getByPlaceholder('Search port, service, HL7, RDP, risk…').fill('HL7')
    await page.waitForTimeout(350)
    await page.locator('tbody tr').first().click()
  },
  async () => {
    await page.getByRole('button', { name: /Forge safe rule/i }).click()
    await page.waitForTimeout(450)
  },
  async () => {
    await page.getByRole('button', { name: 'Conflicts' }).click()
    await page.waitForTimeout(450)
  },
  async () => {
    await page.getByRole('button', { name: 'Export' }).click()
    await page.waitForTimeout(450)
  },
  async () => {
    await page.getByRole('button', { name: 'markdown' }).click()
    await page.waitForTimeout(250)
  },
]

for (let i = 0; i < steps.length; i++) {
  await steps[i]()
  await page.screenshot({ path: join(framesDir, `frame-${String(i).padStart(2, '0')}.png`) })
}

await browser.close()

// Build GIF with ffmpeg if available, else copy a still as placeholder note
try {
  execSync(
    `ffmpeg -y -framerate 1.2 -i "${framesDir}/frame-%02d.png" -vf "scale=1200:-1:flags=lanczos,fps=6" -loop 0 "${join(media, 'portforge-tour.gif')}"`,
    { stdio: 'inherit' },
  )
  console.log('GIF created')
} catch {
  // Fallback: use first conflict screenshot as tour still and write a tiny animated-ish copy note
  console.log('ffmpeg missing — will try sips/Python GIF fallback')
  try {
    const { default: sharp } = await import('sharp').catch(() => ({ default: null }))
    if (!sharp) throw new Error('no sharp')
  } catch {
    // Copy frames into an ordered PNG sequence; use Python Pillow if present
    try {
      execSync(`python3 - <<'PY'
from pathlib import Path
try:
    from PIL import Image
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pillow', '-q'])
    from PIL import Image
frames = sorted(Path(${JSON.stringify(framesDir)}).glob('frame-*.png'))
imgs = [Image.open(f).convert('P', palette=Image.ADAPTIVE) for f in frames]
imgs[0].save(${JSON.stringify(join(media, 'portforge-tour.gif'))}, save_all=True, append_images=imgs[1:], duration=900, loop=0, optimize=True)
print('pillow gif ok')
PY`, { stdio: 'inherit' })
    } catch (e) {
      console.error(e)
      writeFileSync(join(media, 'NOTE.txt'), 'GIF generation failed; screenshots are present.')
    }
  }
}

console.log('Media capture complete')
