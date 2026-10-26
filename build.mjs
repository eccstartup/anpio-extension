// Build the ANP wallet MV3 extension into dist/ (Load unpacked).
// esbuild bundles each entry to a self-contained IIFE; static assets are copied.
import { build } from 'esbuild'
import { deflateSync } from 'node:zlib'
import { copyFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(fileURLToPath(import.meta.url))
const dist = join(root, 'dist')
mkdirSync(join(dist, 'icons'), { recursive: true })

const common = {
  bundle: true,
  minify: false,
  sourcemap: 'inline',
  format: 'iife',
  target: ['chrome110'],
  platform: 'browser',
  logLevel: 'info',
}

await Promise.all([
  build({ entryPoints: [join(root, 'src/background.ts')], outfile: join(dist, 'background.js'), ...common }),
  build({ entryPoints: [join(root, 'src/content.ts')], outfile: join(dist, 'content.js'), ...common }),
  build({ entryPoints: [join(root, 'src/injected.ts')], outfile: join(dist, 'injected.js'), ...common }),
  build({ entryPoints: [join(root, 'src/popup/popup.ts')], outfile: join(dist, 'popup.js'), ...common }),
])

copyFileSync(join(root, 'src/manifest.json'), join(dist, 'manifest.json'))
copyFileSync(join(root, 'src/popup/popup.html'), join(dist, 'popup.html'))
copyFileSync(join(root, 'src/popup/popup.css'), join(dist, 'popup.css'))

for (const size of [16, 48, 128]) {
  writeIcon(join(dist, `icons/icon-${size}.png`), size)
}

console.log(`\nBuilt extension -> ${dist}`)

// ---------------------------------------------------------------------------
// Minimal valid PNG (RGBA) generator — teal rounded-square app icon.
// ---------------------------------------------------------------------------
function writeIcon(path, size) {
  writeFileSync(path, pngEncode(size, size, renderIcon(size)))
}

function renderIcon(size) {
  const px = new Uint8Array(size * size * 4)
  const radius = Math.max(2, Math.round(size * 0.22))
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4
      // rounded corner mask
      const dx = Math.min(x + 1, size - x)
      const dy = Math.min(y + 1, size - y)
      if (dx < radius && dy < radius) {
        const dist = Math.hypot(radius - dx, radius - dy)
        if (dist > radius) {
          px[i + 3] = 0
          continue
        }
      }
      px[i] = 44
      px[i + 1] = 122
      px[i + 2] = 123
      px[i + 3] = 255
    }
  }
  // subtle lighter diagonal
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4
      if (px[i + 3] === 0) continue
      const t = (x + y) / (2 * size)
      px[i] = Math.round(44 + t * 40)
      px[i + 1] = Math.round(122 + t * 40)
      px[i + 2] = Math.round(123 + t * 40)
    }
  }
  return px
}

function pngEncode(width, height, rgba) {
  const raw = Buffer.alloc((width * 4 + 1) * height)
  for (let y = 0; y < height; y++) {
    raw[y * (width * 4 + 1)] = 0 // filter type 0 (None)
    Buffer.from(rgba.buffer, rgba.byteOffset + y * width * 4, width * 4).copy(raw, y * (width * 4 + 1) + 1)
  }
  const idat = deflateSync(raw)

  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(width, 0)
  ihdr.writeUInt32BE(height, 4)
  ihdr[8] = 8 // bit depth
  ihdr[9] = 6 // color type RGBA
  ihdr[10] = 0
  ihdr[11] = 0
  ihdr[12] = 0

  const crcTable = makeCrc()
  const chunk = (type, data) => {
    const typeBuf = Buffer.from(type, 'ascii')
    const len = Buffer.alloc(4)
    len.writeUInt32BE(data.length, 0)
    const crcBuf = Buffer.alloc(4)
    crcBuf.writeUInt32BE(crc32(crcTable, Buffer.concat([typeBuf, data])) >>> 0, 0)
    return Buffer.concat([len, typeBuf, data, crcBuf])
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', idat),
    chunk('IEND', Buffer.alloc(0)),
  ])
}

function makeCrc() {
  const table = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    table[n] = c >>> 0
  }
  return table
}

function crc32(table, buf) {
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) c = table[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  return c ^ 0xffffffff
}
