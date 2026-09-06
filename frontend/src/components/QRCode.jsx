import { memo, useRef, useEffect } from "react";

// Minimal QR code renderer using Canvas API.
// Encodes the data as a QR matrix and renders it as a canvas element.
// Only supports alphanumeric/byte mode up to ~120 chars (sufficient for otpauth:// URIs).

const EC_LEVEL = 1; // L (low) — 7% error correction, maximises data capacity

// Galois field GF(256) arithmetic
const EXP = new Uint8Array(256);
const LOG = new Uint8Array(256);
{
  let v = 1;
  for (let i = 0; i < 256; i++) {
    EXP[i] = v;
    LOG[v] = i;
    v = (v << 1) ^ (v >= 128 ? 0x11d : 0);
  }
}
function gfMul(a, b) {
  return a === 0 || b === 0 ? 0 : EXP[(LOG[a] + LOG[b]) % 255];
}

function generatorPoly(nsym) {
  let g = new Uint8Array([1]);
  for (let i = 0; i < nsym; i++) {
    const ng = new Uint8Array(g.length + 1);
    for (let j = 0; j < g.length; j++) {
      ng[j] ^= g[j];
      ng[j + 1] ^= gfMul(g[j], EXP[i]);
    }
    g = ng;
  }
  return g;
}

function ecPoly(data, nsym) {
  const gen = generatorPoly(nsym);
  const res = new Uint8Array(data.length + nsym);
  res.set(data);
  for (let i = 0; i < data.length; i++) {
    const coef = res[i];
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j++) {
        res[i + j] ^= gfMul(gen[j], coef);
      }
    }
  }
  return res.slice(data.length);
}

// QR version info: [totalCodewords, ecCodewordsPerBlock, group1Blocks, group1DataCW, group2Blocks, group2DataCW]
const VERSION_TABLE = [
  null,
  [26, 7, 1, 19, 0, 0], [44, 10, 1, 34, 0, 0], [70, 15, 1, 55, 0, 0],
  [100, 20, 1, 80, 0, 0], [134, 26, 1, 108, 0, 0], [172, 18, 2, 68, 0, 0],
  [196, 20, 2, 78, 0, 0], [242, 24, 2, 97, 0, 0], [292, 30, 2, 116, 0, 0],
  [346, 18, 2, 68, 2, 69], [404, 20, 4, 81, 0, 0], [466, 24, 2, 92, 2, 93],
  [532, 26, 4, 107, 0, 0], [581, 30, 3, 115, 1, 116], [655, 22, 5, 87, 1, 88],
  [733, 24, 5, 98, 1, 99], [815, 28, 1, 107, 5, 108], [901, 30, 5, 120, 1, 121],
  [991, 28, 1, 113, 5, 114], [1085, 28, 5, 107, 1, 108], [1156, 28, 3, 115, 4, 116],
  [1258, 28, 3, 115, 2, 116], [1364, 28, 4, 115, 4, 116], [1474, 28, 2, 121, 6, 122],
  [1588, 30, 4, 121, 6, 122], [1706, 30, 2, 122, 7, 123], [1828, 30, 4, 122, 4, 123],
  [1921, 30, 6, 117, 4, 118], [2051, 30, 8, 116, 4, 117], [2185, 30, 10, 115, 2, 116],
];

const ALIGNMENT_PATTERNS = [
  null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54],
  [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70],
];

function chooseVersion(dataLen) {
  for (let v = 1; v <= 31; v++) {
    const info = VERSION_TABLE[v];
    if (!info) break;
    const [totalCW] = info;
    const dataBits = v <= 9 ? 8 : 16;
    const maxData = Math.floor((totalCW - ecCodewordsForVersion(v)) * 8 / dataBits);
    // Byte mode: 4 bit mode + char count indicator
    const countBits = v <= 9 ? 8 : 16;
    const needed = 4 + countBits + dataLen * 8;
    if (needed <= (totalCW - ecCodewordsForVersion(v)) * 8) return v;
  }
  return -1;
}

function ecCodewordsForVersion(v) {
  let total = 0;
  const info = VERSION_TABLE[v];
  if (!info) return 0;
  const [, ecPerBlock, g1Blocks, g1Data, g2Blocks, g2Data] = info;
  total = (g1Blocks + g2Blocks) * ecPerBlock;
  return total;
}

function makeDataBits(text, version) {
  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
  push(0b0100, 4); // byte mode
  const countBits = version <= 9 ? 8 : 16;
  push(text.length, countBits);
  for (let i = 0; i < text.length; i++) push(text.charCodeAt(i) & 0xff, 8);
  return bits;
}

function padBits(bits, totalBits) {
  let i = bits.length;
  while (i < totalBits) {
    bits.push(1, 1, 1, 0, 1, 1, 0, 0);
    i += 8;
  }
  bits.length = totalBits;
  return bits;
}

function bitsToBytes(bits) {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) bytes[i >> 3] |= bits[i] << (7 - (i & 7));
  return bytes;
}

function buildCodewords(text, version) {
  const info = VERSION_TABLE[version];
  const [, ecPerBlock, g1Blocks, g1Data, g2Blocks, g2Data] = info;
  const totalDataCW = g1Blocks * g1Data + (g2Blocks ? g2Blocks * g2Data : 0);
  const totalBits = totalDataCW * 8;

  let bits = makeDataBits(text, version);
  bits = padBits(bits, totalBits);
  const dataBytes = bitsToBytes(bits);

  // Split into blocks
  const blocks = [];
  let offset = 0;
  for (let i = 0; i < g1Blocks; i++) {
    blocks.push(dataBytes.slice(offset, offset + g1Data));
    offset += g1Data;
  }
  for (let i = 0; i < g2Blocks; i++) {
    blocks.push(dataBytes.slice(offset, offset + g2Data));
    offset += g2Data;
  }

  // EC for each block
  const ecBlocks = blocks.map((b) => ecPoly(b, ecPerBlock));

  // Interleave data
  const maxDataLen = Math.max(g1Data, g2Data || 0);
  const interleaved = [];
  for (let i = 0; i < maxDataLen; i++) {
    for (const b of blocks) {
      if (i < b.length) interleaved.push(b[i]);
    }
  }
  // Interleave EC
  for (let i = 0; i < ecPerBlock; i++) {
    for (const ec of ecBlocks) {
      interleaved.push(ec[i]);
    }
  }

  return new Uint8Array(interleaved);
}

function createMatrix(size) {
  const m = new Int8Array(size * size); // 0 = unset, 1 = dark, -1 = light, 2 = reserved
  return {
    get(x, y) { return (x >= 0 && x < size && y >= 0 && y < size) ? m[y * size + x] : 1; },
    set(x, y, v) { if (x >= 0 && x < size && y >= 0 && y < size) m[y * size + x] = v; },
    size,
  };
}

function placeFunctionPatterns(mat) {
  const s = mat.size;
  const put = (x, y, dark) => mat.set(x, y, dark ? 1 : -1);

  // Finder patterns
  for (const [cx, cy] of [[7, 7], [s - 8, 7], [7, s - 8]]) {
    for (let dy = -1; dy <= 7; dy++) {
      for (let dx = -1; dx <= 7; dx++) {
        const x = cx + dx, y = cy + dy;
        const inOuter = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6;
        const inInner = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
        const onBorder = dx === 0 || dx === 6 || dy === 0 || dy === 6;
        if (inInner || (inOuter && onBorder)) put(x, y, true);
        else if (inOuter) put(x, y, false);
      }
    }
  }

  // Separators
  for (let i = 0; i < 8; i++) {
    put(7, i, false); put(i, 7, false);
    put(s - 8, i, false); put(i, s - 8, false);
    put(7, s - 1 - i, false); put(s - 1 - i, 7, false);
  }

  // Timing patterns
  for (let i = 8; i < s - 8; i++) {
    put(i, 6, i % 2 === 0);
    put(6, i, i % 2 === 0);
  }

  // Dark module
  put(8, s - 8, true);

  // Alignment patterns (version 2+)
  if (s > 21) {
    const positions = ALIGNMENT_PATTERNS[Math.floor(s / 4 + 1)] || [];
    for (const ay of positions) {
      for (const ax of positions) {
        // Skip if overlapping finder patterns
        if ((ax < 9 && ay < 9) || (ax > s - 10 && ay < 9) || (ax < 9 && ay > s - 10)) continue;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) {
            put(ax + dx, ay + dy, Math.abs(dx) === 2 || Math.abs(dy) === 2 || (dx === 0 && dy === 0));
          }
        }
      }
    }
  }

  // Reserve format info areas
  for (let i = 0; i < 15; i++) {
    if (i < 6) mat.set(i, 8, 2);
    else if (i < 8) mat.set(i + 1, 8, 2);
    else if (i < 9) mat.set(8, 14 - i, 2);
    else mat.set(8, 15 - i, 2);

    if (i < 8) mat.set(8, s - 1 - i, 2);
    else if (i < 15) mat.set(14 - i, 8, 2);
  }
  mat.set(8, 8, 2);
}

function placeData(mat, codewords) {
  const s = mat.size;
  let bitIdx = 0;
  const totalBits = codewords.length * 8;
  let col = s - 1;

  while (col >= 0) {
    if (col === 6) col--; // skip timing column
    for (let row = 0; row < s; row++) {
      for (let c = 0; c < 2; c++) {
        const x = col - c;
        if (mat.get(x, s - 1 - row) === 0) {
          if (bitIdx < totalBits) {
            const byteIdx = bitIdx >> 3;
            const bit = (codewords[byteIdx] >> (7 - (bitIdx & 7))) & 1;
            mat.set(x, s - 1 - row, bit ? 1 : -1);
            bitIdx++;
          } else {
            mat.set(x, s - 1 - row, -1);
          }
        }
      }
    }
    col -= 2;
  }
}

function applyMask(mat, maskFn) {
  const s = mat.size;
  const result = createMatrix(s);
  for (let y = 0; y < s; y++) {
    for (let x = 0; x < s; x++) {
      const val = mat.get(x, y);
      if (val === 2) { result.set(x, y, 2); continue; }
      const masked = maskFn(x, y) ? (val === 1 ? -1 : 1) : val;
      result.set(x, y, masked);
    }
  }
  return result;
}

function maskFunctions() {
  return [
    (x, y) => (x + y) % 2 === 0,
    (x) => x % 2 === 0,
    (y) => y % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 2) + Math.floor(y / 3)) % 2 === 0,
    (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
    (x, y) => ((x + y) % 2 + (x * y) % 3) % 2 === 0,
  ];
}

function renderToCanvas(mat, canvas, scale = 4) {
  const s = mat.size;
  const total = s + 8; // quiet zone
  canvas.width = total * scale;
  canvas.height = total * scale;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#000000";

  for (let y = 0; y < s; y++) {
    for (let x = 0; x < s; x++) {
      if (mat.get(x, y) === 1) {
        ctx.fillRect((x + 4) * scale, (y + 4) * scale, scale, scale);
      }
    }
  }
}

function encode(text) {
  const version = chooseVersion(text.length);
  if (version < 0) throw new Error("Data too long for QR code");
  const size = version * 4 + 17;
  const codewords = buildCodewords(text, version);

  const mat = createMatrix(size);
  placeFunctionPatterns(mat);

  const filled = createMatrix(size);
  placeFunctionPatterns(filled);
  placeData(filled, codewords);

  // Try all masks, pick best
  const masks = maskFunctions();
  let bestMat = null;
  let bestScore = Infinity;
  for (const maskFn of masks) {
    const masked = applyMask(filled, maskFn);
    // Copy function patterns back
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (mat.get(x, y) === 2 || mat.get(x, y) === 1) {
          masked.set(x, y, mat.get(x, y));
        }
      }
    }
    // Simple score: penalise runs and blocks
    let score = 0;
    for (let y = 0; y < size; y++) {
      let run = 1;
      for (let x = 1; x < size; x++) {
        if (masked.get(x, y) === masked.get(x - 1, y)) { run++; if (run === 5) score += 3; else if (run > 5) score++; }
        else run = 1;
      }
    }
    for (let x = 0; x < size; x++) {
      let run = 1;
      for (let y = 1; y < size; y++) {
        if (masked.get(x, y) === masked.get(x, y - 1)) { run++; if (run === 5) score += 3; else if (run > 5) score++; }
        else run = 1;
      }
    }
    if (score < bestScore) { bestScore = score; bestMat = masked; }
  }

  return bestMat;
}

function QRCode({ data, size = 160, className = "" }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    if (!data || !canvasRef.current) return;
    try {
      const mat = encode(data);
      renderToCanvas(mat, canvasRef.current, Math.max(2, Math.floor(size / (mat.size + 8))));
    } catch {
      // If encoding fails, show a placeholder
      const c = canvasRef.current;
      const ctx = c.getContext("2d");
      c.width = size;
      c.height = size;
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, size, size);
      ctx.fillStyle = "#999999";
      ctx.font = `${size / 8}px sans-serif`;
      ctx.textAlign = "center";
      ctx.fillText("QR Error", size / 2, size / 2);
    }
  }, [data, size]);

  return (
    <canvas
      ref={canvasRef}
      width={size}
      height={size}
      className={className}
      style={{ width: size, height: size, imageRendering: "pixelated" }}
    />
  );
}

export default memo(QRCode);
