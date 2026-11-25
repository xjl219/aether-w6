// FILE: 05-entropy-zstd.mjs
/**
 * AETHER-W6 Shannon Entropy-Aware Adaptive Zstd Pipeline
 * - Fast 256-bin byte frequency Shannon entropy estimator H in [0, 8]
 * - Zero-copy bypass for high-entropy/pre-compressed payloads (H >= 7.2)
 * - Native Node.js v24 zlib.zstdCompressSync / zstdDecompressSync
 */

import { zstdCompressSync, zstdDecompressSync, constants } from 'node:zlib';

const LOG2 = Math.LN2;

function asBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new TypeError('Expected Buffer or Uint8Array');
}

/**
 * Compute Shannon entropy H in [0, 8] bits/byte for a Buffer/Uint8Array.
 * Returns 0 for empty input.
 * @param {Buffer | Uint8Array} input
 * @returns {number}
 */
export function shannonEntropy(input) {
  const len = input.length;
  if (len === 0) {
    return 0;
  }

  const counts = new Uint32Array(256);
  for (let i = 0; i < len; i++) {
    counts[input[i]]++;
  }

  let entropy = 0;
  const invLen = 1 / len;
  for (let i = 0; i < 256; i++) {
    const c = counts[i];
    if (c > 0) {
      const p = c * invLen;
      entropy -= p * (Math.log(p) / LOG2);
    }
  }
  return entropy;
}

/**
 * Entropy-gated adaptive Zstd compression.
 * Only compresses when buf.length >= minBytes, entropy < entropyThreshold,
 * and compressed output is strictly shorter than the original payload.
 * @param {Buffer | Uint8Array} input
 * @param {object} [options]
 * @param {number} [options.entropyThreshold=7.2]
 * @param {number} [options.minBytes=64]
 * @param {number} [options.level=2]
 * @returns {{ data: Buffer, compressed: boolean, entropy: number, origLen: number, outLen: number }}
 */
export function adaptiveCompress(
  input,
  { entropyThreshold = 7.2, minBytes = 64, level = 2 } = {}
) {
  const buf = asBuffer(input);
  const origLen = buf.length;
  const entropy = shannonEntropy(buf);

  if (origLen < minBytes || entropy >= entropyThreshold) {
    return {
      data: buf,
      compressed: false,
      entropy,
      origLen,
      outLen: origLen,
    };
  }

  const compressedBuf = zstdCompressSync(buf, {
    params: {
      [constants.ZSTD_c_compressionLevel]: level,
    },
  });

  if (compressedBuf.length < origLen) {
    return {
      data: compressedBuf,
      compressed: true,
      entropy,
      origLen,
      outLen: compressedBuf.length,
    };
  }

  return {
    data: buf,
    compressed: false,
    entropy,
    origLen,
    outLen: origLen,
  };
}

/**
 * Decompress payload if marked as Zstd-compressed; otherwise return zero-copy Buffer view.
 * @param {Buffer | Uint8Array} input
 * @param {boolean} isCompressed
 * @returns {Buffer}
 */
export function adaptiveDecompress(input, isCompressed) {
  const buf = asBuffer(input);
  if (!isCompressed) {
    return buf;
  }
  return zstdDecompressSync(buf);
}