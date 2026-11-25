// FILE: 01-gf256.mjs
/**
 * AETHER-W6 GF(2^8) Finite Field Arithmetic & Deterministic PRNG
 * Primitive polynomial: P(x) = x^8 + x^4 + x^3 + x^2 + 1 (0x11d)
 * Generator: alpha = 2
 */

const PRIMITIVE_POLY = 0x11d;
const DEFAULT_PRNG_SEED = 0x9e3779b9;

/** Double-length exponentiation table (eliminates modulo in hot paths) */
export const GF_EXP = new Uint8Array(512);

/** Discrete logarithm table (GF_LOG[0] is unused / 0) */
export const GF_LOG = new Uint8Array(256);

/** Multiplicative inverse table (GF_INV[0] = 0) */
export const GF_INV = new Uint8Array(256);

/** Flattened 64KB multiplication lookup table: GF_MUL_TABLE[(a << 8) | b] = a * b */
export const GF_MUL_TABLE = new Uint8Array(65536);

// Precompute GF_EXP, GF_LOG, GF_INV, and GF_MUL_TABLE at module load
(function initGf256Tables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_EXP[i + 255] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) {
      x ^= PRIMITIVE_POLY;
    }
  }
  GF_EXP[510] = GF_EXP[0];
  GF_EXP[511] = GF_EXP[1];

  GF_INV[0] = 0;
  for (let a = 1; a < 256; a++) {
    GF_INV[a] = GF_EXP[255 - GF_LOG[a]];
  }

  for (let a = 1; a < 256; a++) {
    const rowOffset = a << 8;
    const logA = GF_LOG[a];
    for (let b = 1; b < 256; b++) {
      GF_MUL_TABLE[rowOffset | b] = GF_EXP[logA + GF_LOG[b]];
    }
  }
})();

/**
 * Branchless GF(2^8) multiplication via 64KB LUT.
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function gfMul(a, b) {
  return GF_MUL_TABLE[((a & 0xff) << 8) | (b & 0xff)];
}

/**
 * GF(2^8) multiplicative inverse.
 * @param {number} a
 * @returns {number}
 */
export function gfInv(a) {
  const v = a & 0xff;
  if (v === 0) {
    throw new RangeError('GF(2^8) multiplicative inverse of 0 is undefined');
  }
  return GF_INV[v];
}

/**
 * GF(2^8) division: a / b.
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
export function gfDiv(a, b) {
  const num = a & 0xff;
  const den = b & 0xff;
  if (den === 0) {
    throw new RangeError('GF(2^8) division by zero');
  }
  if (num === 0) {
    return 0;
  }
  return GF_MUL_TABLE[(num << 8) | GF_INV[den]];
}

/**
 * In-place row scaling over GF(2^8): row[i] = row[i] * factor.
 * @param {Uint8Array} row
 * @param {number} factor
 * @param {number} [len=row.length]
 */
export function scaleRow(row, factor, len = row.length) {
  const f = factor & 0xff;
  if (f === 1 || len <= 0) {
    return;
  }
  if (f === 0) {
    row.fill(0, 0, len);
    return;
  }
  const offset = f << 8;
  for (let i = 0; i < len; i++) {
    row[i] = GF_MUL_TABLE[offset | row[i]];
  }
}

/**
 * In-place fused multiply-add over GF(2^8): dst[i] ^= src[i] * factor.
 * @param {Uint8Array} dst
 * @param {Uint8Array} src
 * @param {number} factor
 * @param {number} [len=Math.min(dst.length, src.length)]
 */
export function mulAddRow(dst, src, factor, len = Math.min(dst.length, src.length)) {
  const f = factor & 0xff;
  if (f === 0 || len <= 0) {
    return;
  }
  if (f === 1) {
    for (let i = 0; i < len; i++) {
      dst[i] ^= src[i];
    }
    return;
  }
  const offset = f << 8;
  for (let i = 0; i < len; i++) {
    dst[i] ^= GF_MUL_TABLE[offset | src[i]];
  }
}

/**
 * Deterministic 32-bit xorshift PRNG step (unsigned uint32).
 * @param {number} seed
 * @returns {number}
 */
export function xorshift32(seed) {
  let s = (seed >>> 0) || DEFAULT_PRNG_SEED;
  s ^= (s << 13) >>> 0;
  s ^= s >>> 17;
  s ^= (s << 5) >>> 0;
  return s >>> 0;
}

/**
 * Deterministically generates `count` non-zero GF(2^8) coding coefficients from a 32-bit seed.
 * @param {number} seed
 * @param {number} count
 * @returns {Uint8Array}
 */
export function generateCoeffs(seed, count) {
  if (count < 0) {
    throw new RangeError(`Invalid coefficient count: ${count}`);
  }
  const coeffs = new Uint8Array(count);
  let s = (seed >>> 0) || DEFAULT_PRNG_SEED;
  for (let i = 0; i < count; i++) {
    s = xorshift32(s);
    coeffs[i] = (s & 0xff) || 1;
  }
  return coeffs;
}