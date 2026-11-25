// FILE: 02-rlnc-codec.mjs
/**
 * AETHER-W6 Systematic Sliding-Window RLNC Codec over GF(2^8)
 * - RlncEncoder: Zero-delay systematic window + PRNG-seeded linear repair generator
 * - RlncDecoder: Incremental On-the-Fly Gauss-Jordan Elimination (OFGE) with instant cascading recovery
 */

import {
  GF_INV,
  gfMul,
  scaleRow,
  mulAddRow,
  xorshift32,
  generateCoeffs,
} from './01-gf256.mjs';

/**
 * Resize a Uint8Array upward with zero-padding if needed.
 * @param {Uint8Array} buf
 * @param {number} targetLen
 * @returns {Uint8Array}
 */
function ensureLength(buf, targetLen) {
  if (buf.length >= targetLen) {
    return buf;
  }
  const resized = new Uint8Array(targetLen);
  resized.set(buf);
  return resized;
}

/**
 * Find the minimum integer key in a Map<number, number>.
 * @param {Map<number, number>} map
 * @returns {number} Minimum key, or -1 if empty
 */
function findMinKey(map) {
  let min = Infinity;
  for (const key of map.keys()) {
    if (key < min) {
      min = key;
    }
  }
  return min === Infinity ? -1 : min;
}

export class RlncEncoder {
  /**
   * @param {object} [options]
   * @param {number} [options.maxWindowSize=48]
   * @param {number} [options.maxSymbolSize=1328]
   */
  constructor({ maxWindowSize = 48, maxSymbolSize = 1328 } = {}) {
    this.maxWindowSize = maxWindowSize;
    this.maxSymbolSize = maxSymbolSize;
    /** @type {Map<number, Uint8Array>} */
    this.window = new Map();
    this._seedState = 0xa5a55a5a;
  }

  /**
   * Insert a source symbol into the sliding window (supports in-order or out-of-order writes).
   * Evicts oldest entries if window size or sequence span exceeds maxWindowSize.
   * @param {number} sourceSeq
   * @param {Uint8Array} symbolBytes
   * @returns {number} Current active symbol count in window
   */
  addSourceSymbol(sourceSeq, symbolBytes) {
    if (!Number.isInteger(sourceSeq) || sourceSeq < 1) {
      throw new RangeError(`sourceSeq must be a positive integer, got ${sourceSeq}`);
    }
    if (symbolBytes.length > this.maxSymbolSize) {
      throw new RangeError(
        `Symbol length ${symbolBytes.length} exceeds maxSymbolSize ${this.maxSymbolSize}`
      );
    }

    const copy = new Uint8Array(symbolBytes.length);
    copy.set(symbolBytes);
    this.window.set(sourceSeq, copy);

    // Enforce both count bound and span bound by evicting oldest sequence numbers
    if (this.window.size > 1) {
      let maxSeq = -1;
      for (const seq of this.window.keys()) {
        if (seq > maxSeq) maxSeq = seq;
      }
      const minAllowedSeq = maxSeq - this.maxWindowSize + 1;
      for (const seq of Array.from(this.window.keys())) {
        if (seq < minAllowedSeq) {
          this.window.delete(seq);
        }
      }
    }

    while (this.window.size > this.maxWindowSize) {
      const oldest = findMinKey(this.window);
      if (oldest === -1) break;
      this.window.delete(oldest);
    }

    return this.window.size;
  }

  /**
   * Release all source symbols with seq <= cumSourceSeq.
   * @param {number} cumSourceSeq
   */
  ackCumulative(cumSourceSeq) {
    for (const seq of Array.from(this.window.keys())) {
      if (seq <= cumSourceSeq) {
        this.window.delete(seq);
      }
    }
  }

  /**
   * Return the active contiguous span { winStart, winLen } or null if empty.
   * @returns {{ winStart: number, winLen: number } | null}
   */
  getWindowRange() {
    if (this.window.size === 0) {
      return null;
    }
    let minSeq = Infinity;
    let maxSeq = -1;
    for (const seq of this.window.keys()) {
      if (seq < minSeq) minSeq = seq;
      if (seq > maxSeq) maxSeq = seq;
    }
    return {
      winStart: minSeq,
      winLen: maxSeq - minSeq + 1,
    };
  }

  /**
   * Retrieve a defensive copy of a cached source symbol for fallback retransmission.
   * @param {number} sourceSeq
   * @returns {Uint8Array | null}
   */
  getSourceSymbol(sourceSeq) {
    const sym = this.window.get(sourceSeq);
    if (!sym) {
      return null;
    }
    const copy = new Uint8Array(sym.length);
    copy.set(sym);
    return copy;
  }

  /**
   * Generate a coded repair symbol over the active window [winStart, winStart + winLen - 1].
   * Missing holes are treated as all-zero; shorter symbols are implicitly zero-padded to symbolLen.
   * @param {number} [seed]
   * @returns {{ winStart: number, winLen: number, prngSeed: number, symbolLen: number, codedSymbol: Uint8Array } | null}
   */
  generateRepair(seed) {
    const range = this.getWindowRange();
    if (!range) {
      return null;
    }

    const { winStart, winLen } = range;
    let prngSeed;
    if (seed === undefined || seed === null) {
      this._seedState = xorshift32(this._seedState);
      prngSeed = this._seedState;
    } else {
      prngSeed = (seed >>> 0) || 0x9e3779b9;
    }

    let symbolLen = 0;
    for (let i = 0; i < winLen; i++) {
      const sym = this.window.get(winStart + i);
      if (sym && sym.length > symbolLen) {
        symbolLen = sym.length;
      }
    }

    const coeffs = generateCoeffs(prngSeed, winLen);
    const codedSymbol = new Uint8Array(symbolLen);

    for (let i = 0; i < winLen; i++) {
      const sym = this.window.get(winStart + i);
      if (sym && sym.length > 0) {
        mulAddRow(codedSymbol, sym, coeffs[i], sym.length);
      }
    }

    return {
      winStart,
      winLen,
      prngSeed,
      symbolLen,
      codedSymbol,
    };
  }
}

export class RlncDecoder {
  /**
   * @param {object} [options]
   * @param {number} [options.maxKnownHistory=512]
   * @param {number} [options.maxActiveEquations=128]
   */
  constructor({ maxKnownHistory = 512, maxActiveEquations = 128 } = {}) {
    this.maxKnownHistory = maxKnownHistory;
    this.maxActiveEquations = maxActiveEquations;

    /** @type {Map<number, Uint8Array>} */
    this.knownSymbols = new Map();

    /**
     * Reduced Row Echelon Form (RREF) sparse pivot table:
     * pivotSeq -> { coeffs: Map<number, number>, data: Uint8Array }
     * Invariant: for every pivot p, coeffs.get(p) === 1, p is min key,
     * and no other pivot q appears in coeffs.
     * @type {Map<number, { coeffs: Map<number, number>, data: Uint8Array }>}
     */
    this.pivots = new Map();

    /** Highest contiguous delivered sourceSeq (sourceSeq starts at 1) */
    this.cumSeq = 0;

    this.stats = {
      systematicReceived: 0,
      repairReceived: 0,
      recoveredByRlnc: 0,
      redundantEquations: 0,
      pivotsInserted: 0,
      evictedEquations: 0,
    };
  }

  /**
   * Advance cumSeq across contiguous known symbols.
   */
  _advanceCumSeq() {
    while (this.knownSymbols.has(this.cumSeq + 1)) {
      this.cumSeq++;
    }
  }

  /**
   * Enforce maxKnownHistory by pruning oldest delivered symbols (seq <= cumSeq).
   */
  _autoPruneKnown() {
    if (this.knownSymbols.size <= this.maxKnownHistory) {
      return;
    }
    const minKeep = Math.max(1, this.cumSeq - Math.floor(this.maxKnownHistory / 2) + 1);
    for (const seq of Array.from(this.knownSymbols.keys())) {
      if (this.knownSymbols.size <= this.maxKnownHistory) break;
      if (seq < minKeep && seq <= this.cumSeq) {
        this.knownSymbols.delete(seq);
      }
    }
  }

  /**
   * Substitute a newly known symbol into all active pivot rows and cascade any newly solved symbols.
   * @param {number} initialSeq
   * @param {Uint8Array} initialData
   * @param {Array<{ sourceSeq: number, data: Uint8Array }>} newlySolved
   */
  _substituteKnownCascade(initialSeq, initialData, newlySolved) {
    /** @type {Array<{ seq: number, data: Uint8Array }>} */
    const queue = [{ seq: initialSeq, data: initialData }];

    while (queue.length > 0) {
      const { seq, data } = queue.shift();

      // 1. If an active pivot row has `seq` as its own pivot column, detach, eliminate, and re-insert
      if (this.pivots.has(seq)) {
        const pivotRow = this.pivots.get(seq);
        this.pivots.delete(seq);

        const factor = pivotRow.coeffs.get(seq);
        if (factor) {
          if (data.length > pivotRow.data.length) {
            pivotRow.data = ensureLength(pivotRow.data, data.length);
          }
          mulAddRow(pivotRow.data, data, factor, data.length);
          pivotRow.coeffs.delete(seq);
        }

        const solvedFromReinsert = [];
        this._insertReducedEquation(pivotRow.coeffs, pivotRow.data, solvedFromReinsert);
        for (const item of solvedFromReinsert) {
          newlySolved.push(item);
          queue.push({ seq: item.sourceSeq, data: item.data });
        }
      }

      // 2. Eliminate `seq` from all remaining pivot rows that reference `seq` as a non-pivot column
      for (const [p, row] of Array.from(this.pivots.entries())) {
        const factor = row.coeffs.get(seq);
        if (!factor) continue;

        if (data.length > row.data.length) {
          row.data = ensureLength(row.data, data.length);
        }
        mulAddRow(row.data, data, factor, data.length);
        row.coeffs.delete(seq);

        // Because `p` has coeff 1 and is untouched, size === 1 means `p` is immediately solved
        if (row.coeffs.size === 1) {
          this.pivots.delete(p);
          if (!this.knownSymbols.has(p)) {
            this.knownSymbols.set(p, row.data);
            this.stats.recoveredByRlnc++;
            const copy = new Uint8Array(row.data.length);
            copy.set(row.data);
            newlySolved.push({ sourceSeq: p, data: copy });
            queue.push({ seq: p, data: row.data });
          }
        }
      }
    }
  }

  /**
   * Insert an equation (coeffs, data) using full Gauss-Jordan incremental reduction (RREF):
   * 1. Substitute all knownSymbols
   * 2. Forward elimination against existing pivots
   * 3. Normalize on new minimum pivot p
   * 4. Eliminate any existing pivots at columns > p (keeping RREF)
   * 5. If single-unknown -> solve & cascade; else store pivot and backward-substitute into all other pivots
   * @param {Map<number, number>} coeffs
   * @param {Uint8Array} data
   * @param {Array<{ sourceSeq: number, data: Uint8Array }>} newlySolved
   */
  _insertReducedEquation(coeffs, data, newlySolved) {
    // Step 1: Substitute all currently known symbols
    for (const [seq, coeff] of Array.from(coeffs.entries())) {
      const known = this.knownSymbols.get(seq);
      if (known) {
        if (known.length > data.length) {
          data = ensureLength(data, known.length);
        }
        mulAddRow(data, known, coeff, known.length);
        coeffs.delete(seq);
      }
    }

    // Step 2: Forward elimination against existing pivot columns
    let pivotCol = -1;
    while (true) {
      const minCol = findMinKey(coeffs);
      if (minCol === -1) {
        this.stats.redundantEquations++;
        return;
      }
      if (!this.pivots.has(minCol)) {
        pivotCol = minCol;
        break;
      }
      const pivotRow = this.pivots.get(minCol);
      const factor = coeffs.get(minCol);
      if (pivotRow.data.length > data.length) {
        data = ensureLength(data, pivotRow.data.length);
      }
      mulAddRow(data, pivotRow.data, factor, pivotRow.data.length);
      for (const [pCol, pCoeff] of pivotRow.coeffs.entries()) {
        const nextVal = (coeffs.get(pCol) || 0) ^ gfMul(pCoeff, factor);
        if (nextVal === 0) {
          coeffs.delete(pCol);
        } else {
          coeffs.set(pCol, nextVal);
        }
      }
    }

    // Step 3: Normalize the new pivot row so coeffs.get(pivotCol) === 1
    const leadCoeff = coeffs.get(pivotCol);
    if (leadCoeff !== 1) {
      const inv = GF_INV[leadCoeff];
      scaleRow(data, inv, data.length);
      for (const [col, val] of coeffs.entries()) {
        coeffs.set(col, gfMul(val, inv));
      }
    }

    // Step 4: Eliminate any existing pivots at columns > pivotCol to preserve strict RREF
    let reduced = true;
    while (reduced) {
      reduced = false;
      for (const col of Array.from(coeffs.keys())) {
        if (col !== pivotCol && this.pivots.has(col)) {
          const pivotRow = this.pivots.get(col);
          const factor = coeffs.get(col);
          if (pivotRow.data.length > data.length) {
            data = ensureLength(data, pivotRow.data.length);
          }
          mulAddRow(data, pivotRow.data, factor, pivotRow.data.length);
          for (const [pCol, pCoeff] of pivotRow.coeffs.entries()) {
            const nextVal = (coeffs.get(pCol) || 0) ^ gfMul(pCoeff, factor);
            if (nextVal === 0) {
              coeffs.delete(pCol);
            } else {
              coeffs.set(pCol, nextVal);
            }
          }
          reduced = true;
        }
      }
    }

    // Step 5a: If reduced to a single unknown, immediately solve and cascade
    if (coeffs.size === 1) {
      if (!this.knownSymbols.has(pivotCol)) {
        this.knownSymbols.set(pivotCol, data);
        this.stats.recoveredByRlnc++;
        const copy = new Uint8Array(data.length);
        copy.set(data);
        newlySolved.push({ sourceSeq: pivotCol, data: copy });
        this._substituteKnownCascade(pivotCol, data, newlySolved);
      }
      return;
    }

    // Step 5b: Insert new pivot row and backward-substitute `pivotCol` out of all existing pivots
    this.pivots.set(pivotCol, { coeffs, data });
    this.stats.pivotsInserted++;

    /** @type {Array<{ seq: number, data: Uint8Array }>} */
    const resolvedPivots = [];

    for (const [otherPivot, otherRow] of Array.from(this.pivots.entries())) {
      if (otherPivot === pivotCol) continue;
      const factor = otherRow.coeffs.get(pivotCol);
      if (!factor) continue;

      if (data.length > otherRow.data.length) {
        otherRow.data = ensureLength(otherRow.data, data.length);
      }
      mulAddRow(otherRow.data, data, factor, data.length);
      for (const [cCol, cVal] of coeffs.entries()) {
        const nextVal = (otherRow.coeffs.get(cCol) || 0) ^ gfMul(cVal, factor);
        if (nextVal === 0) {
          otherRow.coeffs.delete(cCol);
        } else {
          otherRow.coeffs.set(cCol, nextVal);
        }
      }

      if (otherRow.coeffs.size === 1) {
        this.pivots.delete(otherPivot);
        if (!this.knownSymbols.has(otherPivot)) {
          this.knownSymbols.set(otherPivot, otherRow.data);
          this.stats.recoveredByRlnc++;
          const copy = new Uint8Array(otherRow.data.length);
          copy.set(otherRow.data);
          newlySolved.push({ sourceSeq: otherPivot, data: copy });
          resolvedPivots.push({ seq: otherPivot, data: otherRow.data });
        }
      }
    }

    // Cascade any pivots that became single-unknown during backward substitution
    for (const item of resolvedPivots) {
      this._substituteKnownCascade(item.seq, item.data, newlySolved);
    }

    // Enforce active equation cap by evicting the oldest pivot
    while (this.pivots.size > this.maxActiveEquations) {
      const oldestPivot = findMinKey(this.pivots);
      if (oldestPivot === -1) break;
      this.pivots.delete(oldestPivot);
      this.stats.evictedEquations++;
    }
  }

  /**
   * Process an incoming systematic source symbol.
   * Returns only newly recovered symbols from RLNC equations (excludes sourceSeq itself).
   * @param {number} sourceSeq
   * @param {Uint8Array} bytes
   * @returns {Array<{ sourceSeq: number, data: Uint8Array }>}
   */
  addSourceSymbol(sourceSeq, bytes) {
    if (!Number.isInteger(sourceSeq) || sourceSeq < 1) {
      throw new RangeError(`sourceSeq must be a positive integer, got ${sourceSeq}`);
    }
    this.stats.systematicReceived++;

    if (this.knownSymbols.has(sourceSeq) || sourceSeq <= this.cumSeq) {
      return [];
    }

    const copy = new Uint8Array(bytes.length);
    copy.set(bytes);
    this.knownSymbols.set(sourceSeq, copy);

    /** @type {Array<{ sourceSeq: number, data: Uint8Array }>} */
    const newlySolved = [];
    this._substituteKnownCascade(sourceSeq, copy, newlySolved);

    this._advanceCumSeq();
    this._autoPruneKnown();
    return newlySolved;
  }

  /**
   * Process an incoming RLNC repair symbol.
   * Returns all source symbols newly recovered via Gauss-Jordan elimination.
   * @param {number} winStart
   * @param {number} winLen
   * @param {number} prngSeed
   * @param {Uint8Array} codedSymbol
   * @returns {Array<{ sourceSeq: number, data: Uint8Array }>}
   */
  addRepairSymbol(winStart, winLen, prngSeed, codedSymbol) {
    this.stats.repairReceived++;
    if (winLen <= 0) {
      return [];
    }

    const coeffArr = generateCoeffs(prngSeed, winLen);
    /** @type {Map<number, number>} */
    const coeffs = new Map();
    for (let i = 0; i < winLen; i++) {
      coeffs.set(winStart + i, coeffArr[i]);
    }

    const data = new Uint8Array(codedSymbol.length);
    data.set(codedSymbol);

    /** @type {Array<{ sourceSeq: number, data: Uint8Array }>} */
    const newlySolved = [];
    this._insertReducedEquation(coeffs, data, newlySolved);

    this._advanceCumSeq();
    this._autoPruneKnown();
    return newlySolved;
  }

  /**
   * @returns {number}
   */
  getCumulativeSeq() {
    return this.cumSeq;
  }

  /**
   * @param {number} seq
   * @returns {boolean}
   */
  hasSymbol(seq) {
    return this.knownSymbols.has(seq) || (seq > 0 && seq <= this.cumSeq);
  }

  /**
   * @returns {object}
   */
  getStats() {
    return {
      ...this.stats,
      knownCount: this.knownSymbols.size,
      activePivots: this.pivots.size,
      cumSeq: this.cumSeq,
    };
  }

  /**
   * Prune known symbols and stale pivot rows strictly below minKeepSeq.
   * @param {number} minKeepSeq
   */
  pruneBelow(minKeepSeq) {
    for (const seq of Array.from(this.knownSymbols.keys())) {
      if (seq < minKeepSeq) {
        this.knownSymbols.delete(seq);
      }
    }
    for (const p of Array.from(this.pivots.keys())) {
      if (p < minKeepSeq) {
        this.pivots.delete(p);
      }
    }
  }
}