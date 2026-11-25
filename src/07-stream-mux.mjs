// FILE: 07-stream-mux.mjs
/**
 * AETHER-W6 Multi-Stream HoL-Free Multiplexer
 * - Sender: Weighted priority round-robin scheduling + entropy-aware Zstd compression
 * - Receiver: Per-stream independent reordering (zero cross-stream HoL blocking) & FCT tracking
 */

import { performance } from 'node:perf_hooks';
import { adaptiveCompress, adaptiveDecompress } from './05-entropy-zstd.mjs';
import { MAX_STREAM_PAYLOAD } from './03-wire-format.mjs';

function asBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new TypeError('Expected Buffer or Uint8Array');
}

export class AetherStream {
  /**
   * @param {number} streamId
   * @param {number} [priority=3] 0 (lowest) .. 7 (highest)
   */
  constructor(streamId, priority = 3) {
    this.streamId = streamId;
    this.priority = Math.max(0, Math.min(7, priority | 0));

    // Sender state
    this.nextTxOffset = 0;
    /** @type {Array<{ streamId: number, streamOffset: number, priority: number, fin: boolean, zstd: boolean, payload: Buffer, origLen: number }>} */
    this.txQueue = [];

    // Receiver state
    /** @type {Map<number, Buffer>} */
    this.rxChunks = new Map();
    this.rxNextContiguousOffset = 0;
    this.rxFinOffset = null;
    this.rxCompleted = false;
    this.rxFirstSeenMs = null;
    this.rxCompletedMs = null;
    this.fctMs = null;
    /** @type {Buffer | null} */
    this.assembledData = null;
  }
}

export class StreamMultiplexer {
  /**
   * @param {object} [options]
   * @param {(result: { streamId: number, priority: number, data: Buffer, fctMs: number, chunks: number }) => void} [options.onStreamComplete]
   * @param {number} [options.entropyThreshold=7.2]
   * @param {number} [options.zstdLevel=2]
   */
  constructor({ onStreamComplete = null, entropyThreshold = 7.2, zstdLevel = 2 } = {}) {
    this.onStreamComplete = onStreamComplete;
    this.entropyThreshold = entropyThreshold;
    this.zstdLevel = zstdLevel;

    /** @type {Map<number, AetherStream>} */
    this.streams = new Map();

    // Weighted round-robin deficit counters per streamId (prevents low-priority starvation)
    /** @type {Map<number, number>} */
    this._deficits = new Map();
    /** @type {number[]} */
    this._rrOrder = [];
    this._rrCursor = 0;

    // Compression & transfer telemetry
    this.txOrigBytes = 0;
    this.txWireBytes = 0;
    this.txCompressedChunks = 0;
    this.txBypassChunks = 0;
    this.rxTotalUnits = 0;
    this.rxDuplicateUnits = 0;
  }

  /**
   * Open or retrieve a stream with a given priority (0..7).
   * @param {number} streamId
   * @param {number} [priority=3]
   * @returns {AetherStream}
   */
  openStream(streamId, priority = 3) {
    let stream = this.streams.get(streamId);
    if (!stream) {
      stream = new AetherStream(streamId, priority);
      this.streams.set(streamId, stream);
      this._deficits.set(streamId, 0);
      this._rrOrder.push(streamId);
    }
    return stream;
  }

  /**
   * Slice application data into chunks, apply entropy-aware Zstd compression, and enqueue for transmission.
   * @param {number} streamId
   * @param {Buffer | Uint8Array} dataBuf
   * @param {object} [options]
   * @param {boolean} [options.fin=true]
   * @param {number} [options.chunkSize=1240]
   * @param {number} [options.priority=3]
   * @returns {number} Number of chunks enqueued
   */
  enqueueStreamData(streamId, dataBuf, { fin = true, chunkSize = 1240, priority = 3 } = {}) {
    const buf = asBuffer(dataBuf);
    const maxChunk = Math.min(chunkSize, MAX_STREAM_PAYLOAD);
    if (maxChunk <= 0) {
      throw new RangeError(`Invalid chunkSize: ${chunkSize}`);
    }

    const stream = this.openStream(streamId, priority);
    let enqueued = 0;

    if (buf.length === 0) {
      stream.txQueue.push({
        streamId,
        streamOffset: stream.nextTxOffset++,
        priority: stream.priority,
        fin: Boolean(fin),
        zstd: false,
        payload: Buffer.alloc(0),
        origLen: 0,
      });
      this.txBypassChunks++;
      return 1;
    }

    for (let pos = 0; pos < buf.length; pos += maxChunk) {
      const end = Math.min(buf.length, pos + maxChunk);
      const slice = buf.subarray(pos, end);
      const isLast = end >= buf.length;

      const comp = adaptiveCompress(slice, {
        entropyThreshold: this.entropyThreshold,
        level: this.zstdLevel,
      });

      this.txOrigBytes += comp.origLen;
      this.txWireBytes += comp.outLen;
      if (comp.compressed) {
        this.txCompressedChunks++;
      } else {
        this.txBypassChunks++;
      }

      stream.txQueue.push({
        streamId,
        streamOffset: stream.nextTxOffset++,
        priority: stream.priority,
        fin: Boolean(fin && isLast),
        zstd: comp.compressed,
        payload: comp.data,
        origLen: comp.origLen,
      });
      enqueued++;
    }

    return enqueued;
  }

  /**
   * @returns {boolean}
   */
  hasPendingChunks() {
    for (const stream of this.streams.values()) {
      if (stream.txQueue.length > 0) {
        return true;
      }
    }
    return false;
  }

  /**
   * Pop the next chunk using Deficit Weighted Round-Robin (weight = priority + 1).
   * Guarantees higher-priority streams get proportionally more bandwidth without starving lower-priority streams.
   * @returns {object | null}
   */
  popNextChunk() {
    const n = this._rrOrder.length;
    if (n === 0) return null;

    // Try up to 2 full passes: pass 0 drains existing deficits, pass 1 refills all active streams proportionally
    for (let pass = 0; pass < 2; pass++) {
      if (pass === 1) {
        for (const sid of this._rrOrder) {
          const s = this.streams.get(sid);
          if (s && s.txQueue.length > 0) {
            this._deficits.set(sid, (this._deficits.get(sid) ?? 0) + s.priority + 1);
          }
        }
      }
      for (let i = 0; i < n; i++) {
        const idx = (this._rrCursor + i) % n;
        const streamId = this._rrOrder[idx];
        const stream = this.streams.get(streamId);
        if (!stream || stream.txQueue.length === 0) {
          continue;
        }

        const deficit = this._deficits.get(streamId) ?? 0;
        if (deficit >= 1) {
          this._deficits.set(streamId, deficit - 1);
          this._rrCursor = (idx + 1) % n;
          return stream.txQueue.shift();
        }
      }
    }

    return null;
  }

  /**
   * Receive a decoded stream symbol unit, reorder independently per stream, decompress,
   * and trigger onStreamComplete once FIN and all preceding offsets are contiguous.
   * @param {object} unit
   * @returns {{ completed: boolean, streamId: number, data?: Buffer, fctMs?: number }}
   */
  onStreamUnit({
    streamId,
    streamOffset,
    fin = false,
    zstd = false,
    priority = 3,
    payload,
    nowMs = performance.now(),
  }) {
    this.rxTotalUnits++;
    const stream = this.openStream(streamId, priority);
    stream.priority = priority;

    if (stream.rxFirstSeenMs === null) {
      stream.rxFirstSeenMs = nowMs;
    }

    if (stream.rxCompleted || stream.rxChunks.has(streamOffset)) {
      this.rxDuplicateUnits++;
      return { completed: false, streamId };
    }

    const decompressed = adaptiveDecompress(payload, zstd);
    stream.rxChunks.set(streamOffset, decompressed);

    if (fin) {
      stream.rxFinOffset = streamOffset;
    }

    while (stream.rxChunks.has(stream.rxNextContiguousOffset)) {
      stream.rxNextContiguousOffset++;
    }

    if (
      !stream.rxCompleted &&
      stream.rxFinOffset !== null &&
      stream.rxNextContiguousOffset > stream.rxFinOffset
    ) {
      const totalChunks = stream.rxFinOffset + 1;
      /** @type {Buffer[]} */
      const ordered = new Array(totalChunks);
      let totalBytes = 0;
      for (let i = 0; i < totalChunks; i++) {
        const chunk = stream.rxChunks.get(i);
        ordered[i] = chunk;
        totalBytes += chunk.length;
      }

      stream.assembledData = Buffer.concat(ordered, totalBytes);
      stream.rxCompleted = true;
      stream.rxCompletedMs = nowMs;
      stream.fctMs = Math.max(0, nowMs - stream.rxFirstSeenMs);

      const result = {
        streamId,
        priority: stream.priority,
        data: stream.assembledData,
        fctMs: stream.fctMs,
        chunks: totalChunks,
      };
      if (typeof this.onStreamComplete === 'function') {
        this.onStreamComplete(result);
      }
      return {
        completed: true,
        streamId,
        data: stream.assembledData,
        fctMs: stream.fctMs,
      };
    }

    return { completed: false, streamId };
  }

  /**
   * Retrieve assembled result for a completed stream.
   * @param {number} streamId
   * @returns {{ streamId: number, priority: number, completed: boolean, fctMs: number | null, data: Buffer | null } | null}
   */
  getStreamResult(streamId) {
    const stream = this.streams.get(streamId);
    if (!stream) return null;
    return {
      streamId: stream.streamId,
      priority: stream.priority,
      completed: stream.rxCompleted,
      fctMs: stream.fctMs,
      data: stream.assembledData,
    };
  }

  /**
   * Return multiplexer telemetry: compression savings, per-stream FCTs, and high/low priority FCT comparison.
   * @returns {object}
   */
  getStats() {
    const compressionSavingsRatio =
      this.txOrigBytes > 0 ? (this.txOrigBytes - this.txWireBytes) / this.txOrigBytes : 0;

    const streamFcts = [];
    const highPrioFcts = [];
    const lowPrioFcts = [];

    for (const stream of this.streams.values()) {
      if (stream.rxCompleted && stream.fctMs !== null) {
        streamFcts.push({
          streamId: stream.streamId,
          priority: stream.priority,
          fctMs: Number(stream.fctMs.toFixed(2)),
          bytes: stream.assembledData ? stream.assembledData.length : 0,
        });
        if (stream.priority >= 4) {
          highPrioFcts.push(stream.fctMs);
        } else {
          lowPrioFcts.push(stream.fctMs);
        }
      }
    }

    const avg = (arr) =>
      arr.length > 0 ? Number((arr.reduce((a, b) => a + b, 0) / arr.length).toFixed(2)) : null;

    return {
      txOrigBytes: this.txOrigBytes,
      txWireBytes: this.txWireBytes,
      compressionSavingsPct: Number((compressionSavingsRatio * 100).toFixed(2)),
      txCompressedChunks: this.txCompressedChunks,
      txBypassChunks: this.txBypassChunks,
      rxTotalUnits: this.rxTotalUnits,
      rxDuplicateUnits: this.rxDuplicateUnits,
      completedStreams: streamFcts.length,
      totalStreams: this.streams.size,
      avgHighPriorityFctMs: avg(highPrioFcts),
      avgLowPriorityFctMs: avg(lowPrioFcts),
      streamFcts,
    };
  }
}