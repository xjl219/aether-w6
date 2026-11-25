// FILE: 09-chaos-bench.mjs
/**
 * AETHER-W6 vs TCP-Reno/AIMD Wi-Fi 6 Weak-Network Chaos Benchmark
 * + Multi-Core 16-Core RLNC Compute Headroom Benchmark
 * Zero external dependencies — Node.js v24.21.0 ESM
 */

import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';

import { AetherEndpoint } from '../src/08-aether-endpoint.mjs';
import { runMultiCoreRlncBench } from '../src/worker-rlnc.mjs';

const WIFI6_LINK_MBPS = 173.3;

// Deterministic Mulberry32 PRNG for reproducible chaos injection & payloads
function createPrng(seed) {
  let state = (seed >>> 0) || 0x9e3779b9;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function deterministicRandomBytes(len, seed) {
  const rng = createPrng(seed);
  const buf = Buffer.allocUnsafe(len);
  for (let i = 0; i < len; i++) {
    buf[i] = (rng() * 256) | 0;
  }
  return buf;
}

// ===========================================================================
// 1. Bidirectional Transparent Wi-Fi 6 Chaos UDP Proxy
// ===========================================================================

class DirectionalChaosLink {
  constructor(opts, seed) {
    this.baseDelayMs = opts.baseDelayMs ?? 4;
    this.bandwidthMbps = opts.bandwidthMbps ?? 173.3;
    this.maxQueueDelayMs = opts.maxQueueDelayMs ?? 80;
    this.jitterSigma = opts.jitterSigma ?? 0.4;
    this.jitterScaleMs = opts.jitterScaleMs ?? 1.2;
    this.reorderRate = opts.reorderRate ?? 0;
    this.reorderExtraMs = opts.reorderExtraMs ?? 8;
    this.lossRate = opts.lossRate ?? 0;
    this.ge = opts.ge || null; // { pGoodLoss, pBadLoss, pG2B, pB2G }

    this.bytesPerMs = (this.bandwidthMbps * 1e6) / 8 / 1000;
    this.rng = createPrng(seed);
    this.inBadState = false;
    this.nextFreeMs = 0;

    this.stats = {
      totalPackets: 0,
      deliveredPackets: 0,
      droppedPackets: 0,
      wirelessDropped: 0,
      tailDropped: 0,
      reorderedPackets: 0,
      queueDelaySumMs: 0,
      queuedSamples: 0,
      maxQueueDelayMs: 0,
    };
  }

  _gaussian() {
    const u1 = Math.max(1e-12, this.rng());
    const u2 = this.rng();
    return Math.sqrt(-2.0 * Math.log(u1)) * Math.cos(2.0 * Math.PI * u2);
  }

  _shouldWirelessDrop() {
    if (this.ge) {
      if (!this.inBadState) {
        if (this.rng() < this.ge.pG2B) this.inBadState = true;
      } else {
        if (this.rng() < this.ge.pB2G) this.inBadState = false;
      }
      const pLoss = this.inBadState ? this.ge.pBadLoss : this.ge.pGoodLoss;
      return this.rng() < pLoss;
    }
    return this.lossRate > 0 && this.rng() < this.lossRate;
  }

  /**
   * Process an arriving datagram through wireless loss, bottleneck token-bucket queue,
   * log-normal jitter, and reordering injection.
   * @param {number} byteLen
   * @param {number} nowMs
   * @returns {{ drop: boolean, delayMs: number }}
   */
  process(byteLen, nowMs) {
    this.stats.totalPackets++;

    // 1. Wireless loss (Gilbert-Elliott burst or independent random)
    if (this._shouldWirelessDrop()) {
      this.stats.droppedPackets++;
      this.stats.wirelessDropped++;
      return { drop: true, delayMs: 0 };
    }

    // 2. Bottleneck link serialization queue + finite-depth tail drop (Bufferbloat)
    const txMs = byteLen / this.bytesPerMs;
    const backlogMs = Math.max(0, this.nextFreeMs - nowMs);
    if (backlogMs + txMs > this.maxQueueDelayMs) {
      this.stats.droppedPackets++;
      this.stats.tailDropped++;
      return { drop: true, delayMs: 0 };
    }

    const queueDelayMs = backlogMs;
    this.nextFreeMs = Math.max(nowMs, this.nextFreeMs) + txMs;

    this.stats.queueDelaySumMs += queueDelayMs;
    this.stats.queuedSamples++;
    if (queueDelayMs > this.stats.maxQueueDelayMs) {
      this.stats.maxQueueDelayMs = queueDelayMs;
    }

    // 3. Log-normal jitter via Box-Muller transform
    let jitterMs = 0;
    if (this.jitterSigma > 0) {
      const z = this._gaussian();
      jitterMs = Math.min(25, Math.max(0, (Math.exp(this.jitterSigma * z) - 1) * this.jitterScaleMs));
    }

    // 4. Out-of-order injection
    let reorderDelayMs = 0;
    if (this.reorderRate > 0 && this.rng() < this.reorderRate) {
      reorderDelayMs = this.reorderExtraMs * (0.5 + this.rng());
      this.stats.reorderedPackets++;
    }

    this.stats.deliveredPackets++;
    const totalDelayMs = queueDelayMs + txMs + this.baseDelayMs + jitterMs + reorderDelayMs;
    return { drop: false, delayMs: totalDelayMs };
  }
}

export class Wifi6ChaosProxy {
  /**
   * @param {object} opts
   * @param {string} [opts.targetHost='127.0.0.1']
   * @param {number} opts.targetPort
   * @param {number} [opts.baseDelayMs=4]
   * @param {number} [opts.bandwidthMbps=173.3]
   * @param {number} [opts.maxQueueDelayMs=80]
   * @param {number} [opts.jitterSigma=0.4]
   * @param {number} [opts.reorderRate=0]
   * @param {number} [opts.lossRate=0]
   * @param {object | null} [opts.ge=null]
   * @param {number} [opts.seed=42]
   */
  constructor(opts) {
    this.targetHost = opts.targetHost || '127.0.0.1';
    this.targetPort = opts.targetPort;
    this.uplink = new DirectionalChaosLink(opts, (opts.seed ?? 42) ^ 0x11111111);
    this.downlink = new DirectionalChaosLink(opts, (opts.seed ?? 42) ^ 0x22222222);

    this.clientSock = dgram.createSocket('udp4');
    this.serverSock = dgram.createSocket('udp4');
    this.clientAddr = null;
    this.closed = false;
    /** @type {Set<NodeJS.Timeout>} */
    this._timers = new Set();

    this.clientSock.on('message', (msg, rinfo) => {
      if (this.closed) return;
      this.clientAddr = { address: rinfo.address, port: rinfo.port };
      const res = this.uplink.process(msg.length, performance.now());
      if (res.drop) return;
      const copy = Buffer.from(msg);
      this._schedule(res.delayMs, () => {
        if (!this.closed) {
          this.serverSock.send(copy, this.targetPort, this.targetHost);
        }
      });
    });

    this.serverSock.on('message', (msg) => {
      if (this.closed || !this.clientAddr) return;
      const res = this.downlink.process(msg.length, performance.now());
      if (res.drop) return;
      const copy = Buffer.from(msg);
      const { port, address } = this.clientAddr;
      this._schedule(res.delayMs, () => {
        if (!this.closed) {
          this.clientSock.send(copy, port, address);
        }
      });
    });
  }

  _schedule(delayMs, fn) {
    if (delayMs <= 0.5) {
      fn();
      return;
    }
    const timer = setTimeout(() => {
      this._timers.delete(timer);
      fn();
    }, Math.round(delayMs));
    this._timers.add(timer);
  }

  async start() {
    const bindSock = (sock) =>
      new Promise((resolve, reject) => {
        sock.once('error', reject);
        sock.bind(0, '127.0.0.1', () => {
          sock.off('error', reject);
          resolve(sock.address());
        });
      });
    const [clientAddr] = await Promise.all([
      bindSock(this.clientSock),
      bindSock(this.serverSock),
    ]);
    return clientAddr;
  }

  getStats() {
    const up = this.uplink.stats;
    const dn = this.downlink.stats;
    const totalPackets = up.totalPackets + dn.totalPackets;
    const droppedPackets = up.droppedPackets + dn.droppedPackets;
    const queuedSamples = up.queuedSamples + dn.queuedSamples;
    const queueDelaySumMs = up.queueDelaySumMs + dn.queueDelaySumMs;

    return {
      totalPackets,
      deliveredPackets: up.deliveredPackets + dn.deliveredPackets,
      droppedPackets,
      wirelessDropped: up.wirelessDropped + dn.wirelessDropped,
      tailDropped: up.tailDropped + dn.tailDropped,
      reorderedPackets: up.reorderedPackets + dn.reorderedPackets,
      actualLossPct: totalPackets > 0 ? Number(((droppedPackets / totalPackets) * 100).toFixed(2)) : 0,
      avgQueueDelayMs: queuedSamples > 0 ? Number((queueDelaySumMs / queuedSamples).toFixed(2)) : 0,
      maxQueueDelayMs: Number(Math.max(up.maxQueueDelayMs, dn.maxQueueDelayMs).toFixed(2)),
    };
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    for (const t of this._timers) clearTimeout(t);
    this._timers.clear();

    const closeSock = (sock) =>
      new Promise((resolve) => {
        try {
          sock.close(() => resolve());
        } catch {
          resolve();
        }
      });
    await Promise.all([closeSock(this.clientSock), closeSock(this.serverSock)]);
  }
}

// ===========================================================================
// 2. Packet-Level TCP-Reno/AIMD + Single-Stream HoL Reference Over UDP
// ===========================================================================

const TCP_HDR_LEN = 12;
const TCP_MSS = 1280;
const TCP_PKT_DATA = 1;
const TCP_PKT_ACK = 2;

function encodeTcpPkt(type, seq, txTimeUs, payload = null) {
  const payLen = payload ? payload.length : 0;
  const buf = Buffer.allocUnsafe(TCP_HDR_LEN + payLen);
  buf.writeUInt8(type, 0);
  buf.writeUInt8(0, 1);
  buf.writeUInt16BE(payLen, 2);
  buf.writeUInt32BE(seq >>> 0, 4);
  buf.writeUInt32BE(txTimeUs >>> 0, 8);
  if (payload && payLen > 0) payload.copy(buf, TCP_HDR_LEN);
  return buf;
}

function decodeTcpPkt(buf) {
  if (buf.length < TCP_HDR_LEN) return null;
  const type = buf.readUInt8(0);
  const payLen = buf.readUInt16BE(2);
  const seq = buf.readUInt32BE(4);
  const txTimeUs = buf.readUInt32BE(8);
  const payload = buf.subarray(TCP_HDR_LEN, TCP_HDR_LEN + payLen);
  return { type, seq, txTimeUs, payload };
}

/**
 * Serialize multiple logical streams into a single ordered TCP byte stream
 * (interleaved in 1200-byte records so TCP's single-stream HoL blocking affects all streams).
 */
function muxStreamsToSingleTcpBytes(streams) {
  const CHUNK = 1200;
  const cursors = streams.map((s) => ({ ...s, offset: 0 }));
  const parts = [];

  let remaining = cursors.length;
  while (remaining > 0) {
    for (const c of cursors) {
      if (c.offset >= c.data.length) continue;
      const end = Math.min(c.data.length, c.offset + CHUNK);
      const slice = c.data.subarray(c.offset, end);
      const fin = end >= c.data.length ? 1 : 0;
      const recHdr = Buffer.allocUnsafe(7);
      recHdr.writeUInt16BE(c.streamId, 0);
      recHdr.writeUInt32BE(slice.length, 2);
      recHdr.writeUInt8(fin, 6);
      parts.push(recHdr, slice);
      c.offset = end;
      if (fin) remaining--;
    }
  }
  return Buffer.concat(parts);
}

export class TcpRenoOverUdpRef {
  constructor() {
    this.serverSock = dgram.createSocket('udp4');
    this.clientSock = dgram.createSocket('udp4');
    this.closed = false;
    this._tickTimer = null;
  }

  async bindServer() {
    return new Promise((resolve, reject) => {
      this.serverSock.once('error', reject);
      this.serverSock.bind(0, '127.0.0.1', () => {
        this.serverSock.off('error', reject);
        resolve(this.serverSock.address());
      });
    });
  }

  /**
   * Transfer all logical streams through the given proxy port using TCP-Reno/AIMD
   * with strict in-order delivery and single-stream HoL blocking.
   */
  async transferStreams(proxyPort, streams, timeoutMs = 15_000) {
    await new Promise((resolve, reject) => {
      this.clientSock.once('error', reject);
      this.clientSock.bind(0, '127.0.0.1', () => {
        this.clientSock.off('error', reject);
        resolve();
      });
    });

    const wireBytes = muxStreamsToSingleTcpBytes(streams);
    /** @type {Buffer[]} */
    const segments = [];
    for (let off = 0; off < wireBytes.length; off += TCP_MSS) {
      segments.push(wireBytes.subarray(off, Math.min(wireBytes.length, off + TCP_MSS)));
    }
    const totalSegs = segments.length;

    const startMs = performance.now();

    // Receiver state (strict in-order delivery -> HoL blocking)
    let rcvNxt = 1;
    /** @type {Map<number, Buffer>} */
    const rxBuf = new Map();
    let parseBuf = Buffer.alloc(0);
    /** @type {Map<number, Buffer[]>} */
    const rxStreamChunks = new Map();
    /** @type {Map<number, { data: Buffer, fctMs: number }>} */
    const completedStreams = new Map();

    // Sender TCP-Reno state
    let sndUna = 1;
    let nextSeq = 1;
    let cwnd = 10 * TCP_MSS;
    let ssthresh = 256 * TCP_MSS;
    let dupAckCount = 0;
    let inFastRecovery = false;

    let srttMs = 20;
    let rttvarMs = 10;
    let rtoMs = 60;

    /** @type {Map<number, { sentMs: number, retransmitted: boolean }>} */
    const inFlight = new Map();
    const metrics = {
      txPackets: 0,
      txBytes: 0,
      fastRetransmits: 0,
      rtoRetransmits: 0,
      acksReceived: 0,
    };

    const sendSegment = (seq, isRetx = false) => {
      if (this.closed || seq < 1 || seq > totalSegs) return;
      const nowMs = performance.now();
      const txUs = Math.trunc(nowMs * 1000) >>> 0;
      const pkt = encodeTcpPkt(TCP_PKT_DATA, seq, txUs, segments[seq - 1]);
      inFlight.set(seq, { sentMs: nowMs, retransmitted: isRetx });
      metrics.txPackets++;
      metrics.txBytes += pkt.length;
      this.clientSock.send(pkt, proxyPort, '127.0.0.1');
    };

    const pumpWindow = () => {
      const cwndSegs = Math.max(2, Math.floor(cwnd / TCP_MSS));
      while (nextSeq <= totalSegs && nextSeq - sndUna < cwndSegs) {
        sendSegment(nextSeq, false);
        nextSeq++;
      }
    };

    return new Promise((resolve, reject) => {
      const doneTimeout = setTimeout(() => {
        cleanup();
        reject(new Error(`TcpRenoOverUdpRef timed out after ${timeoutMs}ms (rcvNxt=${rcvNxt}/${totalSegs})`));
      }, timeoutMs);

      const cleanup = () => {
        clearTimeout(doneTimeout);
        if (this._tickTimer) {
          clearInterval(this._tickTimer);
          this._tickTimer = null;
        }
      };

      const parseOrderedBytes = (chunk, nowMs) => {
        parseBuf = parseBuf.length === 0 ? chunk : Buffer.concat([parseBuf, chunk]);
        while (parseBuf.length >= 7) {
          const streamId = parseBuf.readUInt16BE(0);
          const recLen = parseBuf.readUInt32BE(2);
          const fin = parseBuf.readUInt8(6);
          if (parseBuf.length < 7 + recLen) break;

          const body = Buffer.from(parseBuf.subarray(7, 7 + recLen));
          parseBuf = parseBuf.subarray(7 + recLen);

          let list = rxStreamChunks.get(streamId);
          if (!list) {
            list = [];
            rxStreamChunks.set(streamId, list);
          }
          list.push(body);
          if (fin === 1 && !completedStreams.has(streamId)) {
            completedStreams.set(streamId, {
              data: Buffer.concat(list),
              fctMs: nowMs - startMs,
            });
          }
        }
      };

      // Server: strict in-order reassembly + cumulative ACK
      this.serverSock.on('message', (msg, rinfo) => {
        if (this.closed) return;
        const pkt = decodeTcpPkt(msg);
        if (!pkt || pkt.type !== TCP_PKT_DATA) return;

        const nowMs = performance.now();
        if (pkt.seq >= rcvNxt && !rxBuf.has(pkt.seq)) {
          rxBuf.set(pkt.seq, Buffer.from(pkt.payload));
        }

        // Advance rcvNxt strictly in-order (HoL blocking when any earlier seq is missing)
        while (rxBuf.has(rcvNxt)) {
          const orderedPayload = rxBuf.get(rcvNxt);
          rxBuf.delete(rcvNxt);
          parseOrderedBytes(orderedPayload, nowMs);
          rcvNxt++;
        }

        const ackPkt = encodeTcpPkt(TCP_PKT_ACK, rcvNxt, pkt.txTimeUs);
        this.serverSock.send(ackPkt, rinfo.port, rinfo.address);

        if (completedStreams.size === streams.length) {
          cleanup();
          const elapsedMs = nowMs - startMs;
          resolve({
            elapsedMs,
            completedStreams,
            metrics,
          });
        }
      });

      // Client: TCP-Reno cumulative ACK + 3 DupACK Fast Retransmit + AIMD
      this.clientSock.on('message', (msg) => {
        if (this.closed) return;
        const pkt = decodeTcpPkt(msg);
        if (!pkt || pkt.type !== TCP_PKT_ACK) return;
        metrics.acksReceived++;

        const nowMs = performance.now();
        const ackSeq = pkt.seq;

        if (ackSeq > sndUna) {
          const newlyAcked = ackSeq - sndUna;
          // RTT estimation on non-retransmitted segment (Karn's algorithm)
          const meta = inFlight.get(ackSeq - 1);
          if (meta && !meta.retransmitted) {
            const sampleRtt = Math.max(1, nowMs - meta.sentMs);
            rttvarMs = 0.75 * rttvarMs + 0.25 * Math.abs(srttMs - sampleRtt);
            srttMs = 0.875 * srttMs + 0.125 * sampleRtt;
          }
          // RFC 6298: reset exponential backoff RTO whenever cumulative ACK advances sndUna
          rtoMs = Math.min(800, Math.max(40, srttMs + 4 * rttvarMs));

          for (let s = sndUna; s < ackSeq; s++) {
            inFlight.delete(s);
          }
          sndUna = ackSeq;
          dupAckCount = 0;

          if (inFastRecovery) {
            cwnd = ssthresh;
            inFastRecovery = false;
          } else if (cwnd < ssthresh) {
            cwnd += newlyAcked * TCP_MSS;
          } else {
            cwnd += (newlyAcked * TCP_MSS * TCP_MSS) / cwnd;
          }
          pumpWindow();
        } else if (ackSeq === sndUna && sndUna < nextSeq) {
          dupAckCount++;
          if (dupAckCount === 3) {
            ssthresh = Math.max(2 * TCP_MSS, Math.floor(cwnd / 2));
            cwnd = ssthresh + 3 * TCP_MSS;
            inFastRecovery = true;
            metrics.fastRetransmits++;
            sendSegment(sndUna, true);
          } else if (dupAckCount > 3 && inFastRecovery) {
            cwnd += TCP_MSS;
            pumpWindow();
          }
        }
      });

      // RTO watchdog (2ms tick)
      this._tickTimer = setInterval(() => {
        if (this.closed || sndUna > totalSegs) return;
        const nowMs = performance.now();
        const oldest = inFlight.get(sndUna);
        if (oldest && nowMs - oldest.sentMs >= rtoMs) {
          ssthresh = Math.max(2 * TCP_MSS, Math.floor(cwnd / 2));
          cwnd = 2 * TCP_MSS;
          inFastRecovery = false;
          dupAckCount = 0;
          rtoMs = Math.min(800, rtoMs * 1.5);
          metrics.rtoRetransmits++;
          sendSegment(sndUna, true);
        }
        pumpWindow();
      }, 2);

      // Kick off initial window
      pumpWindow();
    });
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    if (this._tickTimer) {
      clearInterval(this._tickTimer);
      this._tickTimer = null;
    }
    const closeSock = (sock) =>
      new Promise((resolve) => {
        try {
          sock.close(() => resolve());
        } catch {
          resolve();
        }
      });
    await Promise.all([closeSock(this.clientSock), closeSock(this.serverSock)]);
  }
}

// ===========================================================================
// 3. Workload Generator & 4-Scenario Wi-Fi 6 Chaos Matrix
// ===========================================================================

function buildMixedWorkload() {
  const streams = [];

  // 4 low-entropy structured JSON business streams (~38 KB each = ~152 KB)
  for (let i = 1; i <= 4; i++) {
    const records = [];
    for (let r = 0; r < 275; r++) {
      records.push({
        stream: i,
        seq: r,
        service: 'aether-telemetry-bus',
        region: 'us-west-wifi6',
        status: 'ACTIVE',
        metrics: { rssi: -54, mcs: 9, retries: 0, healthy: true },
      });
    }
    const data = Buffer.from(JSON.stringify(records)).subarray(0, 38 * 1024);
    streams.push({
      streamId: i,
      kind: 'json',
      priority: 3,
      data,
    });
  }

  // 2 high-entropy random media streams (42 KB each = 84 KB)
  for (let i = 5; i <= 6; i++) {
    streams.push({
      streamId: i,
      kind: 'media',
      priority: 2,
      data: deterministicRandomBytes(42 * 1024, 1000 + i),
    });
  }

  // 2 high-priority small control streams (2 KB each = 4 KB)
  for (let i = 7; i <= 8; i++) {
    const ctrl = JSON.stringify({
      ctrlId: i,
      priority: 'CRITICAL',
      cmds: Array.from({ length: 32 }, (_, idx) => ({ op: 'SYNC_STATE', slot: idx, ack: true })),
    });
    const data = Buffer.from(ctrl).subarray(0, 2 * 1024);
    streams.push({
      streamId: i,
      kind: 'control',
      priority: 7,
      data,
    });
  }

  const totalBytes = streams.reduce((acc, s) => acc + s.data.length, 0);
  return { streams, totalBytes };
}

export const SCENARIOS = [
  {
    id: 'S1',
    name: '正常 Wi-Fi 轻抖动',
    proxyOpts: {
      baseDelayMs: 4,
      bandwidthMbps: 173.3,
      maxQueueDelayMs: 60,
      lossRate: 0.005,
      jitterSigma: 0.4,
      jitterScaleMs: 1.0,
      reorderRate: 0.005,
      reorderExtraMs: 5,
      seed: 101,
    },
  },
  {
    id: 'S2',
    name: '10% 随机无线丢包',
    proxyOpts: {
      baseDelayMs: 8,
      bandwidthMbps: 173.3,
      maxQueueDelayMs: 60,
      lossRate: 0.10,
      jitterSigma: 0.6,
      jitterScaleMs: 1.2,
      reorderRate: 0.02,
      reorderExtraMs: 8,
      seed: 202,
    },
  },
  {
    id: 'S3',
    name: '20% GE 突发丢包+乱序',
    proxyOpts: {
      baseDelayMs: 10,
      bandwidthMbps: 120.0,
      maxQueueDelayMs: 80,
      // GE steady-state: pi_B = 0.0925/(0.0925+0.25) = 0.270, mean burst = 1/0.25 = 4 pkts,
      // overall loss = 0.73*0.02 + 0.27*0.65 = 19.01%
      ge: { pGoodLoss: 0.02, pBadLoss: 0.65, pG2B: 0.0925, pB2G: 0.25 },
      jitterSigma: 0.6,
      jitterScaleMs: 1.5,
      reorderRate: 0.08,
      reorderExtraMs: 10,
      seed: 303,
    },
  },
  {
    id: 'S4',
    name: '高 Bufferbloat 队列膨胀',
    proxyOpts: {
      baseDelayMs: 6,
      bandwidthMbps: 8.0,
      maxQueueDelayMs: 250,
      lossRate: 0.03,
      jitterSigma: 0.3,
      jitterScaleMs: 0.8,
      reorderRate: 0.01,
      reorderExtraMs: 5,
      seed: 404,
    },
  },
];

// ===========================================================================
// 4. Scenario Runners (AETHER-W6 & TCP-Reno Reference)
// ===========================================================================

async function runAetherScenario(scenario, workload) {
  const server = new AetherEndpoint({ role: 'server' });
  const client = new AetherEndpoint({ role: 'client' });
  let proxy = null;

  try {
    const serverAddr = await server.bind(0, '127.0.0.1');
    proxy = new Wifi6ChaosProxy({
      ...scenario.proxyOpts,
      targetHost: '127.0.0.1',
      targetPort: serverAddr.port,
    });
    const proxyAddr = await proxy.start();

    const { connId } = await client.connect('127.0.0.1', proxyAddr.port, {
      timeoutMs: 8000,
    });

    const t0 = performance.now();
    /** @type {Map<number, number>} */
    const streamFcts = new Map();
    server.on('stream', (ev) => {
      if (ev.connId === connId && !streamFcts.has(ev.streamId)) {
        streamFcts.set(ev.streamId, performance.now() - t0);
      }
    });

    const streamIds = workload.streams.map((s) => s.streamId);
    for (const s of workload.streams) {
      client.sendStream(s.streamId, s.data, { priority: s.priority, fin: true });
    }

    const received = await server.waitForStreams(streamIds, 15_000, connId);
    const elapsedMs = performance.now() - t0;

    // Strict byte-for-byte payload integrity verification
    for (const s of workload.streams) {
      const rx = received.get(s.streamId);
      assert.ok(rx && rx.completed, `AETHER-W6 ${scenario.id} stream ${s.streamId} incomplete`);
      assert.equal(
        Buffer.compare(Buffer.from(rx.data), s.data),
        0,
        `AETHER-W6 ${scenario.id} stream ${s.streamId} payload mismatch`
      );
    }

    const ctrlFcts = workload.streams
      .filter((s) => s.kind === 'control')
      .map((s) => streamFcts.get(s.streamId) ?? elapsedMs);
    const allFcts = Array.from(streamFcts.values());

    const goodputMbps = (workload.totalBytes * 8) / (elapsedMs / 1000) / 1e6;
    const proxyStats = proxy.getStats();
    const clientMetrics = client.getMetrics(connId);
    const serverMetrics = server.getMetrics(connId);

    const pct = (arr, p) => {
      const sorted = [...arr].sort((a, b) => a - b);
      const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
      return Number(sorted[idx].toFixed(1));
    };

    return {
      elapsedMs: Number(elapsedMs.toFixed(1)),
      goodputMbps: Number(goodputMbps.toFixed(2)),
      ctrlAvgFctMs: Number((ctrlFcts.reduce((a, b) => a + b, 0) / ctrlFcts.length).toFixed(1)),
      avgStreamFctMs: Number((allFcts.reduce((a, b) => a + b, 0) / allFcts.length).toFixed(1)),
      p50FctMs: pct(allFcts, 50),
      p95FctMs: pct(allFcts, 95),
      p99FctMs: pct(allFcts, 99),
      actualLossPct: proxyStats.actualLossPct,
      avgQueueDelayMs: proxyStats.avgQueueDelayMs,
      txBytes: clientMetrics.txBytes,
      txSystematic: clientMetrics.txSystematic,
      txRepairs: clientMetrics.txRepairs,
      rlncRecoveredUnits: serverMetrics.rlncRecoveredUnits,
      arqRetransmits: clientMetrics.arqRetransmits,
      compressionSavingsPct: clientMetrics.mux.compressionSavingsPct,
      wirelessLossEvents: clientMetrics.cc.wirelessLossEvents,
      congestionLossEvents: clientMetrics.cc.congestionLossEvents,
      finalRho: clientMetrics.cc.redundancyRho,
    };
  } finally {
    await Promise.allSettled([
      client.close(),
      server.close(),
      proxy ? proxy.close() : Promise.resolve(),
    ]);
  }
}

async function runTcpRenoScenario(scenario, workload) {
  const tcp = new TcpRenoOverUdpRef();
  let proxy = null;

  try {
    const serverAddr = await tcp.bindServer();
    proxy = new Wifi6ChaosProxy({
      ...scenario.proxyOpts,
      targetHost: '127.0.0.1',
      targetPort: serverAddr.port,
    });
    const proxyAddr = await proxy.start();

    const res = await tcp.transferStreams(proxyAddr.port, workload.streams, 25_000);

    // Strict byte-for-byte payload integrity verification
    for (const s of workload.streams) {
      const rx = res.completedStreams.get(s.streamId);
      assert.ok(rx, `TCP-Reno ${scenario.id} stream ${s.streamId} missing`);
      assert.equal(
        Buffer.compare(rx.data, s.data),
        0,
        `TCP-Reno ${scenario.id} stream ${s.streamId} payload mismatch`
      );
    }

    const ctrlFcts = workload.streams
      .filter((s) => s.kind === 'control')
      .map((s) => res.completedStreams.get(s.streamId).fctMs);
    const allFcts = workload.streams.map((s) => res.completedStreams.get(s.streamId).fctMs);
    const pct = (arr, p) => {
      const sorted = [...arr].sort((a, b) => a - b);
      const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
      return Number(sorted[idx].toFixed(1));
    };

    const goodputMbps = (workload.totalBytes * 8) / (res.elapsedMs / 1000) / 1e6;
    const proxyStats = proxy.getStats();

    return {
      elapsedMs: Number(res.elapsedMs.toFixed(1)),
      goodputMbps: Number(goodputMbps.toFixed(2)),
      ctrlAvgFctMs: Number((ctrlFcts.reduce((a, b) => a + b, 0) / ctrlFcts.length).toFixed(1)),
      avgStreamFctMs: Number((allFcts.reduce((a, b) => a + b, 0) / allFcts.length).toFixed(1)),
      p50FctMs: pct(allFcts, 50),
      p95FctMs: pct(allFcts, 95),
      p99FctMs: pct(allFcts, 99),
      actualLossPct: proxyStats.actualLossPct,
      avgQueueDelayMs: proxyStats.avgQueueDelayMs,
      txBytes: res.metrics.txBytes,
      fastRetransmits: res.metrics.fastRetransmits,
      rtoRetransmits: res.metrics.rtoRetransmits,
    };
  } finally {
    await Promise.allSettled([
      tcp.close(),
      proxy ? proxy.close() : Promise.resolve(),
    ]);
  }
}

// ===========================================================================
// 5. Full Benchmark Orchestrator, Markdown Table & JSON Report
// ===========================================================================

export async function runChaosBenchmark() {
  const benchStart = performance.now();
  const workload = buildMixedWorkload();

  console.log(
    `=== AETHER-W6 Wi-Fi 6 Chaos Benchmark (Payload: ${(workload.totalBytes / 1024).toFixed(1)} KB, 8 mixed streams) ===\n`
  );

  const scenarioResults = [];

  for (const sc of SCENARIOS) {
    console.log(`[RUN] ${sc.id} ${sc.name} ...`);
    const aether = await runAetherScenario(sc, workload);
    const tcpReno = await runTcpRenoScenario(sc, workload);

    const goodputSpeedup = Number((aether.goodputMbps / Math.max(0.01, tcpReno.goodputMbps)).toFixed(2));
    const ctrlFctReductionPct = Number(
      (((tcpReno.ctrlAvgFctMs - aether.ctrlAvgFctMs) / Math.max(0.1, tcpReno.ctrlAvgFctMs)) * 100).toFixed(1)
    );

    scenarioResults.push({
      id: sc.id,
      name: sc.name,
      aether,
      tcpReno,
      goodputSpeedup,
      ctrlFctReductionPct,
    });
  }

  // Multi-Core RLNC Compute Benchmark (1, 4, 8, 16 workers)
  console.log('\n[RUN] Multi-Core RLNC GF(2^8) Compute Benchmark (1, 4, 8, 16 workers) ...');
  const rlncBench = [];
  for (const workerCount of [1, 4, 8, 16]) {
    const r = await runMultiCoreRlncBench({
      workerCount,
      windowSize: 32,
      symbolLen: 1320,
      totalRepairs: 8000,
    });
    rlncBench.push(r);
  }

  const totalElapsedSec = Number(((performance.now() - benchStart) / 1000).toFixed(2));

  // Print Markdown Comparison Tables
  console.log('\n### Wi-Fi 6 四场景弱网混沌对比压测结果\n');
  console.log(
    '| 场景 | AETHER 耗时(ms) | TCP-Reno 耗时(ms) | AETHER Goodput(Mbps) | TCP-Reno Goodput(Mbps) | 吞吐倍率 | 控制流 FCT (AETHER / TCP ms) | 实际丢包率 (A / T %) | 平均排队延迟 (A / T ms) | RLNC恢复单元 |'
  );
  console.log(
    '| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |'
  );
  for (const r of scenarioResults) {
    console.log(
      `| **${r.id}** ${r.name} | ${r.aether.elapsedMs} | ${r.tcpReno.elapsedMs} | ${r.aether.goodputMbps} | ${r.tcpReno.goodputMbps} | **${r.goodputSpeedup}x** | ${r.aether.ctrlAvgFctMs} / ${r.tcpReno.ctrlAvgFctMs} | ${r.aether.actualLossPct}% / ${r.tcpReno.actualLossPct}% | ${r.aether.avgQueueDelayMs} / ${r.tcpReno.avgQueueDelayMs} | ${r.aether.rlncRecoveredUnits} |`
    );
  }

  console.log('\n### 多核 RLNC 算力基准（对比 173.3 Mbps Wi-Fi 6 链路）\n');
  console.log('| Worker 核数 | 总修复包数 | 耗时 (ms) | 编码吞吐 (Mbps) | 相对 173.3 Mbps 算力富裕倍数 |');
  console.log('| :---: | :---: | :---: | :---: | :---: |');
  for (const r of rlncBench) {
    console.log(
      `| ${r.workerCount} | ${r.totalRepairs} | ${r.elapsedMs} | ${r.throughputMbps} | **${r.linkHeadroomFactor}x** |`
    );
  }

  const report = {
    generatedAt: new Date().toISOString(),
    nodeVersion: process.version,
    wifi6LinkMbps: WIFI6_LINK_MBPS,
    workloadBytes: workload.totalBytes,
    streamCount: workload.streams.length,
    totalBenchSec: totalElapsedSec,
    scenarios: scenarioResults,
    multiCoreRlnc: rlncBench,
  };

  const outUrl = new URL('./bench-results.json', import.meta.url);
  await writeFile(outUrl, JSON.stringify(report, null, 2), 'utf8');
  console.log(`\n[DONE] Saved JSON report to ${outUrl.pathname} (total elapsed: ${totalElapsedSec}s)`);

  return report;
}

const isDirectRun =
  process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;

if (isDirectRun) {
  await runChaosBenchmark();
}