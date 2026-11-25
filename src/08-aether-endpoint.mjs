// FILE: 08-aether-endpoint.mjs
/**
 * AETHER-W6 UDP Transport Endpoint (Client & Server Unified State Machine)
 * - 1-RTT & 0-RTT X25519 + HKDF-SHA256 + ChaCha20-Poly1305 AEAD handshake
 * - Sliding-Window RLNC over GF(2^8) + Kalman Wireless Loss-Decoupled CC + MicroPacer
 * - Multi-Stream HoL-Free Multiplexing + Selective ARQ Fallback + SACK Telemetry
 */

import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import { randomBytes, hkdfSync } from 'node:crypto';
import { performance } from 'node:perf_hooks';

import { RlncEncoder, RlncDecoder } from './02-rlnc-codec.mjs';
import {
  PROTO_VERSION,
  MAX_UDP_PAYLOAD,
  MAX_CODED_SYMBOL,
  PKT_TYPE,
  FRAME_TYPE,
  encodeStreamSymbolUnit,
  decodeStreamSymbolUnit,
  encodeFrames,
  decodeFrames,
} from './03-wire-format.mjs';
import { SessionTicketManager, AetherCrypto } from './04-crypto-0rtt.mjs';
import {
  KalmanDelayFilter,
  WirelessCongestionCtrl,
  MicroPacer,
} from './06-cc-kalman.mjs';
import { StreamMultiplexer } from './07-stream-mux.mjs';

const INFO_RESUMPTION_PSK = Buffer.from('aether-w6-resumption-psk');
const TICK_INTERVAL_MS = 2;
const HANDSHAKE_RETX_MS = 35;
const ACK_EVERY_N_PKTS = 4;
const ACK_MAX_DELAY_MS = 6;
const REORDER_THRESHOLD = 3;
const MAX_SACK_BITS = 256;

function nowUs32() {
  return Math.trunc(performance.now() * 1000) >>> 0;
}

class SessionState {
  /**
   * @param {object} opts
   */
  constructor({
    connId,
    remoteHost,
    remotePort,
    isServer,
    maxWindowSize = 48,
    ccOptions = {},
    entropyThreshold = 7.2,
    zstdLevel = 2,
    onStreamComplete = null,
  }) {
    this.connId = connId >>> 0;
    this.remoteHost = remoteHost;
    this.remotePort = remotePort;
    this.isServer = Boolean(isServer);
    this.maxWindowSize = maxWindowSize;

    this.crypto = new AetherCrypto();
    this.rlncEncoder = new RlncEncoder({
      maxWindowSize,
      maxSymbolSize: MAX_CODED_SYMBOL,
    });
    this.rlncDecoder = new RlncDecoder({
      maxKnownHistory: 1024,
      maxActiveEquations: 128,
    });
    this.cc = new WirelessCongestionCtrl(ccOptions);
    this.pacer = new MicroPacer({
      rateBps: this.cc.getPacingRateBps(),
      maxBurstBytes: 32 * MAX_UDP_PAYLOAD,
    });
    this.rxKalman = new KalmanDelayFilter();
    this.mux = new StreamMultiplexer({
      onStreamComplete,
      entropyThreshold,
      zstdLevel,
    });

    // Handshake state
    this.handshakeComplete = false;
    this.clientSalt = null;
    this.serverSalt = null;
    this.localKeyPair = null;
    /** @type {Buffer | null} */
    this.cachedServerHello = null;

    // Sender state
    this.nextPacketNum = 1;
    this.nextSourceSeq = 1;
    this.repairCredit = 0;
    this.lastTailRepairMs = 0;

    /** @type {Map<number, { pktNum: number, bytes: number, sentMs: number, sourceSeq: number | null, isRepair: boolean }>} */
    this.inFlightPkts = new Map();

    /** @type {Map<number, { firstSentMs: number, lastSentMs: number, symbolUnit: Buffer }>} */
    this.sourceSeqMeta = new Map();

    // Receiver state
    this.largestRxPktNum = 0;
    this.largestRxArrivalMs = 0;
    /** @type {Set<number>} */
    this.rxSeenPkts = new Set();
    this.pktsSinceAck = 0;
    this.lastAckSentMs = performance.now();
    this.lastRecvOwdGrad = 0;

    // Metrics
    this.metrics = {
      txPackets: 0,
      txBytes: 0,
      txSystematic: 0,
      txRepairs: 0,
      arqRetransmits: 0,
      rxPackets: 0,
      rxBytes: 0,
      rlncRecoveredUnits: 0,
      authFailures: 0,
      zeroRttTx: 0,
      zeroRttRx: 0,
      acksSent: 0,
      acksReceived: 0,
    };
  }
}

export class AetherEndpoint extends EventEmitter {
  /**
   * @param {object} [options]
   * @param {'client' | 'server'} [options.role='client']
   * @param {number} [options.maxWindowSize=48]
   * @param {object} [options.ccOptions={}]
   * @param {number} [options.entropyThreshold=7.2]
   * @param {number} [options.zstdLevel=2]
   * @param {SessionTicketManager} [options.ticketManager]
   */
  constructor({
    role = 'client',
    maxWindowSize = 48,
    ccOptions = {},
    entropyThreshold = 7.2,
    zstdLevel = 2,
    ticketManager = null,
  } = {}) {
    super();
    this.role = role;
    this.maxWindowSize = maxWindowSize;
    this.ccOptions = ccOptions;
    this.entropyThreshold = entropyThreshold;
    this.zstdLevel = zstdLevel;
    this.ticketManager =
      ticketManager || (role === 'server' ? new SessionTicketManager() : null);

    this.socket = dgram.createSocket('udp4');
    this.bound = false;
    this.closed = false;

    /** @type {Map<number, SessionState>} */
    this.sessions = new Map();
    /** @type {SessionState | null} */
    this.clientSession = null;

    /** Buffer out-of-order 0-RTT datagrams arriving before ClientHello on server */
    /** @type {Map<number, Array<{ msg: Buffer, rinfo: dgram.RemoteInfo }>>} */
    this._early0RttPending = new Map();

    /** Saved 0-RTT resumption credentials on client */
    /** @type {{ ticket: Buffer, psk: Buffer } | null} */
    this.savedSession = null;

    /** Active stream waiters */
    /** @type {Set<{ streamIds: number[], resolve: Function, reject: Function, timer: NodeJS.Timeout, session: SessionState }>} */
    this._streamWaiters = new Set();

    /** Pending client handshake resolver */
    this._handshakePromise = null;
    this._handshakeTimer = null;
    this._handshakeTimeout = null;

    this._tickTimer = null;

    this.socket.on('message', (msg, rinfo) => this._onDatagram(msg, rinfo));
    this.socket.on('error', (err) => {
      if (!this.closed) {
        this.emit('error', err);
      }
    });
  }

  /**
   * Bind UDP socket and start the 2ms protocol scheduler loop.
   * @param {number} [port=0]
   * @param {string} [host='127.0.0.1']
   * @returns {Promise<{ address: string, port: number }>}
   */
  bind(port = 0, host = '127.0.0.1') {
    if (this.bound) {
      return Promise.resolve(this.socket.address());
    }
    return new Promise((resolve, reject) => {
      const onErr = (err) => {
        this.socket.off('listening', onListening);
        reject(err);
      };
      const onListening = () => {
        this.socket.off('error', onErr);
        this.bound = true;
        this._startTickLoop();
        resolve(this.socket.address());
      };
      this.socket.once('error', onErr);
      this.socket.once('listening', onListening);
      this.socket.bind(port, host);
    });
  }

  _startTickLoop() {
    if (this._tickTimer || this.closed) return;
    this._tickTimer = setInterval(() => this._onTick(), TICK_INTERVAL_MS);
  }

  /**
   * Client: initiate 1-RTT or 0-RTT handshake with server.
   * @param {string} host
   * @param {number} port
   * @param {object} [options]
   * @param {Buffer} [options.ticket]
   * @param {Buffer} [options.psk]
   * @param {Array<{ streamId: number, data: Buffer | Uint8Array, priority?: number, fin?: boolean }>} [options.earlyStreams=[]]
   * @param {number} [options.timeoutMs=5000]
   * @returns {Promise<{ connId: number, used0Rtt: boolean }>}
   */
  async connect(host, port, { ticket = null, psk = null, earlyStreams = [], timeoutMs = 5000 } = {}) {
    if (this.role !== 'client') {
      throw new Error('connect() can only be called on a client endpoint');
    }
    if (!this.bound) {
      await this.bind(0, '127.0.0.1');
    }

    const connId = (randomBytes(4).readUInt32BE(0) || 1) >>> 0;
    const session = new SessionState({
      connId,
      remoteHost: host,
      remotePort: port,
      isServer: false,
      maxWindowSize: this.maxWindowSize,
      ccOptions: this.ccOptions,
      entropyThreshold: this.entropyThreshold,
      zstdLevel: this.zstdLevel,
      onStreamComplete: (res) => this._handleStreamComplete(session, res),
    });

    session.clientSalt = randomBytes(16);
    session.localKeyPair = AetherCrypto.generateKeyPair();
    this.sessions.set(connId, session);
    this.clientSession = session;

    const use0Rtt = Boolean(ticket && psk && ticket.length > 0 && psk.length === 32);

    const hsPlaintext = encodeFrames([
      {
        type: FRAME_TYPE.HANDSHAKE,
        isServer: false,
        ephemeralPubKey: session.localKeyPair.publicKeyRaw,
        nonceSalt: session.clientSalt,
        sessionTicket: use0Rtt ? ticket : Buffer.alloc(0),
      },
    ]);

    const clientHello = session.crypto.sealHandshakePacket(
      {
        version: PROTO_VERSION,
        pktType: PKT_TYPE.HANDSHAKE,
        connId,
        packetNum: 0,
        txTimeUs: nowUs32(),
      },
      hsPlaintext
    );

    const sendClientHello = () => {
      if (this.closed || session.handshakeComplete) return;
      this._sendRaw(session, clientHello);
    };

    // Send ClientHello immediately
    sendClientHello();

    // If 0-RTT credentials provided, install 0-RTT keys and immediately transmit earlyStreams
    if (use0Rtt) {
      session.crypto.install0RttKeys(psk, session.clientSalt, false);
      for (const es of earlyStreams) {
        session.mux.enqueueStreamData(es.streamId, es.data, {
          priority: es.priority ?? 5,
          fin: es.fin ?? true,
        });
      }
      this._flushEarly0Rtt(session);
    }

    return new Promise((resolve, reject) => {
      this._handshakePromise = { resolve, reject, connId, used0Rtt: use0Rtt };

      this._handshakeTimer = setInterval(() => {
        sendClientHello();
      }, HANDSHAKE_RETX_MS);

      this._handshakeTimeout = setTimeout(() => {
        this._clearHandshakeTimers();
        if (this._handshakePromise) {
          const rej = this._handshakePromise.reject;
          this._handshakePromise = null;
          rej(new Error(`AETHER-W6 handshake timed out after ${timeoutMs}ms`));
        }
      }, timeoutMs);
    });
  }

  _clearHandshakeTimers() {
    if (this._handshakeTimer) {
      clearInterval(this._handshakeTimer);
      this._handshakeTimer = null;
    }
    if (this._handshakeTimeout) {
      clearTimeout(this._handshakeTimeout);
      this._handshakeTimeout = null;
    }
  }

  /**
   * Immediately flush queued early-data chunks using 0-RTT encryption.
   * @param {SessionState} session
   */
  _flushEarly0Rtt(session) {
    const nowMs = performance.now();
    while (
      session.mux.hasPendingChunks() &&
      session.rlncEncoder.window.size < session.maxWindowSize
    ) {
      const chunk = session.mux.popNextChunk();
      if (!chunk) break;
      this._sendStreamChunk(session, chunk, nowMs, { use0Rtt: true });
    }
  }

  /**
   * Enqueue application data on a stream.
   * @param {number} streamId
   * @param {Buffer | Uint8Array} buf
   * @param {object} [options]
   * @param {number} [options.priority=3]
   * @param {boolean} [options.fin=true]
   * @param {number} [options.connId]
   */
  sendStream(streamId, buf, { priority = 3, fin = true, connId = null } = {}) {
    const session = this._resolveSession(connId);
    if (!session) {
      throw new Error('No active session available for sendStream()');
    }
    return session.mux.enqueueStreamData(streamId, buf, { priority, fin });
  }

  /**
   * Wait until all specified streamIds have been completely received and reassembled.
   * @param {number[]} streamIds
   * @param {number} [timeoutMs=15000]
   * @param {number | null} [connId=null]
   * @returns {Promise>}
   */
  waitForStreams(streamIds, timeoutMs = 15_000, connId = null) {
    const ids = Array.from(new Set(streamIds));
    const checkSession = () => {
      const session = this._resolveSession(connId);
      if (!session) return null;
      for (const id of ids) {
        const res = session.mux.getStreamResult(id);
        if (!res || !res.completed) return null;
      }
      const out = new Map();
      for (const id of ids) {
        out.set(id, session.mux.getStreamResult(id));
      }
      return out;
    };

    const immediate = checkSession();
    if (immediate) {
      return Promise.resolve(immediate);
    }

    return new Promise((resolve, reject) => {
      const waiter = {
        streamIds: ids,
        connId,
        resolve,
        reject,
        timer: setTimeout(() => {
          this._streamWaiters.delete(waiter);
          reject(new Error(`waitForStreams timed out after ${timeoutMs}ms`));
        }, timeoutMs),
      };
      this._streamWaiters.add(waiter);
    });
  }

  _handleStreamComplete(session, result) {
    this.emit('stream', { connId: session.connId, ...result });

    for (const waiter of Array.from(this._streamWaiters)) {
      if (waiter.connId !== null && waiter.connId !== session.connId) continue;
      let allDone = true;
      for (const id of waiter.streamIds) {
        const res = session.mux.getStreamResult(id);
        if (!res || !res.completed) {
          allDone = false;
          break;
        }
      }
      if (allDone) {
        clearTimeout(waiter.timer);
        this._streamWaiters.delete(waiter);
        const out = new Map();
        for (const id of waiter.streamIds) {
          out.set(id, session.mux.getStreamResult(id));
        }
        waiter.resolve(out);
      }
    }
  }

  _resolveSession(connId = null) {
    if (connId !== null && connId !== undefined) {
      return this.sessions.get(connId) || null;
    }
    if (this.clientSession) {
      return this.clientSession;
    }
    for (const s of this.sessions.values()) {
      return s;
    }
    return null;
  }

  /**
   * @returns {{ ticket: Buffer, psk: Buffer } | null}
   */
  getSavedSession() {
    return this.savedSession;
  }

  /**
   * Aggregate endpoint telemetry across active session(s).
   * @param {number | null} [connId=null]
   * @returns {object}
   */
  getMetrics(connId = null) {
    const session = this._resolveSession(connId);
    if (!session) {
      return { sessions: this.sessions.size };
    }
    return {
      connId: session.connId,
      handshakeComplete: session.handshakeComplete,
      ...session.metrics,
      cc: session.cc.getSnapshot(),
      rlncDecoder: session.rlncDecoder.getStats(),
      mux: session.mux.getStats(),
    };
  }

  /**
   * Cleanly close socket, clear all timers, and reject any pending waiters.
   * @returns {Promise<void>}
   */
  close() {
    if (this.closed) return Promise.resolve();
    this.closed = true;

    this._clearHandshakeTimers();
    if (this._tickTimer) {
      clearInterval(this._tickTimer);
      this._tickTimer = null;
    }

    if (this._handshakePromise) {
      const rej = this._handshakePromise.reject;
      this._handshakePromise = null;
      rej(new Error('Endpoint closed during handshake'));
    }

    for (const waiter of Array.from(this._streamWaiters)) {
      clearTimeout(waiter.timer);
      this._streamWaiters.delete(waiter);
      waiter.reject(new Error('Endpoint closed'));
    }

    return new Promise((resolve) => {
      if (!this.bound) {
        try {
          this.socket.close();
        } catch {
          // ignore
        }
        resolve();
        return;
      }
      this.bound = false;
      this.socket.close(() => resolve());
    });
  }

  // =========================================================================
  // Packet Transmission & 2ms Scheduler
  // =========================================================================

  _sendRaw(session, datagram) {
    if (this.closed) return;
    session.metrics.txPackets++;
    session.metrics.txBytes += datagram.length;
    this.socket.send(datagram, session.remotePort, session.remoteHost);
  }

  _sendStreamChunk(session, chunk, nowMs, { use0Rtt = false } = {}) {
    const symbolUnit = encodeStreamSymbolUnit({
      priority: chunk.priority,
      fin: chunk.fin,
      zstd: chunk.zstd,
      streamId: chunk.streamId,
      streamOffset: chunk.streamOffset,
      payload: chunk.payload,
    });

    const sourceSeq = session.nextSourceSeq++;
    session.rlncEncoder.addSourceSymbol(sourceSeq, symbolUnit);
    session.sourceSeqMeta.set(sourceSeq, {
      firstSentMs: nowMs,
      lastSentMs: nowMs,
      symbolUnit,
    });

    const plaintext = encodeFrames([
      {
        type: FRAME_TYPE.STREAM,
        sourceSeq,
        symbolUnit,
      },
    ]);

    const pktNum = session.nextPacketNum++;
    const datagram = session.crypto.encryptPacket(
      {
        version: PROTO_VERSION,
        pktType: use0Rtt ? PKT_TYPE.ZERO_RTT : PKT_TYPE.DATA,
        is0Rtt: use0Rtt,
        connId: session.connId,
        packetNum: pktNum,
        txTimeUs: nowUs32(),
      },
      plaintext,
      { use0Rtt }
    );

    session.inFlightPkts.set(pktNum, {
      pktNum,
      bytes: datagram.length,
      sentMs: nowMs,
      sourceSeq,
      isRepair: false,
    });
    session.cc.onPacketSent(datagram.length, nowMs);
    session.pacer.consume(datagram.length, nowMs);
    session.metrics.txSystematic++;
    if (use0Rtt) session.metrics.zeroRttTx++;

    this._sendRaw(session, datagram);
  }

  _sendRepairPacket(session, nowMs) {
    const repair = session.rlncEncoder.generateRepair();
    if (!repair) return false;

    const plaintext = encodeFrames([
      {
        type: FRAME_TYPE.RLNC_REPAIR,
        flags: 0,
        winStart: repair.winStart,
        winLen: repair.winLen,
        prngSeed: repair.prngSeed,
        codedSymbol: repair.codedSymbol,
      },
    ]);

    const pktNum = session.nextPacketNum++;
    const datagram = session.crypto.encryptPacket(
      {
        version: PROTO_VERSION,
        pktType: PKT_TYPE.DATA,
        connId: session.connId,
        packetNum: pktNum,
        txTimeUs: nowUs32(),
      },
      plaintext
    );

    session.inFlightPkts.set(pktNum, {
      pktNum,
      bytes: datagram.length,
      sentMs: nowMs,
      sourceSeq: null,
      isRepair: true,
    });
    session.cc.onPacketSent(datagram.length, nowMs);
    session.pacer.consume(datagram.length, nowMs);
    session.metrics.txRepairs++;

    this._sendRaw(session, datagram);
    return true;
  }

  _sendArqRetransmit(session, sourceSeq, meta, nowMs) {
    const plaintext = encodeFrames([
      {
        type: FRAME_TYPE.STREAM,
        sourceSeq,
        symbolUnit: meta.symbolUnit,
      },
    ]);

    const pktNum = session.nextPacketNum++;
    const datagram = session.crypto.encryptPacket(
      {
        version: PROTO_VERSION,
        pktType: PKT_TYPE.DATA,
        connId: session.connId,
        packetNum: pktNum,
        txTimeUs: nowUs32(),
      },
      plaintext
    );

    meta.lastSentMs = nowMs;
    session.inFlightPkts.set(pktNum, {
      pktNum,
      bytes: datagram.length,
      sentMs: nowMs,
      sourceSeq,
      isRepair: false,
    });
    session.cc.onPacketSent(datagram.length, nowMs);
    session.pacer.consume(datagram.length, nowMs);
    session.metrics.arqRetransmits++;

    this._sendRaw(session, datagram);
  }

  _sendAckTelemetry(session, nowMs) {
    if (!session.handshakeComplete || session.largestRxPktNum === 0) return;

    const largest = session.largestRxPktNum;
    const sackBitmap = new Uint32Array(8);
    let highestWord = 0;

    for (let bit = 0; bit < MAX_SACK_BITS; bit++) {
      const pktNum = largest - 1 - bit;
      if (pktNum <= 0) break;
      if (session.rxSeenPkts.has(pktNum)) {
        const wordIdx = bit >>> 5;
        sackBitmap[wordIdx] |= 1 << (bit & 31);
        highestWord = wordIdx + 1;
      }
    }

    const ackDelayUs = Math.max(0, Math.trunc((nowMs - session.largestRxArrivalMs) * 1000));
    const plaintext = encodeFrames([
      {
        type: FRAME_TYPE.ACK_TELEMETRY,
        largestAckedPkt: largest,
        ackDelayUs,
        cumSourceSeq: session.rlncDecoder.getCumulativeSeq(),
        recvOwdGrad: Math.round(session.lastRecvOwdGrad),
        sackBitmap: sackBitmap.subarray(0, highestWord),
      },
    ]);

    const pktNum = session.nextPacketNum++;
    const datagram = session.crypto.encryptPacket(
      {
        version: PROTO_VERSION,
        pktType: PKT_TYPE.DATA,
        connId: session.connId,
        packetNum: pktNum,
        txTimeUs: nowUs32(),
      },
      plaintext
    );

    session.pktsSinceAck = 0;
    session.lastAckSentMs = nowMs;
    session.metrics.acksSent++;
    this._sendRaw(session, datagram);
  }

  _onTick() {
    if (this.closed) return;
    const nowMs = performance.now();

    for (const session of this.sessions.values()) {
      if (!session.handshakeComplete) continue;

      // 1. Timeout retirement for severely lost in-flight packets to prevent cwnd deadlock
      const lossTimeoutMs = Math.max(60, session.cc.srttMs * 3.0);
      let timedOutCount = 0;
      for (const [pktNum, pkt] of Array.from(session.inFlightPkts.entries())) {
        if (nowMs - pkt.sentMs > lossTimeoutMs) {
          session.inFlightPkts.delete(pktNum);
          session.cc.onPacketRetired(pkt.bytes);
          timedOutCount++;
        }
      }
      if (timedOutCount > 0) {
        session.cc.onAckTelemetry({
          ackedBytes: 0,
          lostCount: timedOutCount,
          totalTracked: timedOutCount,
          rttMs: session.cc.srttMs,
          maxBurstLen: timedOutCount,
          nowMs,
        });
        session.pacer.setRate(session.cc.getPacingRateBps());
      }

      // 2. Active transmission micro-batch (systematic STREAM + proportional RLNC_REPAIR)
      const maxPerTick = Math.max(
        24,
        Math.min(96, Math.ceil(((session.cc.getPacingRateBps() / 8 / 1000) * 16) / MAX_UDP_PAYLOAD))
      );
      let sentThisTick = 0;
      while (sentThisTick < maxPerTick) {
        let didSend = false;

        if (
          session.mux.hasPendingChunks() &&
          session.rlncEncoder.window.size < session.maxWindowSize &&
          session.cc.canSend(MAX_UDP_PAYLOAD) &&
          session.pacer.canSend(MAX_UDP_PAYLOAD, nowMs)
        ) {
          const chunk = session.mux.popNextChunk();
          if (chunk) {
            this._sendStreamChunk(session, chunk, nowMs);
            session.repairCredit += session.cc.getRedundancyRho();
            sentThisTick++;
            didSend = true;
          }
        }

        while (
          session.repairCredit >= 1 &&
          session.rlncEncoder.window.size > 0 &&
          session.cc.canSend(MAX_UDP_PAYLOAD) &&
          session.pacer.canSend(MAX_UDP_PAYLOAD, nowMs) &&
          sentThisTick < maxPerTick
        ) {
          session.repairCredit -= 1;
          if (this._sendRepairPacket(session, nowMs)) {
            sentThisTick++;
            didSend = true;
          } else {
            break;
          }
        }

        if (!didSend) break;
      }

      // 3. Tail protection & window-stall rescue (proactive RLNC repair + selective ARQ fallback)
      const windowStalled =
        !session.mux.hasPendingChunks() || session.rlncEncoder.window.size >= session.maxWindowSize;
      if (windowStalled && session.rlncEncoder.window.size > 0) {
        const tailIntervalMs = Math.max(6, session.cc.srttMs * 0.35);
        if (
          nowMs - session.lastTailRepairMs >= tailIntervalMs &&
          session.cc.canSend(MAX_UDP_PAYLOAD) &&
          session.pacer.canSend(MAX_UDP_PAYLOAD, nowMs)
        ) {
          session.lastTailRepairMs = nowMs;
          this._sendRepairPacket(session, nowMs);
        }

        // Selective ARQ for oldest unacknowledged symbol exceeding timeout
        const arqTimeoutMs = Math.max(35, session.cc.srttMs * 2.2);
        const range = session.rlncEncoder.getWindowRange();
        if (range) {
          const oldestSeq = range.winStart;
          const meta = session.sourceSeqMeta.get(oldestSeq);
          if (
            meta &&
            nowMs - meta.lastSentMs >= arqTimeoutMs &&
            session.cc.canSend(MAX_UDP_PAYLOAD) &&
            session.pacer.canSend(MAX_UDP_PAYLOAD, nowMs)
          ) {
            this._sendArqRetransmit(session, oldestSeq, meta, nowMs);
          }
        }
      }

      // 4. Periodic ACK flush on receiver side
      if (session.pktsSinceAck > 0 && nowMs - session.lastAckSentMs >= ACK_MAX_DELAY_MS) {
        this._sendAckTelemetry(session, nowMs);
      }
    }
  }

  // =========================================================================
  // Incoming Datagram Demux & Handshake
  // =========================================================================

  _onDatagram(msg, rinfo) {
    if (this.closed || msg.length < 16) return;

    const pktType = msg.readUInt8(1);
    const connId = msg.readUInt32BE(4);

    if (pktType === PKT_TYPE.HANDSHAKE) {
      this._handleHandshakeDatagram(msg, rinfo, connId);
      return;
    }

    const session = this.sessions.get(connId);
    if (!session) {
      // Server: buffer out-of-order 0-RTT packets arriving ahead of ClientHello
      if (this.role === 'server' && pktType === PKT_TYPE.ZERO_RTT) {
        let list = this._early0RttPending.get(connId);
        if (!list) {
          list = [];
          this._early0RttPending.set(connId, list);
        }
        if (list.length < 64) {
          list.push({ msg: Buffer.from(msg), rinfo });
        }
      }
      return;
    }

    // Update peer endpoint on NAT port rebinding
    session.remoteHost = rinfo.address;
    session.remotePort = rinfo.port;

    this._handleProtectedDatagram(session, msg, pktType === PKT_TYPE.ZERO_RTT);
  }

  _handleHandshakeDatagram(msg, rinfo, connId) {
    let opened;
    try {
      opened = new AetherCrypto().openHandshakePacket(msg);
    } catch {
      return;
    }

    let frames;
    try {
      frames = decodeFrames(opened.plaintext);
    } catch {
      return;
    }

    const hsFrame = frames.find((f) => f.type === FRAME_TYPE.HANDSHAKE);
    if (!hsFrame) return;

    if (this.role === 'server' && !hsFrame.isServer) {
      // Duplicate ClientHello: resend cached ServerHello to prevent handshake deadlock
      const existing = this.sessions.get(connId);
      if (existing && existing.cachedServerHello) {
        existing.remoteHost = rinfo.address;
        existing.remotePort = rinfo.port;
        this._sendRaw(existing, existing.cachedServerHello);
        return;
      }

      const session = new SessionState({
        connId,
        remoteHost: rinfo.address,
        remotePort: rinfo.port,
        isServer: true,
        maxWindowSize: this.maxWindowSize,
        ccOptions: this.ccOptions,
        entropyThreshold: this.entropyThreshold,
        zstdLevel: this.zstdLevel,
        onStreamComplete: (res) => this._handleStreamComplete(session, res),
      });

      // Verify optional 0-RTT SessionTicket
      if (hsFrame.hasTicket && hsFrame.sessionTicket.length > 0 && this.ticketManager) {
        try {
          const { psk } = this.ticketManager.verifyAndConsumeTicket(hsFrame.sessionTicket);
          session.crypto.install0RttKeys(psk, hsFrame.nonceSalt, true);
        } catch {
          // Invalid/replayed ticket: silently fall back to full 1-RTT
        }
      }

      // Complete 1-RTT X25519 ECDH
      session.clientSalt = hsFrame.nonceSalt;
      session.serverSalt = randomBytes(16);
      session.localKeyPair = AetherCrypto.generateKeyPair();

      const sharedSecret = AetherCrypto.computeSharedSecret(
        session.localKeyPair.privateKey,
        hsFrame.ephemeralPubKey
      );
      const fullSalt = Buffer.concat([session.clientSalt, session.serverSalt]);
      session.crypto.install1RttKeys(sharedSecret, fullSalt, true);

      // Derive resumption PSK and issue new SessionTicket
      const resumptionPsk = Buffer.from(
        hkdfSync('sha256', sharedSecret, fullSalt, INFO_RESUMPTION_PSK, 32)
      );
      const { ticket: newTicket } = this.ticketManager.issueTicket(resumptionPsk);

      const shPlaintext = encodeFrames([
        {
          type: FRAME_TYPE.HANDSHAKE,
          isServer: true,
          ephemeralPubKey: session.localKeyPair.publicKeyRaw,
          nonceSalt: session.serverSalt,
          sessionTicket: newTicket,
        },
      ]);

      session.cachedServerHello = session.crypto.sealHandshakePacket(
        {
          version: PROTO_VERSION,
          pktType: PKT_TYPE.HANDSHAKE,
          connId,
          packetNum: 0,
          txTimeUs: nowUs32(),
        },
        shPlaintext
      );
      session.handshakeComplete = true;
      this.sessions.set(connId, session);
      this._sendRaw(session, session.cachedServerHello);

      // Replay any out-of-order 0-RTT packets buffered before ClientHello
      const pending = this._early0RttPending.get(connId);
      if (pending) {
        this._early0RttPending.delete(connId);
        for (const item of pending) {
          this._handleProtectedDatagram(session, item.msg, true);
        }
      }
      this.emit('session', { connId, remoteHost: rinfo.address, remotePort: rinfo.port });
    } else if (this.role === 'client' && hsFrame.isServer) {
      const session = this.sessions.get(connId);
      if (!session || session.handshakeComplete) return;

      session.serverSalt = hsFrame.nonceSalt;
      const sharedSecret = AetherCrypto.computeSharedSecret(
        session.localKeyPair.privateKey,
        hsFrame.ephemeralPubKey
      );
      const fullSalt = Buffer.concat([session.clientSalt, session.serverSalt]);
      session.crypto.install1RttKeys(sharedSecret, fullSalt, false);

      if (hsFrame.hasTicket && hsFrame.sessionTicket.length > 0) {
        const resumptionPsk = Buffer.from(
          hkdfSync('sha256', sharedSecret, fullSalt, INFO_RESUMPTION_PSK, 32)
        );
        this.savedSession = {
          ticket: Buffer.from(hsFrame.sessionTicket),
          psk: resumptionPsk,
        };
      }

      session.handshakeComplete = true;
      this._clearHandshakeTimers();

      if (this._handshakePromise) {
        const { resolve, used0Rtt } = this._handshakePromise;
        this._handshakePromise = null;
        resolve({ connId, used0Rtt });
      }
    }
  }

  _handleProtectedDatagram(session, msg, is0Rtt) {
    let decrypted;
    try {
      decrypted = session.crypto.decryptPacket(msg, { use0Rtt: is0Rtt });
    } catch {
      session.metrics.authFailures++;
      return;
    }

    const nowMs = performance.now();
    const { header, plaintext } = decrypted;
    session.metrics.rxPackets++;
    session.metrics.rxBytes += msg.length;
    if (is0Rtt) session.metrics.zeroRttRx++;

    // Update receiver Kalman OWD filter
    const rawOwdMs = ((nowUs32() - header.txTimeUs) | 0) / 1000;
    const kf = session.rxKalman.update(rawOwdMs, nowMs);
    session.lastRecvOwdGrad = kf.delayGradient;

    let frames;
    try {
      frames = decodeFrames(plaintext);
    } catch {
      return;
    }

    let hasDataFrame = false;

    for (const frame of frames) {
      switch (frame.type) {
        case FRAME_TYPE.STREAM: {
          hasDataFrame = true;
          session.mux.onStreamUnit({
            streamId: frame.streamId,
            streamOffset: frame.streamOffset,
            fin: frame.fin,
            zstd: frame.zstd,
            priority: frame.priority,
            payload: frame.payload,
            nowMs,
          });

          const recovered = session.rlncDecoder.addSourceSymbol(
            frame.sourceSeq,
            frame.symbolUnit
          );
          this._deliverRecoveredSymbols(session, recovered, nowMs);
          break;
        }

        case FRAME_TYPE.RLNC_REPAIR: {
          hasDataFrame = true;
          const recovered = session.rlncDecoder.addRepairSymbol(
            frame.winStart,
            frame.winLen,
            frame.prngSeed,
            frame.codedSymbol
          );
          this._deliverRecoveredSymbols(session, recovered, nowMs);
          break;
        }

        case FRAME_TYPE.ACK_TELEMETRY: {
          this._handleAckTelemetry(session, frame, nowMs);
          break;
        }

        default:
          break;
      }
    }

    // Track received packet numbers for SACK bitmap (only for data-carrying packets)
    if (hasDataFrame) {
      const pn = header.packetNum;
      session.rxSeenPkts.add(pn);
      if (pn > session.largestRxPktNum) {
        session.largestRxPktNum = pn;
        session.largestRxArrivalMs = nowMs;
      }
      // Prune old SACK history beyond 512 packets
      if (session.rxSeenPkts.size > 512) {
        const minKeep = session.largestRxPktNum - 384;
        for (const p of Array.from(session.rxSeenPkts)) {
          if (p < minKeep) session.rxSeenPkts.delete(p);
        }
      }

      session.pktsSinceAck++;
      if (
        session.pktsSinceAck >= ACK_EVERY_N_PKTS ||
        nowMs - session.lastAckSentMs >= ACK_MAX_DELAY_MS
      ) {
        this._sendAckTelemetry(session, nowMs);
      }
    }
  }

  _deliverRecoveredSymbols(session, recovered, nowMs) {
    for (const item of recovered) {
      session.metrics.rlncRecoveredUnits++;
      try {
        const unit = decodeStreamSymbolUnit(item.data);
        session.mux.onStreamUnit({
          streamId: unit.streamId,
          streamOffset: unit.streamOffset,
          fin: unit.fin,
          zstd: unit.zstd,
          priority: unit.priority,
          payload: unit.payload,
          nowMs,
        });
      } catch {
        // Ignore malformed recovered symbol if any
      }
    }
  }

  _handleAckTelemetry(session, ack, nowMs) {
    session.metrics.acksReceived++;
    const largestAcked = ack.largestAckedPkt;
    const ackDelayMs = ack.ackDelayUs / 1000;

    // 1. Identify newly acknowledged packets from largestAckedPkt + SACK bitmap
    let ackedBytes = 0;
    let ackedCount = 0;
    let sampleRttMs = 0;

    const isAckedBySack = (pktNum) => {
      if (pktNum === largestAcked) return true;
      const delta = largestAcked - 1 - pktNum;
      if (delta < 0 || delta >= ack.sackBitmap.length * 32) return false;
      const word = ack.sackBitmap[delta >>> 5];
      return ((word >>> (delta & 31)) & 1) === 1;
    };

    /** @type {number[]} */
    const newlyLostPktNums = [];
    const lossTimeoutMs = Math.max(50, session.cc.srttMs * 2.5);

    for (const [pktNum, pkt] of Array.from(session.inFlightPkts.entries())) {
      if (isAckedBySack(pktNum)) {
        session.inFlightPkts.delete(pktNum);
        ackedBytes += pkt.bytes;
        ackedCount++;
        if (pktNum === largestAcked || sampleRttMs === 0) {
          sampleRttMs = Math.max(0.5, nowMs - pkt.sentMs - ackDelayMs);
        }
      } else if (
        pktNum <= largestAcked - REORDER_THRESHOLD ||
        nowMs - pkt.sentMs > lossTimeoutMs
      ) {
        session.inFlightPkts.delete(pktNum);
        session.cc.onPacketRetired(pkt.bytes);
        newlyLostPktNums.push(pktNum);
      }
    }

    // Compute maximum consecutive loss burst length
    let maxBurstLen = 0;
    if (newlyLostPktNums.length > 0) {
      newlyLostPktNums.sort((a, b) => a - b);
      let curBurst = 1;
      maxBurstLen = 1;
      for (let i = 1; i < newlyLostPktNums.length; i++) {
        if (newlyLostPktNums[i] === newlyLostPktNums[i - 1] + 1) {
          curBurst++;
          if (curBurst > maxBurstLen) maxBurstLen = curBurst;
        } else {
          curBurst = 1;
        }
      }
    }

    // 2. Feed congestion controller (note: onAckTelemetry retires ackedBytes internally)
    const totalTracked = Math.max(1, ackedCount + newlyLostPktNums.length);
    session.cc.onAckTelemetry({
      ackedBytes,
      lostCount: newlyLostPktNums.length,
      totalTracked,
      rttMs: sampleRttMs,
      recvOwdGrad: ack.recvOwdGrad,
      maxBurstLen,
      nowMs,
    });
    session.pacer.setRate(session.cc.getPacingRateBps());

    // 3. Slide RLNC encoder window based on receiver's cumulative decoded sourceSeq
    if (ack.cumSourceSeq > 0) {
      session.rlncEncoder.ackCumulative(ack.cumSourceSeq);
      for (const seq of Array.from(session.sourceSeqMeta.keys())) {
        if (seq <= ack.cumSourceSeq) {
          session.sourceSeqMeta.delete(seq);
        }
      }
    }
  }
}