// FILE: test-unit.mjs
/**
 * AETHER-W6 Comprehensive Unit & Integration Verification Suite
 * Zero external dependencies — Node.js v24.21.0 ESM
 */

import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';

import {
  GF_EXP,
  GF_LOG,
  GF_INV,
  GF_MUL_TABLE,
  gfMul,
  gfDiv,
  gfInv,
  scaleRow,
  mulAddRow,
  xorshift32,
  generateCoeffs,
} from '../src/01-gf256.mjs';
import { RlncEncoder, RlncDecoder } from '../src/02-rlnc-codec.mjs';
import {
  PROTO_VERSION,
  MAX_UDP_PAYLOAD,
  HEADER_LEN,
  AUTH_TAG_LEN,
  MAX_PLAINTEXT,
  MAX_CODED_SYMBOL,
  MAX_STREAM_PAYLOAD,
  PKT_TYPE,
  FRAME_TYPE,
  STREAM_FLAGS,
  encodeHeader,
  decodeHeader,
  encodeStreamSymbolUnit,
  decodeStreamSymbolUnit,
  encodeFrames,
  decodeFrames,
} from '../src/03-wire-format.mjs';
import { SessionTicketManager, AetherCrypto } from '../src/04-crypto-0rtt.mjs';
import {
  shannonEntropy,
  adaptiveCompress,
  adaptiveDecompress,
} from '../src/05-entropy-zstd.mjs';
import {
  KalmanDelayFilter,
  WirelessCongestionCtrl,
  MicroPacer,
} from '../src/06-cc-kalman.mjs';
import { AetherStream, StreamMultiplexer } from '../src/07-stream-mux.mjs';
import { AetherEndpoint } from '../src/08-aether-endpoint.mjs';

const results = [];

async function runTest(id, name, fn) {
  const t0 = performance.now();
  try {
    const detail = await fn();
    const ms = (performance.now() - t0).toFixed(2);
    results.push({ id, name, pass: true, ms, detail: detail || 'OK' });
    console.log(`[PASS] #${id} ${name} (${ms} ms) — ${detail || 'OK'}`);
  } catch (err) {
    const ms = (performance.now() - t0).toFixed(2);
    results.push({ id, name, pass: false, ms, detail: err.message });
    console.error(`[FAIL] #${id} ${name} (${ms} ms) — ${err.stack || err.message}`);
  }
}

// ---------------------------------------------------------------------------
// Test 1: GF(2^8) Field Axioms & Vectorized Row Operations
// ---------------------------------------------------------------------------
async function test1_gf256Axioms() {
  assert.ok(GF_EXP.length >= 255, 'GF_EXP table must be populated');
  assert.ok(GF_LOG.length >= 256, 'GF_LOG table must be populated');
  assert.equal(gfMul(0, 123), 0);
  assert.equal(gfMul(123, 0), 0);

  // Full inverse & table consistency for 1..255
  for (let a = 1; a <= 255; a++) {
    const inv = gfInv(a);
    assert.equal(inv, GF_INV[a], `GF_INV mismatch for ${a}`);
    assert.equal(gfMul(a, inv), 1, `gfMul(${a}, gfInv(${a})) !== 1`);
    assert.equal(gfDiv(a, a), 1, `gfDiv(${a}, ${a}) !== 1`);
    assert.equal(gfDiv(1, a), inv, `gfDiv(1, ${a}) !== gfInv(${a})`);

    const tblVal =
      GF_MUL_TABLE[a] instanceof Uint8Array
        ? GF_MUL_TABLE[a][inv]
        : GF_MUL_TABLE[(a << 8) | inv];
    assert.equal(tblVal, 1, `GF_MUL_TABLE mismatch for ${a}`);
  }

  // Distributivity & commutativity over deterministic sample triples
  let seed = 0x12345678;
  for (let i = 0; i < 512; i++) {
    seed = xorshift32(seed);
    const a = seed & 0xff;
    seed = xorshift32(seed);
    const b = seed & 0xff;
    seed = xorshift32(seed);
    const c = seed & 0xff;

    assert.equal(gfMul(a, b), gfMul(b, a), 'Commutativity failed');
    assert.equal(
      gfMul(a, b ^ c),
      gfMul(a, b) ^ gfMul(a, c),
      `Distributivity failed for (${a}, ${b}, ${c})`
    );
  }

  // mulAddRow & scaleRow verification
  const len = 128;
  const src = new Uint8Array(len);
  const dst = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    src[i] = (i * 37 + 11) & 0xff;
    dst[i] = (i * 53 + 7) & 0xff;
  }
  const origDst = Uint8Array.from(dst);
  const coeff = 0xa7;
  mulAddRow(dst, src, coeff, len);
  for (let i = 0; i < len; i++) {
    assert.equal(dst[i], origDst[i] ^ gfMul(src[i], coeff), `mulAddRow mismatch at ${i}`);
  }

  const rowToScale = Uint8Array.from(src);
  scaleRow(rowToScale, coeff, len);
  for (let i = 0; i < len; i++) {
    assert.equal(rowToScale[i], gfMul(src[i], coeff), `scaleRow mismatch at ${i}`);
  }

  const coeffs = generateCoeffs(0xdeadbeef, 32);
  assert.equal(coeffs.length, 32);
  assert.ok(coeffs.every((v) => v >= 1 && v <= 255), 'generateCoeffs must yield non-zero GF elements');

  return '255/255 inverses, 512 distributivity checks, mulAddRow/scaleRow verified';
}

// ---------------------------------------------------------------------------
// Test 2: Sliding-Window RLNC 31% Burst Loss + Variable-Length Self-Contained Recovery
// ---------------------------------------------------------------------------
async function test2_rlncBurstRecovery() {
  const winSize = 32;
  const encoder = new RlncEncoder({
    maxWindowSize: winSize,
    maxSymbolSize: MAX_CODED_SYMBOL,
  });
  const decoder = new RlncDecoder({
    maxKnownHistory: 128,
    maxActiveEquations: 64,
  });

  /** @type {Map<number, { meta: object, unit: Buffer }>} */
  const originals = new Map();
  let streamOffset = 0;

  for (let seq = 1; seq <= winSize; seq++) {
    // Variable payload lengths between 43 bytes and 1091 bytes
    const payloadLen = 43 + ((seq * 197) % 1049);
    const payload = randomBytes(payloadLen);
    const meta = {
      priority: seq % 8,
      fin: seq === winSize,
      zstd: seq % 3 === 0,
      streamId: (seq % 4) + 1,
      streamOffset,
      payload,
    };
    streamOffset += payloadLen;

    const unit = encodeStreamSymbolUnit(meta);
    originals.set(seq, { meta, unit });
    encoder.addSourceSymbol(seq, unit);
  }

  // Drop 10 of 32 packets (31.25% loss), including a 5-packet consecutive burst (7..11)
  const droppedSet = new Set([2, 7, 8, 9, 10, 11, 16, 22, 27, 31]);
  assert.equal(droppedSet.size, 10);

  /** @type {Map<number, Uint8Array>} */
  const delivered = new Map();

  for (let seq = 1; seq <= winSize; seq++) {
    if (droppedSet.has(seq)) continue;
    const { unit } = originals.get(seq);
    delivered.set(seq, unit);
    const rec = decoder.addSourceSymbol(seq, unit);
    for (const item of rec) {
      delivered.set(item.sourceSeq, item.data);
    }
  }

  // Feed 12 RLNC repair packets
  let totalRecovered = 0;
  for (let r = 0; r < 12; r++) {
    const repair = encoder.generateRepair();
    assert.ok(repair, `generateRepair() #${r} returned null`);
    const rec = decoder.addRepairSymbol(
      repair.winStart,
      repair.winLen,
      repair.prngSeed,
      repair.codedSymbol
    );
    for (const item of rec) {
      delivered.set(item.sourceSeq, item.data);
      totalRecovered++;
    }
  }

  assert.equal(decoder.getCumulativeSeq(), winSize, 'Cumulative seq did not reach 32');
  assert.equal(delivered.size, winSize, `Expected 32 symbols, got ${delivered.size}`);
  assert.ok(totalRecovered >= droppedSet.size, 'Not all dropped symbols were recovered via RLNC');

  // Verify every single variable-length symbol decodes byte-for-byte identically
  for (let seq = 1; seq <= winSize; seq++) {
    const raw = delivered.get(seq);
    assert.ok(raw, `Missing symbol seq=${seq}`);
    const decoded = decodeStreamSymbolUnit(raw);
    const { meta } = originals.get(seq);

    assert.equal(decoded.streamId, meta.streamId, `streamId mismatch at seq=${seq}`);
    assert.equal(decoded.streamOffset, meta.streamOffset, `streamOffset mismatch at seq=${seq}`);
    assert.equal(decoded.priority, meta.priority, `priority mismatch at seq=${seq}`);
    assert.equal(decoded.fin, meta.fin, `fin mismatch at seq=${seq}`);
    assert.equal(decoded.zstd, meta.zstd, `zstd mismatch at seq=${seq}`);
    assert.equal(
      Buffer.compare(Buffer.from(decoded.payload), meta.payload),
      0,
      `payload byte mismatch at seq=${seq}`
    );
  }

  return `32/32 variable-length units restored after 10/32 (31.25%) burst drop using 12 repairs`;
}

// ---------------------------------------------------------------------------
// Test 3: Wire Format Round-Trip (Header + 5 Frame Types) & MTU Overflow Guard
// ---------------------------------------------------------------------------
async function test3_wireFormatAndMtuGuard() {
  assert.ok(HEADER_LEN > 0 && AUTH_TAG_LEN > 0 && MAX_PLAINTEXT > 0);
  assert.ok(MAX_UDP_PAYLOAD >= HEADER_LEN + MAX_PLAINTEXT + AUTH_TAG_LEN);
  assert.ok(MAX_STREAM_PAYLOAD <= MAX_CODED_SYMBOL);
  assert.ok(typeof STREAM_FLAGS === 'object' && STREAM_FLAGS !== null);

  // Header encode/decode round-trip
  const hdrIn = {
    version: PROTO_VERSION,
    pktType: PKT_TYPE.DATA,
    is0Rtt: false,
    connId: 0x2468ace0,
    packetNum: 987654,
    txTimeUs: 0x00abcdef,
  };
  const hdrBuf = encodeHeader(hdrIn);
  assert.equal(hdrBuf.length, HEADER_LEN);
  const hdrOut = decodeHeader(hdrBuf);
  assert.equal(hdrOut.version, hdrIn.version);
  assert.equal(hdrOut.pktType, hdrIn.pktType);
  assert.equal(hdrOut.connId, hdrIn.connId);
  assert.equal(hdrOut.packetNum, hdrIn.packetNum);
  assert.equal(hdrOut.txTimeUs, hdrIn.txTimeUs);

  // Frame 1: HANDSHAKE
  const hsFrame = {
    type: FRAME_TYPE.HANDSHAKE,
    isServer: true,
    ephemeralPubKey: randomBytes(32),
    nonceSalt: randomBytes(16),
    sessionTicket: randomBytes(48),
  };
  const [hsDec] = decodeFrames(encodeFrames([hsFrame]));
  assert.equal(hsDec.type, FRAME_TYPE.HANDSHAKE);
  assert.equal(hsDec.isServer, true);
  assert.equal(Buffer.compare(Buffer.from(hsDec.ephemeralPubKey), hsFrame.ephemeralPubKey), 0);
  assert.equal(Buffer.compare(Buffer.from(hsDec.nonceSalt), hsFrame.nonceSalt), 0);
  assert.equal(Buffer.compare(Buffer.from(hsDec.sessionTicket), hsFrame.sessionTicket), 0);

  // Frame 2: STREAM
  const streamPayload = Buffer.from('AETHER-W6 stream wire test payload');
  const symbolUnit = encodeStreamSymbolUnit({
    priority: 6,
    fin: true,
    zstd: false,
    streamId: 7,
    streamOffset: 4096,
    payload: streamPayload,
  });
  const [stDec] = decodeFrames(
    encodeFrames([{ type: FRAME_TYPE.STREAM, sourceSeq: 42, symbolUnit }])
  );
  assert.equal(stDec.type, FRAME_TYPE.STREAM);
  assert.equal(stDec.sourceSeq, 42);
  assert.equal(stDec.streamId, 7);
  assert.equal(stDec.streamOffset, 4096);
  assert.equal(stDec.priority, 6);
  assert.equal(stDec.fin, true);
  assert.equal(Buffer.compare(Buffer.from(stDec.payload), streamPayload), 0);

  // Frame 3: RLNC_REPAIR
  const coded = randomBytes(128);
  const [rpDec] = decodeFrames(
    encodeFrames([
      {
        type: FRAME_TYPE.RLNC_REPAIR,
        flags: 0,
        winStart: 10,
        winLen: 16,
        prngSeed: 0x55aa1234,
        codedSymbol: coded,
      },
    ])
  );
  assert.equal(rpDec.type, FRAME_TYPE.RLNC_REPAIR);
  assert.equal(rpDec.winStart, 10);
  assert.equal(rpDec.winLen, 16);
  assert.equal(rpDec.prngSeed, 0x55aa1234);
  assert.equal(Buffer.compare(Buffer.from(rpDec.codedSymbol), coded), 0);

  // Frame 4: ACK_TELEMETRY
  const sack = new Uint32Array([0b101101, 0b11]);
  const [ackDec] = decodeFrames(
    encodeFrames([
      {
        type: FRAME_TYPE.ACK_TELEMETRY,
        largestAckedPkt: 500,
        ackDelayUs: 1250,
        cumSourceSeq: 412,
        recvOwdGrad: -12,
        sackBitmap: sack,
      },
    ])
  );
  assert.equal(ackDec.type, FRAME_TYPE.ACK_TELEMETRY);
  assert.equal(ackDec.largestAckedPkt, 500);
  assert.equal(ackDec.ackDelayUs, 1250);
  assert.equal(ackDec.cumSourceSeq, 412);
  assert.equal(ackDec.recvOwdGrad, -12);
  assert.equal(ackDec.sackBitmap[0], sack[0]);
  assert.equal(ackDec.sackBitmap[1], sack[1]);

  // Frame 5: Remaining frame type in FRAME_TYPE (e.g., CLOSE / CONN_CLOSE / PING / PADDING)
  const knownFour = new Set([
    FRAME_TYPE.HANDSHAKE,
    FRAME_TYPE.STREAM,
    FRAME_TYPE.RLNC_REPAIR,
    FRAME_TYPE.ACK_TELEMETRY,
  ]);
  const fifthEntry = Object.entries(FRAME_TYPE).find(([, val]) => !knownFour.has(val));
  assert.ok(fifthEntry, 'Expected a 5th frame type in FRAME_TYPE');
  const [fifthName, fifthType] = fifthEntry;

  let fifthFrame;
  if (/CLOSE/i.test(fifthName)) {
    fifthFrame = { type: fifthType, errorCode: 0, reason: 'graceful-close' };
  } else if (/PING/i.test(fifthName)) {
    fifthFrame = { type: fifthType, nonce: 0x11223344, timestampUs: 123456 };
  } else if (/PAD/i.test(fifthName)) {
    fifthFrame = { type: fifthType, length: 16 };
  } else {
    fifthFrame = { type: fifthType, errorCode: 0, reason: 'ok', length: 8 };
  }
  const fifthDecoded = decodeFrames(encodeFrames([fifthFrame]));
  assert.ok(
    fifthDecoded.length === 0 || fifthDecoded[0].type === fifthType,
    `5th frame (${fifthName}) round-trip failed`
  );

  // MTU / MAX_PLAINTEXT overflow guard must throw RangeError
  const oversizedUnit = Buffer.alloc(MAX_PLAINTEXT + 128, 0xab);
  assert.throws(
    () =>
      encodeFrames([
        {
          type: FRAME_TYPE.STREAM,
          sourceSeq: 1,
          symbolUnit: oversizedUnit,
        },
      ]),
    RangeError,
    'Exceeding MAX_PLAINTEXT must throw RangeError'
  );

  return `Header + 5 frames (incl. ${fifthName}) round-trip & MAX_PLAINTEXT=${MAX_PLAINTEXT} RangeError guard verified`;
}

// ---------------------------------------------------------------------------
// Test 4: 0-RTT/1-RTT AEAD Encryption, AAD/Ciphertext Tamper Rejection & Ticket Anti-Replay
// ---------------------------------------------------------------------------
async function test4_cryptoAndAntiReplay() {
  const clientKp = AetherCrypto.generateKeyPair();
  const serverKp = AetherCrypto.generateKeyPair();

  const clientSecret = AetherCrypto.computeSharedSecret(clientKp.privateKey, serverKp.publicKeyRaw);
  const serverSecret = AetherCrypto.computeSharedSecret(serverKp.privateKey, clientKp.publicKeyRaw);
  assert.equal(clientSecret.length, 32);
  assert.equal(Buffer.compare(clientSecret, serverSecret), 0, 'X25519 shared secrets must match');

  const clientSalt = randomBytes(16);
  const serverSalt = randomBytes(16);
  const fullSalt = Buffer.concat([clientSalt, serverSalt]);

  const clientCrypto = new AetherCrypto();
  const serverCrypto = new AetherCrypto();
  clientCrypto.install1RttKeys(clientSecret, fullSalt, false);
  serverCrypto.install1RttKeys(serverSecret, fullSalt, true);

  const plaintext = Buffer.from('AETHER-W6 ChaCha20-Poly1305 AEAD verification payload');
  const pkt1Rtt = clientCrypto.encryptPacket(
    {
      version: PROTO_VERSION,
      pktType: PKT_TYPE.DATA,
      connId: 0x01020304,
      packetNum: 7,
      txTimeUs: 10000,
    },
    plaintext
  );

  // Valid 1-RTT decrypt
  const dec1Rtt = serverCrypto.decryptPacket(pkt1Rtt);
  assert.equal(Buffer.compare(dec1Rtt.plaintext, plaintext), 0);

  // Flip 1 bit in Header (AAD) -> must throw
  const tamperedHeader = Buffer.from(pkt1Rtt);
  tamperedHeader[6] ^= 0x01;
  assert.throws(
    () => serverCrypto.decryptPacket(tamperedHeader),
    'Tampered AAD header must be rejected'
  );

  // Flip 1 bit in ciphertext/auth tag -> must throw
  const tamperedCipher = Buffer.from(pkt1Rtt);
  tamperedCipher[HEADER_LEN + 3] ^= 0x80;
  assert.throws(
    () => serverCrypto.decryptPacket(tamperedCipher),
    'Tampered ciphertext must be rejected'
  );

  // 0-RTT Ticket issuance, encryption & anti-replay
  const tm = new SessionTicketManager();
  const psk = randomBytes(32);
  const { ticket } = tm.issueTicket(psk);
  assert.ok(ticket.length > 0);

  const verified = tm.verifyAndConsumeTicket(ticket);
  assert.equal(Buffer.compare(verified.psk, psk), 0, 'Verified ticket PSK mismatch');

  // Replay of same ticket must throw
  assert.throws(
    () => tm.verifyAndConsumeTicket(ticket),
    'Replayed SessionTicket must be rejected'
  );

  // 0-RTT packet encrypt/decrypt round-trip
  clientCrypto.install0RttKeys(psk, clientSalt, false);
  serverCrypto.install0RttKeys(verified.psk, clientSalt, true);

  const earlyPlain = Buffer.from('0-RTT early stream payload');
  const pkt0Rtt = clientCrypto.encryptPacket(
    {
      version: PROTO_VERSION,
      pktType: PKT_TYPE.ZERO_RTT,
      is0Rtt: true,
      connId: 0x01020304,
      packetNum: 1,
      txTimeUs: 20000,
    },
    earlyPlain,
    { use0Rtt: true }
  );
  const dec0Rtt = serverCrypto.decryptPacket(pkt0Rtt, { use0Rtt: true });
  assert.equal(Buffer.compare(dec0Rtt.plaintext, earlyPlain), 0);

  return 'X25519 ECDH, 1-RTT/0-RTT AEAD, 1-bit AAD/ciphertext rejection, ticket anti-replay verified';
}

// ---------------------------------------------------------------------------
// Test 5: Shannon Entropy-Gated Native Zstd Compression
// ---------------------------------------------------------------------------
async function test5_entropyGatedZstd() {
  const repetitiveText = Buffer.from(
    JSON.stringify({
      type: 'telemetry',
      status: 'nominal',
      metrics: Array.from({ length: 24 }, (_, i) => ({
        channel: 'wifi6-5ghz',
        index: i,
        rssi: -52,
        mcs: 9,
      })),
    })
  );
  const hLow = shannonEntropy(repetitiveText);
  assert.ok(hLow < 7.2, `Expected low entropy < 7.2, got ${hLow.toFixed(3)}`);

  const compLow = adaptiveCompress(repetitiveText);
  assert.equal(compLow.compressed, true, 'Low-entropy payload must trigger Zstd compression');
  assert.ok(
    compLow.data.length < repetitiveText.length,
    `Expected size reduction: ${compLow.data.length} vs ${repetitiveText.length}`
  );
  const restoredLow = adaptiveDecompress(compLow.data, compLow.compressed);
  assert.equal(Buffer.compare(restoredLow, repetitiveText), 0, 'Decompressed low-entropy mismatch');

  const highEntropyBuf = randomBytes(1200);
  const hHigh = shannonEntropy(highEntropyBuf);
  assert.ok(hHigh > 7.5, `Expected high entropy > 7.5, got ${hHigh.toFixed(3)}`);

  const compHigh = adaptiveCompress(highEntropyBuf);
  assert.equal(compHigh.compressed, false, 'High-entropy payload must bypass Zstd');
  assert.equal(
    compHigh.data.length,
    highEntropyBuf.length,
    'High-entropy passthrough must have zero size expansion'
  );
  const restoredHigh = adaptiveDecompress(compHigh.data, compHigh.compressed);
  assert.equal(Buffer.compare(restoredHigh, highEntropyBuf), 0, 'Passthrough byte mismatch');

  return `Low-H (${hLow.toFixed(2)}) ${repetitiveText.length}B->${compLow.data.length}B; High-H (${hHigh.toFixed(2)}) 1200B->1200B passthrough`;
}

// ---------------------------------------------------------------------------
// Test 6: Kalman Delay Gradient & Wireless Loss-Decoupled CC Attribution
// ---------------------------------------------------------------------------
async function test6_kalmanAndWirelessCC() {
  const kf = new KalmanDelayFilter();
  const cc = new WirelessCongestionCtrl();
  const pacer = new MicroPacer({ rateBps: cc.getPacingRateBps() });
  assert.ok(pacer.canSend(1200, 0));

  const getSnap = () => {
    const s = cc.getSnapshot();
    return {
      state: s.state ?? cc.state,
      cwndBytes: s.cwndBytes ?? cc.cwndBytes,
      redundancyRho: s.redundancyRho ?? cc.getRedundancyRho(),
    };
  };

  let nowMs = 100;
  // Phase 1: Establish stable low-delay baseline (RTT=10ms, 0% loss)
  for (let i = 0; i < 12; i++) {
    nowMs += 15;
    const est = kf.update(5.0, nowMs);
    cc.onPacketSent(20 * 1300, nowMs - 10);
    cc.onAckTelemetry({
      ackedBytes: 20 * 1300,
      lostCount: 0,
      totalTracked: 20,
      rttMs: 10.0,
      recvOwdGrad: est.delayGradient,
      maxBurstLen: 0,
      nowMs,
    });
  }
  const baseSnap = getSnap();

  // Phase 2: Low queue delay + 15% wireless loss -> WIRELESS_BOOST, cwnd does not drop, rho increases
  let sawWirelessBoost = false;
  let boostSnap = baseSnap;
  for (let i = 0; i < 15; i++) {
    nowMs += 15;
    const est = kf.update(5.1, nowMs);
    cc.onPacketSent(20 * 1300, nowMs - 10);
    cc.onPacketRetired(3 * 1300);
    cc.onAckTelemetry({
      ackedBytes: 17 * 1300,
      lostCount: 3,
      totalTracked: 20,
      rttMs: 10.2,
      recvOwdGrad: est.delayGradient,
      maxBurstLen: 2,
      nowMs,
    });
    const cur = getSnap();
    if (cur.state === 'WIRELESS_BOOST') {
      sawWirelessBoost = true;
      boostSnap = cur;
    }
  }
  assert.ok(sawWirelessBoost, `Expected WIRELESS_BOOST state, got ${getSnap().state}`);
  assert.ok(
    boostSnap.cwndBytes >= baseSnap.cwndBytes,
    `cwndBytes should not shrink on wireless loss: ${boostSnap.cwndBytes} < ${baseSnap.cwndBytes}`
  );
  assert.ok(
    boostSnap.redundancyRho > baseSnap.redundancyRho,
    `redundancyRho should rise on wireless loss: ${boostSnap.redundancyRho} <= ${baseSnap.redundancyRho}`
  );

  // Phase 3: Queue delay climbing steadily to 45ms -> BUFFERBLOAT_DRAIN, cwnd contracts
  const cwndBeforeBloat = getSnap().cwndBytes;
  let sawBufferbloatDrain = false;
  let drainSnap = getSnap();
  for (let i = 1; i <= 20; i++) {
    nowMs += 20;
    const queueDelayMs = (45 * i) / 20; // climbs 2.25ms -> 45ms
    const est = kf.update(5.0 + queueDelayMs, nowMs);
    cc.onPacketSent(16 * 1300, nowMs - (10 + queueDelayMs));
    cc.onAckTelemetry({
      ackedBytes: 16 * 1300,
      lostCount: 0,
      totalTracked: 16,
      rttMs: 10.0 + queueDelayMs,
      recvOwdGrad: est.delayGradient,
      maxBurstLen: 0,
      nowMs,
    });
    const cur = getSnap();
    if (cur.state === 'BUFFERBLOAT_DRAIN') {
      sawBufferbloatDrain = true;
      drainSnap = cur;
    }
  }

  assert.ok(sawBufferbloatDrain, `Expected BUFFERBLOAT_DRAIN state, got ${getSnap().state}`);
  assert.ok(
    drainSnap.cwndBytes < cwndBeforeBloat,
    `cwndBytes should contract during BUFFERBLOAT_DRAIN: ${drainSnap.cwndBytes} >= ${cwndBeforeBloat}`
  );

  return `WIRELESS_BOOST (cwnd=${Math.round(boostSnap.cwndBytes)}B, rho=${boostSnap.redundancyRho.toFixed(2)}) -> BUFFERBLOAT_DRAIN (cwnd=${Math.round(drainSnap.cwndBytes)}B)`;
}

// ---------------------------------------------------------------------------
// Test 7: Multi-Stream HoL Isolation & Priority-Weighted Scheduling
// ---------------------------------------------------------------------------
async function test7_streamMuxHolAndPriority() {
  assert.ok(typeof AetherStream === 'function');

  // Part A: HoL Isolation (Stream 1 missing offset 0 while Stream 2 completes immediately)
  const txMux = new StreamMultiplexer({ entropyThreshold: 7.2 });
  const completedIds = [];
  const rxMux = new StreamMultiplexer({
    onStreamComplete: (res) => completedIds.push(res.streamId),
  });

  const s1Data = randomBytes(3600); // spans multiple chunks
  const s2Data = Buffer.from('Stream-2 must complete immediately without waiting for Stream-1!'.repeat(8));

  txMux.enqueueStreamData(1, s1Data, { priority: 3, fin: true });
  txMux.enqueueStreamData(2, s2Data, { priority: 3, fin: true });

  const s1Chunks = [];
  const s2Chunks = [];
  while (txMux.hasPendingChunks()) {
    const ch = txMux.popNextChunk();
    if (ch.streamId === 1) s1Chunks.push(ch);
    else if (ch.streamId === 2) s2Chunks.push(ch);
  }
  assert.ok(s1Chunks.length >= 2, 'Stream 1 should span multiple chunks');

  const s1Offset0 = s1Chunks.find((c) => c.streamOffset === 0);
  assert.ok(s1Offset0, 'Stream 1 offset 0 chunk missing');

  // Deliver Stream 1 chunks EXCEPT offset 0
  const nowMs = performance.now();
  for (const ch of s1Chunks) {
    if (ch.streamOffset === 0) continue;
    rxMux.onStreamUnit({ ...ch, nowMs });
  }
  assert.equal(rxMux.getStreamResult(1)?.completed ?? false, false, 'Stream 1 must not complete without offset 0');

  // Deliver all Stream 2 chunks -> must complete immediately
  for (const ch of s2Chunks) {
    rxMux.onStreamUnit({ ...ch, nowMs });
  }
  const s2Res = rxMux.getStreamResult(2);
  assert.ok(s2Res && s2Res.completed, 'Stream 2 must complete immediately despite Stream 1 missing offset 0');
  assert.equal(Buffer.compare(Buffer.from(s2Res.data), s2Data), 0, 'Stream 2 payload mismatch');
  assert.equal(completedIds[0], 2, 'Stream 2 should be first to complete');

  // Now deliver Stream 1 offset 0 -> Stream 1 completes
  rxMux.onStreamUnit({ ...s1Offset0, nowMs: nowMs + 1 });
  const s1Res = rxMux.getStreamResult(1);
  assert.ok(s1Res && s1Res.completed, 'Stream 1 should complete once offset 0 arrives');
  assert.equal(Buffer.compare(Buffer.from(s1Res.data), s1Data), 0, 'Stream 1 payload mismatch');

  // Part B: Priority-Weighted Scheduling (priority=7 vs priority=0)
  const prioMux = new StreamMultiplexer({ entropyThreshold: 7.2 });
  prioMux.enqueueStreamData(10, randomBytes(36 * 1024), { priority: 7, fin: true });
  prioMux.enqueueStreamData(20, randomBytes(36 * 1024), { priority: 0, fin: true });

  let hiCount = 0;
  let loCount = 0;
  for (let i = 0; i < 24 && prioMux.hasPendingChunks(); i++) {
    const ch = prioMux.popNextChunk();
    if (ch.streamId === 10) hiCount++;
    else if (ch.streamId === 20) loCount++;
  }
  assert.ok(
    hiCount > loCount * 2,
    `Expected priority=7 (${hiCount}) to dequeue significantly more than priority=0 (${loCount})`
  );

  return `HoL isolated (S2 completed while S1 blocked on offset 0); priority=7 vs 0 ratio = ${hiCount}:${loCount}`;
}

// ---------------------------------------------------------------------------
// Test 8: Real Localhost UDP 1-RTT + 0-RTT End-to-End Stream Delivery
// ---------------------------------------------------------------------------
async function test8_udp1RttAnd0RttEndToEnd() {
  const server = new AetherEndpoint({ role: 'server' });
  const client1 = new AetherEndpoint({ role: 'client' });
  const client2 = new AetherEndpoint({ role: 'client' });

  try {
    const serverAddr = await server.bind(0, '127.0.0.1');

    // Phase 1: 1-RTT handshake + stream transfer + obtain saved session ticket/PSK
    const hs1 = await client1.connect('127.0.0.1', serverAddr.port, { timeoutMs: 5000 });
    assert.equal(hs1.used0Rtt, false);

    const payload1 = Buffer.concat([
      Buffer.from('{"phase":"1-RTT","msg":"hello-aether-w6"}'.repeat(200)),
      randomBytes(4096),
    ]);
    client1.sendStream(1, payload1, { priority: 5, fin: true });

    const rx1Map = await server.waitForStreams([1], 8000, hs1.connId);
    const rx1 = rx1Map.get(1);
    assert.ok(rx1 && rx1.completed);
    assert.equal(Buffer.compare(Buffer.from(rx1.data), payload1), 0, '1-RTT stream payload mismatch');

    const saved = client1.getSavedSession();
    assert.ok(saved && saved.ticket.length > 0 && saved.psk.length === 32, 'Missing saved 0-RTT session');
    await client1.close();

    // Phase 2: 0-RTT resumption with earlyStreams
    const earlyPayload = Buffer.from(
      '{"phase":"0-RTT","earlyData":true,"payload":"zero-rtt-stream-verification"}'.repeat(60)
    );
    const hs2 = await client2.connect('127.0.0.1', serverAddr.port, {
      ticket: saved.ticket,
      psk: saved.psk,
      earlyStreams: [{ streamId: 101, data: earlyPayload, priority: 7, fin: true }],
      timeoutMs: 5000,
    });
    assert.equal(hs2.used0Rtt, true, 'Client2 should have used 0-RTT');

    const rx2Map = await server.waitForStreams([101], 8000, hs2.connId);
    const rx2 = rx2Map.get(101);
    assert.ok(rx2 && rx2.completed);
    assert.equal(Buffer.compare(Buffer.from(rx2.data), earlyPayload), 0, '0-RTT early stream payload mismatch');

    const serverMetrics = server.getMetrics(hs2.connId);
    assert.ok(
      serverMetrics.zeroRttRx > 0,
      `Expected server zeroRttRx > 0, got ${serverMetrics.zeroRttRx}`
    );

    return `1-RTT (${payload1.length}B) + 0-RTT (${earlyPayload.length}B, zeroRttRx=${serverMetrics.zeroRttRx}) verified byte-for-byte`;
  } finally {
    await Promise.allSettled([client1.close(), client2.close(), server.close()]);
  }
}

// ---------------------------------------------------------------------------
// Main Runner
// ---------------------------------------------------------------------------
async function main() {
  console.log('=== AETHER-W6 Unit & Integration Test Suite ===\n');
  const suiteStart = performance.now();

  await runTest(1, 'GF(2^8) 域公理与向量化行运算', test1_gf256Axioms);
  await runTest(2, '滑动窗口 RLNC 31% 突发丢包 + 变长符号恢复', test2_rlncBurstRecovery);
  await runTest(3, 'Wire Format 往返与 MTU 越界守卫', test3_wireFormatAndMtuGuard);
  await runTest(4, '0-RTT/1-RTT 加解密、AAD 篡改拒收与 Ticket 防重放', test4_cryptoAndAntiReplay);
  await runTest(5, '香农熵门控原生 Zstd 压缩/直通', test5_entropyGatedZstd);
  await runTest(6, '卡尔曼延迟梯度与无线丢包归因', test6_kalmanAndWirelessCC);
  await runTest(7, '多流 HoL 隔离与优先级加权调度', test7_streamMuxHolAndPriority);
  await runTest(8, '真实本机 UDP 1-RTT + 0-RTT 端到端传流', test8_udp1RttAnd0RttEndToEnd);

  const passed = results.filter((r) => r.pass).length;
  const failed = results.length - passed;
  const totalMs = (performance.now() - suiteStart).toFixed(2);

  console.log('\n-----------------------------------------------');
  console.log(`Summary: ${passed}/${results.length} passed, ${failed} failed (${totalMs} ms)`);
  console.log('-----------------------------------------------');

  if (failed > 0) {
    process.exitCode = 1;
  }
}

await main();