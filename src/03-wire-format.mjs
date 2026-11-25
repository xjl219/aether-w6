// FILE: 03-wire-format.mjs
/**
 * AETHER-W6 Binary Wire Format Codec
 * Pure IPv4 MTU=1500 safe envelope:
 *   MAX_UDP_PAYLOAD (1380 B) = HEADER_LEN (16 B) + MAX_PLAINTEXT (1348 B) + AUTH_TAG_LEN (16 B)
 * All multi-byte integers are encoded in Big-Endian (network byte order).
 */

export const PROTO_VERSION = 1;
export const MAX_UDP_PAYLOAD = 1380;
export const HEADER_LEN = 16;
export const AUTH_TAG_LEN = 16;
export const MAX_PLAINTEXT = 1348;
export const MAX_CODED_SYMBOL = 1328;
export const MAX_STREAM_PAYLOAD = 1319;

const STREAM_SYMBOL_HDR_LEN = 9; // FrameFlags(1) + StreamID(2) + StreamOffset(4) + DataLen(2)
const MAX_SACK_WORDS = 8;

export const PKT_TYPE = Object.freeze({
  DATA: 0x01,
  HANDSHAKE: 0x02,
  ZERO_RTT: 0x03,
  PROBE: 0x04,
});

export const FRAME_TYPE = Object.freeze({
  STREAM: 0x10,
  RLNC_REPAIR: 0x20,
  ACK_TELEMETRY: 0x30,
  HANDSHAKE: 0x40,
  PING: 0x50,
});

export const STREAM_FLAGS = Object.freeze({
  FIN: 0x80,
  ZSTD: 0x40,
  PRIORITY_MASK: 0x38,
  PRIORITY_SHIFT: 3,
});

/**
 * Normalize Uint8Array / Buffer input to a Node.js Buffer view without unnecessary copies.
 * @param {Buffer | Uint8Array} data
 * @returns {Buffer}
 */
function asBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new TypeError('Expected Buffer or Uint8Array');
}

/**
 * Encode 16-byte fixed AETHER-W6 packet header (used directly as ChaCha20-Poly1305 AAD).
 * Layout: VerFlags(1) | PktType(1) | PayloadLen(2) | ConnID(4) | PacketNum(4) | TxTimeUs(4)
 * @param {object} hdr
 * @returns {Buffer}
 */
export function encodeHeader({
  version = PROTO_VERSION,
  keyPhase = 0,
  is0Rtt = false,
  coalesced = false,
  pktType = PKT_TYPE.DATA,
  payloadLen = 0,
  connId = 0,
  packetNum = 0,
  txTimeUs = 0,
}) {
  if (version < 0 || version > 15) {
    throw new RangeError(`Invalid protocol version: ${version}`);
  }
  if (payloadLen < 0 || payloadLen > MAX_PLAINTEXT) {
    throw new RangeError(`payloadLen ${payloadLen} exceeds MAX_PLAINTEXT (${MAX_PLAINTEXT})`);
  }

  const buf = Buffer.allocUnsafe(HEADER_LEN);
  const verFlags =
    ((version & 0x0f) << 4) |
    (keyPhase ? 0x08 : 0) |
    (is0Rtt ? 0x04 : 0) |
    (coalesced ? 0x02 : 0);

  buf.writeUInt8(verFlags, 0);
  buf.writeUInt8(pktType & 0xff, 1);
  buf.writeUInt16BE(payloadLen & 0xffff, 2);
  buf.writeUInt32BE(connId >>> 0, 4);
  buf.writeUInt32BE(packetNum >>> 0, 8);
  buf.writeUInt32BE(txTimeUs >>> 0, 12);
  return buf;
}

/**
 * Decode 16-byte fixed AETHER-W6 packet header.
 * @param {Buffer | Uint8Array} input
 * @param {number} [offset=0]
 * @returns {object}
 */
export function decodeHeader(input, offset = 0) {
  const buf = asBuffer(input);
  if (offset < 0 || offset + HEADER_LEN > buf.length) {
    throw new RangeError(`Header truncated: need ${HEADER_LEN} bytes at offset ${offset}`);
  }

  const verFlags = buf.readUInt8(offset);
  const version = (verFlags >>> 4) & 0x0f;
  if (version !== PROTO_VERSION) {
    throw new RangeError(`Unsupported protocol version: ${version} (expected ${PROTO_VERSION})`);
  }

  const keyPhase = (verFlags & 0x08) !== 0 ? 1 : 0;
  const is0Rtt = (verFlags & 0x04) !== 0;
  const coalesced = (verFlags & 0x02) !== 0;
  const pktType = buf.readUInt8(offset + 1);
  const payloadLen = buf.readUInt16BE(offset + 2);

  if (payloadLen > MAX_PLAINTEXT) {
    throw new RangeError(`Header payloadLen ${payloadLen} exceeds MAX_PLAINTEXT (${MAX_PLAINTEXT})`);
  }

  const connId = buf.readUInt32BE(offset + 4);
  const packetNum = buf.readUInt32BE(offset + 8);
  const txTimeUs = buf.readUInt32BE(offset + 12);

  return {
    version,
    keyPhase,
    is0Rtt,
    coalesced,
    pktType,
    payloadLen,
    connId,
    packetNum,
    txTimeUs,
  };
}

/**
 * Encode a self-contained RLNC stream symbol unit:
 * [FrameFlags(1B) | StreamID(2B) | StreamOffset(4B) | DataLen(2B) | Payload(L B)]
 * Total length = 9 + L <= MAX_CODED_SYMBOL (1328 B).
 * @param {object} unit
 * @returns {Buffer}
 */
export function encodeStreamSymbolUnit({
  flags,
  priority = 0,
  fin = false,
  zstd = false,
  streamId,
  streamOffset,
  payload = Buffer.alloc(0),
}) {
  const payloadBuf = asBuffer(payload);
  const dataLen = payloadBuf.length;
  if (dataLen > MAX_STREAM_PAYLOAD) {
    throw new RangeError(
      `Stream payload length ${dataLen} exceeds MAX_STREAM_PAYLOAD (${MAX_STREAM_PAYLOAD})`
    );
  }
  if (streamId < 0 || streamId > 0xffff) {
    throw new RangeError(`Invalid streamId: ${streamId}`);
  }

  const frameFlags =
    typeof flags === 'number'
      ? flags & 0xff
      : (fin ? STREAM_FLAGS.FIN : 0) |
        (zstd ? STREAM_FLAGS.ZSTD : 0) |
        ((priority & 0x07) << STREAM_FLAGS.PRIORITY_SHIFT);

  const out = Buffer.allocUnsafe(STREAM_SYMBOL_HDR_LEN + dataLen);
  out.writeUInt8(frameFlags, 0);
  out.writeUInt16BE(streamId & 0xffff, 1);
  out.writeUInt32BE(streamOffset >>> 0, 3);
  out.writeUInt16BE(dataLen, 7);
  if (dataLen > 0) {
    payloadBuf.copy(out, STREAM_SYMBOL_HDR_LEN);
  }
  return out;
}

/**
 * Decode a self-contained RLNC stream symbol unit.
 * Uses embedded DataLen to slice exact payload, safely ignoring any trailing RLNC zero-padding.
 * @param {Buffer | Uint8Array} input
 * @returns {object}
 */
export function decodeStreamSymbolUnit(input) {
  const buf = asBuffer(input);
  if (buf.length < STREAM_SYMBOL_HDR_LEN) {
    throw new RangeError(
      `Stream symbol unit too short: ${buf.length} < ${STREAM_SYMBOL_HDR_LEN}`
    );
  }

  const flags = buf.readUInt8(0);
  const streamId = buf.readUInt16BE(1);
  const streamOffset = buf.readUInt32BE(3);
  const dataLen = buf.readUInt16BE(7);

  if (dataLen > MAX_STREAM_PAYLOAD) {
    throw new RangeError(
      `Decoded dataLen ${dataLen} exceeds MAX_STREAM_PAYLOAD (${MAX_STREAM_PAYLOAD})`
    );
  }
  if (STREAM_SYMBOL_HDR_LEN + dataLen > buf.length) {
    throw new RangeError(
      `Stream symbol unit truncated: need ${STREAM_SYMBOL_HDR_LEN + dataLen} bytes, got ${buf.length}`
    );
  }

  const fin = (flags & STREAM_FLAGS.FIN) !== 0;
  const zstd = (flags & STREAM_FLAGS.ZSTD) !== 0;
  const priority = (flags & STREAM_FLAGS.PRIORITY_MASK) >>> STREAM_FLAGS.PRIORITY_SHIFT;
  const payload = Buffer.from(
    buf.subarray(STREAM_SYMBOL_HDR_LEN, STREAM_SYMBOL_HDR_LEN + dataLen)
  );

  return {
    flags,
    fin,
    zstd,
    priority,
    streamId,
    streamOffset,
    dataLen,
    payload,
  };
}

/**
 * Encode one or more frames into a coalesced plaintext buffer (strictly <= MAX_PLAINTEXT).
 * @param {Array<object>} frames
 * @returns {Buffer}
 */
export function encodeFrames(frames) {
  if (!Array.isArray(frames) || frames.length === 0) {
    throw new RangeError('encodeFrames requires a non-empty array of frames');
  }

  /** @type {Buffer[]} */
  const chunks = [];
  let totalLen = 0;

  for (const frame of frames) {
    let chunk;
    switch (frame.type) {
      case FRAME_TYPE.STREAM: {
        // Layout: FrameType(1) | SourceSeq(4) | StreamSymbolUnit(9 + L)
        const symbolUnit = frame.symbolUnit
          ? asBuffer(frame.symbolUnit)
          : encodeStreamSymbolUnit(frame);
        if (symbolUnit.length < STREAM_SYMBOL_HDR_LEN || symbolUnit.length > MAX_CODED_SYMBOL) {
          throw new RangeError(`Invalid STREAM symbolUnit length: ${symbolUnit.length}`);
        }
        chunk = Buffer.allocUnsafe(5 + symbolUnit.length);
        chunk.writeUInt8(FRAME_TYPE.STREAM, 0);
        chunk.writeUInt32BE(frame.sourceSeq >>> 0, 1);
        symbolUnit.copy(chunk, 5);
        break;
      }

      case FRAME_TYPE.RLNC_REPAIR: {
        // Layout: FrameType(1) | FrameFlags(1) | WinStart(4) | WinLen(2) | PrngSeed(4) | SymbolLen(2) | CodedSymbol(S)
        const coded = asBuffer(frame.codedSymbol);
        const symbolLen = coded.length;
        if (symbolLen > MAX_CODED_SYMBOL) {
          throw new RangeError(
            `RLNC_REPAIR symbol length ${symbolLen} exceeds MAX_CODED_SYMBOL (${MAX_CODED_SYMBOL})`
          );
        }
        if (frame.winLen < 1 || frame.winLen > 0xffff) {
          throw new RangeError(`Invalid RLNC_REPAIR winLen: ${frame.winLen}`);
        }
        chunk = Buffer.allocUnsafe(14 + symbolLen);
        chunk.writeUInt8(FRAME_TYPE.RLNC_REPAIR, 0);
        chunk.writeUInt8((frame.flags ?? 0) & 0xff, 1);
        chunk.writeUInt32BE(frame.winStart >>> 0, 2);
        chunk.writeUInt16BE(frame.winLen & 0xffff, 6);
        chunk.writeUInt32BE(frame.prngSeed >>> 0, 8);
        chunk.writeUInt16BE(symbolLen, 12);
        if (symbolLen > 0) {
          coded.copy(chunk, 14);
        }
        break;
      }

      case FRAME_TYPE.ACK_TELEMETRY: {
        // Layout: FrameType(1) | SackWordCount(1) | LargestAckedPkt(4) | AckDelayUs(4) | CumSourceSeq(4) | RecvOwdGrad(2) | SackBitmap(4*N)
        const sackBitmap = frame.sackBitmap ?? [];
        const sackCount = sackBitmap.length;
        if (sackCount > MAX_SACK_WORDS) {
          throw new RangeError(`SackWordCount ${sackCount} exceeds max ${MAX_SACK_WORDS}`);
        }
        const owdGrad = Math.max(-32768, Math.min(32767, Math.trunc(frame.recvOwdGrad ?? 0)));
        chunk = Buffer.allocUnsafe(16 + sackCount * 4);
        chunk.writeUInt8(FRAME_TYPE.ACK_TELEMETRY, 0);
        chunk.writeUInt8(sackCount, 1);
        chunk.writeUInt32BE((frame.largestAckedPkt ?? 0) >>> 0, 2);
        chunk.writeUInt32BE((frame.ackDelayUs ?? 0) >>> 0, 6);
        chunk.writeUInt32BE((frame.cumSourceSeq ?? 0) >>> 0, 10);
        chunk.writeInt16BE(owdGrad, 14);
        for (let i = 0; i < sackCount; i++) {
          chunk.writeUInt32BE(sackBitmap[i] >>> 0, 16 + i * 4);
        }
        break;
      }

      case FRAME_TYPE.HANDSHAKE: {
        // Layout: FrameType(1) | FrameFlags(1) | EphemeralPubKey(32) | NonceSalt(16) | TicketLen(2) | SessionTicket(T)
        const pubKey = asBuffer(frame.ephemeralPubKey);
        const nonceSalt = asBuffer(frame.nonceSalt);
        const ticket = frame.sessionTicket ? asBuffer(frame.sessionTicket) : Buffer.alloc(0);

        if (pubKey.length !== 32) {
          throw new RangeError(`HANDSHAKE ephemeralPubKey must be 32 bytes, got ${pubKey.length}`);
        }
        if (nonceSalt.length !== 16) {
          throw new RangeError(`HANDSHAKE nonceSalt must be 16 bytes, got ${nonceSalt.length}`);
        }

        const hasTicket = ticket.length > 0;
        const flags =
          typeof frame.flags === 'number'
            ? frame.flags & 0xff
            : (frame.isServer ? 0x80 : 0) | (hasTicket ? 0x40 : 0);

        chunk = Buffer.allocUnsafe(52 + ticket.length);
        chunk.writeUInt8(FRAME_TYPE.HANDSHAKE, 0);
        chunk.writeUInt8(flags, 1);
        pubKey.copy(chunk, 2);
        nonceSalt.copy(chunk, 34);
        chunk.writeUInt16BE(ticket.length, 50);
        if (ticket.length > 0) {
          ticket.copy(chunk, 52);
        }
        break;
      }

      case FRAME_TYPE.PING: {
        // Layout: FrameType(1) | FrameFlags(1) | PingId(4) | TimestampUs(4)
        const flags =
          typeof frame.flags === 'number'
            ? frame.flags & 0xff
            : frame.isPong ? 0x01 : 0x00;
        chunk = Buffer.allocUnsafe(10);
        chunk.writeUInt8(FRAME_TYPE.PING, 0);
        chunk.writeUInt8(flags, 1);
        chunk.writeUInt32BE((frame.pingId ?? 0) >>> 0, 2);
        chunk.writeUInt32BE((frame.timestampUs ?? 0) >>> 0, 6);
        break;
      }

      default:
        throw new RangeError(`Unknown frame type: 0x${Number(frame.type).toString(16)}`);
    }

    totalLen += chunk.length;
    if (totalLen > MAX_PLAINTEXT) {
      throw new RangeError(
        `Coalesced frames length ${totalLen} exceeds MAX_PLAINTEXT (${MAX_PLAINTEXT})`
      );
    }
    chunks.push(chunk);
  }

  return chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, totalLen);
}

/**
 * Decode all coalesced frames from a decrypted plaintext buffer.
 * @param {Buffer | Uint8Array} input
 * @returns {Array<object>}
 */
export function decodeFrames(input) {
  const buf = asBuffer(input);
  if (buf.length > MAX_PLAINTEXT) {
    throw new RangeError(`Plaintext length ${buf.length} exceeds MAX_PLAINTEXT (${MAX_PLAINTEXT})`);
  }

  const frames = [];
  let offset = 0;

  while (offset < buf.length) {
    const type = buf.readUInt8(offset);

    switch (type) {
      case FRAME_TYPE.STREAM: {
        if (offset + 5 + STREAM_SYMBOL_HDR_LEN > buf.length) {
          throw new RangeError(`Truncated STREAM frame header at offset ${offset}`);
        }
        const sourceSeq = buf.readUInt32BE(offset + 1);
        const dataLen = buf.readUInt16BE(offset + 5 + 7);
        const unitLen = STREAM_SYMBOL_HDR_LEN + dataLen;
        if (unitLen > MAX_CODED_SYMBOL || offset + 5 + unitLen > buf.length) {
          throw new RangeError(`Truncated or oversized STREAM frame payload at offset ${offset}`);
        }
        const symbolUnit = Buffer.from(buf.subarray(offset + 5, offset + 5 + unitLen));
        const decodedUnit = decodeStreamSymbolUnit(symbolUnit);
        frames.push({
          type: FRAME_TYPE.STREAM,
          sourceSeq,
          symbolUnit,
          ...decodedUnit,
        });
        offset += 5 + unitLen;
        break;
      }

      case FRAME_TYPE.RLNC_REPAIR: {
        if (offset + 14 > buf.length) {
          throw new RangeError(`Truncated RLNC_REPAIR frame header at offset ${offset}`);
        }
        const flags = buf.readUInt8(offset + 1);
        const winStart = buf.readUInt32BE(offset + 2);
        const winLen = buf.readUInt16BE(offset + 6);
        const prngSeed = buf.readUInt32BE(offset + 8);
        const symbolLen = buf.readUInt16BE(offset + 12);
        if (symbolLen > MAX_CODED_SYMBOL || offset + 14 + symbolLen > buf.length) {
          throw new RangeError(
            `Truncated or oversized RLNC_REPAIR payload (${symbolLen} B) at offset ${offset}`
          );
        }
        const codedSymbol = Buffer.from(buf.subarray(offset + 14, offset + 14 + symbolLen));
        frames.push({
          type: FRAME_TYPE.RLNC_REPAIR,
          flags,
          winStart,
          winLen,
          prngSeed,
          symbolLen,
          codedSymbol,
        });
        offset += 14 + symbolLen;
        break;
      }

      case FRAME_TYPE.ACK_TELEMETRY: {
        if (offset + 16 > buf.length) {
          throw new RangeError(`Truncated ACK_TELEMETRY frame header at offset ${offset}`);
        }
        const sackWordCount = buf.readUInt8(offset + 1);
        if (sackWordCount > MAX_SACK_WORDS) {
          throw new RangeError(`Invalid SackWordCount ${sackWordCount} at offset ${offset}`);
        }
        const frameLen = 16 + sackWordCount * 4;
        if (offset + frameLen > buf.length) {
          throw new RangeError(`Truncated ACK_TELEMETRY SACK bitmap at offset ${offset}`);
        }
        const largestAckedPkt = buf.readUInt32BE(offset + 2);
        const ackDelayUs = buf.readUInt32BE(offset + 6);
        const cumSourceSeq = buf.readUInt32BE(offset + 10);
        const recvOwdGrad = buf.readInt16BE(offset + 14);
        const sackBitmap = new Uint32Array(sackWordCount);
        for (let i = 0; i < sackWordCount; i++) {
          sackBitmap[i] = buf.readUInt32BE(offset + 16 + i * 4);
        }
        frames.push({
          type: FRAME_TYPE.ACK_TELEMETRY,
          largestAckedPkt,
          ackDelayUs,
          cumSourceSeq,
          recvOwdGrad,
          sackBitmap,
        });
        offset += frameLen;
        break;
      }

      case FRAME_TYPE.HANDSHAKE: {
        if (offset + 52 > buf.length) {
          throw new RangeError(`Truncated HANDSHAKE frame header at offset ${offset}`);
        }
        const flags = buf.readUInt8(offset + 1);
        const isServer = (flags & 0x80) !== 0;
        const hasTicket = (flags & 0x40) !== 0;
        const ephemeralPubKey = Buffer.from(buf.subarray(offset + 2, offset + 34));
        const nonceSalt = Buffer.from(buf.subarray(offset + 34, offset + 50));
        const ticketLen = buf.readUInt16BE(offset + 50);
        if (offset + 52 + ticketLen > buf.length) {
          throw new RangeError(`Truncated HANDSHAKE SessionTicket at offset ${offset}`);
        }
        const sessionTicket =
          ticketLen > 0
            ? Buffer.from(buf.subarray(offset + 52, offset + 52 + ticketLen))
            : Buffer.alloc(0);
        frames.push({
          type: FRAME_TYPE.HANDSHAKE,
          flags,
          isServer,
          hasTicket,
          ephemeralPubKey,
          nonceSalt,
          sessionTicket,
        });
        offset += 52 + ticketLen;
        break;
      }

      case FRAME_TYPE.PING: {
        if (offset + 10 > buf.length) {
          throw new RangeError(`Truncated PING frame at offset ${offset}`);
        }
        const flags = buf.readUInt8(offset + 1);
        const isPong = (flags & 0x01) !== 0;
        const pingId = buf.readUInt32BE(offset + 2);
        const timestampUs = buf.readUInt32BE(offset + 6);
        frames.push({
          type: FRAME_TYPE.PING,
          flags,
          isPong,
          pingId,
          timestampUs,
        });
        offset += 10;
        break;
      }

      default:
        throw new RangeError(`Unknown frame type 0x${type.toString(16)} at offset ${offset}`);
    }
  }

  return frames;
}