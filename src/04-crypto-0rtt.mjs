// FILE: 04-crypto-0rtt.mjs
/**
 * AETHER-W6 0-RTT & 1-RTT Cryptographic Layer
 * - X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 AEAD (16 B Packet Header as AAD)
 * - Encrypted SessionTicket with replay protection & TTL expiration
 * - Zero external dependencies (Node.js v24 native node:crypto)
 */

import {
  generateKeyPairSync,
  createPublicKey,
  diffieHellman,
  hkdfSync,
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';
import {
  encodeHeader,
  decodeHeader,
  HEADER_LEN,
  AUTH_TAG_LEN,
  MAX_UDP_PAYLOAD,
  PKT_TYPE,
} from './03-wire-format.mjs';

/** Fixed ASN.1 SPKI DER prefix for 32-byte raw X25519 public keys */
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

const TICKET_NONCE_LEN = 12;
const TICKET_PLAINTEXT_LEN = 44; // 32 B PSK + 8 B expiresAtMs + 4 B ticketId
const TICKET_TOTAL_LEN = TICKET_NONCE_LEN + TICKET_PLAINTEXT_LEN + AUTH_TAG_LEN; // 72 B

const INFO_1RTT_C2S = Buffer.from('aether-w6-1rtt-c2s');
const INFO_1RTT_S2C = Buffer.from('aether-w6-1rtt-s2c');
const INFO_0RTT_C2S = Buffer.from('aether-w6-0rtt-c2s');

const DIR_C2S = 0x01;
const DIR_S2C = 0x02;
const DIR_0RTT = 0x03;

function asBuffer(data) {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof Uint8Array) {
    return Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new TypeError('Expected Buffer or Uint8Array');
}

export class SessionTicketManager {
  /**
   * @param {object} [options]
   * @param {Buffer | Uint8Array} [options.masterKey] 32-byte server ticket encryption key
   * @param {number} [options.ttlMs=300000] Ticket lifetime in milliseconds
   */
  constructor({ masterKey = randomBytes(32), ttlMs = 300_000 } = {}) {
    const keyBuf = asBuffer(masterKey);
    if (keyBuf.length !== 32) {
      throw new RangeError(`masterKey must be 32 bytes, got ${keyBuf.length}`);
    }
    this.masterKey = Buffer.from(keyBuf);
    this.ttlMs = ttlMs;
    /** @type {Set<number>} Anti-replay set of consumed ticketIds */
    this.usedTickets = new Set();
    this._nextTicketId = (randomBytes(4).readUInt32BE(0) & 0x7fffffff) || 1;
  }

  /**
   * Issue an encrypted 72-byte SessionTicket binding a 32-byte PSK, expiration, and unique ticketId.
   * @param {Buffer | Uint8Array} psk 32-byte pre-shared key
   * @param {number} [nowMs=Date.now()]
   * @returns {{ ticket: Buffer, ticketId: number, expiresAtMs: number }}
   */
  issueTicket(psk, nowMs = Date.now()) {
    const pskBuf = asBuffer(psk);
    if (pskBuf.length !== 32) {
      throw new RangeError(`PSK must be 32 bytes, got ${pskBuf.length}`);
    }

    const ticketId = this._nextTicketId >>> 0;
    this._nextTicketId = (this._nextTicketId + 1) >>> 0;
    const expiresAtMs = Math.trunc(nowMs + this.ttlMs);

    const plaintext = Buffer.allocUnsafe(TICKET_PLAINTEXT_LEN);
    pskBuf.copy(plaintext, 0);
    plaintext.writeBigUInt64BE(BigInt(expiresAtMs), 32);
    plaintext.writeUInt32BE(ticketId, 40);

    const nonce = randomBytes(TICKET_NONCE_LEN);
    const cipher = createCipheriv('chacha20-poly1305', this.masterKey, nonce, {
      authTagLength: AUTH_TAG_LEN,
    });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      ticket: Buffer.concat([nonce, ciphertext, authTag]),
      ticketId,
      expiresAtMs,
    };
  }

  /**
   * Decrypt, authenticate, validate TTL, and enforce single-use anti-replay on a SessionTicket.
   * @param {Buffer | Uint8Array} ticketInput
   * @param {number} [nowMs=Date.now()]
   * @returns {{ psk: Buffer, expiresAtMs: number, ticketId: number }}
   */
  verifyAndConsumeTicket(ticketInput, nowMs = Date.now()) {
    const ticketBuf = asBuffer(ticketInput);
    if (ticketBuf.length !== TICKET_TOTAL_LEN) {
      throw new Error(`Invalid SessionTicket length: ${ticketBuf.length} (expected ${TICKET_TOTAL_LEN})`);
    }

    const nonce = ticketBuf.subarray(0, TICKET_NONCE_LEN);
    const ciphertext = ticketBuf.subarray(TICKET_NONCE_LEN, TICKET_NONCE_LEN + TICKET_PLAINTEXT_LEN);
    const authTag = ticketBuf.subarray(TICKET_NONCE_LEN + TICKET_PLAINTEXT_LEN);

    const decipher = createDecipheriv('chacha20-poly1305', this.masterKey, nonce, {
      authTagLength: AUTH_TAG_LEN,
    });
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const psk = Buffer.from(plaintext.subarray(0, 32));
    const expiresAtMs = Number(plaintext.readBigUInt64BE(32));
    const ticketId = plaintext.readUInt32BE(40);

    if (nowMs > expiresAtMs) {
      throw new Error(`SessionTicket ${ticketId} expired at ${expiresAtMs} (now=${nowMs})`);
    }
    if (this.usedTickets.has(ticketId)) {
      throw new Error(`SessionTicket ${ticketId} replay detected`);
    }

    this.usedTickets.add(ticketId);
    return { psk, expiresAtMs, ticketId };
  }
}

export class AetherCrypto {
  constructor() {
    this.isServer = false;
    this.has1RttKeys = false;
    this.has0RttKeys = false;

    /** @type {Buffer | null} */
    this.txKey = null;
    /** @type {Buffer | null} */
    this.txIv = null;
    this.txDir = DIR_C2S;

    /** @type {Buffer | null} */
    this.rxKey = null;
    /** @type {Buffer | null} */
    this.rxIv = null;
    this.rxDir = DIR_S2C;

    /** @type {Buffer | null} */
    this.zeroRttTxKey = null;
    /** @type {Buffer | null} */
    this.zeroRttTxIv = null;
    /** @type {Buffer | null} */
    this.zeroRttRxKey = null;
    /** @type {Buffer | null} */
    this.zeroRttRxIv = null;
  }

  /**
   * Generate an ephemeral X25519 key pair and extract the raw 32-byte public key.
   * @returns {{ publicKeyRaw: Buffer, privateKey: import('node:crypto').KeyObject }}
   */
  static generateKeyPair() {
    const { publicKey, privateKey } = generateKeyPairSync('x25519');
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const publicKeyRaw = Buffer.from(spkiDer.subarray(spkiDer.length - 32));
    return { publicKeyRaw, privateKey };
  }

  /**
   * Compute 32-byte X25519 ECDH shared secret from local privateKey and peer's raw 32-byte public key.
   * @param {import('node:crypto').KeyObject} privateKey
   * @param {Buffer | Uint8Array} peerPublicKeyRaw
   * @returns {Buffer}
   */
  static computeSharedSecret(privateKey, peerPublicKeyRaw) {
    const rawBuf = asBuffer(peerPublicKeyRaw);
    if (rawBuf.length !== 32) {
      throw new RangeError(`Peer X25519 public key must be 32 bytes, got ${rawBuf.length}`);
    }
    const spkiDer = Buffer.concat([X25519_SPKI_PREFIX, rawBuf]);
    const peerPublicKey = createPublicKey({
      key: spkiDer,
      format: 'der',
      type: 'spki',
    });
    return diffieHellman({ privateKey, publicKey: peerPublicKey });
  }

  /**
   * Derive and install bidirectional 1-RTT traffic keys (32 B key + 12 B IV per direction).
   * @param {Buffer | Uint8Array} sharedSecret
   * @param {Buffer | Uint8Array} salt
   * @param {boolean} isServer
   */
  install1RttKeys(sharedSecret, salt, isServer) {
    const secretBuf = asBuffer(sharedSecret);
    const saltBuf = asBuffer(salt);

    const c2sMat = Buffer.from(hkdfSync('sha256', secretBuf, saltBuf, INFO_1RTT_C2S, 44));
    const s2cMat = Buffer.from(hkdfSync('sha256', secretBuf, saltBuf, INFO_1RTT_S2C, 44));

    this.isServer = Boolean(isServer);
    if (this.isServer) {
      this.txKey = Buffer.from(s2cMat.subarray(0, 32));
      this.txIv = Buffer.from(s2cMat.subarray(32, 44));
      this.txDir = DIR_S2C;

      this.rxKey = Buffer.from(c2sMat.subarray(0, 32));
      this.rxIv = Buffer.from(c2sMat.subarray(32, 44));
      this.rxDir = DIR_C2S;
    } else {
      this.txKey = Buffer.from(c2sMat.subarray(0, 32));
      this.txIv = Buffer.from(c2sMat.subarray(32, 44));
      this.txDir = DIR_C2S;

      this.rxKey = Buffer.from(s2cMat.subarray(0, 32));
      this.rxIv = Buffer.from(s2cMat.subarray(32, 44));
      this.rxDir = DIR_S2C;
    }
    this.has1RttKeys = true;
  }

  /**
   * Derive and install 0-RTT early data keys from PSK and clientSalt.
   * @param {Buffer | Uint8Array} psk
   * @param {Buffer | Uint8Array} clientSalt
   * @param {boolean} isServer
   */
  install0RttKeys(psk, clientSalt, isServer) {
    const pskBuf = asBuffer(psk);
    const saltBuf = asBuffer(clientSalt);

    const earlyMat = Buffer.from(hkdfSync('sha256', pskBuf, saltBuf, INFO_0RTT_C2S, 44));
    const key = Buffer.from(earlyMat.subarray(0, 32));
    const iv = Buffer.from(earlyMat.subarray(32, 44));

    this.isServer = Boolean(isServer);
    if (this.isServer) {
      this.zeroRttRxKey = key;
      this.zeroRttRxIv = iv;
    } else {
      this.zeroRttTxKey = key;
      this.zeroRttTxIv = iv;
    }
    this.has0RttKeys = true;
  }

  /**
   * Construct 12-byte AEAD nonce: iv XOR [dirByte, keyPhase, 0,0,0,0,0,0, pktNumBE(4B)].
   * @param {Buffer} iv
   * @param {number} dirByte
   * @param {number} keyPhase
   * @param {number} packetNum
   * @returns {Buffer}
   */
  buildNonce(iv, dirByte, keyPhase, packetNum) {
    const nonce = Buffer.allocUnsafe(12);
    nonce[0] = iv[0] ^ (dirByte & 0xff);
    nonce[1] = iv[1] ^ (keyPhase & 0xff);
    nonce[2] = iv[2];
    nonce[3] = iv[3];
    nonce[4] = iv[4];
    nonce[5] = iv[5];
    nonce[6] = iv[6];
    nonce[7] = iv[7];
    const pn = packetNum >>> 0;
    nonce[8] = iv[8] ^ ((pn >>> 24) & 0xff);
    nonce[9] = iv[9] ^ ((pn >>> 16) & 0xff);
    nonce[10] = iv[10] ^ ((pn >>> 8) & 0xff);
    nonce[11] = iv[11] ^ (pn & 0xff);
    return nonce;
  }

  /**
   * Encrypt and authenticate a packet with ChaCha20-Poly1305 (16 B Header as AAD).
   * Returns [Header(16) | Ciphertext(L) | AuthTag(16)] <= MAX_UDP_PAYLOAD.
   * @param {object} headerObj
   * @param {Buffer | Uint8Array} plaintextInput
   * @param {object} [options]
   * @param {boolean} [options.use0Rtt=false]
   * @returns {Buffer}
   */
  encryptPacket(headerObj, plaintextInput, { use0Rtt = false } = {}) {
    const plaintext = asBuffer(plaintextInput);
    const totalLen = HEADER_LEN + plaintext.length + AUTH_TAG_LEN;
    if (totalLen > MAX_UDP_PAYLOAD) {
      throw new RangeError(
        `Encrypted datagram length ${totalLen} exceeds MAX_UDP_PAYLOAD (${MAX_UDP_PAYLOAD})`
      );
    }

    const key = use0Rtt ? this.zeroRttTxKey : this.txKey;
    const iv = use0Rtt ? this.zeroRttTxIv : this.txIv;
    const dir = use0Rtt ? DIR_0RTT : this.txDir;

    if (!key || !iv) {
      throw new Error(`Missing ${use0Rtt ? '0-RTT' : '1-RTT'} transmit keys`);
    }

    const hdr = {
      ...headerObj,
      is0Rtt: use0Rtt ? true : Boolean(headerObj.is0Rtt),
      payloadLen: plaintext.length,
    };
    const headerBuf = encodeHeader(hdr);
    const nonce = this.buildNonce(iv, dir, hdr.keyPhase ?? 0, hdr.packetNum ?? 0);

    const cipher = createCipheriv('chacha20-poly1305', key, nonce, {
      authTagLength: AUTH_TAG_LEN,
    });
    cipher.setAAD(headerBuf);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return Buffer.concat([headerBuf, ciphertext, authTag], totalLen);
  }

  /**
   * Decrypt and verify a ChaCha20-Poly1305 protected datagram.
   * Throws on any header/payload/tag tampering or length mismatch.
   * @param {Buffer | Uint8Array} datagramInput
   * @param {object} [options]
   * @param {boolean} [options.use0Rtt=false]
   * @returns {{ header: object, plaintext: Buffer }}
   */
  decryptPacket(datagramInput, { use0Rtt = false } = {}) {
    const datagram = asBuffer(datagramInput);
    if (datagram.length < HEADER_LEN + AUTH_TAG_LEN || datagram.length > MAX_UDP_PAYLOAD) {
      throw new RangeError(`Invalid encrypted datagram length: ${datagram.length}`);
    }

    const header = decodeHeader(datagram, 0);
    const expectedLen = HEADER_LEN + header.payloadLen + AUTH_TAG_LEN;
    if (datagram.length !== expectedLen) {
      throw new RangeError(
        `Datagram length mismatch: got ${datagram.length}, header expects ${expectedLen}`
      );
    }

    const isZeroRtt = use0Rtt || header.is0Rtt || header.pktType === PKT_TYPE.ZERO_RTT;
    const key = isZeroRtt ? this.zeroRttRxKey : this.rxKey;
    const iv = isZeroRtt ? this.zeroRttRxIv : this.rxIv;
    const dir = isZeroRtt ? DIR_0RTT : this.rxDir;

    if (!key || !iv) {
      throw new Error(`Missing ${isZeroRtt ? '0-RTT' : '1-RTT'} receive keys`);
    }

    const aad = datagram.subarray(0, HEADER_LEN);
    const ciphertext = datagram.subarray(HEADER_LEN, HEADER_LEN + header.payloadLen);
    const authTag = datagram.subarray(HEADER_LEN + header.payloadLen);
    const nonce = this.buildNonce(iv, dir, header.keyPhase, header.packetNum);

    const decipher = createDecipheriv('chacha20-poly1305', key, nonce, {
      authTagLength: AUTH_TAG_LEN,
    });
    decipher.setAAD(aad);
    decipher.setAuthTag(authTag);

    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return { header, plaintext };
  }

  /**
   * Seal a plaintext HANDSHAKE packet: [Header(16) | Plaintext(L)] (no AuthTag).
   * @param {object} headerObj
   * @param {Buffer | Uint8Array} plaintextInput
   * @returns {Buffer}
   */
  sealHandshakePacket(headerObj, plaintextInput) {
    const plaintext = asBuffer(plaintextInput);
    const totalLen = HEADER_LEN + plaintext.length;
    if (totalLen > MAX_UDP_PAYLOAD) {
      throw new RangeError(`Handshake packet ${totalLen} exceeds MAX_UDP_PAYLOAD (${MAX_UDP_PAYLOAD})`);
    }
    const headerBuf = encodeHeader({
      ...headerObj,
      pktType: PKT_TYPE.HANDSHAKE,
      payloadLen: plaintext.length,
    });
    return Buffer.concat([headerBuf, plaintext], totalLen);
  }

  /**
   * Open a plaintext HANDSHAKE packet: [Header(16) | Plaintext(L)].
   * @param {Buffer | Uint8Array} datagramInput
   * @returns {{ header: object, plaintext: Buffer }}
   */
  openHandshakePacket(datagramInput) {
    const datagram = asBuffer(datagramInput);
    if (datagram.length < HEADER_LEN || datagram.length > MAX_UDP_PAYLOAD) {
      throw new RangeError(`Invalid handshake datagram length: ${datagram.length}`);
    }
    const header = decodeHeader(datagram, 0);
    if (header.pktType !== PKT_TYPE.HANDSHAKE) {
      throw new Error(`Expected HANDSHAKE pktType (0x02), got 0x${header.pktType.toString(16)}`);
    }
    if (datagram.length !== HEADER_LEN + header.payloadLen) {
      throw new RangeError(
        `Handshake length mismatch: got ${datagram.length}, expected ${HEADER_LEN + header.payloadLen}`
      );
    }
    const plaintext = Buffer.from(datagram.subarray(HEADER_LEN));
    return { header, plaintext };
  }
}