// FILE: 06-cc-kalman.mjs
/**
 * AETHER-W6 Wireless Loss-Decoupled Congestion Control & Microsecond A-MPDU Pacer
 * - 2D Kalman Delay-Gradient Filter tracking [queueDelayMs, delayGradientMsPerSec]
 * - Wireless vs. Bufferbloat loss discriminator (holds cwnd on wireless loss, boosts RLNC rho)
 * - High-precision performance.now() token bucket pacer for 802.11ax A-MPDU micro-bursts
 */

import { performance } from 'node:perf_hooks';

function clamp(val, min, max) {
  return val < min ? min : val > max ? max : val;
}

export class KalmanDelayFilter {
  /**
   * @param {object} [options]
   * @param {number} [options.baseWindowMs=10000] Sliding window for minimum base OWD tracking
   * @param {number} [options.processNoiseQ=0.15] Process noise scalar
   * @param {number} [options.measNoiseR=2.5] Measurement noise variance (absorbs CSMA/CA jitter)
   */
  constructor({ baseWindowMs = 10_000, processNoiseQ = 0.15, measNoiseR = 2.5 } = {}) {
    this.baseWindowMs = baseWindowMs;
    this.qNoise = processNoiseQ;
    this.rNoise = measNoiseR;

    // State vector x = [queueDelayMs, delayGradientMsPerSec]
    this.x0 = 0;
    this.x1 = 0;

    // 2x2 error covariance matrix P
    this.p00 = 10;
    this.p01 = 0;
    this.p10 = 0;
    this.p11 = 10;

    this.lastUpdateMs = null;
    this.baseOwdMs = Infinity;
    /** @type {Array<{ t: number, owd: number }>} Monotonic deque for sliding min baseOwdMs */
    this._minDeque = [];
  }

  /**
   * Update sliding minimum base OWD to absorb static clock offset and slow drift.
   * @param {number} rawOwdMs
   * @param {number} nowMs
   * @returns {number}
   */
  _updateBaseOwd(rawOwdMs, nowMs) {
    const cutoff = nowMs - this.baseWindowMs;
    while (this._minDeque.length > 0 && this._minDeque[0].t < cutoff) {
      this._minDeque.shift();
    }
    while (
      this._minDeque.length > 0 &&
      this._minDeque[this._minDeque.length - 1].owd >= rawOwdMs
    ) {
      this._minDeque.pop();
    }
    this._minDeque.push({ t: nowMs, owd: rawOwdMs });
    this.baseOwdMs = this._minDeque[0].owd;
    return this.baseOwdMs;
  }

  /**
   * Feed a new raw one-way delay observation and return smoothed queue delay & gradient.
   * @param {number} rawOwdMs
   * @param {number} [nowMs=performance.now()]
   * @returns {{ queueDelayMs: number, delayGradient: number, baseOwdMs: number, sampleQueueMs: number }}
   */
  update(rawOwdMs, nowMs = performance.now()) {
    const baseOwdMs = this._updateBaseOwd(rawOwdMs, nowMs);
    const z = Math.max(0, rawOwdMs - baseOwdMs);

    if (this.lastUpdateMs === null) {
      this.x0 = z;
      this.x1 = 0;
      this.lastUpdateMs = nowMs;
      return {
        queueDelayMs: this.x0,
        delayGradient: this.x1,
        baseOwdMs,
        sampleQueueMs: z,
      };
    }

    const dtSec = clamp((nowMs - this.lastUpdateMs) / 1000, 0.001, 2.0);
    this.lastUpdateMs = nowMs;

    // 1. Predict: x_pred = F * x, P_pred = F * P * F^T + Q
    const x0Pred = this.x0 + dtSec * this.x1;
    const x1Pred = this.x1;

    const p00Pred =
      this.p00 + dtSec * (this.p10 + this.p01) + dtSec * dtSec * this.p11 + this.qNoise * dtSec;
    const p01Pred = this.p01 + dtSec * this.p11;
    const p10Pred = this.p10 + dtSec * this.p11;
    const p11Pred = this.p11 + this.qNoise * 4.0 * dtSec;

    // 2. Innovation: y = z - H * x_pred (H = [1, 0])
    const innovation = z - x0Pred;
    const s = p00Pred + this.rNoise;
    const k0 = p00Pred / s;
    const k1 = p10Pred / s;

    // 3. Update state and covariance
    this.x0 = Math.max(0, x0Pred + k0 * innovation);
    this.x1 = x1Pred + k1 * innovation;

    this.p00 = (1 - k0) * p00Pred;
    this.p01 = (1 - k0) * p01Pred;
    this.p10 = p10Pred - k1 * p00Pred;
    this.p11 = p11Pred - k1 * p01Pred;

    return {
      queueDelayMs: this.x0,
      delayGradient: this.x1,
      baseOwdMs,
      sampleQueueMs: z,
    };
  }
}

export class WirelessCongestionCtrl {
  /**
   * Defaults tailored for 173.3 Mbps Wi-Fi 6 (802.11ax, MTU=1500, payload=1380 B).
   * @param {object} [options]
   */
  constructor({
    maxRateBps = 173_300_000,
    minRateBps = 2_000_000,
    initCwndBytes = 64 * 1380,
    qLowMs = 8,
    qHighMs = 25,
    gradThresh = 18,
  } = {}) {
    this.maxRateBps = maxRateBps;
    this.minRateBps = minRateBps;
    this.minCwndBytes = 12 * 1380;
    this.maxCwndBytes = 512 * 1380;

    this.qLowMs = qLowMs;
    this.qHighMs = qHighMs;
    this.gradThresh = gradThresh;

    this.kalman = new KalmanDelayFilter();

    this.rttMinMs = Infinity;
    this.srttMs = 15;
    this.deliveryRateBps = Math.min(maxRateBps, 60_000_000);
    this.cwndBytes = initCwndBytes;
    this.inFlightBytes = 0;
    this.pacingRateBps = Math.min(maxRateBps, 80_000_000);
    this.redundancyRho = 0.05;
    this.lossRateEwma = 0;
    this.burstLenEwma = 1;
    this.state = 'PROBE'; // 'PROBE' | 'CRUISE' | 'WIRELESS_BOOST' | 'BUFFERBLOAT_DRAIN'

    this.wirelessLossEvents = 0;
    this.congestionLossEvents = 0;

    this._lastAckTimeMs = null;
    this._lastQueueDelayMs = 0;
    this._lastDelayGradient = 0;
  }

  /**
   * Record bytes placed on the wire.
   * @param {number} bytes
   * @param {number} [nowMs]
   */
  onPacketSent(bytes, nowMs = performance.now()) {
    this.inFlightBytes += bytes;
    if (this._lastAckTimeMs === null) {
      this._lastAckTimeMs = nowMs;
    }
  }

  /**
   * Retire bytes from in-flight accounting (acked or declared lost).
   * @param {number} bytes
   */
  onPacketRetired(bytes) {
    this.inFlightBytes = Math.max(0, this.inFlightBytes - bytes);
  }

  /**
   * Process ACK telemetry, run Kalman filter, attribute loss, and adjust cwnd / pacing / RLNC rho.
   * @param {object} telemetry
   */
  onAckTelemetry({
    ackedBytes = 0,
    lostCount = 0,
    totalTracked = 1,
    rttMs = 0,
    rawOwdMs = null,
    recvOwdGrad = null,
    maxBurstLen = 1,
    nowMs = performance.now(),
  }) {
    if (ackedBytes > 0) {
      this.onPacketRetired(ackedBytes);
    }

    // 1. Update RTT and delivery rate estimate
    if (rttMs > 0) {
      if (rttMs < this.rttMinMs) {
        this.rttMinMs = rttMs;
      }
      this.srttMs = this.srttMs === 0 ? rttMs : 0.875 * this.srttMs + 0.125 * rttMs;
    }

    if (this._lastAckTimeMs !== null && ackedBytes > 0) {
      const dtSec = Math.max(0.001, (nowMs - this._lastAckTimeMs) / 1000);
      const sampleBps = (ackedBytes * 8) / dtSec;
      const boundedSample = clamp(sampleBps, this.minRateBps, this.maxRateBps);
      this.deliveryRateBps = 0.75 * this.deliveryRateBps + 0.25 * boundedSample;
    }
    this._lastAckTimeMs = nowMs;

    // 2. Update 2D Kalman delay-gradient filter (skip invalid/zero RTT samples)
    let queueDelayMs = this._lastQueueDelayMs;
    let delayGradient = this._lastDelayGradient;
    const hasOwdSample =
      (rawOwdMs !== null && rawOwdMs !== undefined && Number.isFinite(rawOwdMs)) || rttMs > 0;
    if (hasOwdSample) {
      const owdObs = rawOwdMs !== null && rawOwdMs !== undefined ? rawOwdMs : rttMs * 0.5;
      const kf = this.kalman.update(owdObs, nowMs);
      queueDelayMs = kf.queueDelayMs;
      delayGradient =
        recvOwdGrad !== null && recvOwdGrad !== undefined
          ? 0.5 * kf.delayGradient + 0.5 * recvOwdGrad
          : kf.delayGradient;
    }

    this._lastQueueDelayMs = queueDelayMs;
    this._lastDelayGradient = delayGradient;

    // 3. Update EWMA loss rate and Gilbert-Elliott burst length
    const tracked = Math.max(1, totalTracked);
    const sampleLoss = clamp(lostCount / tracked, 0, 0.95);
    this.lossRateEwma = 0.7 * this.lossRateEwma + 0.3 * sampleLoss;
    if (lostCount > 0) {
      const burstSample = Math.max(1, maxBurstLen);
      this.burstLenEwma = 0.7 * this.burstLenEwma + 0.3 * burstSample;
    } else {
      this.burstLenEwma = Math.max(1, this.burstLenEwma * 0.95);
    }

    // 4. Wireless vs. Bufferbloat Loss Discriminator
    const isCongested =
      queueDelayMs >= this.qHighMs || delayGradient > this.gradThresh * 1.8;

    if (isCongested) {
      // Bufferbloat queue buildup -> drain gently
      if (lostCount > 0) {
        this.congestionLossEvents++;
      }
      this.state = 'BUFFERBLOAT_DRAIN';
      this.cwndBytes = clamp(Math.round(this.cwndBytes * 0.85), this.minCwndBytes, this.maxCwndBytes);
      const targetDrainRate = Math.min(this.pacingRateBps, this.deliveryRateBps) * 0.75;
      this.pacingRateBps = clamp(targetDrainRate, this.minRateBps, this.maxRateBps);
      // Keep moderate baseline redundancy during congestion without aggravating queue
      this.redundancyRho = clamp(this.redundancyRho * 0.9, 0.05, 0.35);
    } else if (lostCount > 0 && queueDelayMs < this.qLowMs && delayGradient <= this.gradThresh) {
      // Non-congestive wireless random/burst loss -> HOLD cwnd, BOOST RLNC redundancy
      this.wirelessLossEvents++;
      this.state = 'WIRELESS_BOOST';
      const pEff = Math.max(this.lossRateEwma, sampleLoss);
      const burstFactor = 1 + 0.35 * Math.sqrt(Math.max(1, this.burstLenEwma));
      this.redundancyRho = clamp(
        (pEff / Math.max(0.05, 1 - pEff)) * burstFactor + 0.06,
        0.05,
        0.75
      );
      // Maintain pacing rate (do not collapse on wireless loss)
      const bdpRate = Math.max(this.pacingRateBps, this.deliveryRateBps * 1.05);
      this.pacingRateBps = clamp(bdpRate, this.minRateBps, this.maxRateBps);
    } else {
      // Clean or lightly loaded channel -> BBR-style cruise / gentle probe
      const baseRttSec = Math.max(0.002, (Number.isFinite(this.rttMinMs) ? this.rttMinMs : this.srttMs) / 1000);
      const targetBdpBytes = (this.deliveryRateBps / 8) * baseRttSec * 2.0;

      if (queueDelayMs < this.qLowMs) {
        this.state = 'PROBE';
        this.cwndBytes = clamp(
          Math.round(Math.max(this.cwndBytes + 2 * 1380, targetBdpBytes)),
          this.minCwndBytes,
          this.maxCwndBytes
        );
        this.pacingRateBps = clamp(
          Math.max(this.pacingRateBps * 1.06, this.deliveryRateBps * 1.12),
          this.minRateBps,
          this.maxRateBps
        );
      } else {
        this.state = 'CRUISE';
        this.cwndBytes = clamp(
          Math.round(0.8 * this.cwndBytes + 0.2 * targetBdpBytes),
          this.minCwndBytes,
          this.maxCwndBytes
        );
        this.pacingRateBps = clamp(this.deliveryRateBps, this.minRateBps, this.maxRateBps);
      }

      // Smoothly decay redundancy toward baseline proportional to residual loss
      const targetRho = clamp(
        (this.lossRateEwma / Math.max(0.05, 1 - this.lossRateEwma)) * 1.2 + 0.05,
        0.05,
        0.5
      );
      this.redundancyRho = 0.8 * this.redundancyRho + 0.2 * targetRho;
    }
  }

  /**
   * @param {number} bytes
   * @returns {boolean}
   */
  canSend(bytes) {
    return this.inFlightBytes + bytes <= this.cwndBytes;
  }

  /**
   * @returns {number}
   */
  getRedundancyRho() {
    return this.redundancyRho;
  }

  /**
   * @returns {number}
   */
  getPacingRateBps() {
    return this.pacingRateBps;
  }

  /**
   * @returns {object}
   */
  getSnapshot() {
    return {
      state: this.state,
      cwndBytes: this.cwndBytes,
      inFlightBytes: this.inFlightBytes,
      pacingRateBps: Math.round(this.pacingRateBps),
      deliveryRateBps: Math.round(this.deliveryRateBps),
      redundancyRho: Number(this.redundancyRho.toFixed(4)),
      lossRateEwma: Number(this.lossRateEwma.toFixed(4)),
      burstLenEwma: Number(this.burstLenEwma.toFixed(2)),
      rttMinMs: Number.isFinite(this.rttMinMs) ? Number(this.rttMinMs.toFixed(2)) : null,
      srttMs: Number(this.srttMs.toFixed(2)),
      queueDelayMs: Number(this._lastQueueDelayMs.toFixed(2)),
      delayGradient: Number(this._lastDelayGradient.toFixed(2)),
      wirelessLossEvents: this.wirelessLossEvents,
      congestionLossEvents: this.congestionLossEvents,
    };
  }
}

export class MicroPacer {
  /**
   * High-precision token bucket pacer supporting Wi-Fi 6 A-MPDU micro-bursts.
   * @param {object} [options]
   * @param {number} [options.rateBps=80000000]
   * @param {number} [options.maxBurstBytes=8280] Default 6 * 1380 B
   */
  constructor({ rateBps = 80_000_000, maxBurstBytes = 6 * 1380 } = {}) {
    this.rateBytesPerMs = Math.max(1, rateBps / 8 / 1000);
    this.maxBurstBytes = maxBurstBytes;
    this.tokens = maxBurstBytes;
    this.lastRefillMs = performance.now();
  }

  /**
   * @param {number} rateBps
   */
  setRate(rateBps) {
    this.rateBytesPerMs = Math.max(1, rateBps / 8 / 1000);
  }

  /**
   * Refill tokens up to maxBurstBytes.
   * @param {number} nowMs
   */
  _refill(nowMs) {
    const dtMs = nowMs - this.lastRefillMs;
    if (dtMs > 0) {
      this.tokens = Math.min(this.maxBurstBytes, this.tokens + dtMs * this.rateBytesPerMs);
      this.lastRefillMs = nowMs;
    }
  }

  /**
   * @param {number} bytes
   * @param {number} [nowMs=performance.now()]
   * @returns {boolean}
   */
  canSend(bytes, nowMs = performance.now()) {
    this._refill(nowMs);
    return this.tokens >= bytes;
  }

  /**
   * Consume tokens for a transmitted datagram.
   * @param {number} bytes
   * @param {number} [nowMs=performance.now()]
   */
  consume(bytes, nowMs = performance.now()) {
    this._refill(nowMs);
    this.tokens = Math.max(-this.maxBurstBytes, this.tokens - bytes);
  }

  /**
   * Compute milliseconds to wait before `bytes` can be sent.
   * @param {number} bytes
   * @param {number} [nowMs=performance.now()]
   * @returns {number}
   */
  delayUntilReadyMs(bytes, nowMs = performance.now()) {
    this._refill(nowMs);
    if (this.tokens >= bytes) {
      return 0;
    }
    return (bytes - this.tokens) / this.rateBytesPerMs;
  }
}