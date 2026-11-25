// FILE: worker-rlnc.mjs
/**
 * AETHER-W6 Multi-Core Worker Thread RLNC Encoder & Benchmark
 * - Worker mode: Batch GF(2^8) linear combination repair generation via parentPort
 * - Main thread mode: Parallel multi-core throughput benchmark vs. 173.3 Mbps Wi-Fi 6 link
 */

import { parentPort, isMainThread, Worker } from 'node:worker_threads';
import { performance } from 'node:perf_hooks';
import { mulAddRow, generateCoeffs, xorshift32 } from './01-gf256.mjs';

const WIFI6_LINK_MBPS = 173.3;

if (!isMainThread && parentPort) {
  parentPort.on('message', ({ jobId, symbols, symbolLen, repairCount, baseSeed }) => {
    const t0 = performance.now();
    const winLen = symbols.length;
    const outBuf = new Uint8Array(symbolLen);
    let seed = (baseSeed >>> 0) || 0x9e3779b9;
    let checksum = 0;

    for (let r = 0; r < repairCount; r++) {
      seed = xorshift32(seed);
      const coeffs = generateCoeffs(seed, winLen);
      outBuf.fill(0);
      for (let i = 0; i < winLen; i++) {
        mulAddRow(outBuf, symbols[i], coeffs[i], symbolLen);
      }
      // Prevent dead-code elimination while keeping overhead negligible
      checksum ^= outBuf[r % symbolLen];
    }

    const elapsedMs = Math.max(0.001, performance.now() - t0);
    parentPort.postMessage({
      jobId,
      repairCount,
      bytesProcessed: repairCount * symbolLen,
      elapsedMs,
      checksum,
    });
  });
}

/**
 * Spawn `workerCount` Worker threads to benchmark parallel GF(2^8) RLNC repair generation.
 * Automatically terminates all workers before returning.
 * @param {object} [options]
 * @param {number} [options.workerCount=4]
 * @param {number} [options.windowSize=32]
 * @param {number} [options.symbolLen=1320]
 * @param {number} [options.totalRepairs=16000]
 * @returns {Promise<{ workerCount: number, totalRepairs: number, totalBytes: number, elapsedMs: number, throughputMbps: number, linkHeadroomFactor: number }>}
 */
export async function runMultiCoreRlncBench({
  workerCount = 4,
  windowSize = 32,
  symbolLen = 1320,
  totalRepairs = 16000,
} = {}) {
  const count = Math.max(1, Math.trunc(workerCount));

  // Prepare deterministic source window symbols
  const symbols = new Array(windowSize);
  let initSeed = 0x13579bdf;
  for (let i = 0; i < windowSize; i++) {
    const sym = new Uint8Array(symbolLen);
    for (let j = 0; j < symbolLen; j++) {
      initSeed = xorshift32(initSeed);
      sym[j] = initSeed & 0xff;
    }
    symbols[i] = sym;
  }

  const workerUrl = new URL(import.meta.url);
  const workers = [];
  for (let i = 0; i < count; i++) {
    workers.push(new Worker(workerUrl));
  }

  try {
    const basePerWorker = Math.floor(totalRepairs / count);
    const remainder = totalRepairs % count;

    const wallStart = performance.now();
    const jobs = workers.map((worker, idx) => {
      const repairCount = basePerWorker + (idx < remainder ? 1 : 0);
      const baseSeed = ((idx + 1) * 0x27d4eb2d) >>> 0;
      return new Promise((resolve, reject) => {
        const onMessage = (msg) => {
          cleanup();
          resolve(msg);
        };
        const onError = (err) => {
          cleanup();
          reject(err);
        };
        const onExit = (code) => {
          if (code !== 0) {
            cleanup();
            reject(new Error(`RLNC worker ${idx} exited with code ${code}`));
          }
        };
        const cleanup = () => {
          worker.off('message', onMessage);
          worker.off('error', onError);
          worker.off('exit', onExit);
        };

        worker.on('message', onMessage);
        worker.on('error', onError);
        worker.on('exit', onExit);
        worker.postMessage({
          jobId: idx,
          symbols,
          symbolLen,
          repairCount,
          baseSeed,
        });
      });
    });

    const results = await Promise.all(jobs);
    const elapsedMs = Math.max(0.001, performance.now() - wallStart);

    const totalBytes = results.reduce((acc, r) => acc + r.bytesProcessed, 0);
    const throughputMbps = (totalBytes * 8) / (elapsedMs / 1000) / 1e6;
    const linkHeadroomFactor = throughputMbps / WIFI6_LINK_MBPS;

    return {
      workerCount: count,
      totalRepairs,
      totalBytes,
      elapsedMs: Number(elapsedMs.toFixed(2)),
      throughputMbps: Number(throughputMbps.toFixed(2)),
      linkHeadroomFactor: Number(linkHeadroomFactor.toFixed(2)),
    };
  } finally {
    await Promise.all(workers.map((w) => w.terminate()));
  }
}