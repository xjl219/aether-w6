# AETHER-W6

**Adaptive Entropy-aware Transport with Hybrid Erasure-coding & Resilient-control for Wi-Fi 6**

> 零外部依赖的 **Node.js v24+** 实验性用户态 UDP 传输协议原型，针对高算力终端（16 核）与受限纯 IPv4 无线链路（Wi-Fi 6 / 173.3 Mbps / MTU 1500）之间的算力带宽不对称特征设计。

---

## 核心特性

- **系统滑动窗口随机线性网络编码（RLNC over GF(2⁸)）**：原始系统帧零编码延迟直发；修复帧以 32-bit `xorshift32` 种子替代显式系数向量，接收端通过增量在线高斯-约当消元（OFGE / RREF）原地恢复丢失数据，将 `STREAM` 元数据（流号、`FIN`、`ZSTD`、真实载荷长度）整体纳入编码符号体实现无损自包含还原。
- **卡尔曼延迟梯度与无线丢包解耦拥塞控制**：二维卡尔曼滤波器持续追踪相对单向延迟残差与排队延迟梯度，区分**无线随机/突发丢包**与**路由器队列膨胀（Bufferbloat）**；无线丢包时拒绝缩减 `cwnd` 而瞬间拉升 RLNC 冗余率 $\rho$，队列膨胀时温和降速排空队列。
- **纯 IPv4 MTU=1500 精确封装与多流 HoL 隔离**：锁定最大 UDP 载荷 **1380 B**（预留 92 B 隧道封装余量防 IPv4 分片）；多路独立流按优先级赤字加权轮询（DWRR）调度与独立重排，消除跨流队头阻塞。
- **香农熵门控原生 Zstd 压缩**：单趟估算分片字节香农熵 $H \in [0, 8]$，$H < 7.2$ 时调用 Node.js v24 原生 `zlib.zstdCompressSync` 压缩，高熵/已压缩负载零膨胀直通。
- **0-RTT 加密认证安全层**：基于 Node.js 原生 `X25519` ECDH + `HKDF-SHA256` + `ChaCha20-Poly1305` AEAD（16 B 包头作为 AAD），结合加密 `SessionTicket` 与单次防重放校验实现 0-RTT 首包传流。
- **内置 Wi-Fi 6 弱网混沌信道模拟器与对照基准**：在同一套双向透明 UDP 混沌代理（Gilbert-Elliott 两态突发丢包 + 对数正态抖动 + 乱序 + 限速队列尾丢弃）上对比 AETHER-W6 与包级 RFC 6298/5681 TCP-Reno/HoL 参考实现。

---

## 协议栈数据流

```mermaid
flowchart LR
    App["多路业务流 Stream 0..N"] --> Ent["L4 香农熵门控 H<7.2 ? Zstd : Bypass"]
    Ent --> Mux["L4 优先级赤字轮询 DWRR & 独立流重排"]
    Mux --> RLNC["L3 系统滑动窗口 RLNC over GF(2^8)"]
    RLNC --> Wire["L1 多帧聚合 Coalescing (<=1348B)"]
    Wire --> Crypto["L1 0-RTT X25519 + ChaCha20-Poly1305 AEAD"]
    Crypto --> Pace["L2 微秒级 A-MPDU 令牌桶 Pacing"]
    Pace --> UDP["IPv4 UDP <=1380B (MTU 1500 防分片)"]
    UDP -. "ACK_TELEMETRY + OWD梯度 + SACK位图" .-> CC["L2 卡尔曼滤波 & 无线丢包归因器"]
    CC -- "动态调节冗余率 rho" --> RLNC
    CC -- "调控 cwnd 与发送速率" --> Pace
```

---

## 快速开始

环境要求：**Node.js >= 24.0.0**（使用原生 `zlib.zstdCompressSync` 与 `node:crypto`，零第三方 `npm` 依赖）。

```bash
# 运行 8 项核心算法、安全边界与真实本机 UDP 1-RTT/0-RTT 单元测试
npm test

# 运行 Wi-Fi 6 四场景弱网混沌对比压测与多核 RLNC 算力基准
npm run bench
```

### 代码接入示例

```javascript
import { AetherEndpoint } from './src/index.mjs';

const server = new AetherEndpoint({ role: 'server' });
const client = new AetherEndpoint({ role: 'client' });

const { port } = await server.bind(0, '127.0.0.1');
const { connId } = await client.connect('127.0.0.1', port);

client.sendStream(1, Buffer.from('hello aether-w6'), { priority: 7, fin: true });
const received = await server.waitForStreams([1], 5000, connId);
console.log(received.get(1).data.toString());

await client.close();
await server.close();
```

---

## 实测对比结果（本机回环同信道 UDP 混沌代理，Node.js v24.21.0）

测试负载：8 路并发混合流共 **238.6 KB**（4 路 JSON 业务流 + 2 路不可压缩高熵随机媒体流 + 2 路高优先级控制流），全部数据通过逐字节一致性校验。

| 场景 | 总耗时 AETHER / TCP (ms) | 有效吞吐 AETHER / TCP (Mbps) | 吞吐倍率 | 高优控制流 FCT AETHER / TCP (ms) | 实测丢包率 A / T | RLNC 恢复 / ARQ 兜底 | 熵压缩节省 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **S1 正常 Wi-Fi 轻抖动** | 182.4 / 1155.8 | **10.72** / 1.69 | **6.34x** | **18.0** / 42.9 | 0% / 0.25% | 15 / 0 | 55.89% |
| **S2 10% 随机无线丢包** | 280.5 / 6794.0 | **6.97** / 0.29 | **24.03x** | **16.7** / 72.8 | 11.05% / 11.96% | 29 / 2 | 55.89% |
| **S3 20% GE 突发丢包+乱序** | 251.3 / 14411.7 | **7.78** / 0.14 | **55.57x** | **40.2** / 78.3 | 16.11% / 15.88% | 45 / 3 | 55.89% |
| **S4 高 Bufferbloat 队列膨胀** | 220.7 / 1131.6 | **8.86** / 1.73 | **5.12x** | **22.4** / 64.6 | 4.59% / 3.33% | 8 / 0 | 55.89% |

多线程 $\text{GF}(2^8)$ RLNC 编码基准（窗口 $W=32$，符号 `1320 B`，8000 修复包）：单核 **260.24 Mbps**，4 核 **717.69 Mbps**，8 核峰值 **947.35 Mbps**（相对 173.3 Mbps 无线链路具备 **5.47x** 算力冗余）。

---

## 目录结构

```text
aether-w6/
├── docs/
│   └── RFC-AETHER-W6.md      # 完整 RFC 风格协议规范、字节布局、数学模型与压测分析
├── src/
│   ├── 01-gf256.mjs          # GF(2^8) (0x11d) 64KB LUT 与 xorshift32 系数生成器
│   ├── 02-rlnc-codec.mjs     # 系统滑动窗口 RlncEncoder 与稀疏 RREF 在线高斯消元解码器
│   ├── 03-wire-format.mjs    # 16B 包头、自包含 STREAM 符号体与 5 类帧编解码
│   ├── 04-crypto-0rtt.mjs    # X25519 + HKDF-SHA256 + ChaCha20-Poly1305 与 0-RTT 票据
│   ├── 05-entropy-zstd.mjs   # 香农熵估算与 Node v24 原生 Zstd 压缩门控
│   ├── 06-cc-kalman.mjs      # 二维卡尔曼延迟梯度滤波、无线丢包归因与微秒令牌桶
│   ├── 07-stream-mux.mjs     # 多流 HoL 隔离重排与优先级赤字轮询（DWRR）
│   ├── 08-aether-endpoint.mjs# 双端 UDP 状态机、握手、SACK 遥测与选择性 ARQ 兜底
│   ├── worker-rlnc.mjs       # worker_threads 多核并行 RLNC 编码算力基准
│   └── index.mjs             # 统一模块导出入口
├── test/
│   └── test-unit.mjs         # 8 项核心单测与真实 UDP 1-RTT/0-RTT 集成验证
├── bench/
│   ├── 09-chaos-bench.mjs    # Wi-Fi 6 混沌代理、TCP-Reno 参考基线与四场景压测器
│   └── bench-results.json    # 实测快照数据
├── package.json
└── LICENSE
```

完整字节级规范与详细数学推导见 [docs/RFC-AETHER-W6.md](./docs/RFC-AETHER-W6.md)。

## License

[MIT](./LICENSE)
