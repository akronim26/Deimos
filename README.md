# Deimos — zkVM Mobile Benchmarking Suite

**Deimos** is an open-source benchmarking suite for evaluating zero-knowledge virtual machines (zkVMs) on mobile devices. It provides consistent, repeatable performance tests across various zkVM tools, starting with [MoPro](https://github.com/zkmopro/mopro).

## Overview

The goal of Deimos is to:
* Benchmark zkVM performance for mobile-specific environments.
* Compare multiple tools (initially **MoPro**, **imp1**, and **ProveKit**).
* Measure performance of common cryptographic and proof-related functions such as **Poseidon2**, **SHA-256**, **Keccak-256**, and **EdDSA**.
* Present results via a centralized **website dashboard**.

> **Note:** This project is under active development and undergoes frequent changes in the `dev` branch.

---

## Repository Structure

```
deimos/
│
├── website/                  # Dashboard for displaying benchmark results
│   ├── frontend/            # React-based UI
│   ├── backend/             # API server and database
│   └── package.json
│
├── mobile-apps/              # Mobile benchmarking apps for each zkVM
│   ├── mopro/
│   │   ├── poseidon2/        # Poseidon2 hash benchmark
│   │   │   ├── android/
│   │   │   ├── ios/
│   │   │   └── README.md
│   │   ├── sha256/           # SHA-256 hash benchmark
│   │   │   ├── android/
│   │   │   ├── ios/
│   │   │   └── README.md
│   │   ├── keccak/           # Keccak-256 hash benchmark
│   │   │   ├── android/
│   │   │   ├── ios/
│   │   │   └── README.md
│   │   ├── eddsa/            # EdDSA signature benchmark
│   │   │   ├── android/
│   │   │   ├── ios/
│   │   │   └── README.md
│   │   └── README.md
│   │
│   ├── imp1/                 # imp1 benchmarks (coming soon)
│   ├── provekit/             # ProveKit benchmarks (coming soon)
│   └── README.md
│
├── .github/                  # CI/CD and benchmark automation scripts
│   └── workflows/
│
├── docs/                     # Documentation and methodology
├── .gitignore
├── README.md
├── CONTRIBUTING.md
├── proposal.md
└── LICENSE
```

---

## Benchmarked Frameworks

### Currently Supported
<!-- * **[MoPro](https://zkmopro.org/)** — Mobile-first ZK proving toolkit -->

### Planned Integration
<!-- * **[imp1](https://github.com/ingonyama-zk/zkml)** — Ingonyama's mobile proving solution
* **[ProveKit](https://github.com/worldfnd/ProveKit)** — Worldcoin's Noir-based toolkit
* **RISC Zero** — General-purpose zkVM
* **SP1** — Succinct's zkVM -->

## Benchmarked Primitives

<!-- * **Hash Functions:** Poseidon2, SHA-256, Keccak-256
* **Digital Signatures:** EdDSA, ECDSA (planned)
* **Basic Arithmetic:** Fibonacci sequence
* **Application-Level:** JWT parsing (planned) -->

## Measured Metrics

<!-- * **Proving Time** — Time to generate ZK proof
* **Peak Memory Usage** — Maximum RAM consumption during proving
* **Battery Impact** — Energy consumption per proof (planned)
* **Proof Size** — Generated proof artifact size -->

---

## Development Status

* **Current focus:** MoPro integration and core hash function benchmarks.
* **Next milestone:** Database integration and basic web dashboard.
* **Branch policy:**
  * `main` → Stable releases only.
  * `dev` → Active development; frequent breaking changes.

---

## Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/BlocSoc-iitr/deimos.git
   cd deimos
   ```

2. **Explore the website dashboard**
   ```bash
   cd website
   npm install
   npm run dev
   ```

3. **Run mobile benchmarks**
   * Navigate to the corresponding mobile app directory (e.g., `mobile-apps/mopro/sha256/android/`).
   * Follow the platform-specific README for setup instructions.
   * Build and run on physical devices for accurate performance measurements.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](/contributing.md) for:
* Setting up the development environment
* Adding new zkVM frameworks
* Contributing benchmark circuits
* Reporting issues

## License

This project is licensed under the [MIT License](LICENSE).

---

*Building neutral, comprehensive benchmarks for mobile ZK proving.*
