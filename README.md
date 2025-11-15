# IVF - Ink! Verifier Factory for Noir Circuits

> Automated generation of ink! v6 smart contract verifiers from Noir zero-knowledge proof circuits for PolkaVM.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![ink! v5.0](https://img.shields.io/badge/ink!-v6.0.0beta-blue)](https://use.ink/)
[![Noir](https://img.shields.io/badge/Noir-Compatible-purple)](https://noir-lang.org/)

## Overview

ink! Verifier Factory(iVF) bridges the gap between Noir's zero-knowledge proof circuits and Polkadot's ink! and PolkaVM, enabling developers to deploy privacy-preserving applications on any Polkadot parachain without external dependencies or bridges.

### Key Features

- **One-Command Generation**: Transform Noir VK files into production-ready ink! contracts
- **Native PolkaVM Integration**: Uses Pallet-Revive's BN128 precompiles for optimal performance
- **Circuit Agnostic**: Handles circuits of any complexity (tested from 57 to 128 field elements)
- **Gas Optimized**: Efficient field arithmetic and minimal storage footprint
- **Type-Safe**: Comprehensive error handling with detailed diagnostics
- **Zero External Dependencies**: Fully self-contained verification on-chain

![alt text](image.png)
