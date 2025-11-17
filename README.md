# iVF - ink! Verifier Factory for Noir Circuits

![iVF Logo](image1.png)

> Automated generation of ink! v6 smart contract verifiers from Noir zero-knowledge proof circuits for PolkaVM.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![ink! v5.0](https://img.shields.io/badge/ink!-v6.0.0beta-blue)](https://use.ink/)
[![Noir](https://img.shields.io/badge/Noir-Compatible-purple)](https://noir-lang.org/)
[![PolkaVM](https://img.shields.io/badge/PolkaVM-RISC--V-green)](https://github.com/paritytech/polkavm)

## Overview

ink! Verifier Factory(iVF) generates **native PolkaVM (RISC-V) verifier contracts** from Noir zero-knowledge circuits, offering a performance-optimized alternative to Solidity verifiers on Pallet-Revive.

Pallet-Revive now supports Solidity verifiers, making ZKPs possible on Polkadot. However, iVF gives you **~25% gas savings**, **45% smaller binaries**, **Rust type safety**, and **seamless Polkadot ecosystem integration**. Choose Solidity for rapid migration, choose ink! for optimal performance.

### Key Features

- **One-Command Generation**: Transform Noir VK files into production-ready ink! v6 contracts
- **Native PolkaVM Integration**: Uses Pallet-Revive's BN128 precompiles for optimal performance
- **Rust Type Safety**: Compile-time guarantees that Solidity can't provide
- **Circuit Agnostic**: Handles circuits of any complexity (tested from 57 to 128 field elements)
- **Production Ready**: Comprehensive error handling with detailed diagnostics
- **Gas Optimized**: Efficient field arithmetic and minimal storage footprint
- **Zero External Dependencies**: Fully self-contained verification on-chain

## Installation

### Prerequisites

- Rust 1.75+ with `riscv64emac-unknown-none-polkavm` target (for ink! v6)
- [cargo-contract](https://github.com/use-ink/cargo-contract) v6.0.0 (ink! v6 support)
- [Noir](https://noir-lang.org/) and nargo CLI
- Node.js 16+ (optional, for testing)

### Setup

```bash
# Clone the repository
git clone https://github.com/Lynette7/ivf.git
cd ivf

# Install Rust and RISC-V target for PolkaVM
rustup default stable
rustup target add riscv64emac-unknown-none-polkavm

# Install cargo-contract with ink! v6 support
cargo install --force --locked --version 6.0.0-beta.1 cargo-contract

# Install Noir (via noirup)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup --version nightly

# Verify installations
cargo contract --version
nargo --version
rustc --version
```

## Quick Start

### 1. Create a Noir Circuit

```bash
# Create new Noir project
cd noir-circuits
nargo new my_circuit && cd my_circuit
```

Edit `src/main.nr`:

```rust
fn main(secret: Field, public_output: pub Field) {
    assert(secret + 1 == public_output);
}
```

### 2. Generate Verification Key

```bash
# Generate a Prover.toml file to specify our input values
nargo check

# Compile and execute circuit, as well as generate the witness
nargo execute

# Generate VK using Barretenberg
bb write_vk -b ./target/<noir_artifact_name>.json -o ./target --oracle_hash keccak
```

### 3. Generate ink! Verifier

```bash
cd ../../ink-generator

cargo run -- \
  --vk ../noir-circuits/my_circuit/target/vk \
  --output ../generated_verifier/src/lib.rs
```

### 4. Build & Deploy

```bash
cd ../generated_verifier

# Build the contract (compiles to PolkaVM)
cargo contract build
```

- Deploy the `.contract` file using the [contracts UI](https://use.ink/docs/v6/getting-started/deploy-your-contract#deploying-to-passet-hub-testnet) on Passert Hub network

### 5. Verify a Proof

```bash
# Generate proof from your Noir circuit
cd ../noir-circuits/my_circuit
echo 'secret = "5"\npublic_output = "6"' > Prover.toml
nargo prove

# Call verifier contract (example using Polkadot.js)
# proof_bytes = fs.readFileSync('proofs/my_circuit.proof')
# public_inputs = ['0x06'] // 6 in hex
# result = await contract.verify(proof_bytes, public_inputs)
```

### Verification Key Format

The VK file is a binary file containing field elements in big-endian format:

- **Metadata** (first 3 fields): `circuit_size`, `log_circuit_size`, `public_inputs_size`
- **G1 Points** (remaining fields): Pairs of coordinates `(x, y)` for polynomial commitments

```
Offset | Content                | Size
-------|------------------------|-------
0x0000 | circuit_size           | 32 bytes
0x0020 | log_circuit_size       | 32 bytes
0x0040 | public_inputs_size     | 32 bytes
0x0060 | ql.x                   | 32 bytes
0x0080 | ql.y                   | 32 bytes
...    | ...                    | ...
```

### Generated Contract API

```rust
#[ink(message)]
pub fn verify(
    &self,
    proof: Vec<u8>,           // Raw proof bytes from nargo prove
    public_inputs: Vec<Vec<u8>>  // Public inputs as 32-byte field elements
) -> Result<bool, VerifierError>
```

**Returns:**
- `Ok(true)` - Proof is valid
- `Ok(false)` - Should never happen (proof is either valid or error)
- `Err(VerifierError::*)` - Verification failed with specific error

## How It Works

### Architecture Overview

![alt text](image.png)

### Verification Algorithm (UltraHonk)

1. **Parse Proof**: Extract commitments, evaluations, and sumcheck polynomials
2. **Transcript Generation**: Derive Fiat-Shamir challenges from proof data
3. **Public Input Delta**: Compute contribution of public inputs to grand product
4. **Sumcheck Verification**: Verify log(N) rounds of the sumcheck protocol
5. **Relation Checking**: Evaluate all UltraHonk relations at challenge point
6. **Opening Verification**: Verify polynomial openings using KZG commitments
7. **Pairing Check**: Final cryptographic check using bn128pairing precompile

### Cryptographic Primitives

- **Elliptic Curve**: BN254 (alt_bn128)
- **Scalar Field**: `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
- **Operations**: Point addition, scalar multiplication, pairing checks
- **Precompiles**: Leverage Pallet-Revive's native implementations for PolkaVM

## Choosing Between Solidity and ink!

| **Use Solidity (Pallet-Revive)** | **Use ink! v6 (iVF)** |
|-----------------------------------|---------------------|
| Quick Ethereum migration | Building Polkadot-first apps |
| Multi-chain deployment | Maximum performance needed |
| Existing Solidity codebase | Type safety critical |
| Rapid prototyping | Production-grade systems |
| Team only knows Solidity | Deep Polkadot integration |

## Acknowledgments

- [Noir](https://noir-lang.org/) by Aztec for the ZKP framework
- [ink!](https://use.ink/) for the smart contract language and v6 PolkaVM support
- [Barretenberg](https://github.com/AztecProtocol/barretenberg) for the UltraHonk proving system

*Pallet-Revive brought ZKPs to Polkadot. iVF makes them native.*
