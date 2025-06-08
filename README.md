# Embassy Meshtastic

A Rust/Embassy implementation of Meshtastic firmware for embedded devices.

## Overview

This project is a proof-of-concept implementation of the [Meshtastic](https://meshtastic.org/) mesh networking protocol using [Embassy](https://embassy.dev/), an async runtime for embedded Rust. It provides a foundation for running Meshtastic on microcontrollers with full async capabilities and memory safety guarantees.

**⚠️ This is currently a proof-of-concept and significant reorganization is likely in the future.**

## Supported Hardware

Currently supports:
- **Seeed Studio XIAO nRF52840** with accompanying **SX1262 LoRa module**

The modular design of embassy-rs makes it relatively easy to port to other boards or Embassy-compatible platforms (ESP32, RP2040, etc.).

## Features

### Current Capabilities
- [x] Decode most packets on primary channel
- [x] Send packets on primary channel
- [x] AES encryption/decryption for Meshtastic packets
- [x] Protobuf message parsing for various Meshtastic message types:
  - Text messages
  - Telemetry data
  - Node info
  - Position data
  - Neighbor info
  - Traceroute

### Near term goals
- [ ] Node database
- [ ] Channel database (support encrypting/decrypting other channels)
- [ ] Private messages (PKI encryption)
- [ ] Support for other Embassy-supported hardware (RP2040, ESP32 primarily, possibly others)

### Longer term goals
- [ ] Support official Meshtastic clients
- [ ] Serial support
- [ ] Bluetooth support
- [ ] WiFi support
- [ ] Support configuration (preferably without reboots, preferably support Meshtastic client managed config)
- [ ] Support multiple concurrent client connections
- [ ] Support public connection mode (only access public channels/read-only)
- [ ] Built-in Web Client

## Project Structure

The project is organized into several crates:

### `nrf/`
Main embedded application targeting the nRF52840. Contains the Embassy-based async runtime and LoRa radio management.

### `meshtastic-crypto/`
Encryption/decryption library for Meshtastic packets.

**Features:**
- AES-CTR encryption compatible with Meshtastic protocol
- Header parsing and IV generation
- Support for variable key lengths (128/256bit, supporting meshtastic's default key and 1-byte keys, and 128/256bit keys)
- `no_std` compatible with optional `defmt` logging

### `meshtastic-protobufs/`
Protobuf definitions and generated Rust code for Meshtastic messages.

**Features:**
- Generated from official Meshtastic .proto files
- Uses `femtopb` for `no_std` protobuf support and supports `defmt`
- Includes all major Meshtastic message types

### `packet_creation_test/`
Standalone test utility for validating packet creation and encryption without embedded hardware.

### `experiment/`
Experimental code and tests (C implementations for comparison/validation).

## Getting Started

### Prerequisites

1. Install Rust with the ARM Cortex-M target:
   ```bash
   rustup target add thumbv7em-none-eabi
   ```

2. Install probe tools for flashing:
   - https://probe.rs/docs/getting-started/installation/

3. Hardware setup:
   - Seeed Studio XIAO rp2040 as picoprobe (can use any other probe-rs supported SWD tool)
      - connected to SWD pads on nRF52840
   - Seeed Studio XIAO nRF52840
   - Seeed Studio SX1262 LoRa module

### Building and Flashing

```bash
cd nrf
cargo run
```

This will build the firmware and flash it to your connected nRF52840 device.

### Configuration

Current LoRa configuration (in `nrf/src/main.rs`):
- **Frequency:** 906.875 MHz (US Meshtastic default)
- **Spreading Factor:** 11 (LongFast preset)
- **Bandwidth:** 250 kHz
- **Coding Rate:** 4/5
- **Sync Word:** 0x2B (Meshtastic standard)

## Development

### Testing

Run the standalone packet tests:
```bash
cd packet_creation_test
cargo test
```

Run crypto library tests:
```bash
cd meshtastic-crypto
cargo test
```

### Adding Support for New Hardware

The repo will likely get restructured to better support multiple hardware devices, though some work has started on this.

For now, you'd probably want to copy the nrf directory and create an equivalent for a different board.

### Protocol Compliance

The goal of the project is to be completely compatible with meshtastic firmware.  This firmware may, however, add additional features on top of that using meshtastic's extra packet types and/or frequency switching.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Meshtastic](https://meshtastic.org/) - The original protocol and ecosystem
- [Embassy](https://embassy.dev/) - Async runtime for embedded Rust
- [lora-rs](https://github.com/lora-rs/lora-rs) - LoRa PHY implementation
- [femtopb](https://github.com/cberner/femtopb) - No-std protobuf implementation
- [gatlinnewhouse's rust firmware work](https://github.com/gatlinnewhouse/meshtastic-rust-firmware) - for the idea to use femptopb and random other ideas