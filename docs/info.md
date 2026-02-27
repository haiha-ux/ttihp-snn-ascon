<!---

This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

## How it works

This design implements the NIST-standardized **Ascon-128 authenticated encryption with associated data (AEAD)** algorithm in hardware. Ascon was selected as the NIST Lightweight Cryptography standard in 2023 for resource-constrained environments.

**Ascon-128 specifications:**
- 128-bit key, 128-bit nonce
- 64-bit rate (8 bytes per block)
- 12 rounds for initialization/finalization (pa)
- 6 rounds for data processing (pb)
- 128-bit authentication tag

The design uses a serial 8-bit I/O interface to load the 128-bit key and nonce (16 bytes each), process data in 8-byte blocks, and output ciphertext and authentication tags. The Ascon permutation is implemented iteratively (one round per clock cycle) to minimize area.

This is part of the **UrbanSense-AI** project — a multi-paradigm neural processing SoC integrating BNN, SNN, and cryptographic acceleration for smart city edge sensing.

## How to test

### Encryption
1. Load 128-bit key: send 16 bytes on `ui_in` with `cmd=01` (`uio[7:6]=01`), MSB first
2. Load 128-bit nonce: send 16 bytes with `cmd=10` (`uio[7:6]=10`), MSB first
3. Pulse start: set `uio[4]=1` for one clock cycle (with `uio[3]=0` for encrypt)
4. Wait ~50 clock cycles for initialization
5. Send plaintext: 8 bytes per block with `cmd=11` (`uio[7:6]=11`). Set `uio[5]=1` on the last byte of the last block
6. Read ciphertext on `uo_out` when `uio[1]=1` (output_valid)
7. Read 16-byte authentication tag on `uo_out` when `uio[1]=1` after data completes

### Decryption
Same as encryption but set `uio[3]=1` when pulsing start. Send ciphertext instead of plaintext. Output will be decrypted plaintext.

## External hardware

No external hardware required for basic testing. The design can be tested using the TinyTapeout demo board with a microcontroller (e.g., RP2040) driving the serial protocol.
