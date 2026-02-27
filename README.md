![](../../workflows/gds/badge.svg) ![](../../workflows/docs/badge.svg) ![](../../workflows/test/badge.svg) ![](../../workflows/fpga/badge.svg)

# SNN Motion Detector + Ascon-128 AEAD

- [Read the documentation for project](docs/info.md)

## Overview

Neuromorphic motion detection with NIST Ascon-128 authenticated encryption for secure IoT edge sensing. Part of the UrbanSense-AI multi-paradigm neural processing SoC project.

**Target:** TinyTapeout IHP 26a (IHP SG13G2 130nm)
**Tiles:** 8x2 (16 tiles, ~15K cells)

## Modules

### SNN Motion Detector (Mode 0)
- Leaky Integrate-and-Fire (LIF) neurons for event-driven motion detection
- 16x16 pixel input, 4x4 spatial grid aggregation
- Outputs: motion_detected flag + motion_intensity[7:0]

### Ascon-128 AEAD (Mode 1)
- NIST Lightweight Cryptography standard (2023)
- 128-bit key, 128-bit nonce, 64-bit data blocks
- Authenticated encryption and decryption with 128-bit tag

## Pin Mapping

| Pin | Direction | Function |
|-----|-----------|----------|
| `ui_in[7:0]` | Input | Data (pixel or crypto) |
| `uo_out[7:0]` | Output | Result (motion info or ciphertext) |
| `uio[7]` | Input | Mode: 0=SNN, 1=Ascon |
| `uio[6:5]` | Input | Command |
| `uio[4]` | Input | Data last (Ascon) |
| `uio[3]` | Input | Start (Ascon) |
| `uio[2]` | Input | Decrypt select |
| `uio[1]` | Output | Output valid |
| `uio[0]` | Output | Status |

## What is Tiny Tapeout?

Tiny Tapeout is an educational project that aims to make it easier and cheaper than ever to get your digital and analog designs manufactured on a real chip.

To learn more and get started, visit https://tinytapeout.com.
