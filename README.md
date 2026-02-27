![](../../workflows/gds/badge.svg) ![](../../workflows/docs/badge.svg) ![](../../workflows/test/badge.svg) ![](../../workflows/fpga/badge.svg)

# Ascon-128 AEAD — NIST Lightweight Cryptography on Silicon

- [Read the documentation for project](docs/info.md)

## Overview

Hardware implementation of the NIST-standardized Ascon-128 authenticated encryption (AEAD) algorithm on IHP SG13G2 130nm silicon. Part of the UrbanSense-AI project for secure IoT edge sensing.

**Target:** TinyTapeout IHP 26a (IHP SG13G2 130nm)
**Tiles:** 4x2 (~6K cells)
**Clock:** 20 MHz

## Features

- NIST Ascon-128 AEAD: encryption + authentication in one operation
- 128-bit key, 128-bit nonce, 64-bit data blocks
- 128-bit authentication tag
- Serial 8-bit I/O interface (no wide buses needed)
- Zero DSP blocks — pure digital logic

## Pin Mapping

| Pin | Direction | Function |
|-----|-----------|----------|
| `ui_in[7:0]` | Input | Data (key/nonce/plaintext bytes) |
| `uo_out[7:0]` | Output | Result (ciphertext/tag bytes) |
| `uio[7:6]` | Input | CMD: 00=idle, 01=load_key, 10=load_nonce, 11=process |
| `uio[5]` | Input | Data last (marks final block) |
| `uio[4]` | Input | Start pulse |
| `uio[3]` | Input | Decrypt select (0=encrypt, 1=decrypt) |
| `uio[2]` | Input | Read acknowledge (pulse to get next output byte) |
| `uio[1]` | Output | Output valid (byte ready on uo_out) |
| `uio[0]` | Output | Busy |

## What is Tiny Tapeout?

Tiny Tapeout is an educational project that aims to make it easier and cheaper than ever to get your digital and analog designs manufactured on a real chip.

To learn more and get started, visit https://tinytapeout.com.
