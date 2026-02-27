<!---

This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

## How it works

This design integrates two complementary processing engines for secure IoT edge sensing:

**SNN Motion Detector (Mode 0):** Uses Leaky Integrate-and-Fire (LIF) neuron model for event-driven motion detection. The module compares consecutive 16x16 pixel frames, generates spike events when pixel differences exceed a threshold (20), and aggregates events across a 4x4 spatial grid. Motion is detected when more than 10% of pixels show significant change.

**Ascon-128 AEAD (Mode 1):** Implements the NIST-standardized Ascon-128 authenticated encryption algorithm. Provides both encryption and decryption with 128-bit authentication tags. Uses 12 rounds for initialization/finalization and 6 rounds for data processing. Key and nonce are serially loaded 8 bits at a time through the input pins.

The two modules share I/O pins via a mode select (uio[7]). This allows the chip to detect motion events and then securely encrypt alert data for transmission.

## How to test

### SNN Motion Detection Test
1. Set mode=0 (uio[7]=0)
2. Stream 256 pixels (16x16) with cmd=01 (uio[6:5]=01) — this is the baseline frame
3. Stream a second frame with different pixel values
4. Read uio[0] for motion_detected flag (1=motion present)
5. Read uo_out[7:0] for motion intensity (0-255)

### Ascon-128 Encryption Test
1. Set mode=1 (uio[7]=1)
2. Load 128-bit key: send 16 bytes with cmd=01 (uio[6:5]=01), MSB first
3. Load 128-bit nonce: send 16 bytes with cmd=10 (uio[6:5]=10), MSB first
4. Pulse start (uio[3]=1 for 1 cycle). Set uio[2]=0 for encrypt, uio[2]=1 for decrypt
5. Wait ~50 clock cycles for initialization
6. Send plaintext: 8 bytes with cmd=11 (uio[6:5]=11). Set uio[4]=1 on the last byte
7. Read ciphertext on uo_out[7:0] when uio[1]=1 (output_valid)
8. Read 16-byte authentication tag when uio[1]=1 after data completes

## External hardware

No external hardware required for basic testing. The design can be tested using the TinyTapeout demo board or any FPGA development board with the appropriate pin connections.

For a full demo setup:
- A camera module (e.g., OV7670) can provide pixel data for SNN motion detection
- UART/SPI bridge can be used for Ascon key/data loading
