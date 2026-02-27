# SPDX-FileCopyrightText: © 2024 Tiny Tapeout
# SPDX-License-Identifier: Apache-2.0

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles


@cocotb.test()
async def test_io_direction(dut):
    """Verify I/O enable direction is correct."""
    dut._log.info("Testing I/O direction")

    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start())

    dut.ena.value = 1
    dut.rst_n.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 1)

    oe = dut.uio_oe.value.integer
    dut._log.info(f"uio_oe = {oe:#010b}")
    assert oe == 0b00000011, f"Expected uio_oe=0b00000011, got {oe:#010b}"
    dut._log.info("I/O direction test PASSED")


@cocotb.test()
async def test_ascon_encrypt(dut):
    """Test Ascon-128: load key/nonce, start encryption, verify completion."""
    dut._log.info("Start Ascon encryption test")

    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start())

    # Reset
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 5)

    # Load 128-bit key (16 bytes of 0x01), cmd=01 (uio[7:6]=01)
    dut._log.info("Loading key")
    for i in range(16):
        dut.ui_in.value = 0x01
        dut.uio_in.value = 0b01_0_0_0_000  # cmd=01
        await ClockCycles(dut.clk, 1)

    # Load 128-bit nonce (16 bytes of 0x02), cmd=10 (uio[7:6]=10)
    dut._log.info("Loading nonce")
    for i in range(16):
        dut.ui_in.value = 0x02
        dut.uio_in.value = 0b10_0_0_0_000  # cmd=10
        await ClockCycles(dut.clk, 1)

    dut.uio_in.value = 0  # idle
    await ClockCycles(dut.clk, 2)

    # Start encryption: uio[4]=1, uio[3]=0 (encrypt)
    dut._log.info("Starting encryption")
    dut.uio_in.value = 0b00_0_1_0_000  # start=1, decrypt=0
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0  # clear start
    await ClockCycles(dut.clk, 5)

    # Check busy flag (uio_out[0])
    busy = dut.uio_out.value.integer & 0x01
    dut._log.info(f"Ascon busy={busy}")
    assert busy == 1, "Ascon should be busy after start"

    # Wait for initialization permutation (12 rounds)
    await ClockCycles(dut.clk, 50)

    # Send 8 bytes plaintext with data_last on last byte
    dut._log.info("Sending plaintext block")
    for i in range(8):
        is_last = 1 if i == 7 else 0
        dut.ui_in.value = 0xAA
        # cmd=11, data_last on bit 5
        dut.uio_in.value = (0b11 << 6) | (is_last << 5)
        await ClockCycles(dut.clk, 1)

    dut.uio_in.value = 0  # idle
    await ClockCycles(dut.clk, 200)

    # Should be done
    busy = dut.uio_out.value.integer & 0x01
    dut._log.info(f"Ascon busy after processing={busy}")
    assert busy == 0, "Ascon should complete after processing"

    dut._log.info("Ascon encryption test PASSED")


@cocotb.test()
async def test_ascon_output(dut):
    """Test Ascon-128: verify output data appears."""
    dut._log.info("Start Ascon output test")

    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start())

    # Reset
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 5)

    # Load key (all zeros)
    for i in range(16):
        dut.ui_in.value = 0x00
        dut.uio_in.value = 0b01_0_0_0_000
        await ClockCycles(dut.clk, 1)

    # Load nonce (all zeros)
    for i in range(16):
        dut.ui_in.value = 0x00
        dut.uio_in.value = 0b10_0_0_0_000
        await ClockCycles(dut.clk, 1)

    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 2)

    # Start encryption
    dut.uio_in.value = 0b00_0_1_0_000
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 50)

    # Send plaintext (all zeros), last block
    for i in range(8):
        is_last = 1 if i == 7 else 0
        dut.ui_in.value = 0x00
        dut.uio_in.value = (0b11 << 6) | (is_last << 5)
        await ClockCycles(dut.clk, 1)

    dut.uio_in.value = 0

    # Wait and collect output
    output_bytes = []
    for cycle in range(300):
        await ClockCycles(dut.clk, 1)
        out_valid = (dut.uio_out.value.integer >> 1) & 0x01
        if out_valid:
            output_bytes.append(dut.uo_out.value.integer)

    dut._log.info(f"Collected {len(output_bytes)} output bytes")
    dut._log.info(f"Output: {[hex(b) for b in output_bytes[:24]]}")

    # Ascon with all-zero key/nonce/plaintext should produce non-zero ciphertext+tag
    assert len(output_bytes) > 0, "Should produce output bytes"
    assert any(b != 0 for b in output_bytes), "Output should be non-zero (encrypted)"

    dut._log.info("Ascon output test PASSED")
