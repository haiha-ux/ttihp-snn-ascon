# SPDX-FileCopyrightText: © 2024 Tiny Tapeout
# SPDX-License-Identifier: Apache-2.0

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles


@cocotb.test()
async def test_snn_motion_detection(dut):
    """Test SNN motion detection: stream two frames, detect motion."""
    dut._log.info("Start SNN motion detection test")

    # 50 MHz clock (20ns period)
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

    # SNN mode (uio[7]=0), pixel_valid (cmd=01, uio[6:5]=01)
    # Send frame 1: all zeros (baseline)
    dut._log.info("Sending frame 1 (all zeros)")
    for i in range(256):  # 16x16 pixels
        dut.ui_in.value = 0
        dut.uio_in.value = 0b00_01_0000_0  # mode=0, cmd=01
        dut.uio_in.value = 0b0_01_00000  # uio[7]=0(SNN), uio[6:5]=01(pixel_valid)
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 10)

    # Check: no motion after first frame
    status = dut.uio_out.value.integer & 0x01
    dut._log.info(f"Frame 1: motion_detected={status}")

    # Send frame 2: large changes (motion)
    dut._log.info("Sending frame 2 (with motion)")
    for i in range(256):
        dut.ui_in.value = 200 if i < 128 else 0
        dut.uio_in.value = 0b0_01_00000  # SNN mode, pixel_valid
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 10)

    # Check: motion should be detected
    status = dut.uio_out.value.integer & 0x01
    dut._log.info(f"Frame 2: motion_detected={status}")
    assert status == 1, "Motion should be detected after significant pixel changes"

    # Send frame 3: same as frame 2 (no motion)
    dut._log.info("Sending frame 3 (same as frame 2)")
    for i in range(256):
        dut.ui_in.value = 200 if i < 128 else 0
        dut.uio_in.value = 0b0_01_00000
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 10)

    status = dut.uio_out.value.integer & 0x01
    dut._log.info(f"Frame 3: motion_detected={status}")
    assert status == 0, "No motion on identical frames"

    dut._log.info("SNN motion detection test PASSED")


@cocotb.test()
async def test_ascon_basic(dut):
    """Test Ascon-128: load key/nonce, start encryption, check busy flag."""
    dut._log.info("Start Ascon basic test")

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

    # Ascon mode (uio[7]=1)
    # Load 128-bit key (16 bytes of 0x01), cmd=01 (uio[6:5]=01)
    dut._log.info("Loading key")
    for i in range(16):
        dut.ui_in.value = 0x01
        dut.uio_in.value = 0b1_01_00000  # mode=1(Ascon), cmd=01(load_key)
        await ClockCycles(dut.clk, 1)

    # Load 128-bit nonce (16 bytes of 0x02), cmd=10 (uio[6:5]=10)
    dut._log.info("Loading nonce")
    for i in range(16):
        dut.ui_in.value = 0x02
        dut.uio_in.value = 0b1_10_00000  # mode=1, cmd=10(load_nonce)
        await ClockCycles(dut.clk, 1)

    dut.uio_in.value = 0b1_00_00000  # idle
    await ClockCycles(dut.clk, 2)

    # Start encryption: uio[3]=1, uio[2]=0 (encrypt)
    dut._log.info("Starting encryption")
    dut.uio_in.value = 0b1_00_0_1_0_00  # mode=1, start=1, decrypt=0
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0b1_00_00000  # clear start
    await ClockCycles(dut.clk, 5)

    # Check busy flag (uio_out[0])
    busy = dut.uio_out.value.integer & 0x01
    dut._log.info(f"Ascon busy={busy}")
    assert busy == 1, "Ascon should be busy after start"

    # Wait for initialization permutation (12 rounds)
    await ClockCycles(dut.clk, 50)

    # Send 8 bytes plaintext with data_last
    dut._log.info("Sending plaintext")
    for i in range(8):
        is_last = 1 if i == 7 else 0
        dut.ui_in.value = 0xAA
        # mode=1, cmd=11(process), data_last on last byte
        dut.uio_in.value = (1 << 7) | (0b11 << 5) | (is_last << 4)
        await ClockCycles(dut.clk, 1)

    dut.uio_in.value = 0b1_00_00000
    await ClockCycles(dut.clk, 200)

    # Should be done
    busy = dut.uio_out.value.integer & 0x01
    dut._log.info(f"Ascon busy after processing={busy}")
    assert busy == 0, "Ascon should complete after processing"

    dut._log.info("Ascon basic test PASSED")


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
