# SPDX-FileCopyrightText: © 2024 Tiny Tapeout
# SPDX-License-Identifier: Apache-2.0

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge


async def reset(dut):
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)


async def load_key(dut, key_bytes):
    """Load 16-byte key with cmd=01, keep cmd active throughout."""
    for b in key_bytes:
        dut.ui_in.value = b
        dut.uio_in.value = 0b01_0_0_0_000  # cmd=01
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0


async def load_nonce(dut, nonce_bytes):
    """Load 16-byte nonce with cmd=10, keep cmd active throughout."""
    for b in nonce_bytes:
        dut.ui_in.value = b
        dut.uio_in.value = 0b10_0_0_0_000  # cmd=10
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0


async def start_encrypt(dut):
    dut.uio_in.value = 0b00_0_1_0_000  # start=1
    await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0


async def wait_for_state(dut, target_state, timeout=200):
    """Wait until FSM reaches target state."""
    for _ in range(timeout):
        await RisingEdge(dut.clk)
        try:
            if dut.fsm_state.value.integer == target_state:
                return True
        except Exception:
            pass
    return False


async def send_pt_block(dut, pt_bytes, is_last):
    """Send 8 plaintext bytes with cmd=11. Set data_last on last byte."""
    # Wait for WAIT_DATA state (3)
    await wait_for_state(dut, 3)
    await ClockCycles(dut.clk, 1)

    for i, b in enumerate(pt_bytes):
        dut.ui_in.value = b
        last_flag = (1 << 5) if (i == 7 and is_last) else 0
        dut.uio_in.value = (0b11 << 6) | last_flag
        await ClockCycles(dut.clk, 1)
    dut.uio_in.value = 0


async def read_output_bytes(dut, count, timeout=500):
    """Read output bytes via read_ack handshake."""
    result = []
    for _ in range(timeout):
        await RisingEdge(dut.clk)
        out_valid = (dut.uio_out.value.integer >> 1) & 1
        if out_valid:
            result.append(dut.uo_out.value.integer)
            dut.uio_in.value = 0b00_0_0_0_100  # read_ack
            await ClockCycles(dut.clk, 1)
            dut.uio_in.value = 0
            if len(result) >= count:
                break
    return result


def to_bytes(val, n):
    """Convert integer to MSB-first byte list."""
    return [(val >> (8 * (n - 1 - i))) & 0xFF for i in range(n)]


@cocotb.test()
async def test_io_direction(dut):
    """Verify I/O enable direction is correct."""
    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start())

    dut.ena.value = 1
    dut.rst_n.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 1)

    oe = dut.uio_oe.value.integer
    assert oe == 0b00000011, f"Expected uio_oe=0b00000011, got {oe:#010b}"
    dut._log.info("I/O direction test PASSED")


@cocotb.test()
async def test_ascon_tv0(dut):
    """TV0: K=0, N=0, PT=0 — verify CT and tag."""
    dut._log.info("TV0: K=0, N=0, PT=0")

    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start())
    await reset(dut)

    # Key = 0, Nonce = 0
    await load_key(dut, [0] * 16)
    await load_nonce(dut, [0] * 16)
    await start_encrypt(dut)

    # Send PT = 0 (last block)
    await send_pt_block(dut, [0] * 8, is_last=True)

    # Read 8 CT bytes + 16 tag bytes = 24
    output = await read_output_bytes(dut, 24)
    assert len(output) == 24, f"Expected 24 bytes, got {len(output)}"

    ct_hex = ''.join(f'{b:02x}' for b in output[:8])
    tag_hex = ''.join(f'{b:02x}' for b in output[8:24])

    dut._log.info(f"CT:  {ct_hex}")
    dut._log.info(f"Tag: {tag_hex}")

    assert ct_hex == "b8dff46b0db421f8", f"CT mismatch: {ct_hex}"
    assert tag_hex == "eaf0f7b7a32b807e91ee437183d14b71", f"Tag mismatch: {tag_hex}"
    dut._log.info("TV0 PASSED")


@cocotb.test()
async def test_ascon_tv2(dut):
    """TV2: Counting K/N — verify CT and tag."""
    dut._log.info("TV2: Counting K/N")

    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start())
    await reset(dut)

    key_bytes = to_bytes(0x000102030405060708090A0B0C0D0E0F, 16)
    nonce_bytes = to_bytes(0x00112233445566778899AABBCCDDEEFF, 16)
    pt_bytes = to_bytes(0x0011223344556677, 8)

    await load_key(dut, key_bytes)
    await load_nonce(dut, nonce_bytes)
    await start_encrypt(dut)
    await send_pt_block(dut, pt_bytes, is_last=True)

    output = await read_output_bytes(dut, 24)
    assert len(output) == 24, f"Expected 24 bytes, got {len(output)}"

    ct_hex = ''.join(f'{b:02x}' for b in output[:8])
    tag_hex = ''.join(f'{b:02x}' for b in output[8:24])

    dut._log.info(f"CT:  {ct_hex}")
    dut._log.info(f"Tag: {tag_hex}")

    assert ct_hex == "1b0276e833b5bdc3", f"CT mismatch: {ct_hex}"
    assert tag_hex == "7964b9cac01116190a4ad52d9023ed19", f"Tag mismatch: {tag_hex}"
    dut._log.info("TV2 PASSED")


@cocotb.test()
async def test_ascon_2block(dut):
    """TV1: 2-block encryption — verify CT and tag."""
    dut._log.info("TV1: 2-block")

    clock = Clock(dut.clk, 20, unit="ns")
    cocotb.start_soon(clock.start())
    await reset(dut)

    key_bytes = to_bytes(0x01010101010101010101010101010101, 16)
    nonce_bytes = to_bytes(0x02020202020202020202020202020202, 16)

    await load_key(dut, key_bytes)
    await load_nonce(dut, nonce_bytes)
    await start_encrypt(dut)

    # Block 0 (not last)
    await send_pt_block(dut, to_bytes(0xAAAAAAAAAAAAAAAA, 8), is_last=False)
    ct0 = await read_output_bytes(dut, 8)

    # Block 1 (last)
    await send_pt_block(dut, to_bytes(0xBBBBBBBBBBBBBBBB, 8), is_last=True)
    ct1 = await read_output_bytes(dut, 8)

    # Tag (16 bytes)
    tag = await read_output_bytes(dut, 16)

    ct0_hex = ''.join(f'{b:02x}' for b in ct0)
    ct1_hex = ''.join(f'{b:02x}' for b in ct1)
    tag_hex = ''.join(f'{b:02x}' for b in tag)

    dut._log.info(f"CT[0]: {ct0_hex}")
    dut._log.info(f"CT[1]: {ct1_hex}")
    dut._log.info(f"Tag:   {tag_hex}")

    assert ct0_hex == "32f5bb4d8a0a8b3f", f"CT[0] mismatch: {ct0_hex}"
    assert ct1_hex == "119efc192586e30b", f"CT[1] mismatch: {ct1_hex}"
    assert tag_hex == "0a06465ef67f0a4e184ca4d2ad45ddc5", f"Tag mismatch: {tag_hex}"
    dut._log.info("TV1 PASSED")
