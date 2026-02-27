// ============================================================================
// Testbench for Merged Ascon-128 (Sequential Protocol, 2x2 Target)
// ============================================================================
// Tests the single-module tt_um_snn_ascon with byte-serial protocol:
//   1. Load key (16 bytes, cmd=01)
//   2. Load nonce (16 bytes, cmd=10) → directly into x3/x4
//   3. Pulse start (uio[4])
//   4. For each block: send 8 PT bytes (cmd=11), read 8 CT bytes (read_ack)
//   5. Read 16 tag bytes (8 tag_hi + 8 tag_lo)
// ============================================================================

`timescale 1ns/1ps

module tb_merged;

    reg  [7:0] ui_in;
    wire [7:0] uo_out;
    reg  [7:0] uio_in;
    wire [7:0] uio_out;
    wire [7:0] uio_oe;
    reg        ena, clk, rst_n;

    tt_um_snn_ascon dut (
        .ui_in(ui_in),
        .uo_out(uo_out),
        .uio_in(uio_in),
        .uio_out(uio_out),
        .uio_oe(uio_oe),
        .ena(ena),
        .clk(clk),
        .rst_n(rst_n)
    );

    // Clock: 50ns period (20MHz)
    initial clk = 0;
    always #25 clk = ~clk;

    // Status signals from DUT
    wire busy         = uio_out[0];
    wire output_valid = uio_out[1];

    // Counters
    integer pass_cnt, fail_cnt;
    integer tv_num;

    // ========================================================================
    // Tasks
    // ========================================================================

    task reset_dut;
        begin
            rst_n = 0;
            ena = 1;
            ui_in = 8'd0;
            uio_in = 8'd0;
            repeat(5) @(posedge clk);
            rst_n = 1;
            repeat(2) @(posedge clk);
        end
    endtask

    // Load 16-byte key (MSB first) — keep cmd=01 active throughout
    task load_key(input [127:0] key);
        integer i;
        begin
            for (i = 15; i >= 0; i = i - 1) begin
                @(posedge clk);
                #1;
                ui_in = key[i*8 +: 8];
                uio_in[7:6] = 2'b01;
                uio_in[5:4] = 2'b00;
                uio_in[2] = 0;
            end
            @(posedge clk);
            #1;
            uio_in[7:6] = 2'b00; // back to idle
        end
    endtask

    // Load 16-byte nonce (MSB first) — keep cmd=10 active throughout
    // byte_cnt must increment continuously (default cmd resets it!)
    task load_nonce(input [127:0] nonce);
        integer i;
        begin
            for (i = 15; i >= 0; i = i - 1) begin
                @(posedge clk);
                #1;
                ui_in = nonce[i*8 +: 8];
                uio_in[7:6] = 2'b10;
                uio_in[5:4] = 2'b00;
                uio_in[2] = 0;
            end
            @(posedge clk);
            #1;
            uio_in[7:6] = 2'b00; // back to idle
        end
    endtask

    // Pulse start
    task pulse_start;
        begin
            @(posedge clk);
            #1;
            uio_in[4] = 1;
            uio_in[7:6] = 2'b00;
            @(posedge clk);
            #1;
            uio_in[4] = 0;
        end
    endtask

    // Send 8 PT bytes (MSB first), with data_last on the 8th byte if last_block
    task send_pt_block(input [63:0] pt, input last);
        integer i;
        begin
            // Wait until FSM is in ST_WAIT_DATA (state 3) and not outputting
            wait(dut.fsm_state == 3'd3 && !output_valid);
            @(posedge clk);
            #1;

            for (i = 7; i >= 0; i = i - 1) begin
                ui_in = pt[i*8 +: 8];
                uio_in[7:6] = 2'b11; // cmd = send_data
                uio_in[5] = (i == 0) ? last : 1'b0; // data_last on last byte
                uio_in[4] = 0;
                uio_in[2] = 0;
                @(posedge clk);
                #1;
            end
            uio_in[7:6] = 2'b00;
            uio_in[5] = 0;
        end
    endtask

    // Read 8 output bytes from io_sr via read_ack, return as 64-bit word
    task read_8_bytes(output [63:0] data);
        integer i;
        reg [7:0] bytes [0:7];
        begin
            for (i = 0; i < 8; i = i + 1) begin
                // Wait for output_valid
                wait(output_valid);
                @(posedge clk);
                #1;
                bytes[i] = uo_out;
                // Pulse read_ack
                uio_in[2] = 1;
                @(posedge clk);
                #1;
                uio_in[2] = 0;
            end
            data = {bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7]};
        end
    endtask

    // Read 16 tag bytes (tag_hi then tag_lo)
    task read_tag(output [127:0] tag);
        reg [63:0] tag_hi, tag_lo;
        begin
            read_8_bytes(tag_hi);
            read_8_bytes(tag_lo);
            tag = {tag_hi, tag_lo};
        end
    endtask

    // ========================================================================
    // Check helpers
    // ========================================================================
    task check_ct(input [63:0] got, input [63:0] exp, input integer block_num);
        begin
            if (got === exp) begin
                $display("  CT[%0d] PASS: %016h", block_num, got);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("  CT[%0d] FAIL: got %016h, exp %016h", block_num, got, exp);
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    task check_tag(input [127:0] got, input [127:0] exp);
        begin
            if (got === exp) begin
                $display("  Tag  PASS: %032h", got);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("  Tag  FAIL: got %032h", got);
                $display("             exp %032h", exp);
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    // ========================================================================
    // Main Test
    // ========================================================================
    reg [63:0]  got_ct;
    reg [127:0] got_tag;

    initial begin
        $dumpfile("tb_merged.fst");
        $dumpvars(0, tb_merged);
        pass_cnt = 0;
        fail_cnt = 0;

        // ==================================================================
        // TV0: K=0, N=0, PT=0 (1 block)
        // ==================================================================
        tv_num = 0;
        $display("\n=== TV0: K=0, N=0, PT=0 (1 block) ===");
        reset_dut;
        load_key(128'h0);
        load_nonce(128'h0);
        pulse_start;

        // Wait for init perm to complete
        wait(!busy || dut.fsm_state == 3'd3);

        send_pt_block(64'h0, 1);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'hb8dff46b0db421f8, 0);
        read_tag(got_tag);
        check_tag(got_tag, 128'heaf0f7b7a32b807e91ee437183d14b71);

        // ==================================================================
        // TV2: Counting K/N (1 block)
        // ==================================================================
        tv_num = 2;
        $display("\n=== TV2: Counting K/N (1 block) ===");
        reset_dut;
        load_key(128'h000102030405060708090A0B0C0D0E0F);
        load_nonce(128'h00112233445566778899AABBCCDDEEFF);
        pulse_start;
        wait(!busy || dut.fsm_state == 3'd3);

        send_pt_block(64'h0011223344556677, 1);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'h1b0276e833b5bdc3, 0);
        read_tag(got_tag);
        check_tag(got_tag, 128'h7964b9cac01116190a4ad52d9023ed19);

        // ==================================================================
        // TV1: 2-block
        // ==================================================================
        tv_num = 1;
        $display("\n=== TV1: 2-block (K=01, N=02) ===");
        reset_dut;
        load_key(128'h01010101010101010101010101010101);
        load_nonce(128'h02020202020202020202020202020202);
        pulse_start;
        wait(!busy || dut.fsm_state == 3'd3);

        send_pt_block(64'hAAAAAAAAAAAAAAAA, 0);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'h32f5bb4d8a0a8b3f, 0);

        send_pt_block(64'hBBBBBBBBBBBBBBBB, 1);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'h119efc192586e30b, 1);

        read_tag(got_tag);
        check_tag(got_tag, 128'h0a06465ef67f0a4e184ca4d2ad45ddc5);

        // ==================================================================
        // TV3: 3-block
        // ==================================================================
        tv_num = 3;
        $display("\n=== TV3: 3-block (DEADBEEF key) ===");
        reset_dut;
        load_key(128'hDEADBEEFCAFEBABE0123456789ABCDEF);
        load_nonce(128'hFEDCBA9876543210ABCDEF0123456789);
        pulse_start;
        wait(!busy || dut.fsm_state == 3'd3);

        send_pt_block(64'h1111111111111111, 0);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'hcd1298c8d3539131, 0);

        send_pt_block(64'h2222222222222222, 0);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'h066cb97f9aa1f83c, 1);

        send_pt_block(64'h3333333333333333, 1);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'h5c19466794f98ec0, 2);

        read_tag(got_tag);
        check_tag(got_tag, 128'hb1f686e6a8cf9666cfbf8263ecb557fb);

        // ==================================================================
        // TV4: All FF (1 block)
        // ==================================================================
        tv_num = 4;
        $display("\n=== TV4: All-FF (1 block) ===");
        reset_dut;
        load_key(128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
        load_nonce(128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
        pulse_start;
        wait(!busy || dut.fsm_state == 3'd3);

        send_pt_block(64'hFFFFFFFFFFFFFFFF, 1);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'h5d894a4662a04f6c, 0);
        read_tag(got_tag);
        check_tag(got_tag, 128'h56cc95b482488d079114377726d513a4);

        // ==================================================================
        // TV5: Back-to-back (reuse without reset)
        // Encrypt TV0 then TV2 without reset between them
        // ==================================================================
        tv_num = 5;
        $display("\n=== TV5: Back-to-back (TV0 then TV2, no reset) ===");
        reset_dut;

        // First: TV0
        load_key(128'h0);
        load_nonce(128'h0);
        pulse_start;
        wait(!busy || dut.fsm_state == 3'd3);
        send_pt_block(64'h0, 1);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'hb8dff46b0db421f8, 0);
        read_tag(got_tag);
        check_tag(got_tag, 128'heaf0f7b7a32b807e91ee437183d14b71);

        // Wait for idle
        wait(!busy);
        @(posedge clk); @(posedge clk);

        // Second: TV2 (no reset!)
        load_key(128'h000102030405060708090A0B0C0D0E0F);
        load_nonce(128'h00112233445566778899AABBCCDDEEFF);
        pulse_start;
        wait(!busy || dut.fsm_state == 3'd3);
        send_pt_block(64'h0011223344556677, 1);
        read_8_bytes(got_ct);
        check_ct(got_ct, 64'h1b0276e833b5bdc3, 0);
        read_tag(got_tag);
        check_tag(got_tag, 128'h7964b9cac01116190a4ad52d9023ed19);

        // ==================================================================
        // Summary
        // ==================================================================
        $display("\n========================================");
        $display("  RESULTS: %0d PASS, %0d FAIL", pass_cnt, fail_cnt);
        $display("========================================");
        if (fail_cnt > 0) $display("*** SOME TESTS FAILED ***");
        else $display("*** ALL TESTS PASSED ***");
        $finish;
    end

    // Timeout watchdog
    initial begin
        #5000000;
        $display("TIMEOUT!");
        $finish;
    end

endmodule
