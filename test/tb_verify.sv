// Comprehensive Ascon-128 AEAD testbench with byte-by-byte reference comparison
// 5 test vectors: zeros, ones/2-block, counting, 3-block, all-FF
`timescale 1ns/1ps

module tb_verify;

    reg         clk, rst_n, ena;
    reg  [7:0]  ui_in, uio_in;
    wire [7:0]  uo_out, uio_out, uio_oe;

    tt_um_snn_ascon dut (
        .ui_in(ui_in), .uo_out(uo_out),
        .uio_in(uio_in), .uio_out(uio_out), .uio_oe(uio_oe),
        .ena(ena), .clk(clk), .rst_n(rst_n)
    );

    initial clk = 0;
    always #10 clk = ~clk;

    // Optional: uncomment to trace AEAD handshakes
    // always @(posedge clk) begin
    //     if (dut.u_ascon.s_axis_tvalid && dut.u_ascon.s_axis_tready)
    //         $display("  [AEAD-HANDSHAKE] tdata=%016h tlast=%b",
    //                  dut.u_ascon.s_axis_tdata, dut.u_ascon.s_axis_tlast);
    // end

    wire busy         = uio_out[0];
    wire output_valid = uio_out[1];

    // Storage for test data
    reg [7:0] key_bytes   [0:15];
    reg [7:0] nonce_bytes [0:15];
    reg [7:0] pt_bytes    [0:23];  // max 3 blocks = 24 bytes
    reg [7:0] expected    [0:39];  // max 3*8 CT + 16 tag = 40 bytes
    reg [7:0] actual      [0:39];

    integer i, j, pass_cnt, fail_cnt, total_tests;
    integer num_pt_bytes, num_expected;
    integer out_idx;
    integer byte_errors;

    // ========================================================================
    // Helper Tasks
    // ========================================================================

    task reset_dut;
        begin
            rst_n = 0; ena = 1; ui_in = 0; uio_in = 0;
            repeat(10) @(posedge clk);
            rst_n = 1;
            repeat(5) @(posedge clk);
        end
    endtask

    task load_key;
        begin
            for (i = 0; i < 16; i = i + 1) begin
                ui_in = key_bytes[i];
                uio_in = 8'b01_0_0_0_000;
                @(posedge clk); #1;
            end
            uio_in = 0;
            @(posedge clk); #1;
        end
    endtask

    task load_nonce;
        begin
            for (i = 0; i < 16; i = i + 1) begin
                ui_in = nonce_bytes[i];
                uio_in = 8'b10_0_0_0_000;
                @(posedge clk); #1;
            end
            uio_in = 0;
            @(posedge clk); #1;
        end
    endtask

    task start_enc;
        begin
            uio_in = 8'b00_0_1_0_000;
            @(posedge clk); #1;
            uio_in = 0;
        end
    endtask

    task send_plaintext;
        integer bi, is_last_byte;
        begin
            for (bi = 0; bi < num_pt_bytes; bi = bi + 1) begin
                is_last_byte = (bi == num_pt_bytes - 1) ? 1 : 0;
                // Between blocks: deassert cmd and wait for wrapper handshake
                if (dut.ascon_data_valid) begin
                    uio_in = 0; // cmd=00 to prevent stale byte shifts
                    while (dut.ascon_data_valid) begin
                        @(posedge clk); #1;
                    end
                end
                ui_in = pt_bytes[bi];
                uio_in = {2'b11, is_last_byte ? 1'b1 : 1'b0, 5'b00000};
                @(posedge clk); #1;
            end
            uio_in = 0;
        end
    endtask

    task collect_all_output;
        integer wait_cnt;
        begin
            out_idx = 0;
            wait_cnt = 0;
            repeat(4000) begin
                @(posedge clk); #1;
                if (output_valid && out_idx < 40) begin
                    actual[out_idx] = uo_out;
                    out_idx = out_idx + 1;
                    wait_cnt = 0;
                    // Pulse read_ack
                    uio_in = 8'b00_0_0_0_100;
                    @(posedge clk); #1;
                    uio_in = 0;
                end else begin
                    wait_cnt = wait_cnt + 1;
                end
                // Early exit if we got all expected bytes and not busy
                if (out_idx >= num_expected && !busy) begin
                    repeat(5) @(posedge clk);
                    disable collect_all_output;
                end
                // Timeout: if no output for 500 cycles, something is stuck
                if (wait_cnt > 500 && out_idx > 0 && out_idx < num_expected) begin
                    $display("  DEBUG: stuck after %0d bytes, busy=%b tag_phase=%b out_valid=%b tag_pending=%b tag_valid=%b",
                             out_idx, busy, dut.tag_phase, dut.out_valid, dut.tag_pending, dut.u_ascon.tag_valid);
                    $display("  DEBUG: fsm=%0d m_tvalid=%b out_byte_cnt=%0d tag_byte_cnt=%0d",
                             dut.u_ascon.fsm_state, dut.u_ascon.m_axis_tvalid, dut.out_byte_cnt, dut.tag_byte_cnt);
                    disable collect_all_output;
                end
            end
        end
    endtask

    task compare_output;
        begin
            byte_errors = 0;
            if (out_idx != num_expected) begin
                $display("  BYTE COUNT MISMATCH: got %0d, expected %0d", out_idx, num_expected);
                byte_errors = byte_errors + 1;
            end
            for (j = 0; j < num_expected && j < out_idx; j = j + 1) begin
                if (actual[j] !== expected[j]) begin
                    if (byte_errors < 5) // limit error spam
                        $display("  MISMATCH at byte[%0d]: got %02h, expected %02h", j, actual[j], expected[j]);
                    byte_errors = byte_errors + 1;
                end
            end
            if (byte_errors == 0 && out_idx == num_expected) begin
                $display("  PASS: all %0d bytes match reference", num_expected);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("  FAIL: %0d errors", byte_errors);
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    task print_output;
        integer ct_bytes_n;
        begin
            ct_bytes_n = num_expected - 16;
            $write("  CT:  ");
            for (j = 0; j < ct_bytes_n && j < out_idx; j = j + 1)
                $write("%02h ", actual[j]);
            $display("");
            $write("  Tag: ");
            for (j = ct_bytes_n; j < num_expected && j < out_idx; j = j + 1)
                $write("%02h ", actual[j]);
            $display("");
        end
    endtask

    // ========================================================================
    // Set key/nonce from 128-bit values
    // ========================================================================
    task set_key_128(input [127:0] k);
        begin
            for (i = 0; i < 16; i = i + 1)
                key_bytes[i] = k[8*(15-i) +: 8];
        end
    endtask

    task set_nonce_128(input [127:0] n);
        begin
            for (i = 0; i < 16; i = i + 1)
                nonce_bytes[i] = n[8*(15-i) +: 8];
        end
    endtask

    task set_pt_block(input integer block_idx, input [63:0] data);
        begin
            for (i = 0; i < 8; i = i + 1)
                pt_bytes[block_idx*8 + i] = data[8*(7-i) +: 8];
        end
    endtask

    task set_expected_bytes(input integer idx, input [7:0] b);
        begin
            expected[idx] = b;
        end
    endtask

    // ========================================================================
    // Run one test vector
    // ========================================================================
    task run_test(input [255:0] test_name);
        begin
            $display("\n=== %0s ===", test_name);
            reset_dut;
            load_key;
            load_nonce;
            start_enc;
            repeat(30) @(posedge clk); #1; // wait for init perm (24 cycles for 2-phase)
            send_plaintext;
            collect_all_output;
            print_output;
            compare_output;
        end
    endtask

    // ========================================================================
    // Main Test
    // ========================================================================
    initial begin
        $dumpfile("tb_verify.fst");
        $dumpvars(0, tb_verify);

        pass_cnt = 0;
        fail_cnt = 0;
        total_tests = 0;

        // ==================================================================
        // TV0: All zeros (1 block)
        // ==================================================================
        set_key_128(128'h00000000000000000000000000000000);
        set_nonce_128(128'h00000000000000000000000000000000);
        set_pt_block(0, 64'h0000000000000000);
        num_pt_bytes = 8;
        num_expected = 24;
        // Expected: b8 df f4 6b 0d b4 21 f8 ea f0 f7 b7 a3 2b 80 7e 91 ee 43 71 83 d1 4b 71
        expected[ 0]=8'hb8; expected[ 1]=8'hdf; expected[ 2]=8'hf4; expected[ 3]=8'h6b;
        expected[ 4]=8'h0d; expected[ 5]=8'hb4; expected[ 6]=8'h21; expected[ 7]=8'hf8;
        expected[ 8]=8'hea; expected[ 9]=8'hf0; expected[10]=8'hf7; expected[11]=8'hb7;
        expected[12]=8'ha3; expected[13]=8'h2b; expected[14]=8'h80; expected[15]=8'h7e;
        expected[16]=8'h91; expected[17]=8'hee; expected[18]=8'h43; expected[19]=8'h71;
        expected[20]=8'h83; expected[21]=8'hd1; expected[22]=8'h4b; expected[23]=8'h71;
        total_tests = total_tests + 1;
        run_test("TV0: K=0, N=0, PT=0 (1 block)");

        // ==================================================================
        // TV1: 2-block
        // ==================================================================
        set_key_128(128'h01010101010101010101010101010101);
        set_nonce_128(128'h02020202020202020202020202020202);
        set_pt_block(0, 64'hAAAAAAAAAAAAAAAA);
        set_pt_block(1, 64'hBBBBBBBBBBBBBBBB);
        num_pt_bytes = 16;
        num_expected = 32;
        // Expected: 32 f5 bb 4d 8a 0a 8b 3f 11 9e fc 19 25 86 e3 0b 0a 06 46 5e f6 7f 0a 4e 18 4c a4 d2 ad 45 dd c5
        expected[ 0]=8'h32; expected[ 1]=8'hf5; expected[ 2]=8'hbb; expected[ 3]=8'h4d;
        expected[ 4]=8'h8a; expected[ 5]=8'h0a; expected[ 6]=8'h8b; expected[ 7]=8'h3f;
        expected[ 8]=8'h11; expected[ 9]=8'h9e; expected[10]=8'hfc; expected[11]=8'h19;
        expected[12]=8'h25; expected[13]=8'h86; expected[14]=8'he3; expected[15]=8'h0b;
        expected[16]=8'h0a; expected[17]=8'h06; expected[18]=8'h46; expected[19]=8'h5e;
        expected[20]=8'hf6; expected[21]=8'h7f; expected[22]=8'h0a; expected[23]=8'h4e;
        expected[24]=8'h18; expected[25]=8'h4c; expected[26]=8'ha4; expected[27]=8'hd2;
        expected[28]=8'had; expected[29]=8'h45; expected[30]=8'hdd; expected[31]=8'hc5;
        total_tests = total_tests + 1;
        run_test("TV1: 2-block (K=01, N=02)");

        // ==================================================================
        // TV2: Counting key/nonce
        // ==================================================================
        set_key_128(128'h000102030405060708090A0B0C0D0E0F);
        set_nonce_128(128'h00112233445566778899AABBCCDDEEFF);
        set_pt_block(0, 64'h0011223344556677);
        num_pt_bytes = 8;
        num_expected = 24;
        // Expected: 1b 02 76 e8 33 b5 bd c3 79 64 b9 ca c0 11 16 19 0a 4a d5 2d 90 23 ed 19
        expected[ 0]=8'h1b; expected[ 1]=8'h02; expected[ 2]=8'h76; expected[ 3]=8'he8;
        expected[ 4]=8'h33; expected[ 5]=8'hb5; expected[ 6]=8'hbd; expected[ 7]=8'hc3;
        expected[ 8]=8'h79; expected[ 9]=8'h64; expected[10]=8'hb9; expected[11]=8'hca;
        expected[12]=8'hc0; expected[13]=8'h11; expected[14]=8'h16; expected[15]=8'h19;
        expected[16]=8'h0a; expected[17]=8'h4a; expected[18]=8'hd5; expected[19]=8'h2d;
        expected[20]=8'h90; expected[21]=8'h23; expected[22]=8'hed; expected[23]=8'h19;
        total_tests = total_tests + 1;
        run_test("TV2: Counting K/N (1 block)");

        // ==================================================================
        // TV3: 3-block
        // ==================================================================
        set_key_128(128'hDEADBEEFCAFEBABE0123456789ABCDEF);
        set_nonce_128(128'hFEDCBA9876543210ABCDEF0123456789);
        set_pt_block(0, 64'h1111111111111111);
        set_pt_block(1, 64'h2222222222222222);
        set_pt_block(2, 64'h3333333333333333);
        num_pt_bytes = 24;
        num_expected = 40;
        // Expected: cd 12 98 c8 d3 53 91 31 06 6c b9 7f 9a a1 f8 3c 5c 19 46 67 94 f9 8e c0 b1 f6 86 e6 a8 cf 96 66 cf bf 82 63 ec b5 57 fb
        expected[ 0]=8'hcd; expected[ 1]=8'h12; expected[ 2]=8'h98; expected[ 3]=8'hc8;
        expected[ 4]=8'hd3; expected[ 5]=8'h53; expected[ 6]=8'h91; expected[ 7]=8'h31;
        expected[ 8]=8'h06; expected[ 9]=8'h6c; expected[10]=8'hb9; expected[11]=8'h7f;
        expected[12]=8'h9a; expected[13]=8'ha1; expected[14]=8'hf8; expected[15]=8'h3c;
        expected[16]=8'h5c; expected[17]=8'h19; expected[18]=8'h46; expected[19]=8'h67;
        expected[20]=8'h94; expected[21]=8'hf9; expected[22]=8'h8e; expected[23]=8'hc0;
        expected[24]=8'hb1; expected[25]=8'hf6; expected[26]=8'h86; expected[27]=8'he6;
        expected[28]=8'ha8; expected[29]=8'hcf; expected[30]=8'h96; expected[31]=8'h66;
        expected[32]=8'hcf; expected[33]=8'hbf; expected[34]=8'h82; expected[35]=8'h63;
        expected[36]=8'hec; expected[37]=8'hb5; expected[38]=8'h57; expected[39]=8'hfb;
        total_tests = total_tests + 1;
        run_test("TV3: 3-block (DEADBEEF key)");

        // ==================================================================
        // TV4: All FF
        // ==================================================================
        set_key_128(128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
        set_nonce_128(128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
        set_pt_block(0, 64'hFFFFFFFFFFFFFFFF);
        num_pt_bytes = 8;
        num_expected = 24;
        // Expected: 5d 89 4a 46 62 a0 4f 6c 56 cc 95 b4 82 48 8d 07 91 14 37 77 26 d5 13 a4
        expected[ 0]=8'h5d; expected[ 1]=8'h89; expected[ 2]=8'h4a; expected[ 3]=8'h46;
        expected[ 4]=8'h62; expected[ 5]=8'ha0; expected[ 6]=8'h4f; expected[ 7]=8'h6c;
        expected[ 8]=8'h56; expected[ 9]=8'hcc; expected[10]=8'h95; expected[11]=8'hb4;
        expected[12]=8'h82; expected[13]=8'h48; expected[14]=8'h8d; expected[15]=8'h07;
        expected[16]=8'h91; expected[17]=8'h14; expected[18]=8'h37; expected[19]=8'h77;
        expected[20]=8'h26; expected[21]=8'hd5; expected[22]=8'h13; expected[23]=8'ha4;
        total_tests = total_tests + 1;
        run_test("TV4: All-FF K/N/PT (1 block)");

        // ==================================================================
        // TV5: Back-to-back — run TV0 again without full reset to test re-use
        // ==================================================================
        $display("\n=== TV5: Back-to-back (TV0 re-run, no reset) ===");
        // Don't reset, just re-load and re-run
        set_key_128(128'h00000000000000000000000000000000);
        set_nonce_128(128'h00000000000000000000000000000000);
        set_pt_block(0, 64'h0000000000000000);
        num_pt_bytes = 8;
        num_expected = 24;
        expected[ 0]=8'hb8; expected[ 1]=8'hdf; expected[ 2]=8'hf4; expected[ 3]=8'h6b;
        expected[ 4]=8'h0d; expected[ 5]=8'hb4; expected[ 6]=8'h21; expected[ 7]=8'hf8;
        expected[ 8]=8'hea; expected[ 9]=8'hf0; expected[10]=8'hf7; expected[11]=8'hb7;
        expected[12]=8'ha3; expected[13]=8'h2b; expected[14]=8'h80; expected[15]=8'h7e;
        expected[16]=8'h91; expected[17]=8'hee; expected[18]=8'h43; expected[19]=8'h71;
        expected[20]=8'h83; expected[21]=8'hd1; expected[22]=8'h4b; expected[23]=8'h71;
        total_tests = total_tests + 1;
        // Wait for previous to fully complete
        repeat(20) @(posedge clk); #1;
        load_key;
        load_nonce;
        start_enc;
        repeat(30) @(posedge clk); #1;
        send_plaintext;
        collect_all_output;
        print_output;
        compare_output;

        // ==================================================================
        // Summary
        // ==================================================================
        $display("\n========================================");
        $display("  RESULTS: %0d/%0d PASS", pass_cnt, total_tests);
        $display("========================================\n");

        if (fail_cnt > 0)
            $display("*** %0d TESTS FAILED ***", fail_cnt);
        else
            $display("*** ALL %0d TESTS PASSED ***", total_tests);

        $finish;
    end

endmodule
