// Wrapper debug testbench — trace key/nonce loading for TV2
`timescale 1ns/1ps

module tb_wrapper_debug;

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

    wire busy = uio_out[0];
    wire output_valid = uio_out[1];

    integer i;
    reg [7:0] out_bytes [0:31];
    integer out_idx;

    initial begin
        $dumpfile("tb_wrapper_debug.fst");
        $dumpvars(0, tb_wrapper_debug);

        // Reset
        rst_n = 0; ena = 1; ui_in = 0; uio_in = 0;
        repeat(10) @(posedge clk);
        rst_n = 1;
        repeat(5) @(posedge clk);

        // ================================================================
        // TV2: K=000102030405060708090A0B0C0D0E0F
        //      N=00112233445566778899AABBCCDDEEFF
        //      PT=0011223344556677
        // ================================================================

        // Load key
        $display("Loading key: 000102030405060708090A0B0C0D0E0F");
        for (i = 0; i < 16; i = i + 1) begin
            ui_in = i[7:0]; // 0x00, 0x01, ..., 0x0F
            uio_in = 8'b01_0_0_0_000;
            @(posedge clk);
            #1; // past NBA
            $display("  byte[%0d]=0x%02h: key_sr=%032h byte_cnt=%0d", i, i[7:0], dut.key_sr, dut.byte_cnt);
        end
        uio_in = 0; @(posedge clk); #1;
        $display("  FINAL key_sr = %032h", dut.key_sr);

        // Load nonce
        $display("Loading nonce: 00112233445566778899AABBCCDDEEFF");
        for (i = 0; i < 16; i = i + 1) begin
            case (i)
                 0: ui_in = 8'h00;  1: ui_in = 8'h11;
                 2: ui_in = 8'h22;  3: ui_in = 8'h33;
                 4: ui_in = 8'h44;  5: ui_in = 8'h55;
                 6: ui_in = 8'h66;  7: ui_in = 8'h77;
                 8: ui_in = 8'h88;  9: ui_in = 8'h99;
                10: ui_in = 8'hAA; 11: ui_in = 8'hBB;
                12: ui_in = 8'hCC; 13: ui_in = 8'hDD;
                14: ui_in = 8'hEE; 15: ui_in = 8'hFF;
            endcase
            uio_in = 8'b10_0_0_0_000;
            @(posedge clk); #1;
            $display("  nonce[%0d]: nonce_sr=%032h", i, dut.nonce_sr);
        end
        uio_in = 0; @(posedge clk); #1;
        $display("  FINAL nonce_sr = %032h", dut.nonce_sr);

        // Start encrypt
        $display("Starting encryption");
        uio_in = 8'b00_0_1_0_000;
        @(posedge clk);
        uio_in = 0;

        // Wait for init (2-phase: 12 rounds * 2 = 24 cycles + INIT_XOR)
        repeat(30) @(posedge clk); #1;
        $display("  key  at AEAD: %032h", dut.key_sr);
        $display("  nonce at AEAD: %032h", dut.nonce_sr);
        $display("  AEAD key_reg: %032h", dut.u_ascon.key_reg);
        $display("  AEAD state: x0=%h x1=%h x2=%h x3=%h x4=%h",
                 dut.u_ascon.x0, dut.u_ascon.x1, dut.u_ascon.x2,
                 dut.u_ascon.x3, dut.u_ascon.x4);
        $display("  AEAD fsm=%0d tready=%b busy=%b",
                 dut.u_ascon.fsm_state, dut.u_ascon.s_axis_tready, dut.u_ascon.busy);

        // Send plaintext: 00 11 22 33 44 55 66 77
        $display("Sending plaintext: 0011223344556677");
        for (i = 0; i < 8; i = i + 1) begin
            case (i)
                0: ui_in = 8'h00; 1: ui_in = 8'h11;
                2: ui_in = 8'h22; 3: ui_in = 8'h33;
                4: ui_in = 8'h44; 5: ui_in = 8'h55;
                6: ui_in = 8'h66; 7: ui_in = 8'h77;
            endcase
            uio_in = (i == 7) ? 8'b11_1_0_0_000 : 8'b11_0_0_0_000;
            @(posedge clk); #1;
            $display("  PT[%0d]: data_sr=%016h byte_cnt=%0d valid=%b ready=%b x0=%016h fsm=%0d",
                     i, dut.data_sr, dut.byte_cnt, dut.ascon_data_valid,
                     dut.u_ascon.s_axis_tready, dut.u_ascon.x0, dut.u_ascon.fsm_state);
        end
        uio_in = 0;

        // Trace handshake + output capture for 20 cycles
        $display("--- Tracing AEAD handshake and output ---");
        for (i = 0; i < 20; i = i + 1) begin
            @(posedge clk); #1;
            $display("  cyc%0d: fsm=%0d valid=%b ready=%b out_valid=%b m_tvalid=%b m_tdata=%016h out_sr=%016h uo_out=%02h tag_phase=%b x0=%016h",
                     i, dut.u_ascon.fsm_state,
                     dut.ascon_data_valid, dut.u_ascon.s_axis_tready,
                     dut.out_valid, dut.u_ascon.m_axis_tvalid, dut.u_ascon.m_axis_tdata,
                     dut.out_sr, uo_out, dut.tag_phase);
        end

        // Collect output
        out_idx = 0;
        repeat(1000) begin
            @(posedge clk);
            if (output_valid && out_idx < 32) begin
                out_bytes[out_idx] = uo_out;
                $display("  READ[%0d]: %02h out_sr=%016h tag_sr=%032h tag_phase=%b",
                         out_idx, uo_out, dut.out_sr, dut.tag_sr, dut.tag_phase);
                out_idx = out_idx + 1;
                uio_in = 8'b00_0_0_0_100; // read_ack
                @(posedge clk);
                uio_in = 0;
            end
        end

        $display("Collected %0d bytes:", out_idx);
        $write("  CT:  ");
        for (i = 0; i < 8 && i < out_idx; i = i + 1) $write("%02h ", out_bytes[i]);
        $display("");
        $write("  Tag: ");
        for (i = 8; i < 24 && i < out_idx; i = i + 1) $write("%02h ", out_bytes[i]);
        $display("");

        // Expected: 1b 02 76 e8 33 b5 bd c3 79 64 b9 ca c0 11 16 19 0a 4a d5 2d 90 23 ed 19
        if (out_idx == 24 &&
            out_bytes[0] == 8'h1b && out_bytes[1] == 8'h02 &&
            out_bytes[2] == 8'h76 && out_bytes[3] == 8'he8)
            $display("PASS: TV2 matches reference");
        else
            $display("FAIL: TV2 mismatch");

        $finish;
    end

    initial begin #500000; $display("TIMEOUT"); $finish; end

endmodule
