// Direct AEAD testbench — bypass wrapper to isolate bugs (encrypt-only)
`timescale 1ns/1ps

module tb_aead_direct;

    reg         clk, rst_n;
    reg         start_encrypt;
    reg [127:0] key, nonce;
    reg         s_tvalid, s_tlast;
    reg  [63:0] s_tdata;
    wire        s_tready;
    wire        m_tvalid;
    reg         m_tready;
    wire [63:0] m_tdata;
    wire        m_tlast;
    wire [127:0] tag_out;
    wire        tag_valid;
    wire        busy;

    ascon_aead dut (
        .clk(clk), .rst_n(rst_n),
        .start_encrypt(start_encrypt),
        .key(key), .nonce(nonce),
        .s_axis_tvalid(s_tvalid), .s_axis_tready(s_tready),
        .s_axis_tdata(s_tdata), .s_axis_tlast(s_tlast),
        .m_axis_tvalid(m_tvalid), .m_axis_tready(m_tready),
        .m_axis_tdata(m_tdata), .m_axis_tlast(m_tlast),
        .tag_out(tag_out), .tag_valid(tag_valid),
        .busy(busy)
    );

    initial clk = 0;
    always #10 clk = ~clk;

    integer pass_cnt, fail_cnt;

    task reset;
        begin
            rst_n = 0; start_encrypt = 0;
            s_tvalid = 0; s_tlast = 0; s_tdata = 0; m_tready = 1;
            key = 0; nonce = 0;
            repeat(5) @(posedge clk);
            rst_n = 1;
            repeat(2) @(posedge clk);
        end
    endtask

    task encrypt_start;
        begin
            start_encrypt = 1;
            @(posedge clk);
            start_encrypt = 0;
        end
    endtask

    task send_block(input [63:0] data, input last);
        begin
            // Wait for ready
            while (!s_tready) @(posedge clk);
            s_tdata = data;
            s_tvalid = 1;
            s_tlast = last;
            @(posedge clk);
            s_tvalid = 0;
            s_tlast = 0;
        end
    endtask

    task wait_output(output [63:0] ct);
        begin
            while (!m_tvalid) @(posedge clk);
            ct = m_tdata;
            m_tready = 1;
            @(posedge clk);
        end
    endtask

    task wait_tag(output [127:0] t);
        begin
            while (!tag_valid) @(posedge clk);
            t = tag_out;
        end
    endtask

    reg [63:0]  got_ct;
    reg [127:0] got_tag;

    task check_ct(input [63:0] exp, input integer block_num);
        begin
            if (got_ct === exp) begin
                $display("  CT[%0d] PASS: %016h", block_num, got_ct);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("  CT[%0d] FAIL: got %016h, exp %016h", block_num, got_ct, exp);
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    task check_tag(input [127:0] exp);
        begin
            if (got_tag === exp) begin
                $display("  Tag  PASS: %032h", got_tag);
                pass_cnt = pass_cnt + 1;
            end else begin
                $display("  Tag  FAIL: got %032h", got_tag);
                $display("             exp %032h", exp);
                fail_cnt = fail_cnt + 1;
            end
        end
    endtask

    initial begin
        $dumpfile("tb_aead_direct.fst");
        $dumpvars(0, tb_aead_direct);
        pass_cnt = 0; fail_cnt = 0;

        // ==================================================================
        // TV0: K=0, N=0, PT=0 (1 block)
        // ==================================================================
        $display("\n=== TV0: K=0, N=0, PT=0 ===");
        reset;
        key = 128'h0;
        nonce = 128'h0;
        encrypt_start;
        send_block(64'h0, 1);
        wait_output(got_ct);
        check_ct(64'hb8dff46b0db421f8, 0);
        wait_tag(got_tag);
        check_tag(128'heaf0f7b7a32b807e91ee437183d14b71);

        // ==================================================================
        // TV2: Counting K/N (1 block)
        // ==================================================================
        $display("\n=== TV2: Counting K/N (1 block) ===");
        reset;
        key = 128'h000102030405060708090A0B0C0D0E0F;
        nonce = 128'h00112233445566778899AABBCCDDEEFF;
        encrypt_start;

        // Debug: print state after init
        repeat(50) @(posedge clk); // wait for init perm + INIT_XOR
        $display("  After init: x0=%016h x1=%016h x2=%016h x3=%016h x4=%016h",
                 dut.x0, dut.x1, dut.x2, dut.x3, dut.x4);
        $display("  s_tready=%b busy=%b fsm=%0d", s_tready, busy, dut.fsm_state);

        send_block(64'h0011223344556677, 1);
        wait_output(got_ct);
        check_ct(64'h1b0276e833b5bdc3, 0);
        wait_tag(got_tag);
        check_tag(128'h7964b9cac01116190a4ad52d9023ed19);

        // ==================================================================
        // TV1: 2-block
        // ==================================================================
        $display("\n=== TV1: 2-block (K=01, N=02) ===");
        reset;
        key = 128'h01010101010101010101010101010101;
        nonce = 128'h02020202020202020202020202020202;
        encrypt_start;

        send_block(64'hAAAAAAAAAAAAAAAA, 0); // block 0, not last
        wait_output(got_ct);
        check_ct(64'h32f5bb4d8a0a8b3f, 0);

        send_block(64'hBBBBBBBBBBBBBBBB, 1); // block 1, last
        wait_output(got_ct);
        check_ct(64'h119efc192586e30b, 1);

        wait_tag(got_tag);
        check_tag(128'h0a06465ef67f0a4e184ca4d2ad45ddc5);

        // ==================================================================
        // TV3: 3-block
        // ==================================================================
        $display("\n=== TV3: 3-block (DEADBEEF key) ===");
        reset;
        key = 128'hDEADBEEFCAFEBABE0123456789ABCDEF;
        nonce = 128'hFEDCBA9876543210ABCDEF0123456789;
        encrypt_start;

        send_block(64'h1111111111111111, 0);
        wait_output(got_ct);
        check_ct(64'hcd1298c8d3539131, 0);

        send_block(64'h2222222222222222, 0);
        wait_output(got_ct);
        check_ct(64'h066cb97f9aa1f83c, 1);

        send_block(64'h3333333333333333, 1);
        wait_output(got_ct);
        check_ct(64'h5c19466794f98ec0, 2);

        wait_tag(got_tag);
        check_tag(128'hb1f686e6a8cf9666cfbf8263ecb557fb);

        // ==================================================================
        // TV4: All FF
        // ==================================================================
        $display("\n=== TV4: All-FF ===");
        reset;
        key = 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        nonce = 128'hFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;
        encrypt_start;
        send_block(64'hFFFFFFFFFFFFFFFF, 1);
        wait_output(got_ct);
        check_ct(64'h5d894a4662a04f6c, 0);
        wait_tag(got_tag);
        check_tag(128'h56cc95b482488d079114377726d513a4);

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

    // Timeout
    initial begin
        #2000000;
        $display("TIMEOUT!");
        $finish;
    end

endmodule
