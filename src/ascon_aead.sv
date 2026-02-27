// ============================================================================
// Ascon-128 AEAD Core
// ============================================================================
// Author: UrbanSense-AI Project
// Date: 2025-12-20
//
// Description:
//   Implements Ascon-128 Authenticated Encryption with Associated Data.
//   - 128-bit key, 128-bit nonce
//   - 64-bit rate (8 bytes per block)
//   - 12 rounds for initialization/finalization (pa)
//   - 6 rounds for processing (pb)
//
// Ascon-128 Parameters:
//   IV = 0x80400c0600000000
//   k = 128 bits, r = 64 bits, a = 12, b = 6
//
// Reference: https://ascon.iaik.tugraz.at/
// ============================================================================

`timescale 1ns/1ps

module ascon_aead (
    input  wire         clk,
    input  wire         rst_n,

    // Control
    input  wire         start_encrypt,
    input  wire         start_decrypt,

    // Key and Nonce (128-bit each)
    input  wire [127:0] key,
    input  wire [127:0] nonce,

    // Input data stream (AXI-Stream-like)
    input  wire         s_axis_tvalid,
    output reg          s_axis_tready,
    input  wire  [63:0] s_axis_tdata,
    input  wire         s_axis_tlast,

    // Output data stream (AXI-Stream-like)
    output reg          m_axis_tvalid,
    input  wire         m_axis_tready,
    output reg   [63:0] m_axis_tdata,
    output reg          m_axis_tlast,

    // Authentication tag
    output reg  [127:0] tag_out,
    output reg          tag_valid,

    // For decryption: expected tag input
    input  wire [127:0] tag_in,

    // Status
    output reg          busy,
    output reg          auth_fail
);

    // ========================================================================
    // Ascon-128 Constants
    // ========================================================================

    localparam [63:0] IV_ASCON128 = 64'h80400c0600000000;
    localparam [3:0] ROUNDS_A = 4'd12;  // pa rounds
    localparam [3:0] ROUNDS_B = 4'd6;   // pb rounds

    // ========================================================================
    // State Machine
    // ========================================================================

    localparam [3:0] ST_IDLE       = 4'd0;
    localparam [3:0] ST_INIT_LOAD  = 4'd1;
    localparam [3:0] ST_INIT_PERM  = 4'd2;
    localparam [3:0] ST_INIT_XOR   = 4'd3;
    localparam [3:0] ST_PROC_DATA  = 4'd4;
    localparam [3:0] ST_PROC_PERM  = 4'd5;
    localparam [3:0] ST_FINAL_XOR  = 4'd6;
    localparam [3:0] ST_FINAL_PERM = 4'd7;
    localparam [3:0] ST_OUTPUT_TAG = 4'd8;
    localparam [3:0] ST_VERIFY_TAG = 4'd9;

    reg [3:0] fsm_state;
    reg       is_encrypt;  // 1 for encrypt, 0 for decrypt

    // ========================================================================
    // Internal State (320 bits = 5 x 64-bit words)
    // ========================================================================

    reg [63:0] x0, x1, x2, x3, x4;

    // Saved key for finalization
    reg [127:0] key_reg;

    // Data processing
    reg        last_block;
    reg [63:0] pending_output;
    reg        output_pending;

    // ========================================================================
    // Permutation Interface
    // ========================================================================

    reg         perm_start;
    reg  [3:0]  perm_rounds;
    reg  [63:0] perm_in_0, perm_in_1, perm_in_2, perm_in_3, perm_in_4;
    wire [63:0] perm_out_0, perm_out_1, perm_out_2, perm_out_3, perm_out_4;
    wire        perm_done;
    wire        perm_busy;

    ascon_permutation u_perm (
        .clk(clk),
        .rst_n(rst_n),
        .start(perm_start),
        .num_rounds(perm_rounds),
        .state_in_0(perm_in_0),
        .state_in_1(perm_in_1),
        .state_in_2(perm_in_2),
        .state_in_3(perm_in_3),
        .state_in_4(perm_in_4),
        .state_out_0(perm_out_0),
        .state_out_1(perm_out_1),
        .state_out_2(perm_out_2),
        .state_out_3(perm_out_3),
        .state_out_4(perm_out_4),
        .done(perm_done),
        .busy(perm_busy)
    );

    // ========================================================================
    // Main FSM
    // ========================================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm_state <= ST_IDLE;
            is_encrypt <= 1'b1;
            busy <= 1'b0;
            s_axis_tready <= 1'b0;
            m_axis_tvalid <= 1'b0;
            m_axis_tdata <= 64'd0;
            m_axis_tlast <= 1'b0;
            tag_out <= 128'd0;
            tag_valid <= 1'b0;
            auth_fail <= 1'b0;
            perm_start <= 1'b0;
            perm_rounds <= 4'd12;
            perm_in_0 <= 64'd0;
            perm_in_1 <= 64'd0;
            perm_in_2 <= 64'd0;
            perm_in_3 <= 64'd0;
            perm_in_4 <= 64'd0;
            x0 <= 64'd0;
            x1 <= 64'd0;
            x2 <= 64'd0;
            x3 <= 64'd0;
            x4 <= 64'd0;
            key_reg <= 128'd0;
            last_block <= 1'b0;
            pending_output <= 64'd0;
            output_pending <= 1'b0;

        end else begin
            // Default: clear single-cycle signals
            perm_start <= 1'b0;
            tag_valid <= 1'b0;

            // Handle output handshake
            if (m_axis_tvalid && m_axis_tready) begin
                m_axis_tvalid <= 1'b0;
                m_axis_tlast <= 1'b0;
            end

            case (fsm_state)
                // ============================================================
                // IDLE: Wait for start command
                // ============================================================
                ST_IDLE: begin
                    busy <= 1'b0;
                    s_axis_tready <= 1'b0;

                    if (start_encrypt || start_decrypt) begin
                        is_encrypt <= start_encrypt;
                        key_reg <= key;
                        busy <= 1'b1;
                        auth_fail <= 1'b0;  // Only clear auth_fail when starting new operation
                        fsm_state <= ST_INIT_LOAD;
                    end
                end

                // ============================================================
                // INIT_LOAD: Load initial state IV || K || N
                // ============================================================
                ST_INIT_LOAD: begin
                    // Initial state: IV || K[127:64] || K[63:0] || N[127:64] || N[63:0]
                    x0 <= IV_ASCON128;
                    x1 <= key[127:64];
                    x2 <= key[63:0];
                    x3 <= nonce[127:64];
                    x4 <= nonce[63:0];

                    // Prepare permutation
                    perm_in_0 <= IV_ASCON128;
                    perm_in_1 <= key[127:64];
                    perm_in_2 <= key[63:0];
                    perm_in_3 <= nonce[127:64];
                    perm_in_4 <= nonce[63:0];
                    perm_rounds <= ROUNDS_A;
                    perm_start <= 1'b1;

                    fsm_state <= ST_INIT_PERM;
                end

                // ============================================================
                // INIT_PERM: Wait for initialization permutation
                // ============================================================
                ST_INIT_PERM: begin
                    if (perm_done) begin
                        // Store result
                        x0 <= perm_out_0;
                        x1 <= perm_out_1;
                        x2 <= perm_out_2;
                        x3 <= perm_out_3;
                        x4 <= perm_out_4;

                        fsm_state <= ST_INIT_XOR;
                    end
                end

                // ============================================================
                // INIT_XOR: XOR key at end of state after initialization
                // ============================================================
                ST_INIT_XOR: begin
                    // XOR K to x3, x4
                    x3 <= x3 ^ key_reg[127:64];
                    x4 <= x4 ^ key_reg[63:0];

                    // Ready to receive data
                    s_axis_tready <= 1'b1;
                    last_block <= 1'b0;
                    fsm_state <= ST_PROC_DATA;
                end

                // ============================================================
                // PROC_DATA: Process plaintext/ciphertext blocks
                // ============================================================
                ST_PROC_DATA: begin
                    if (s_axis_tvalid && s_axis_tready) begin
                        s_axis_tready <= 1'b0;

                        if (is_encrypt) begin
                            // Encryption: C = P XOR x0, then x0 = C
                            pending_output <= x0 ^ s_axis_tdata;
                            x0 <= x0 ^ s_axis_tdata;
                        end else begin
                            // Decryption: P = C XOR x0, then x0 = C
                            pending_output <= x0 ^ s_axis_tdata;
                            x0 <= s_axis_tdata;
                        end

                        output_pending <= 1'b1;
                        last_block <= s_axis_tlast;

                        if (s_axis_tlast) begin
                            // Last block - go to finalization
                            fsm_state <= ST_FINAL_XOR;
                        end else begin
                            // More blocks - run pb permutation
                            fsm_state <= ST_PROC_PERM;
                        end
                    end

                    // Output pending data when downstream ready
                    if (output_pending && (!m_axis_tvalid || m_axis_tready)) begin
                        m_axis_tdata <= pending_output;
                        m_axis_tvalid <= 1'b1;
                        m_axis_tlast <= last_block;
                        output_pending <= 1'b0;
                    end
                end

                // ============================================================
                // PROC_PERM: Run pb permutation between blocks
                // ============================================================
                ST_PROC_PERM: begin
                    // Output pending data if needed
                    if (output_pending && (!m_axis_tvalid || m_axis_tready)) begin
                        m_axis_tdata <= pending_output;
                        m_axis_tvalid <= 1'b1;
                        m_axis_tlast <= 1'b0;
                        output_pending <= 1'b0;
                    end

                    if (!perm_busy && !perm_start) begin
                        // Start permutation
                        perm_in_0 <= x0;
                        perm_in_1 <= x1;
                        perm_in_2 <= x2;
                        perm_in_3 <= x3;
                        perm_in_4 <= x4;
                        perm_rounds <= ROUNDS_B;
                        perm_start <= 1'b1;
                    end

                    if (perm_done) begin
                        x0 <= perm_out_0;
                        x1 <= perm_out_1;
                        x2 <= perm_out_2;
                        x3 <= perm_out_3;
                        x4 <= perm_out_4;

                        s_axis_tready <= 1'b1;
                        fsm_state <= ST_PROC_DATA;
                    end
                end

                // ============================================================
                // FINAL_XOR: Prepare for finalization
                // ============================================================
                ST_FINAL_XOR: begin
                    // Output pending data if needed
                    if (output_pending && (!m_axis_tvalid || m_axis_tready)) begin
                        m_axis_tdata <= pending_output;
                        m_axis_tvalid <= 1'b1;
                        m_axis_tlast <= 1'b1;
                        output_pending <= 1'b0;
                    end

                    // XOR key into x1, x2 (rate portion for finalization)
                    x1 <= x1 ^ key_reg[127:64];
                    x2 <= x2 ^ key_reg[63:0];

                    fsm_state <= ST_FINAL_PERM;
                end

                // ============================================================
                // FINAL_PERM: Run pa permutation for finalization
                // ============================================================
                ST_FINAL_PERM: begin
                    // Output pending data if still not sent
                    if (output_pending && (!m_axis_tvalid || m_axis_tready)) begin
                        m_axis_tdata <= pending_output;
                        m_axis_tvalid <= 1'b1;
                        m_axis_tlast <= 1'b1;
                        output_pending <= 1'b0;
                    end

                    if (!perm_busy && !perm_start) begin
                        perm_in_0 <= x0;
                        perm_in_1 <= x1;
                        perm_in_2 <= x2;
                        perm_in_3 <= x3;
                        perm_in_4 <= x4;
                        perm_rounds <= ROUNDS_A;
                        perm_start <= 1'b1;
                    end

                    if (perm_done) begin
                        x0 <= perm_out_0;
                        x1 <= perm_out_1;
                        x2 <= perm_out_2;
                        x3 <= perm_out_3;
                        x4 <= perm_out_4;

                        if (is_encrypt) begin
                            fsm_state <= ST_OUTPUT_TAG;
                        end else begin
                            fsm_state <= ST_VERIFY_TAG;
                        end
                    end
                end

                // ============================================================
                // OUTPUT_TAG: Extract and output authentication tag
                // ============================================================
                ST_OUTPUT_TAG: begin
                    // Tag = (x3 XOR K[127:64]) || (x4 XOR K[63:0])
                    tag_out[127:64] <= x3 ^ key_reg[127:64];
                    tag_out[63:0] <= x4 ^ key_reg[63:0];
                    tag_valid <= 1'b1;

                    fsm_state <= ST_IDLE;
                end

                // ============================================================
                // VERIFY_TAG: Verify tag for decryption
                // ============================================================
                ST_VERIFY_TAG: begin
                    // Compute expected tag
                    tag_out[127:64] <= x3 ^ key_reg[127:64];
                    tag_out[63:0] <= x4 ^ key_reg[63:0];

                    // Compare with provided tag
                    if (((x3 ^ key_reg[127:64]) == tag_in[127:64]) &&
                        ((x4 ^ key_reg[63:0]) == tag_in[63:0])) begin
                        auth_fail <= 1'b0;
                    end else begin
                        auth_fail <= 1'b1;
                    end

                    tag_valid <= 1'b1;
                    fsm_state <= ST_IDLE;
                end

                default: fsm_state <= ST_IDLE;
            endcase
        end
    end

endmodule
