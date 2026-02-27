// ============================================================================
// Ascon-128 AEAD Core — Area-Optimized (Inlined Permutation)
// ============================================================================
// Author: UrbanSense-AI Project
//
// Description:
//   Ascon-128 AEAD with permutation inlined to eliminate register duplication.
//   Saves ~1,088 FFs vs. separate permutation module.
//
//   - 128-bit key, 128-bit nonce
//   - 64-bit rate (8 bytes per block)
//   - 12 rounds for initialization/finalization (pa)
//   - 6 rounds for processing (pb)
//
// Ascon-128 Parameters:
//   IV = 0x80400c0600000000
//   k = 128, r = 64, a = 12, b = 6
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

    // Authentication tag (combinational from state)
    output wire [127:0] tag_out,
    output reg          tag_valid,

    // For decryption: expected tag input
    input  wire [127:0] tag_in,

    // Status
    output reg          busy,
    output reg          auth_fail
);

    // ========================================================================
    // Constants
    // ========================================================================

    localparam [63:0] IV_ASCON128 = 64'h80400c0600000000;

    // ========================================================================
    // State Machine
    // ========================================================================

    localparam [3:0] ST_IDLE       = 4'd0;
    localparam [3:0] ST_PERM       = 4'd1;  // Generic permutation (replaces 3 states)
    localparam [3:0] ST_INIT_XOR   = 4'd2;
    localparam [3:0] ST_PROC_DATA  = 4'd3;
    localparam [3:0] ST_PROC_OUT   = 4'd4;  // Output pending data before perm
    localparam [3:0] ST_FINAL_XOR  = 4'd5;
    localparam [3:0] ST_FINAL_OUT  = 4'd6;  // Output pending data before final perm
    localparam [3:0] ST_OUTPUT_TAG = 4'd7;
    localparam [3:0] ST_VERIFY_TAG = 4'd8;

    reg [3:0] fsm_state;
    reg [3:0] after_perm;   // Where to go after permutation completes
    reg       is_encrypt;

    // ========================================================================
    // Single 320-bit State (NO duplication!)
    // ========================================================================

    reg [63:0] x0, x1, x2, x3, x4;

    // Saved key for finalization
    reg [127:0] key_reg;

    // Permutation round counter
    reg [3:0] round_cnt;

    // Data processing
    reg        last_block;
    reg [63:0] pending_output;
    reg        output_pending;

    // ========================================================================
    // Round Constant
    // ========================================================================

    reg [7:0] round_const;
    always @(*) begin
        case (round_cnt)
            4'd0:  round_const = 8'hf0;
            4'd1:  round_const = 8'he1;
            4'd2:  round_const = 8'hd2;
            4'd3:  round_const = 8'hc3;
            4'd4:  round_const = 8'hb4;
            4'd5:  round_const = 8'ha5;
            4'd6:  round_const = 8'h96;
            4'd7:  round_const = 8'h87;
            4'd8:  round_const = 8'h78;
            4'd9:  round_const = 8'h69;
            4'd10: round_const = 8'h5a;
            4'd11: round_const = 8'h4b;
            default: round_const = 8'hf0;
        endcase
    end

    // ========================================================================
    // Inline Permutation Round (Combinational)
    // ========================================================================

    // Add round constant
    wire [63:0] c2 = x2 ^ {56'b0, round_const};

    // Substitution layer (S-box on all 64 bit positions)
    wire [63:0] t0_pre = x0 ^ x4;
    wire [63:0] t1_pre = x1;
    wire [63:0] t2_pre = c2 ^ x1;
    wire [63:0] t3_pre = x3;
    wire [63:0] t4_pre = x4 ^ x3;

    wire [63:0] chi0 = t0_pre ^ ((~t1_pre) & t2_pre);
    wire [63:0] chi1 = t1_pre ^ ((~t2_pre) & t3_pre);
    wire [63:0] chi2 = t2_pre ^ ((~t3_pre) & t4_pre);
    wire [63:0] chi3 = t3_pre ^ ((~t4_pre) & t0_pre);
    wire [63:0] chi4 = t4_pre ^ ((~t0_pre) & t1_pre);

    wire [63:0] s0 = chi0 ^ chi4;
    wire [63:0] s1 = chi1 ^ chi0;
    wire [63:0] s2 = ~chi2;
    wire [63:0] s3 = chi3 ^ chi2;
    wire [63:0] s4 = chi4;

    // Linear diffusion layer
    wire [63:0] round_out_0 = s0 ^ {s0[18:0], s0[63:19]} ^ {s0[27:0], s0[63:28]};
    wire [63:0] round_out_1 = s1 ^ {s1[60:0], s1[63:61]} ^ {s1[38:0], s1[63:39]};
    wire [63:0] round_out_2 = s2 ^ {s2[0],    s2[63:1]}  ^ {s2[5:0],  s2[63:6]};
    wire [63:0] round_out_3 = s3 ^ {s3[9:0],  s3[63:10]} ^ {s3[16:0], s3[63:17]};
    wire [63:0] round_out_4 = s4 ^ {s4[6:0],  s4[63:7]}  ^ {s4[40:0], s4[63:41]};

    // ========================================================================
    // Tag output (combinational — no register needed!)
    // ========================================================================

    assign tag_out = {x3 ^ key_reg[127:64], x4 ^ key_reg[63:0]};

    // ========================================================================
    // Main FSM
    // ========================================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm_state    <= ST_IDLE;
            after_perm   <= ST_IDLE;
            is_encrypt   <= 1'b1;
            busy         <= 1'b0;
            s_axis_tready <= 1'b0;
            m_axis_tvalid <= 1'b0;
            m_axis_tdata <= 64'd0;
            m_axis_tlast <= 1'b0;
            tag_valid    <= 1'b0;
            auth_fail    <= 1'b0;
            round_cnt    <= 4'd0;
            x0 <= 64'd0; x1 <= 64'd0; x2 <= 64'd0; x3 <= 64'd0; x4 <= 64'd0;
            key_reg      <= 128'd0;
            last_block   <= 1'b0;
            pending_output <= 64'd0;
            output_pending <= 1'b0;

        end else begin
            // Default: clear single-cycle signals
            tag_valid <= 1'b0;

            // Handle output handshake
            if (m_axis_tvalid && m_axis_tready) begin
                m_axis_tvalid <= 1'b0;
                m_axis_tlast  <= 1'b0;
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
                        key_reg    <= key;
                        busy       <= 1'b1;
                        auth_fail  <= 1'b0;

                        // Load initial state: IV || K || N
                        x0 <= IV_ASCON128;
                        x1 <= key[127:64];
                        x2 <= key[63:0];
                        x3 <= nonce[127:64];
                        x4 <= nonce[63:0];

                        // Start pa permutation (12 rounds, start from round 0)
                        round_cnt  <= 4'd0;
                        after_perm <= ST_INIT_XOR;
                        fsm_state  <= ST_PERM;
                    end
                end

                // ============================================================
                // PERM: Apply one permutation round per clock (generic)
                // ============================================================
                ST_PERM: begin
                    x0 <= round_out_0;
                    x1 <= round_out_1;
                    x2 <= round_out_2;
                    x3 <= round_out_3;
                    x4 <= round_out_4;

                    if (round_cnt == 4'd11) begin
                        fsm_state <= after_perm;
                    end else begin
                        round_cnt <= round_cnt + 1;
                    end
                end

                // ============================================================
                // INIT_XOR: XOR key after initialization permutation
                // ============================================================
                ST_INIT_XOR: begin
                    x3 <= x3 ^ key_reg[127:64];
                    // Domain separator: x4 ^= K1 ^ 1 (no AD)
                    x4 <= x4 ^ key_reg[63:0] ^ 64'd1;
                    s_axis_tready <= 1'b1;
                    last_block <= 1'b0;
                    fsm_state <= ST_PROC_DATA;
                end

                // ============================================================
                // PROC_DATA: Process plaintext/ciphertext blocks
                // ============================================================
                ST_PROC_DATA: begin
                    // Re-assert tready when entering from permutation
                    if (!s_axis_tready && !output_pending)
                        s_axis_tready <= 1'b1;

                    if (s_axis_tvalid && s_axis_tready) begin
                        s_axis_tready <= 1'b0;

                        if (is_encrypt) begin
                            pending_output <= x0 ^ s_axis_tdata;
                            x0 <= x0 ^ s_axis_tdata;
                        end else begin
                            pending_output <= x0 ^ s_axis_tdata;
                            x0 <= s_axis_tdata;
                        end

                        output_pending <= 1'b1;
                        last_block <= s_axis_tlast;

                        if (s_axis_tlast) begin
                            fsm_state <= ST_FINAL_OUT;
                        end else begin
                            fsm_state <= ST_PROC_OUT;
                        end
                    end

                    // Output pending data
                    if (output_pending && (!m_axis_tvalid || m_axis_tready)) begin
                        m_axis_tdata  <= pending_output;
                        m_axis_tvalid <= 1'b1;
                        m_axis_tlast  <= last_block;
                        output_pending <= 1'b0;
                    end
                end

                // ============================================================
                // PROC_OUT: Flush output then run pb permutation
                // ============================================================
                ST_PROC_OUT: begin
                    if (output_pending && (!m_axis_tvalid || m_axis_tready)) begin
                        m_axis_tdata  <= pending_output;
                        m_axis_tvalid <= 1'b1;
                        m_axis_tlast  <= 1'b0;
                        output_pending <= 1'b0;
                    end

                    if (!output_pending) begin
                        // Start pb permutation (6 rounds, start from round 6)
                        round_cnt  <= 4'd6;
                        after_perm <= ST_PROC_DATA;
                        fsm_state  <= ST_PERM;
                    end
                end

                // ============================================================
                // FINAL_OUT: Flush output then start finalization
                // ============================================================
                ST_FINAL_OUT: begin
                    if (output_pending && (!m_axis_tvalid || m_axis_tready)) begin
                        m_axis_tdata  <= pending_output;
                        m_axis_tvalid <= 1'b1;
                        m_axis_tlast  <= 1'b1;
                        output_pending <= 1'b0;
                    end

                    if (!output_pending) begin
                        fsm_state <= ST_FINAL_XOR;
                    end
                end

                // ============================================================
                // FINAL_XOR: XOR key then run pa permutation
                // ============================================================
                ST_FINAL_XOR: begin
                    x1 <= x1 ^ key_reg[127:64];
                    x2 <= x2 ^ key_reg[63:0];

                    // Start pa permutation (12 rounds)
                    round_cnt <= 4'd0;
                    after_perm <= is_encrypt ? ST_OUTPUT_TAG : ST_VERIFY_TAG;
                    fsm_state <= ST_PERM;
                end

                // ============================================================
                // OUTPUT_TAG: Signal tag valid (tag_out is combinational)
                // ============================================================
                ST_OUTPUT_TAG: begin
                    tag_valid <= 1'b1;
                    fsm_state <= ST_IDLE;
                end

                // ============================================================
                // VERIFY_TAG: Check tag for decryption
                // ============================================================
                ST_VERIFY_TAG: begin
                    if (tag_out == tag_in)
                        auth_fail <= 1'b0;
                    else
                        auth_fail <= 1'b1;

                    tag_valid <= 1'b1;
                    fsm_state <= ST_IDLE;
                end

                default: fsm_state <= ST_IDLE;
            endcase
        end
    end

endmodule
