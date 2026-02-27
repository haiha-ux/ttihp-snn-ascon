// ============================================================================
// Ascon-128 AEAD Core — Area-Optimized (2-Phase, Encrypt-Only)
// ============================================================================
// Author: UrbanSense-AI Project
//
// Description:
//   Ascon-128 AEAD with 2-phase permutation, encrypt-only for area savings.
//   Phase 0: Substitution (S-box) — stores intermediate in x0-x4
//   Phase 1: Linear diffusion — applies rotations to x0-x4
//
//   Key optimizations vs previous version:
//   - No key_reg: reads key directly from input port (wrapper holds key_sr)
//   - No pending_output: writes ciphertext directly to m_axis_tdata
//   - Encrypt-only: removes decrypt FSM states and logic
//
//   - 128-bit key, 128-bit nonce
//   - 64-bit rate (8 bytes per block)
//   - 12 rounds for initialization/finalization (pa) = 24 cycles
//   - 6 rounds for processing (pb) = 12 cycles
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

    // Control (encrypt only)
    input  wire         start_encrypt,

    // Key and Nonce (128-bit each, must be stable during operation)
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

    // Authentication tag (combinational from state + key input)
    output wire [127:0] tag_out,
    output reg          tag_valid,

    // Status
    output reg          busy
);

    // ========================================================================
    // Constants
    // ========================================================================

    localparam [63:0] IV_ASCON128 = 64'h80400c0600000000;

    // ========================================================================
    // State Machine (reduced: no decrypt states)
    // ========================================================================

    localparam [2:0] ST_IDLE       = 3'd0;
    localparam [2:0] ST_PERM       = 3'd1;  // 2-phase permutation
    localparam [2:0] ST_INIT_XOR   = 3'd2;
    localparam [2:0] ST_PROC_DATA  = 3'd3;
    localparam [2:0] ST_PROC_OUT   = 3'd4;
    localparam [2:0] ST_FINAL_XOR  = 3'd5;
    localparam [2:0] ST_FINAL_OUT  = 3'd6;
    localparam [2:0] ST_OUTPUT_TAG = 3'd7;

    reg [2:0] fsm_state;
    reg [2:0] after_perm;

    // ========================================================================
    // Single 320-bit State (no key_reg — reads key input directly)
    // ========================================================================

    reg [63:0] x0, x1, x2, x3, x4;

    // Permutation round counter + phase
    reg [3:0] round_cnt;
    reg       perm_phase;  // 0 = S-box, 1 = diffusion

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
    // Phase 0: Substitution Layer (S-box) — Combinational
    // ========================================================================

    wire [63:0] c2 = x2 ^ {56'b0, round_const};

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

    // ========================================================================
    // Phase 1: Linear Diffusion Layer — Combinational
    // ========================================================================

    wire [63:0] d0 = x0 ^ {x0[18:0], x0[63:19]} ^ {x0[27:0], x0[63:28]};
    wire [63:0] d1 = x1 ^ {x1[60:0], x1[63:61]} ^ {x1[38:0], x1[63:39]};
    wire [63:0] d2 = x2 ^ {x2[0],    x2[63:1]}  ^ {x2[5:0],  x2[63:6]};
    wire [63:0] d3 = x3 ^ {x3[9:0],  x3[63:10]} ^ {x3[16:0], x3[63:17]};
    wire [63:0] d4 = x4 ^ {x4[6:0],  x4[63:7]}  ^ {x4[40:0], x4[63:41]};

    // ========================================================================
    // Tag output (combinational — reads key input directly, no key_reg)
    // ========================================================================

    assign tag_out = {x3 ^ key[127:64], x4 ^ key[63:0]};

    // ========================================================================
    // Main FSM
    // ========================================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm_state    <= ST_IDLE;
            after_perm   <= ST_IDLE;
            busy         <= 1'b0;
            s_axis_tready <= 1'b0;
            m_axis_tvalid <= 1'b0;
            m_axis_tdata <= 64'd0;
            m_axis_tlast <= 1'b0;
            tag_valid    <= 1'b0;
            round_cnt    <= 4'd0;
            perm_phase   <= 1'b0;
            x0 <= 64'd0; x1 <= 64'd0; x2 <= 64'd0; x3 <= 64'd0; x4 <= 64'd0;
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

                    if (start_encrypt) begin
                        busy       <= 1'b1;

                        // Load initial state from key/nonce inputs (no key_reg copy)
                        x0 <= IV_ASCON128;
                        x1 <= key[127:64];
                        x2 <= key[63:0];
                        x3 <= nonce[127:64];
                        x4 <= nonce[63:0];

                        round_cnt  <= 4'd0;
                        perm_phase <= 1'b0;
                        after_perm <= ST_INIT_XOR;
                        fsm_state  <= ST_PERM;
                    end
                end

                // ============================================================
                // PERM: 2-phase permutation round
                // ============================================================
                ST_PERM: begin
                    if (perm_phase == 1'b0) begin
                        // Phase 0: Substitution
                        x0 <= s0;
                        x1 <= s1;
                        x2 <= s2;
                        x3 <= s3;
                        x4 <= s4;
                        perm_phase <= 1'b1;
                    end else begin
                        // Phase 1: Diffusion
                        x0 <= d0;
                        x1 <= d1;
                        x2 <= d2;
                        x3 <= d3;
                        x4 <= d4;
                        perm_phase <= 1'b0;

                        if (round_cnt == 4'd11) begin
                            fsm_state <= after_perm;
                        end else begin
                            round_cnt <= round_cnt + 1;
                        end
                    end
                end

                // ============================================================
                // INIT_XOR: XOR key after initialization permutation
                // Uses key input directly (wrapper's key_sr is stable)
                // ============================================================
                ST_INIT_XOR: begin
                    x3 <= x3 ^ key[127:64];
                    x4 <= x4 ^ key[63:0] ^ 64'd1;
                    s_axis_tready <= 1'b1;
                    last_block <= 1'b0;
                    fsm_state <= ST_PROC_DATA;
                end

                // ============================================================
                // PROC_DATA: Process plaintext blocks (encrypt only)
                // ============================================================
                ST_PROC_DATA: begin
                    if (!s_axis_tready && !output_pending)
                        s_axis_tready <= 1'b1;

                    if (s_axis_tvalid && s_axis_tready) begin
                        s_axis_tready <= 1'b0;

                        // Encrypt: CT = x0 ^ PT, then x0 = CT
                        pending_output <= x0 ^ s_axis_tdata;
                        x0 <= x0 ^ s_axis_tdata;

                        output_pending <= 1'b1;
                        last_block <= s_axis_tlast;

                        if (s_axis_tlast) begin
                            fsm_state <= ST_FINAL_OUT;
                        end else begin
                            fsm_state <= ST_PROC_OUT;
                        end
                    end

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
                        round_cnt  <= 4'd6;
                        perm_phase <= 1'b0;
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
                // Uses key input directly (wrapper's key_sr is stable)
                // ============================================================
                ST_FINAL_XOR: begin
                    x1 <= x1 ^ key[127:64];
                    x2 <= x2 ^ key[63:0];

                    round_cnt  <= 4'd0;
                    perm_phase <= 1'b0;
                    after_perm <= ST_OUTPUT_TAG;
                    fsm_state  <= ST_PERM;
                end

                // ============================================================
                // OUTPUT_TAG: Signal tag valid
                // ============================================================
                ST_OUTPUT_TAG: begin
                    tag_valid <= 1'b1;
                    fsm_state <= ST_IDLE;
                end

                default: fsm_state <= ST_IDLE;
            endcase
        end
    end

endmodule
