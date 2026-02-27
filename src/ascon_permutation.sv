// ============================================================================
// Ascon Permutation Module
// ============================================================================
// Author: UrbanSense-AI Project
// Date: 2025-12-20
//
// Description:
//   Implements the Ascon permutation function used in Ascon-128 AEAD.
//   The permutation operates on a 320-bit state (5 x 64-bit words).
//
// Ascon Permutation Rounds:
//   1. Addition of round constant (pc)
//   2. Substitution layer (ps) - 5-bit S-box applied bitwise
//   3. Linear diffusion layer (pl) - rotations and XORs
//
// Reference: https://ascon.iaik.tugraz.at/
// ============================================================================

`timescale 1ns/1ps

module ascon_permutation (
    input  wire         clk,
    input  wire         rst_n,

    // Control
    input  wire         start,
    input  wire  [3:0]  num_rounds,

    // State input/output (320 bits = 5 x 64-bit words)
    input  wire  [63:0] state_in_0,
    input  wire  [63:0] state_in_1,
    input  wire  [63:0] state_in_2,
    input  wire  [63:0] state_in_3,
    input  wire  [63:0] state_in_4,

    output reg   [63:0] state_out_0,
    output reg   [63:0] state_out_1,
    output reg   [63:0] state_out_2,
    output reg   [63:0] state_out_3,
    output reg   [63:0] state_out_4,

    // Status
    output reg          done,
    output reg          busy
);

    // ========================================================================
    // Round Constants
    // ========================================================================

    function [7:0] get_round_constant;
        input [3:0] round;
        begin
            case (round)
                4'd0:  get_round_constant = 8'hf0;
                4'd1:  get_round_constant = 8'he1;
                4'd2:  get_round_constant = 8'hd2;
                4'd3:  get_round_constant = 8'hc3;
                4'd4:  get_round_constant = 8'hb4;
                4'd5:  get_round_constant = 8'ha5;
                4'd6:  get_round_constant = 8'h96;
                4'd7:  get_round_constant = 8'h87;
                4'd8:  get_round_constant = 8'h78;
                4'd9:  get_round_constant = 8'h69;
                4'd10: get_round_constant = 8'h5a;
                4'd11: get_round_constant = 8'h4b;
                default: get_round_constant = 8'hf0;
            endcase
        end
    endfunction

    // ========================================================================
    // State Machine
    // ========================================================================

    localparam [1:0] ST_IDLE  = 2'd0;
    localparam [1:0] ST_ROUND = 2'd1;
    localparam [1:0] ST_DONE  = 2'd2;

    reg [1:0]  fsm_state;
    reg [3:0]  round_cnt;

    // Internal state registers
    reg [63:0] x0, x1, x2, x3, x4;

    // Combinational: after adding round constant
    wire [63:0] c0, c1, c2, c3, c4;
    assign c0 = x0;
    assign c1 = x1;
    assign c2 = x2 ^ {56'b0, get_round_constant(round_cnt)};
    assign c3 = x3;
    assign c4 = x4;

    // ========================================================================
    // Substitution Layer (S-box applied to all 64 bit positions)
    // ========================================================================
    // The Ascon S-box operates on 5 bits (one from each word at the same position)
    // We compute it for all 64 positions in parallel using bitwise operations
    //
    // S-box definition:
    // x0 ^= x4; x4 ^= x3; x2 ^= x1;
    // (t0,t1,t2,t3,t4) = chi(~x0,~x1,~x2,~x3,~x4, x1,x2,x3,x4,x0)
    // x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
    // x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;

    wire [63:0] s0, s1, s2, s3, s4;

    // First layer of XORs
    wire [63:0] t0_pre, t1_pre, t2_pre, t3_pre, t4_pre;
    assign t0_pre = c0 ^ c4;
    assign t1_pre = c1;
    assign t2_pre = c2 ^ c1;
    assign t3_pre = c3;
    assign t4_pre = c4 ^ c3;

    // Chi-like layer: ti = xi ^ ((~x(i+1)) & x(i+2))
    wire [63:0] chi0, chi1, chi2, chi3, chi4;
    assign chi0 = t0_pre ^ ((~t1_pre) & t2_pre);
    assign chi1 = t1_pre ^ ((~t2_pre) & t3_pre);
    assign chi2 = t2_pre ^ ((~t3_pre) & t4_pre);
    assign chi3 = t3_pre ^ ((~t4_pre) & t0_pre);
    assign chi4 = t4_pre ^ ((~t0_pre) & t1_pre);

    // Second layer of XORs
    assign s1 = chi1 ^ chi0;
    assign s0 = chi0 ^ chi4;
    assign s3 = chi3 ^ chi2;
    assign s2 = ~chi2;
    assign s4 = chi4;

    // ========================================================================
    // Linear Diffusion Layer
    // ========================================================================

    wire [63:0] l0, l1, l2, l3, l4;

    // x0 = s0 ^ (s0 >>> 19) ^ (s0 >>> 28)
    assign l0 = s0 ^ {s0[18:0], s0[63:19]} ^ {s0[27:0], s0[63:28]};

    // x1 = s1 ^ (s1 >>> 61) ^ (s1 >>> 39)
    assign l1 = s1 ^ {s1[60:0], s1[63:61]} ^ {s1[38:0], s1[63:39]};

    // x2 = s2 ^ (s2 >>> 1) ^ (s2 >>> 6)
    assign l2 = s2 ^ {s2[0], s2[63:1]} ^ {s2[5:0], s2[63:6]};

    // x3 = s3 ^ (s3 >>> 10) ^ (s3 >>> 17)
    assign l3 = s3 ^ {s3[9:0], s3[63:10]} ^ {s3[16:0], s3[63:17]};

    // x4 = s4 ^ (s4 >>> 7) ^ (s4 >>> 41)
    assign l4 = s4 ^ {s4[6:0], s4[63:7]} ^ {s4[40:0], s4[63:41]};

    // ========================================================================
    // Main FSM
    // ========================================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm_state <= ST_IDLE;
            round_cnt <= 4'd0;
            done <= 1'b0;
            busy <= 1'b0;
            x0 <= 64'd0;
            x1 <= 64'd0;
            x2 <= 64'd0;
            x3 <= 64'd0;
            x4 <= 64'd0;
            state_out_0 <= 64'd0;
            state_out_1 <= 64'd0;
            state_out_2 <= 64'd0;
            state_out_3 <= 64'd0;
            state_out_4 <= 64'd0;

        end else begin
            case (fsm_state)
                ST_IDLE: begin
                    done <= 1'b0;

                    if (start) begin
                        // Load input state
                        x0 <= state_in_0;
                        x1 <= state_in_1;
                        x2 <= state_in_2;
                        x3 <= state_in_3;
                        x4 <= state_in_4;

                        // Calculate starting round
                        round_cnt <= 4'd12 - num_rounds;

                        fsm_state <= ST_ROUND;
                        busy <= 1'b1;
                    end
                end

                ST_ROUND: begin
                    // Apply one round of permutation
                    x0 <= l0;
                    x1 <= l1;
                    x2 <= l2;
                    x3 <= l3;
                    x4 <= l4;

                    // Check if done
                    if (round_cnt == 4'd11) begin
                        fsm_state <= ST_DONE;
                    end else begin
                        round_cnt <= round_cnt + 1;
                    end
                end

                ST_DONE: begin
                    // Output final state
                    state_out_0 <= x0;
                    state_out_1 <= x1;
                    state_out_2 <= x2;
                    state_out_3 <= x3;
                    state_out_4 <= x4;
                    done <= 1'b1;
                    busy <= 1'b0;
                    fsm_state <= ST_IDLE;
                end

                default: fsm_state <= ST_IDLE;
            endcase
        end
    end

endmodule
