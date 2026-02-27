// ============================================================================
// TinyTapeout Ascon-128 AEAD — Merged Ultra-Compact (2x2 Target)
// ============================================================================
// Target: TinyTapeout IHP 26a (IHP SG13G2 130nm), 2x2 tiles
// Author: UrbanSense-AI Project
//
// Description:
//   Ascon-128 authenticated encryption, fully merged (no submodules).
//   All register sharing optimizations for minimal area:
//   - No nonce_sr: nonce loaded directly into x3/x4
//   - No separate data_sr/out_sr/pending_output: single io_sr
//   - No key_reg in AEAD: reads key_sr directly
//   - Encrypt-only (no decrypt)
//   - 2-phase permutation (S-box + diffusion split)
//   - Sequential protocol: MCU reads CT before sending next PT block
//
//   Register budget: ~537 FFs (vs ~860 in previous design)
//
// Pin Mapping:
//   ui_in[7:0]   = Data input (8 bits at a time)
//   uo_out[7:0]  = Data output (ciphertext or tag bytes)
//   uio[7:6]     = CMD: 00=idle, 01=load_key, 10=load_nonce, 11=send_data
//   uio[5]       = DATA_LAST: marks last data block (sampled on 8th byte)
//   uio[4]       = START: pulse to begin encryption
//   uio[2]       = READ_ACK: pulse to advance to next output byte
//   uio[1]       = OUTPUT_VALID (output): byte ready to read
//   uio[0]       = BUSY (output): encryption in progress
//
// Sequential Protocol:
//   1. Load key:   16 bytes with cmd=01, MSB first
//   2. Load nonce: 16 bytes with cmd=10, MSB first (→ x3, x4 directly)
//   3. Pulse start (uio[4]=1)
//   4. For each 8-byte block:
//      a. Send 8 PT bytes with cmd=11. Set data_last=1 on final block.
//      b. Wait for output_valid. Read 8 CT bytes with read_ack.
//   5. Read 16 tag bytes (8 tag_hi + 8 tag_lo) with read_ack.
//   NOTE: Must reload nonce before each encryption (x3/x4 are modified).
// ============================================================================

`default_nettype none
`timescale 1ns/1ps

module tt_um_snn_ascon (
    input  wire [7:0] ui_in,    // Dedicated inputs
    output wire [7:0] uo_out,   // Dedicated outputs
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path
    input  wire       ena,      // always 1 when powered
    input  wire       clk,
    input  wire       rst_n
);

    // ========================================================================
    // Pin Decode
    // ========================================================================
    wire [1:0] cmd         = uio_in[7:6];
    wire       data_last   = uio_in[5];
    wire       start_pulse = uio_in[4];
    wire       read_ack    = uio_in[2];

    // [1:0] = output (output_valid, busy), [7:2] = input
    assign uio_oe = 8'b0000_0011;

    // ========================================================================
    // Constants
    // ========================================================================
    localparam [63:0] IV_ASCON128 = 64'h80400c0600000000;

    // ========================================================================
    // FSM States (3-bit, 8 states)
    // ========================================================================
    localparam [2:0] ST_IDLE      = 3'd0;  // Accept key/nonce, wait for start
    localparam [2:0] ST_PERM      = 3'd1;  // 2-phase permutation
    localparam [2:0] ST_INIT_XOR  = 3'd2;  // Post-init key XOR + domain sep
    localparam [2:0] ST_WAIT_DATA = 3'd3;  // Accept PT bytes from MCU
    localparam [2:0] ST_ENCRYPT   = 3'd4;  // XOR: CT=x0^PT, output CT
    localparam [2:0] ST_WAIT_READ = 3'd5;  // Wait for MCU to read all CT bytes
    localparam [2:0] ST_TAG_HI    = 3'd6;  // Output tag[127:64]
    localparam [2:0] ST_TAG_LO    = 3'd7;  // Output tag[63:0]

    // ========================================================================
    // Registers (~537 FFs total)
    // ========================================================================
    reg [2:0]   fsm_state;              // 3  — current state
    reg [2:0]   after_perm;             // 3  — return state after perm
    reg [63:0]  x0, x1, x2, x3, x4;    // 320 — Ascon state
    reg [127:0] key_sr;                 // 128 — key shift register
    reg [63:0]  io_sr;                  // 64  — shared I/O shift register
    reg [3:0]   byte_cnt;              // 4   — byte counter (nonce/data)
    reg [3:0]   out_byte_cnt;          // 4   — output byte counter
    reg [3:0]   round_cnt;             // 4   — permutation round counter
    reg         perm_phase;            // 1   — 0=S-box, 1=diffusion
    reg         last_block;            // 1   — last data block flag
    reg         out_valid;             // 1   — output byte ready
    reg         busy;                  // 1   — encryption in progress

    // ========================================================================
    // Round Constant (combinational)
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
    // Phase 0: S-box (Substitution) — Combinational
    // ========================================================================
    wire [63:0] c2 = x2 ^ {56'b0, round_const};

    wire [63:0] t0 = x0 ^ x4;
    wire [63:0] t1 = x1;
    wire [63:0] t2 = c2 ^ x1;
    wire [63:0] t3 = x3;
    wire [63:0] t4 = x4 ^ x3;

    wire [63:0] chi0 = t0 ^ ((~t1) & t2);
    wire [63:0] chi1 = t1 ^ ((~t2) & t3);
    wire [63:0] chi2 = t2 ^ ((~t3) & t4);
    wire [63:0] chi3 = t3 ^ ((~t4) & t0);
    wire [63:0] chi4 = t4 ^ ((~t0) & t1);

    wire [63:0] s0 = chi0 ^ chi4;
    wire [63:0] s1 = chi1 ^ chi0;
    wire [63:0] s2 = ~chi2;
    wire [63:0] s3 = chi3 ^ chi2;
    wire [63:0] s4 = chi4;

    // ========================================================================
    // Phase 1: Linear Diffusion — Combinational
    // ========================================================================
    wire [63:0] d0 = x0 ^ {x0[18:0], x0[63:19]} ^ {x0[27:0], x0[63:28]};
    wire [63:0] d1 = x1 ^ {x1[60:0], x1[63:61]} ^ {x1[38:0], x1[63:39]};
    wire [63:0] d2 = x2 ^ {x2[0],    x2[63:1]}  ^ {x2[5:0],  x2[63:6]};
    wire [63:0] d3 = x3 ^ {x3[9:0],  x3[63:10]} ^ {x3[16:0], x3[63:17]};
    wire [63:0] d4 = x4 ^ {x4[6:0],  x4[63:7]}  ^ {x4[40:0], x4[63:41]};

    // ========================================================================
    // Output Mux
    // ========================================================================
    assign uo_out  = out_valid ? io_sr[63:56] : 8'd0;
    assign uio_out = {6'b000000, out_valid, busy};

    // ========================================================================
    // Main FSM + Independent Read Mechanism
    // ========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            fsm_state    <= ST_IDLE;
            after_perm   <= ST_IDLE;
            x0 <= 64'd0; x1 <= 64'd0; x2 <= 64'd0; x3 <= 64'd0; x4 <= 64'd0;
            key_sr       <= 128'd0;
            io_sr        <= 64'd0;
            byte_cnt     <= 4'd0;
            out_byte_cnt <= 4'd0;
            round_cnt    <= 4'd0;
            perm_phase   <= 1'b0;
            last_block   <= 1'b0;
            out_valid    <= 1'b0;
            busy         <= 1'b0;

        end else begin

            // ============================================================
            // Independent: MCU read mechanism (byte-by-byte from io_sr)
            // Runs in any FSM state. Mutually exclusive with FSM writes
            // to io_sr because FSM only writes io_sr when out_valid==0.
            // ============================================================
            if (out_valid && read_ack && out_byte_cnt > 0) begin
                io_sr <= {io_sr[55:0], 8'd0};
                out_byte_cnt <= out_byte_cnt - 1;
                if (out_byte_cnt == 4'd1)
                    out_valid <= 1'b0;
            end

            // ============================================================
            // FSM State Machine
            // ============================================================
            case (fsm_state)

                // ========================================================
                // IDLE: Accept key/nonce bytes, wait for start pulse.
                // Commands only accepted when output is fully read.
                // ========================================================
                ST_IDLE: begin
                    busy <= 1'b0;

                    if (!out_valid) begin
                        case (cmd)
                            2'b01: begin // Load key byte (MSB first)
                                key_sr <= {key_sr[119:0], ui_in};
                            end
                            2'b10: begin // Load nonce byte → x3 (first 8) / x4 (last 8)
                                if (!byte_cnt[3])
                                    x3 <= {x3[55:0], ui_in};
                                else
                                    x4 <= {x4[55:0], ui_in};
                                byte_cnt <= byte_cnt + 4'd1;
                            end
                            default: begin
                                byte_cnt <= 4'd0;
                            end
                        endcase

                        // Start encryption
                        if (start_pulse) begin
                            busy <= 1'b1;
                            // Initialize Ascon state: IV || K || N (nonce already in x3/x4)
                            x0 <= IV_ASCON128;
                            x1 <= key_sr[127:64];
                            x2 <= key_sr[63:0];
                            // x3, x4 already loaded with nonce
                            round_cnt  <= 4'd0;
                            perm_phase <= 1'b0;
                            after_perm <= ST_INIT_XOR;
                            fsm_state  <= ST_PERM;
                        end
                    end
                end

                // ========================================================
                // PERM: 2-phase permutation (S-box then diffusion)
                // 2 cycles per round. Returns to after_perm when done.
                // ========================================================
                ST_PERM: begin
                    if (!perm_phase) begin
                        // Phase 0: Substitution
                        x0 <= s0; x1 <= s1; x2 <= s2; x3 <= s3; x4 <= s4;
                        perm_phase <= 1'b1;
                    end else begin
                        // Phase 1: Diffusion
                        x0 <= d0; x1 <= d1; x2 <= d2; x3 <= d3; x4 <= d4;
                        perm_phase <= 1'b0;
                        if (round_cnt == 4'd11)
                            fsm_state <= after_perm;
                        else
                            round_cnt <= round_cnt + 4'd1;
                    end
                end

                // ========================================================
                // INIT_XOR: Post-initialization key XOR + domain separator
                // ========================================================
                ST_INIT_XOR: begin
                    x3 <= x3 ^ key_sr[127:64];
                    x4 <= x4 ^ key_sr[63:0] ^ 64'd1;  // domain sep: no AD
                    byte_cnt <= 4'd0;
                    fsm_state <= ST_WAIT_DATA;
                end

                // ========================================================
                // WAIT_DATA: Accept PT bytes from MCU (8 bytes per block)
                // Only accepts when output has been fully read.
                // ========================================================
                ST_WAIT_DATA: begin
                    if (cmd == 2'b11 && !out_valid) begin
                        io_sr <= {io_sr[55:0], ui_in};
                        byte_cnt <= byte_cnt + 4'd1;
                        if (byte_cnt == 4'd7) begin
                            last_block <= data_last;
                            byte_cnt   <= 4'd0;
                            fsm_state  <= ST_ENCRYPT;
                        end
                    end
                end

                // ========================================================
                // ENCRYPT: XOR plaintext with x0 to produce ciphertext.
                // CT stored in io_sr, x0 updated. Output starts.
                // ========================================================
                ST_ENCRYPT: begin
                    io_sr <= x0 ^ io_sr;
                    x0    <= x0 ^ io_sr;
                    out_valid    <= 1'b1;
                    out_byte_cnt <= 4'd8;
                    fsm_state    <= ST_WAIT_READ;
                end

                // ========================================================
                // WAIT_READ: Wait for MCU to read all CT bytes, then:
                //   - Non-last: run pb6 permutation → WAIT_DATA
                //   - Last: finalization XOR + pa12 → TAG_HI
                // ========================================================
                ST_WAIT_READ: begin
                    if (!out_valid) begin
                        if (last_block) begin
                            // Finalization: XOR key into x1/x2, run pa12
                            x1 <= x1 ^ key_sr[127:64];
                            x2 <= x2 ^ key_sr[63:0];
                            round_cnt  <= 4'd0;
                            perm_phase <= 1'b0;
                            after_perm <= ST_TAG_HI;
                            fsm_state  <= ST_PERM;
                        end else begin
                            // Intermediate: run pb6 permutation
                            round_cnt  <= 4'd6;
                            perm_phase <= 1'b0;
                            after_perm <= ST_WAIT_DATA;
                            fsm_state  <= ST_PERM;
                        end
                    end
                end

                // ========================================================
                // TAG_HI: Load tag[127:64] into io_sr for MCU to read.
                // ========================================================
                ST_TAG_HI: begin
                    if (!out_valid) begin
                        io_sr        <= x3 ^ key_sr[127:64];
                        out_valid    <= 1'b1;
                        out_byte_cnt <= 4'd8;
                        fsm_state    <= ST_TAG_LO;
                    end
                end

                // ========================================================
                // TAG_LO: Load tag[63:0] into io_sr for MCU to read.
                // Returns to IDLE after MCU finishes reading.
                // ========================================================
                ST_TAG_LO: begin
                    if (!out_valid) begin
                        io_sr        <= x4 ^ key_sr[63:0];
                        out_valid    <= 1'b1;
                        out_byte_cnt <= 4'd8;
                        fsm_state    <= ST_IDLE;
                    end
                end

                default: fsm_state <= ST_IDLE;
            endcase
        end
    end

    // Suppress unused signal warnings
    wire _unused = &{ena, uio_in[3], uio_in[1:0], 1'b0};

endmodule
