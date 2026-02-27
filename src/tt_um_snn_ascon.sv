// ============================================================================
// TinyTapeout Wrapper: Ascon-128 AEAD
// ============================================================================
// Target: TinyTapeout IHP 26a (IHP SG13G2 130nm)
// Author: UrbanSense-AI Project
//
// Description:
//   Ascon-128 authenticated encryption with serial I/O interface.
//   Implements NIST lightweight cryptography standard.
//
// Pin Mapping:
//   ui_in[7:0]   = Data input (8 bits at a time)
//   uo_out[7:0]  = Data output (ciphertext or tag bytes)
//   uio[7:6]     = CMD (input): 00=idle, 01=load_key, 10=load_nonce, 11=process
//   uio[5]       = DATA_LAST (input): marks last data block
//   uio[4]       = START (input): pulse to start encrypt/decrypt
//   uio[3]       = DECRYPT (input): 0=encrypt, 1=decrypt
//   uio[2]       = READ_ACK (input): pulse to advance to next output byte
//   uio[1]       = OUTPUT_VALID (output): data output ready to read
//   uio[0]       = BUSY (output): Ascon is processing
//
// Protocol:
//   1. Load 128-bit key: 16 bytes with cmd=01, MSB first
//   2. Load 128-bit nonce: 16 bytes with cmd=10, MSB first
//   3. Pulse start (uio[4]=1) for 1 cycle
//   4. Process data: send 8-byte blocks with cmd=11, set data_last on final
//   5. Poll output_valid (uio[1]). When high, read uo_out, pulse read_ack (uio[2])
//   6. Repeat step 5 for all ciphertext bytes + 16 tag bytes
// ============================================================================

`default_nettype none
`timescale 1ns/1ps

module tt_um_snn_ascon (
    input  wire [7:0] ui_in,    // Dedicated inputs
    output wire [7:0] uo_out,   // Dedicated outputs
    input  wire [7:0] uio_in,   // IOs: Input path
    output wire [7:0] uio_out,  // IOs: Output path
    output wire [7:0] uio_oe,   // IOs: Enable path (active high: 0=input, 1=output)
    input  wire       ena,      // always 1 when the design is powered
    input  wire       clk,      // clock
    input  wire       rst_n     // reset_n - low to reset
);

    // ========================================================================
    // Pin Decode
    // ========================================================================
    wire [1:0] cmd        = uio_in[7:6]; // Command
    wire       data_last  = uio_in[5];   // Last data block
    wire       start_pulse= uio_in[4];   // Start encrypt/decrypt
    wire       decrypt_sel= uio_in[3];   // 0=encrypt, 1=decrypt
    wire       read_ack   = uio_in[2];   // MCU pulses to read next output byte

    // uio direction: [7:2]=input, [1:0]=output
    assign uio_oe = 8'b0000_0011;

    // ========================================================================
    // Ascon-128 Serial Interface
    // ========================================================================
    reg [127:0] key_sr;
    reg [127:0] nonce_sr;
    reg [63:0]  data_sr;
    reg [3:0]   byte_cnt;
    reg         ascon_start_enc;
    reg         ascon_start_dec;

    // Ascon data input handshake
    reg         ascon_data_valid;
    reg         ascon_data_last;
    wire        ascon_data_ready;

    // Ascon data output
    wire        ascon_out_valid;
    wire [63:0] ascon_out_data;
    wire        ascon_out_last;
    reg         ascon_out_ready;

    // Ascon status
    wire        ascon_busy;
    wire        ascon_auth_fail;
    wire [127:0] ascon_tag_out;
    wire        ascon_tag_valid;

    // Output shift register (64-bit -> 8-bit serialization)
    reg [63:0]  out_sr;
    reg [3:0]   out_byte_cnt;
    reg         out_valid;

    // Tag output shift register (128-bit -> 8-bit)
    reg [127:0] tag_sr;
    reg [4:0]   tag_byte_cnt;
    reg         tag_phase;
    reg         tag_pending;  // Tag captured but waiting for CT output to finish

    ascon_aead u_ascon (
        .clk(clk),
        .rst_n(rst_n),
        .start_encrypt(ascon_start_enc),
        .start_decrypt(ascon_start_dec),
        .key(key_sr),
        .nonce(nonce_sr),
        .s_axis_tvalid(ascon_data_valid),
        .s_axis_tready(ascon_data_ready),
        .s_axis_tdata(data_sr),
        .s_axis_tlast(ascon_data_last),
        .m_axis_tvalid(ascon_out_valid),
        .m_axis_tready(ascon_out_ready),
        .m_axis_tdata(ascon_out_data),
        .m_axis_tlast(ascon_out_last),
        .tag_out(ascon_tag_out),
        .tag_valid(ascon_tag_valid),
        .tag_in(128'd0),
        .busy(ascon_busy),
        .auth_fail(ascon_auth_fail)
    );

    // ========================================================================
    // Serial Protocol FSM
    // ========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_sr          <= 128'd0;
            nonce_sr        <= 128'd0;
            data_sr         <= 64'd0;
            byte_cnt        <= 4'd0;
            ascon_start_enc <= 1'b0;
            ascon_start_dec <= 1'b0;
            ascon_data_valid <= 1'b0;
            ascon_data_last  <= 1'b0;
            ascon_out_ready  <= 1'b0;
            out_sr          <= 64'd0;
            out_byte_cnt    <= 4'd0;
            out_valid       <= 1'b0;
            tag_sr          <= 128'd0;
            tag_byte_cnt    <= 5'd0;
            tag_phase       <= 1'b0;
            tag_pending     <= 1'b0;
        end else begin
            // Clear single-cycle pulses
            ascon_start_enc <= 1'b0;
            ascon_start_dec <= 1'b0;

            // Clear data valid after handshake
            if (ascon_data_valid && ascon_data_ready) begin
                ascon_data_valid <= 1'b0;
                ascon_data_last  <= 1'b0;
            end

            // Capture tag when valid (defer output until CT is done)
            if (ascon_tag_valid) begin
                tag_sr <= ascon_tag_out;
                tag_byte_cnt <= 5'd16;
                if (!out_valid)
                    tag_phase <= 1'b1;
                else
                    tag_pending <= 1'b1;
            end

            // Start tag output once CT output is fully read
            if (tag_pending && !out_valid) begin
                tag_phase <= 1'b1;
                tag_pending <= 1'b0;
            end

            // Output serialization: capture 64-bit output (hold until MCU reads)
            if (ascon_out_valid && !out_valid && !tag_phase) begin
                out_sr <= ascon_out_data;
                out_byte_cnt <= 4'd8;
                out_valid <= 1'b1;
                ascon_out_ready <= 1'b1;
            end else begin
                ascon_out_ready <= 1'b0;
            end

            // Advance to next output byte only when MCU pulses read_ack
            if (out_valid && out_byte_cnt > 0 && read_ack && !tag_phase) begin
                out_byte_cnt <= out_byte_cnt - 1;
                if (out_byte_cnt == 1) out_valid <= 1'b0;
                out_sr <= {out_sr[55:0], 8'd0};
            end

            // Advance to next tag byte only when MCU pulses read_ack
            if (tag_phase && tag_byte_cnt > 0 && read_ack) begin
                tag_byte_cnt <= tag_byte_cnt - 1;
                if (tag_byte_cnt == 1) tag_phase <= 1'b0;
                tag_sr <= {tag_sr[119:0], 8'd0};
            end

            // Process commands
            case (cmd)
                2'b01: begin // Load key (16 bytes, MSB first)
                    key_sr <= {key_sr[119:0], ui_in};
                    byte_cnt <= byte_cnt + 1;
                end

                2'b10: begin // Load nonce (16 bytes, MSB first)
                    nonce_sr <= {nonce_sr[119:0], ui_in};
                    byte_cnt <= byte_cnt + 1;
                end

                2'b11: begin // Process data (8 bytes per block)
                    if (!ascon_data_valid) begin
                        data_sr <= {data_sr[55:0], ui_in};
                        byte_cnt <= byte_cnt + 1;
                        if (byte_cnt == 4'd7) begin
                            ascon_data_valid <= 1'b1;
                            ascon_data_last  <= data_last;
                            byte_cnt <= 4'd0;
                        end
                    end
                end

                default: begin
                    byte_cnt <= 4'd0;
                end
            endcase

            // Start pulse
            if (start_pulse && !ascon_busy) begin
                if (decrypt_sel)
                    ascon_start_dec <= 1'b1;
                else
                    ascon_start_enc <= 1'b1;
                byte_cnt <= 4'd0;
            end
        end
    end

    // ========================================================================
    // Output
    // ========================================================================
    assign uo_out = tag_phase ? tag_sr[127:120] :
                    out_valid ? out_sr[63:56] :
                    8'd0;

    wire output_valid_flag = out_valid | tag_phase;

    assign uio_out = {6'b000000, output_valid_flag, ascon_busy};

    // Suppress unused signal warnings
    wire _unused = &{ena, ascon_auth_fail, ascon_out_last, 1'b0};

endmodule
