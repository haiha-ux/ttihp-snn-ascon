// ============================================================================
// TinyTapeout Wrapper: SNN Motion Detector + Ascon-128 AEAD
// ============================================================================
// Target: TinyTapeout IHP 26a (IHP SG13G2 130nm)
// Author: UrbanSense-AI Project
//
// Description:
//   Combines SNN motion detector and Ascon-128 AEAD cipher into a single
//   TinyTapeout tile design. Two operating modes selected via uio[7].
//
// Pin Mapping:
//   ui_in[7:0]   = Data input (pixels in SNN mode, crypto data in Ascon mode)
//   uo_out[7:0]  = Data output (motion info or crypto output)
//   uio[7]       = MODE (input): 0=SNN, 1=Ascon
//   uio[6:5]     = CMD (input):
//                     SNN:   00=idle, 01=pixel_valid, 10=unused, 11=unused
//                     Ascon: 00=idle, 01=load_key, 10=load_nonce, 11=process
//   uio[4]       = AUX (input): data_last (Ascon) / unused (SNN)
//   uio[3]       = START (input): start_encrypt(Ascon) / unused
//   uio[2]       = DECRYPT (input): 1=decrypt mode (Ascon) / unused
//   uio[1]       = OUTPUT_VALID (output): data output valid
//   uio[0]       = STATUS (output): motion_detected (SNN) / busy (Ascon)
//
// SNN Mode Demo:
//   1. Set mode=0
//   2. Stream 256 pixels (16x16) with cmd=01 (pixel_valid)
//   3. Read motion_detected (uio[0]) and motion_intensity (uo_out[7:0])
//
// Ascon Mode Demo:
//   1. Set mode=1
//   2. Load 128-bit key: 16 bytes with cmd=01, MSB first
//   3. Load 128-bit nonce: 16 bytes with cmd=10, MSB first
//   4. Pulse start (uio[3]=1) for 1 cycle
//   5. Process data: send 8-byte blocks with cmd=11, set data_last on final
//   6. Read output on uo_out when output_valid=1
//   7. Read 16-byte tag after processing completes
// ============================================================================

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
    wire       mode       = uio_in[7];   // 0=SNN, 1=Ascon
    wire [1:0] cmd        = uio_in[6:5]; // Command
    wire       data_last  = uio_in[4];   // Last data block (Ascon)
    wire       start_pulse= uio_in[3];   // Start encrypt/decrypt
    wire       decrypt_sel= uio_in[2];   // 0=encrypt, 1=decrypt

    // uio direction: [7:2]=input, [1:0]=output
    assign uio_oe = 8'b0000_0011;

    // ========================================================================
    // SNN Motion Detector Instance
    // ========================================================================
    wire        snn_pixel_valid = (~mode) & (cmd == 2'b01);
    wire        snn_motion_detected;
    wire [7:0]  snn_motion_intensity;
    wire        snn_frame_done;

    motion_detector #(
        .IMG_WIDTH(16),
        .IMG_HEIGHT(16),
        .PIXEL_WIDTH(8),
        .THRESHOLD(20),
        .GRID_SIZE(4)
    ) u_snn (
        .clk(clk),
        .rst_n(rst_n),
        .pixel_valid(snn_pixel_valid),
        .pixel_data(ui_in),
        .motion_detected(snn_motion_detected),
        .motion_intensity(snn_motion_intensity),
        .frame_done(snn_frame_done),
        .grid_activity(),  // not routed (16 bits, insufficient pins)
        .event_count()     // not routed
    );

    // ========================================================================
    // Ascon-128 Serial Interface
    // ========================================================================
    // Shift registers to accumulate 128-bit key/nonce from 8-bit input
    // and 64-bit data blocks from 8-bit input

    reg [127:0] key_sr;
    reg [127:0] nonce_sr;
    reg [63:0]  data_sr;
    reg [3:0]   byte_cnt;      // counts 0-15 for key/nonce, 0-7 for data
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

    // Output shift register (64-bit → 8-bit serialization)
    reg [63:0]  out_sr;
    reg [3:0]   out_byte_cnt;
    reg         out_valid;

    // Tag output shift register (128-bit → 8-bit)
    reg [127:0] tag_sr;
    reg [4:0]   tag_byte_cnt;  // 0-16
    reg         tag_phase;     // reading tag bytes

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
        .tag_in(128'd0),  // tag verify not used in this wrapper
        .busy(ascon_busy),
        .auth_fail(ascon_auth_fail)
    );

    // ========================================================================
    // Ascon Serial Protocol FSM
    // ========================================================================

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            key_sr         <= 128'd0;
            nonce_sr       <= 128'd0;
            data_sr        <= 64'd0;
            byte_cnt       <= 4'd0;
            ascon_start_enc<= 1'b0;
            ascon_start_dec<= 1'b0;
            ascon_data_valid <= 1'b0;
            ascon_data_last  <= 1'b0;
            ascon_out_ready  <= 1'b0;
            out_sr         <= 64'd0;
            out_byte_cnt   <= 4'd0;
            out_valid      <= 1'b0;
            tag_sr         <= 128'd0;
            tag_byte_cnt   <= 5'd0;
            tag_phase      <= 1'b0;
        end else begin
            // Clear single-cycle pulses
            ascon_start_enc <= 1'b0;
            ascon_start_dec <= 1'b0;

            // Clear data valid after handshake
            if (ascon_data_valid && ascon_data_ready) begin
                ascon_data_valid <= 1'b0;
                ascon_data_last  <= 1'b0;
            end

            // Capture tag when valid
            if (ascon_tag_valid) begin
                tag_sr <= ascon_tag_out;
                tag_byte_cnt <= 5'd16;
                tag_phase <= 1'b1;
            end

            // Output serialization: capture 64-bit output
            if (ascon_out_valid && !out_valid && !tag_phase) begin
                out_sr <= ascon_out_data;
                out_byte_cnt <= 4'd8;
                out_valid <= 1'b1;
                ascon_out_ready <= 1'b1;
            end else begin
                ascon_out_ready <= 1'b0;
            end

            // Shift out output bytes
            if (out_valid && out_byte_cnt > 0) begin
                out_byte_cnt <= out_byte_cnt - 1;
                if (out_byte_cnt == 1) out_valid <= 1'b0;
                out_sr <= {out_sr[55:0], 8'd0};
            end

            // Shift out tag bytes
            if (tag_phase && tag_byte_cnt > 0) begin
                tag_byte_cnt <= tag_byte_cnt - 1;
                if (tag_byte_cnt == 1) tag_phase <= 1'b0;
                tag_sr <= {tag_sr[119:0], 8'd0};
            end

            // Process commands only in Ascon mode
            if (mode) begin
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
                                // Full 64-bit block ready
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
    end

    // ========================================================================
    // Output Mux
    // ========================================================================

    wire [7:0] snn_output = snn_motion_intensity;
    wire [7:0] ascon_output = tag_phase ? tag_sr[127:120] :
                              out_valid ? out_sr[63:56] :
                              8'd0;

    assign uo_out = mode ? ascon_output : snn_output;

    // Status outputs
    wire output_valid_flag = mode ? (out_valid | tag_phase) : snn_frame_done;
    wire status_flag       = mode ? ascon_busy : snn_motion_detected;

    assign uio_out = {6'b000000, output_valid_flag, status_flag};

    // Suppress unused signal warnings
    wire _unused = &{ena, ascon_auth_fail, ascon_out_last, 1'b0};

endmodule
