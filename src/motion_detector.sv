// ============================================================================
// SNN-based Motion Detector
// ============================================================================
// Author: UrbanSense-AI Project
// Date: 2025-12-20
//
// Description:
//   Detects motion by comparing consecutive frames using event-based
//   processing and Spiking Neural Network.
//
//   Algorithm:
//   1. Store previous frame in buffer
//   2. Calculate absolute difference between current and previous pixel
//   3. Generate spike events when difference > threshold
//   4. Aggregate events to detect motion regions
//   5. Use SNN for spatiotemporal pattern filtering
//
//   Features:
//   - Event-driven processing (only significant changes generate spikes)
//   - Spatial aggregation into grid regions
//   - Motion intensity measurement
//   - Configurable sensitivity threshold
// ============================================================================

`timescale 1ns/1ps

module motion_detector #(
    parameter IMG_WIDTH = 16,
    parameter IMG_HEIGHT = 16,
    parameter PIXEL_WIDTH = 8,
    parameter THRESHOLD = 20,       // Motion detection threshold
    parameter GRID_SIZE = 4         // Grid regions for SNN input
)(
    input  logic                              clk,
    input  logic                              rst_n,

    // Pixel stream input
    input  logic                              pixel_valid,
    input  logic [PIXEL_WIDTH-1:0]            pixel_data,

    // Motion output
    output logic                              motion_detected,
    output logic [7:0]                        motion_intensity,
    output logic                              frame_done,

    // Debug outputs
    output logic [GRID_SIZE*GRID_SIZE-1:0]    grid_activity,
    output logic [$clog2(IMG_WIDTH*IMG_HEIGHT):0] event_count
);

    // ========================================================================
    // Local Parameters
    // ========================================================================

    localparam FRAME_SIZE = IMG_WIDTH * IMG_HEIGHT;
    localparam GRID_CELLS = GRID_SIZE * GRID_SIZE;
    localparam PIXELS_PER_GRID = (IMG_WIDTH / GRID_SIZE) * (IMG_HEIGHT / GRID_SIZE);

    // ========================================================================
    // Frame Buffer (stores previous frame)
    // ========================================================================

    logic [PIXEL_WIDTH-1:0] prev_frame [0:FRAME_SIZE-1];

    // ========================================================================
    // Pixel Counters
    // ========================================================================

    logic [$clog2(IMG_WIDTH)-1:0]  col_cnt;
    logic [$clog2(IMG_HEIGHT)-1:0] row_cnt;
    logic [$clog2(FRAME_SIZE)-1:0] pixel_idx;

    assign pixel_idx = row_cnt * IMG_WIDTH + col_cnt;

    // ========================================================================
    // Difference Calculation
    // ========================================================================

    logic [PIXEL_WIDTH-1:0] prev_pixel;
    logic [PIXEL_WIDTH-1:0] abs_diff;
    logic                   spike_event;

    assign prev_pixel = prev_frame[pixel_idx];

    // Absolute difference
    assign abs_diff = (pixel_data > prev_pixel) ?
                      (pixel_data - prev_pixel) :
                      (prev_pixel - pixel_data);

    // Generate spike if difference exceeds threshold
    assign spike_event = (abs_diff > THRESHOLD) && pixel_valid;

    // ========================================================================
    // Grid Mapping
    // ========================================================================

    logic [$clog2(GRID_SIZE)-1:0] grid_row, grid_col;
    logic [$clog2(GRID_CELLS)-1:0] grid_idx;

    assign grid_row = row_cnt >> ($clog2(IMG_HEIGHT) - $clog2(GRID_SIZE));
    assign grid_col = col_cnt >> ($clog2(IMG_WIDTH) - $clog2(GRID_SIZE));
    assign grid_idx = grid_row * GRID_SIZE + grid_col;

    // ========================================================================
    // Event Accumulators per Grid Cell
    // ========================================================================

    logic [7:0] grid_event_cnt [0:GRID_CELLS-1];
    logic [15:0] total_diff_accum;
    logic [$clog2(FRAME_SIZE):0] motion_pixel_count;

    // ========================================================================
    // State Machine
    // ========================================================================

    typedef enum logic [1:0] {
        ST_IDLE,
        ST_PROCESS,
        ST_EVALUATE,
        ST_OUTPUT
    } state_t;

    state_t state;

    // ========================================================================
    // Main Processing Logic
    // ========================================================================

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= ST_IDLE;
            col_cnt <= '0;
            row_cnt <= '0;
            motion_detected <= 1'b0;
            motion_intensity <= '0;
            frame_done <= 1'b0;
            total_diff_accum <= '0;
            motion_pixel_count <= '0;
            event_count <= '0;
            grid_activity <= '0;

            // Initialize grid event counters
            for (int i = 0; i < GRID_CELLS; i++) begin
                grid_event_cnt[i] = '0;
            end

            // Initialize frame buffer to zero
            for (int i = 0; i < FRAME_SIZE; i++) begin
                prev_frame[i] = '0;
            end

        end else begin
            frame_done <= 1'b0;

            case (state)
                ST_IDLE: begin
                    // Reset counters while idle
                    col_cnt <= '0;
                    row_cnt <= '0;

                    if (pixel_valid) begin
                        state <= ST_PROCESS;
                        // Reset accumulators for new frame
                        total_diff_accum <= '0;
                        motion_pixel_count <= '0;
                        event_count <= '0;
                        for (int i = 0; i < GRID_CELLS; i++) begin
                            grid_event_cnt[i] <= '0;
                        end
                    end
                end

                ST_PROCESS: begin
                    if (pixel_valid) begin
                        // Store current pixel to frame buffer
                        prev_frame[pixel_idx] <= pixel_data;

                        // Count motion events
                        if (spike_event) begin
                            motion_pixel_count <= motion_pixel_count + 1;
                            total_diff_accum <= total_diff_accum + abs_diff;
                            event_count <= event_count + 1;

                            // Increment grid cell counter
                            if (grid_event_cnt[grid_idx] < 8'hFF) begin
                                grid_event_cnt[grid_idx] <= grid_event_cnt[grid_idx] + 1;
                            end
                        end

                        // Update pixel position
                        if (col_cnt == IMG_WIDTH - 1) begin
                            col_cnt <= '0;
                            if (row_cnt == IMG_HEIGHT - 1) begin
                                row_cnt <= '0;
                                state <= ST_EVALUATE;
                            end else begin
                                row_cnt <= row_cnt + 1;
                            end
                        end else begin
                            col_cnt <= col_cnt + 1;
                        end
                    end else begin
                        // No valid pixel - frame incomplete, evaluate what we have
                        if (col_cnt > 0 || row_cnt > 0) begin
                            state <= ST_EVALUATE;
                        end
                    end
                end

                ST_EVALUATE: begin
                    // Determine if motion detected based on event count
                    // Motion if more than 10% of pixels changed significantly
                    if (motion_pixel_count > (FRAME_SIZE / 10)) begin
                        motion_detected <= 1'b1;
                    end else begin
                        motion_detected <= 1'b0;
                    end

                    // Calculate motion intensity (scaled average difference)
                    if (motion_pixel_count > 0) begin
                        motion_intensity <= total_diff_accum[15:8];
                    end else begin
                        motion_intensity <= '0;
                    end

                    // Set grid activity flags
                    for (int i = 0; i < GRID_CELLS; i++) begin
                        // Grid cell active if more than 2 events
                        grid_activity[i] <= (grid_event_cnt[i] > 2);
                    end

                    state <= ST_OUTPUT;
                end

                ST_OUTPUT: begin
                    frame_done <= 1'b1;
                    state <= ST_IDLE;
                end

            endcase
        end
    end

    // ========================================================================
    // SNN Layer for Spatiotemporal Filtering (Optional)
    // ========================================================================
    // The grid_activity can be fed to an SNN layer for more sophisticated
    // pattern detection. For now, we output it directly.

    // If SNN filtering is needed:
    // snn_layer #(.NUM_NEURONS(GRID_CELLS)) snn_filter (
    //     .clk(clk),
    //     .rst_n(rst_n),
    //     .spike_in(grid_activity),
    //     .spike_out(snn_output),
    //     ...
    // );

endmodule
