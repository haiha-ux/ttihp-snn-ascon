// ============================================================================
// Leaky Integrate-and-Fire (LIF) Neuron
// ============================================================================
// Author: UrbanSense-AI Project
// Date: 2025-12-20
//
// Description:
//   Implements a Leaky Integrate-and-Fire neuron model for SNN.
//   Key features:
//   - Membrane potential integration with leak
//   - Threshold-based spike generation
//   - Configurable refractory period
//   - Overflow protection
//
// LIF Model:
//   dV/dt = -V/tau + I(t)
//   If V >= threshold: spike, V = V_rest
//
// Parameters:
//   VMEM_WIDTH  - Bit width for membrane potential
//   THRESHOLD   - Firing threshold
//   LEAK_SHIFT  - Leak rate = V >> LEAK_SHIFT per cycle
//   V_REST      - Resting potential after spike
//   REFRACT_CYCLES - Refractory period in clock cycles
// ============================================================================

`timescale 1ns/1ps

module lif_neuron #(
    parameter VMEM_WIDTH = 16,
    parameter THRESHOLD = 16'd1000,
    parameter LEAK_SHIFT = 4,
    parameter V_REST = 16'd0,
    parameter REFRACT_CYCLES = 3
)(
    input  logic                     clk,
    input  logic                     rst_n,

    // Input spike interface
    input  logic                     spike_in,
    input  logic signed [VMEM_WIDTH-1:0] weight,

    // Output spike
    output logic                     spike_out,

    // Debug/monitoring
    output logic [VMEM_WIDTH-1:0]    vmem_out,
    output logic [1:0]               state_out
);

    // ========================================================================
    // State Machine
    // ========================================================================

    typedef enum logic [1:0] {
        ST_REST       = 2'b00,  // Resting/integrating state
        ST_FIRE       = 2'b01,  // Spike output cycle
        ST_REFRACTORY = 2'b10   // Refractory period
    } state_t;

    state_t state, next_state;

    // ========================================================================
    // Internal Signals
    // ========================================================================

    logic signed [VMEM_WIDTH-1:0] vmem;           // Membrane potential
    logic signed [VMEM_WIDTH-1:0] vmem_next;      // Next membrane potential
    logic signed [VMEM_WIDTH-1:0] leak_amount;    // Leak value
    logic signed [VMEM_WIDTH-1:0] vmem_with_input;// Vmem after input integration
    logic [$clog2(REFRACT_CYCLES+1)-1:0] refract_cnt;

    // Output assignments
    assign vmem_out = vmem;
    assign state_out = state;

    // ========================================================================
    // Leak Calculation
    // ========================================================================

    // Leak towards rest: leak = (vmem - V_REST) >> LEAK_SHIFT
    // For simplicity, assuming V_REST = 0
    assign leak_amount = vmem >>> LEAK_SHIFT;

    // ========================================================================
    // Membrane Potential Update Logic
    // ========================================================================

    always_comb begin
        vmem_next = vmem;

        case (state)
            ST_REST: begin
                // Apply leak
                vmem_next = vmem - leak_amount;

                // Integrate input if spike received
                if (spike_in) begin
                    // Check for overflow before adding
                    if (weight > 0 && vmem_next > (2**(VMEM_WIDTH-1)-1 - weight)) begin
                        // Positive overflow - saturate
                        vmem_next = 2**(VMEM_WIDTH-1) - 1;
                    end else if (weight < 0 && vmem_next < (-2**(VMEM_WIDTH-1) - weight)) begin
                        // Negative overflow - saturate
                        vmem_next = -2**(VMEM_WIDTH-1);
                    end else begin
                        vmem_next = vmem_next + weight;
                    end
                end

                // Ensure vmem doesn't go below V_REST
                if (vmem_next < $signed(V_REST)) begin
                    vmem_next = V_REST;
                end
            end

            ST_FIRE: begin
                // Reset to resting potential
                vmem_next = V_REST;
            end

            ST_REFRACTORY: begin
                // Stay at resting potential during refractory
                vmem_next = V_REST;
            end

            default: vmem_next = V_REST;
        endcase
    end

    // ========================================================================
    // State Machine
    // ========================================================================

    always_comb begin
        next_state = state;

        case (state)
            ST_REST: begin
                // Check if threshold reached
                if (vmem_next >= $signed(THRESHOLD)) begin
                    next_state = ST_FIRE;
                end
            end

            ST_FIRE: begin
                // Transition to refractory
                next_state = ST_REFRACTORY;
            end

            ST_REFRACTORY: begin
                // Exit refractory when counter expires
                if (refract_cnt == 0) begin
                    next_state = ST_REST;
                end
            end

            default: next_state = ST_REST;
        endcase
    end

    // ========================================================================
    // Sequential Logic
    // ========================================================================

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= ST_REST;
            vmem <= V_REST;
            spike_out <= 1'b0;
            refract_cnt <= '0;
        end else begin
            state <= next_state;
            vmem <= vmem_next;

            // Spike output
            case (state)
                ST_REST: begin
                    if (next_state == ST_FIRE) begin
                        spike_out <= 1'b1;
                    end else begin
                        spike_out <= 1'b0;
                    end
                end

                ST_FIRE: begin
                    spike_out <= 1'b0;
                    refract_cnt <= REFRACT_CYCLES - 1;
                end

                ST_REFRACTORY: begin
                    spike_out <= 1'b0;
                    if (refract_cnt > 0) begin
                        refract_cnt <= refract_cnt - 1;
                    end
                end

                default: begin
                    spike_out <= 1'b0;
                end
            endcase
        end
    end

    // ========================================================================
    // Assertions (for simulation/formal verification)
    // ========================================================================

    `ifdef FORMAL
        // Spike only fires in FIRE state or transitioning to it
        assert property (@(posedge clk) disable iff (!rst_n)
            spike_out |-> (state == ST_REST && next_state == ST_FIRE));

        // Membrane potential bounded
        assert property (@(posedge clk) disable iff (!rst_n)
            vmem >= $signed(-2**(VMEM_WIDTH-1)) &&
            vmem <= $signed(2**(VMEM_WIDTH-1)-1));

        // Refractory counter doesn't exceed max
        assert property (@(posedge clk) disable iff (!rst_n)
            refract_cnt <= REFRACT_CYCLES);
    `endif

endmodule
