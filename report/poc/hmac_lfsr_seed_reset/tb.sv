`timescale 1ns/1ps
// PoC for Bug 16 (hmac_reg.sv HMAC512_LFSR_SEED reset default changed to 0).
//
// The masking LFSR seed register HMAC512_LFSR_SEED resets to 32'h0 instead
// of the fixed nonzero default 32'h3cabffb0. An XOR-feedback LFSR seeded
// with an all-zero value starts in (or, for a Fibonacci/Galois LFSR, can
// get permanently stuck in) the degenerate all-zero state, producing no
// mask randomness for the SCA countermeasure until firmware explicitly
// reseeds it.
import hmac_reg_pkg::*;

module tb;
  logic clk = 0, rst = 0;
  logic s_cpuif_req = 0, s_cpuif_req_is_wr = 0;
  logic [11:0] s_cpuif_addr = 0;
  logic [31:0] s_cpuif_wr_data = 0, s_cpuif_wr_biten = '1;
  logic s_cpuif_req_stall_wr, s_cpuif_req_stall_rd, s_cpuif_rd_ack, s_cpuif_rd_err;
  logic [31:0] s_cpuif_rd_data;
  logic s_cpuif_wr_ack, s_cpuif_wr_err;

  hmac_reg__in_t hwif_in;
  hmac_reg__out_t hwif_out;

  hmac_reg dut (
    .clk, .rst,
    .s_cpuif_req, .s_cpuif_req_is_wr, .s_cpuif_addr, .s_cpuif_wr_data, .s_cpuif_wr_biten,
    .s_cpuif_req_stall_wr, .s_cpuif_req_stall_rd, .s_cpuif_rd_ack, .s_cpuif_rd_err,
    .s_cpuif_rd_data, .s_cpuif_wr_ack, .s_cpuif_wr_err,
    .hwif_in, .hwif_out
  );

  always #5 clk = ~clk;

  initial begin
    logic [31:0] seeds_or;
    hwif_in = '0;
    hwif_in.reset_b = 0;
    hwif_in.error_reset_b = 0;
    repeat(3) @(posedge clk);
    hwif_in.reset_b = 1;
    hwif_in.error_reset_b = 1;
    repeat(2) @(posedge clk); #1;

    seeds_or = 0;
    for (int i = 0; i < 12; i++) begin
      $display("HMAC512_LFSR_SEED[%0d].LFSR_SEED (post-reset, before any SW write) = 0x%08h",
                i, hwif_out.HMAC512_LFSR_SEED[i].LFSR_SEED.value);
      seeds_or |= hwif_out.HMAC512_LFSR_SEED[i].LFSR_SEED.value;
    end

    $display("--------------------------------------------------------------");
    if (seeds_or == 32'h0) begin
      $display("BUG CONFIRMED: all 12 HMAC512_LFSR_SEED words reset to 0x00000000 instead of the");
      $display("expected nonzero default 0x3cabffb0. Any masking LFSR seeded from this register");
      $display("starts in the degenerate all-zero state (no mask randomness) until firmware");
      $display("explicitly writes a nonzero seed -- any HMAC operation performed before that first");
      $display("SW reseed runs with a predictable/absent SCA mask.");
    end else begin
      $display("No bug observed: at least one LFSR_SEED word reset nonzero.");
    end
    $finish;
  end
endmodule
