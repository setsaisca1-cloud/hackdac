`timescale 1ns/1ps
// PoC for Bug 17 (removed CALIPTRA_ASSERT_STABLE key/seed/control checks).
//
// This isn't independently exploitable RTL -- no functional hardware
// changed, only simulation-time assertions were deleted from
// ecc_dsa_ctrl.sv, hmac.sv, aes_clp_wrapper.sv, and sha512.sv. This test
// demonstrates the practical consequence directly: with the same
// CALIPTRA_ASSERT_STABLE macro used upstream (from libs/rtl/caliptra_sva.svh)
// watching a key register during a busy window, a glitch on that
// register (e.g. from a fault-injection attempt, or a bug elsewhere in
// the design) is caught immediately and fatally; with the assertion
// removed -- as shipped in this drop -- the exact same glitch is
// completely silent.
`include "caliptra_sva.svh"

module dut (
  input logic clk_i,
  input logic rst_ni,
  input logic core_busy,
  input logic [31:0] key_reg
);
`ifdef WITH_ASSERTION
  // Exactly the upstream pattern removed from ecc_dsa_ctrl.sv / hmac.sv /
  // aes_clp_wrapper.sv / sha512.sv:
  //   `CALIPTRA_ASSERT_STABLE(ERR_KEY_NOT_STABLE, key_reg, clk, (!reset_n || ready))
  `CALIPTRA_ASSERT_STABLE(ERR_KEY_NOT_STABLE, key_reg, clk_i, (!rst_ni || !core_busy))
`endif
endmodule

module tb;
  logic clk_i = 0, rst_ni = 0, core_busy = 0;
  logic [31:0] key_reg = 32'hAAAA_AAAA;

  dut u_dut (.*);
  always #5 clk_i = ~clk_i;

  initial begin
    rst_ni = 0; repeat(2) @(posedge clk_i); rst_ni = 1; @(posedge clk_i);

    core_busy = 1; // crypto engine is mid-operation, key must not move
    @(posedge clk_i);

    $display("Simulating a glitch on key_reg while the engine is busy (core_busy=1)...");
    key_reg = 32'hFFFF_FFFF; // the glitch: key changes mid-operation
    @(posedge clk_i); #1;

    $display("key_reg after glitch = 0x%08h -- simulation reached this line without stopping.", key_reg);
`ifdef WITH_ASSERTION
    $display("(built WITH the CALIPTRA_ASSERT_STABLE check restored: if you see this line, the");
    $display(" assert did not fire, which would itself be unexpected -- check CLP_ASSERT_ON is defined)");
`else
    $display("BUG 17 CONFIRMED: built exactly as shipped (assertion removed) -- the glitch on a");
    $display("key register during a busy window went completely undetected by the DV environment.");
    $display("Re-run with -DWITH_ASSERTION -DCLP_ASSERT_ON to see the same glitch caught immediately.");
`endif
    $finish;
  end
endmodule
