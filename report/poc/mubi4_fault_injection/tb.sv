`timescale 1ns/1ps
import caliptra_prim_mubi_pkg::*;

module tb;
  initial begin
    int mismatches;
    mismatches = 0;
    $display("MuBi4True  = %04b (0x%0h)", MuBi4True, MuBi4True);
    $display("MuBi4False = %04b (0x%0h)", MuBi4False, MuBi4False);
    $display("--------------------------------------------------------------");
    $display(" val   | spec-correct(val==True) | actual mubi4_test_true_strict(val)");
    for (int v = 0; v < 16; v++) begin
      logic spec_true;
      logic actual_true;
      spec_true   = (mubi4_t'(v) == MuBi4True);
      actual_true = mubi4_test_true_strict(mubi4_t'(v));
      if (spec_true !== actual_true) begin
        mismatches++;
        $display(" %04b  |          %0b               |          %0b            <== MISMATCH (glitched/invalid value accepted as TRUE)", v, spec_true, actual_true);
      end else begin
        $display(" %04b  |          %0b               |          %0b", v, spec_true, actual_true);
      end
    end
    $display("--------------------------------------------------------------");
    if (mismatches > 0)
      $display("BUG CONFIRMED: %0d multibit value(s) other than the true MuBi4True encoding are ACCEPTED by the 'strict' true-check.", mismatches);
    else
      $display("No mismatch found.");

    // Concretely demonstrate the fault-injection scenario:
    // Attacker flips bit 0 of a MuBi4True signal via a glitch (0110 -> 0111).
    begin
      mubi4_t glitched;
      glitched = MuBi4True ^ 4'h1; // single-bit flip of the LSB
      $display("\nFault-injection scenario: single-bit-flip of MuBi4True (0x%0h) -> glitched value 0x%0h", MuBi4True, glitched);
      if (mubi4_test_true_strict(glitched))
        $display("EXPLOIT SUCCESSFUL: glitched/invalid MuBi4 value 0x%0h passes mubi4_test_true_strict() as TRUE.", glitched);
      else
        $display("Glitched value correctly rejected.");
    end
    $finish;
  end
endmodule
