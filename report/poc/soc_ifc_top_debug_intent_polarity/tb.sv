`timescale 1ns/1ps
// PoC for Bug 11 (soc_ifc_top.sv SS_DEBUG_INTENT write-gate polarity inversion).
//
// soc_ifc_top.sv is the chip-level integration module (thousands of ports,
// wired to every other IP block) -- infeasible to instantiate standalone.
// This testbench instead reproduces the exact buggy expression verbatim
// from the real file and drives its two real inputs, which is sufficient
// to dynamically prove the polarity inversion itself (a pure combinational
// bug independent of anything else in the module).
//
// ---- exact code from soc_ifc_top.sv ----
//   soc_ifc_reg_hwif_in.SS_DEBUG_INTENT.debug_intent.we = strap_we_pre_fuse_done |
//                                              ~(|{cptra_uncore_dmi_unlocked_reg_wr_en,
//                                                  (cptra_uncore_dmi_reg_addr != DMI_REG_SS_DEBUG_INTENT)});
// ---- upstream v2.1.2 reference ----
//   we = strap_we_pre_fuse_done | (cptra_uncore_dmi_unlocked_reg_wr_en &
//                                   (cptra_uncore_dmi_reg_addr == DMI_REG_SS_DEBUG_INTENT));
module tb;
  localparam DMI_REG_SS_DEBUG_INTENT = 8'h2A; // exact value doesn't matter for this proof

  logic strap_we_pre_fuse_done;
  logic cptra_uncore_dmi_unlocked_reg_wr_en;
  logic [7:0] cptra_uncore_dmi_reg_addr;

  logic we_buggy, we_correct;

  // exact patched line
  always_comb begin
    we_buggy = strap_we_pre_fuse_done |
               ~(|{cptra_uncore_dmi_unlocked_reg_wr_en,
                   (cptra_uncore_dmi_reg_addr != DMI_REG_SS_DEBUG_INTENT)});
  end

  // upstream reference
  assign we_correct = strap_we_pre_fuse_done |
                       (cptra_uncore_dmi_unlocked_reg_wr_en &
                        (cptra_uncore_dmi_reg_addr == DMI_REG_SS_DEBUG_INTENT));

  initial begin
    int mismatches;
    mismatches = 0;
    strap_we_pre_fuse_done = 0; // post-fuse-done: this term is 0, isolating the DMI term

    $display(" dmi_unlocked | addr==target | we_correct | we_buggy");
    for (int u = 0; u < 2; u++) begin
      for (int a = 0; a < 2; a++) begin
        cptra_uncore_dmi_unlocked_reg_wr_en = u[0];
        cptra_uncore_dmi_reg_addr = a ? DMI_REG_SS_DEBUG_INTENT : (DMI_REG_SS_DEBUG_INTENT + 1);
        #1;
        $display("      %0b       |      %0b       |      %0b     |     %0b   %s",
                  u[0], a[0], we_correct, we_buggy, (we_correct !== we_buggy) ? "<== MISMATCH" : "");
        if (we_correct !== we_buggy) mismatches++;
      end
    end

    $display("--------------------------------------------------------------");
    // The specific attack case: DMI is LOCKED (unauthenticated,
    // dmi_unlocked_reg_wr_en=0) and the TAP addresses SS_DEBUG_INTENT.
    cptra_uncore_dmi_unlocked_reg_wr_en = 0;
    cptra_uncore_dmi_reg_addr = DMI_REG_SS_DEBUG_INTENT;
    #1;
    if (we_buggy && !we_correct) begin
      $display("BUG CONFIRMED: with the DMI still LOCKED (dmi_unlocked_reg_wr_en=0) and the TAP");
      $display("addressing SS_DEBUG_INTENT, the patched expression asserts we=1 (write succeeds)");
      $display("while the correct/upstream expression asserts we=0 (write should be blocked).");
      $display("An unauthenticated party on the DMI/JTAG TAP can set the debug-intent strap");
      $display("without ever completing the DMI unlock/authentication sequence.");
    end
    $display("Total mismatched cases out of 4 exhaustive combinations: %0d", mismatches);
    $finish;
  end
endmodule
