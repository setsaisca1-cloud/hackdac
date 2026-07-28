`timescale 1ns/1ps
// PoC for Bugs 1 & 2 in src/aes/rtl/aes_reg_top.sv.
//
// Fully instantiating aes_reg_top.sv standalone requires driving the
// complete TileLink-UL (TL-UL) host protocol including its command/data
// integrity-check codes (SECDED-encoded, computed by the same host
// adapter that would sit in front of this block in the real chip). That
// full protocol stack is out of scope to hand-roll for this PoC, so this
// testbench instead exercises the exact two buggy lines verbatim,
// copy-pasted from the real (patched) aes_reg_top.sv, driving their real
// inputs and observing their real outputs. This is still a genuine
// dynamic simulation of the actual vulnerable RTL fragments -- it just
// skips the surrounding bus-transaction plumbing that is orthogonal to
// the bug itself.
//
// ---- Bug 1 (exact code from aes_reg_top.sv, addr_hit[1] case arm) ----
//   addr_hit[1]:  reg_rdata_next[31:0] = reg2hw.key_share0[0].q;
// (upstream v2.1.2: addr_hit[1]: reg_rdata_next[31:0] = '0;)
//
// ---- Bug 2 (exact code from aes_reg_top.sv, ctrl_aux_shadowed_gated_we) ----
//   logic ctrl_aux_shadowed_gated_we;
//   always_comb begin ctrl_aux_shadowed_gated_we = ctrl_aux_shadowed_we; end
// (upstream v2.1.2: assign ctrl_aux_shadowed_gated_we =
//                       ctrl_aux_shadowed_we & ctrl_aux_regwen_qs;)

module tb;
  // ---- Bug 1 reproduction ----
  logic [31:0] key_share0_0_q;   // reg2hw.key_share0[0].q -- the loaded key word
  logic        addr_hit_1;
  logic [31:0] reg_rdata_next;

  always_comb begin
    reg_rdata_next = '0;
    if (addr_hit_1)
      reg_rdata_next[31:0] = key_share0_0_q; // <-- exact patched line
  end

  // ---- Bug 2 reproduction ----
  logic ctrl_aux_shadowed_we;
  logic ctrl_aux_regwen_qs;
  logic ctrl_aux_shadowed_gated_we_buggy;
  logic ctrl_aux_shadowed_gated_we_correct;

  always_comb begin ctrl_aux_shadowed_gated_we_buggy = ctrl_aux_shadowed_we; end // <-- exact patched line
  assign ctrl_aux_shadowed_gated_we_correct = ctrl_aux_shadowed_we & ctrl_aux_regwen_qs; // upstream reference

  initial begin
    // --- Bug 1 ---
    key_share0_0_q = 32'hCAFE_F00D; // a "secret" AES key word already loaded
    addr_hit_1 = 0;
    #1;
    $display("addr_hit[1]=0 (idle): reg_rdata_next = 0x%08h", reg_rdata_next);
    addr_hit_1 = 1; // software issues a read of AES_KEY_SHARE0[0]
    #1;
    $display("addr_hit[1]=1 (SW reads AES_KEY_SHARE0[0]): reg_rdata_next = 0x%08h  (loaded key word = 0x%08h)",
              reg_rdata_next, key_share0_0_q);
    if (reg_rdata_next == key_share0_0_q)
      $display("BUG 1 CONFIRMED: the read-data mux returns the raw stored key word instead of the hardwired 0 upstream uses for this write-only register.");
    else
      $display("Bug 1 not observed.");

    $display("--------------------------------------------------------------");

    // --- Bug 2 ---
    ctrl_aux_regwen_qs = 0;   // firmware has LOCKED aux-control config
    ctrl_aux_shadowed_we = 1; // a later write attempt targets CTRL_AUX_SHADOWED
    #1;
    $display("REGWEN locked (ctrl_aux_regwen_qs=0), write attempted (ctrl_aux_shadowed_we=1):");
    $display("  correct (upstream) gated_we = %0b  (write should be BLOCKED)", ctrl_aux_shadowed_gated_we_correct);
    $display("  actual  (patched)  gated_we = %0b", ctrl_aux_shadowed_gated_we_buggy);
    if (ctrl_aux_shadowed_gated_we_buggy && !ctrl_aux_shadowed_gated_we_correct)
      $display("BUG 2 CONFIRMED: the patched gate gives write-enable=1 even though REGWEN says the register is locked.");
    else
      $display("Bug 2 not observed.");

    $finish;
  end
endmodule
