`timescale 1ns/1ps
// PoC / differential test for Bugs 5 & 6 (kv_write_rule_check.sv "BUG 1A" / "BUG 1C").
//
// Approach: instantiate the real (buggy) DUT and compare its write_allow
// output, cycle by cycle, against a golden reference model that implements
// the spec-correct rule (byte-for-byte transcribed from upstream
// caliptra-rtl v2.1.2, i.e. the version this file was diffed against)
// for the exact same stimulus. Any mismatch is a live, dynamically-proven
// discrepancy between the shipped RTL and the specified security policy.
import kv_defines_pkg::*;

module tb;
  logic clk = 0;
  logic rst_b = 0;
  kv_write_filter_metrics_t write_metrics;
  logic write_allow_dut;

  kv_write_rule_check dut (
    .clk, .rst_b,
    .write_metrics,
    .write_allow(write_allow_dut)
  );

  always #5 clk = ~clk;

  // ---- golden reference model (spec-correct, from upstream v2.1.2) ----
  function automatic logic golden_write_allow(kv_write_filter_metrics_t m);
    logic aes_only_to_key_release, std_to_std, lock_to_lock, aes_dec_to_rt_obf_key;
    logic src0_std, src1_std, src0_lock, src1_lock, dst_std, dst_lock;

    src0_std  = m.kv_data0_present && (m.kv_data0_entry inside {[KV_STANDARD_SLOT_LOW:KV_STANDARD_SLOT_HI]});
    src1_std  = m.kv_data1_present && (m.kv_data1_entry inside {[KV_STANDARD_SLOT_LOW:KV_STANDARD_SLOT_HI]});
    src0_lock = m.kv_data0_present && (m.kv_data0_entry inside {[KV_OCP_LOCK_SLOT_LOW:KV_OCP_LOCK_SLOT_HI]});
    src1_lock = m.kv_data1_present && (m.kv_data1_entry inside {[KV_OCP_LOCK_SLOT_LOW:KV_OCP_LOCK_SLOT_HI]});
    dst_std   = (m.kv_write_entry inside {[KV_STANDARD_SLOT_LOW:KV_STANDARD_SLOT_HI]});     // correct: HI inclusive
    dst_lock  = (m.kv_write_entry inside {[KV_OCP_LOCK_SLOT_LOW:KV_OCP_LOCK_SLOT_HI]});

    aes_only_to_key_release = m.ocp_lock_in_progress &&
                               |(m.kv_write_src & ~(KV_NUM_WRITE'(1) << KV_WRITE_IDX_AES)) &&
                               (m.kv_write_entry == OCP_LOCK_KEY_RELEASE_KV_SLOT);          // correct: no data0_present gate

    std_to_std  = m.ocp_lock_in_progress && (src0_std || src1_std) && !dst_std;
    lock_to_lock = m.ocp_lock_in_progress && (src0_lock || src1_lock) && !dst_lock;

    aes_dec_to_rt_obf_key = m.kv_write_src[KV_WRITE_IDX_AES] &&
                            (!m.ocp_lock_in_progress || !m.aes_decrypt_ecb_op || !m.kv_data0_present ||
                             m.kv_data0_entry != OCP_LOCK_RT_OBF_KEY_KV_SLOT ||
                             m.kv_write_entry != OCP_LOCK_KEY_RELEASE_KV_SLOT);

    return ~(aes_only_to_key_release | std_to_std | lock_to_lock | aes_dec_to_rt_obf_key);
  endfunction

  task automatic clear_metrics;
    write_metrics = '0;
  endtask

  int mismatches;
  int bypass_mismatches;   // DUT allows something golden denies (the dangerous direction)

  task automatic check(string label);
    logic golden;
    @(posedge clk); #1;
    golden = golden_write_allow(write_metrics);
    if (golden !== write_allow_dut) begin
      mismatches++;
      if (write_allow_dut && !golden) begin
        bypass_mismatches++;
        $display("[%s] DUT=%0b golden=%0b  <== SECURITY BYPASS: DUT allows a write the spec forbids", label, write_allow_dut, golden);
      end else begin
        $display("[%s] DUT=%0b golden=%0b  <== DUT over-blocks vs spec (availability bug, not a bypass)", label, write_allow_dut, golden);
      end
    end else begin
      $display("[%s] DUT=%0b golden=%0b  (match)", label, write_allow_dut, golden);
    end
  endtask

  initial begin
    mismatches = 0;
    bypass_mismatches = 0;
    rst_b = 0; clear_metrics();
    repeat(2) @(posedge clk);
    rst_b = 1;

    // ---------------------------------------------------------------
    // BUG 1A candidate: non-AES engine writes to the release slot via
    // a KV-forwarded source that itself lives in the LOCK region (so
    // rule (c) lock_to_lock does NOT independently block it, isolating
    // rule (a)'s own kv_data0_present gate).
    // ---------------------------------------------------------------
    clear_metrics();
    write_metrics.ocp_lock_in_progress = 1;
    write_metrics.kv_write_src         = (KV_NUM_WRITE'(1) << KV_WRITE_IDX_HMAC); // non-AES
    write_metrics.kv_write_entry       = KV_ENTRY_ADDR_W'(OCP_LOCK_KEY_RELEASE_KV_SLOT); // 23, in LOCK region
    write_metrics.kv_data0_present     = 1;                                       // KV-forwarded -> arms BUG 1A
    write_metrics.kv_data0_entry       = KV_ENTRY_ADDR_W'(OCP_LOCK_HEK_SEED_KV_SLOT); // 22, LOCK region -> keeps rule(c) satisfied
    check("BUG 1A: HMAC(non-AES) KV-forwarded write, LOCK-region source, to release slot");

    // Same case, but as a raw (non-forwarded) source: correctly blocked
    // both upstream and here -- isolates that the bug is specifically
    // the kv_data0_present branch, not a broken rule engine.
    clear_metrics();
    write_metrics.ocp_lock_in_progress = 1;
    write_metrics.kv_write_src         = (KV_NUM_WRITE'(1) << KV_WRITE_IDX_HMAC);
    write_metrics.kv_write_entry       = KV_ENTRY_ADDR_W'(OCP_LOCK_KEY_RELEASE_KV_SLOT);
    write_metrics.kv_data0_present     = 0;
    check("Sanity: HMAC(non-AES) RAW write to release slot (kv_data0_present=0)");

    // ---------------------------------------------------------------
    // BUG 1C sweep: exhaustively probe every (write_entry, data0_entry)
    // pair around the STD/LOCK boundary (slots 13..18) with a STD-region
    // source, looking for any DUT-vs-golden divergence introduced by the
    // dst_in_std_region off-by-one.
    // ---------------------------------------------------------------
    for (int dst = 13; dst <= 18; dst++) begin
      clear_metrics();
      write_metrics.ocp_lock_in_progress = 1;
      write_metrics.kv_write_src         = (KV_NUM_WRITE'(1) << KV_WRITE_IDX_HMAC);
      write_metrics.kv_write_entry       = KV_ENTRY_ADDR_W'(dst);
      write_metrics.kv_data0_present     = 1;
      write_metrics.kv_data0_entry       = KV_ENTRY_ADDR_W'(KV_STANDARD_SLOT_LOW); // STD-region source (entry 0)
      check($sformatf("BUG 1C sweep: STD-region source(0) -> dst=%0d", dst));
    end

    // Additional sweep: LOCK-region source across the same boundary, and a
    // dual-source (STD + LOCK simultaneously) case at the boundary slot --
    // covers every combination the dst_in_std_region off-by-one could
    // plausibly affect, to settle whether BUG 1C is a bypass or an
    // over-block (availability) issue.
    for (int dst = 13; dst <= 18; dst++) begin
      clear_metrics();
      write_metrics.ocp_lock_in_progress = 1;
      write_metrics.kv_write_src         = (KV_NUM_WRITE'(1) << KV_WRITE_IDX_HMAC);
      write_metrics.kv_write_entry       = KV_ENTRY_ADDR_W'(dst);
      write_metrics.kv_data0_present     = 1;
      write_metrics.kv_data0_entry       = KV_ENTRY_ADDR_W'(KV_OCP_LOCK_SLOT_LOW); // LOCK-region source (entry 16)
      check($sformatf("BUG 1C sweep: LOCK-region source(16) -> dst=%0d", dst));
    end

    clear_metrics();
    write_metrics.ocp_lock_in_progress = 1;
    write_metrics.kv_write_src         = (KV_NUM_WRITE'(1) << KV_WRITE_IDX_HMAC);
    write_metrics.kv_write_entry       = KV_ENTRY_ADDR_W'(KV_STANDARD_SLOT_HI); // dst=15 boundary
    write_metrics.kv_data0_present     = 1;
    write_metrics.kv_data0_entry       = KV_ENTRY_ADDR_W'(KV_STANDARD_SLOT_LOW);   // src0: STD region
    write_metrics.kv_data1_present     = 1;
    write_metrics.kv_data1_entry       = KV_ENTRY_ADDR_W'(KV_OCP_LOCK_SLOT_LOW);   // src1: LOCK region
    check("BUG 1C sweep: dual-source (STD+LOCK) -> dst=15 boundary");

    $display("--------------------------------------------------------------");
    $display("Total DUT-vs-spec mismatches: %0d  (of which security bypasses: %0d)", mismatches, bypass_mismatches);
    $finish;
  end
endmodule
