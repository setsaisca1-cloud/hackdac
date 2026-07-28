`timescale 1ns/1ps
// PoC / differential test for Bug 7 (kv_read_rule_check.sv DMA-dest bypass).
//
// kv_read_dest is a per-entry bitmask of ALL currently-active read clients
// for that Key-Vault entry (KV_NUM_READ=9 bits: HMAC_KEY, HMAC_BLOCK,
// MLDSA_SEED, ECC_PKEY, ECC_SEED, AES_KEY, MLKEM_SEED, MLKEM_MSG, DMA_DATA),
// not a single client's selector -- multiple engines can legitimately read
// the same entry in the same cycle. Upstream requires the mask to be
// EXACTLY the DMA-only one-hot value; the patched RTL only checks that the
// DMA bit is one of the set bits (bitwise AND/OR instead of exact equality).
import kv_defines_pkg::*;

module tb;
  logic clk = 0;
  logic rst_b = 0;
  logic read_en_i = 0;
  logic read_done = 0;
  logic read_en_o;
  kv_read_filter_metrics_t read_metrics;
  logic read_allow_dut;

  kv_read_rule_check dut (
    .clk, .rst_b,
    .read_en_i, .read_done, .read_en_o,
    .read_metrics,
    .read_allow(read_allow_dut)
  );

  always #5 clk = ~clk;

  // golden reference: exact-match on kv_read_dest, per upstream v2.1.2
  function automatic logic golden_read_allow(kv_read_filter_metrics_t m);
    logic no_read_key_release;
    logic [KV_NUM_READ-1:0] dma_only;
    dma_only = (KV_NUM_READ'(1) << KV_DEST_IDX_DMA_DATA);
    no_read_key_release = m.ocp_lock_in_progress &&
                           (m.kv_read_dest != dma_only) &&
                           (m.kv_key_entry == OCP_LOCK_KEY_RELEASE_KV_SLOT);
    return ~no_read_key_release;
  endfunction

  int mismatches;
  int bypass_mismatches;

  task automatic check(string label);
    logic golden;
    read_en_i = 1;
    @(posedge clk); #1;
    read_en_i = 0;
    golden = golden_read_allow(read_metrics);
    if (golden !== read_allow_dut) begin
      mismatches++;
      if (read_allow_dut && !golden) begin
        bypass_mismatches++;
        $display("[%s] DUT=%0b golden=%0b  <== SECURITY BYPASS: DUT allows a read the spec forbids", label, read_allow_dut, golden);
      end else begin
        $display("[%s] DUT=%0b golden=%0b  <== DUT over-blocks vs spec", label, read_allow_dut, golden);
      end
    end else begin
      $display("[%s] DUT=%0b golden=%0b  (match)", label, read_allow_dut, golden);
    end
    read_done = 1; @(posedge clk); #1; read_done = 0;
  endtask

  initial begin
    mismatches = 0;
    bypass_mismatches = 0;
    rst_b = 0; read_metrics = '0;
    repeat(2) @(posedge clk);
    rst_b = 1;

    // Sanity: pure DMA-only read of the release slot -> allowed both ways.
    read_metrics = '0;
    read_metrics.ocp_lock_in_progress = 1;
    read_metrics.kv_key_entry         = KV_ENTRY_ADDR_W'(OCP_LOCK_KEY_RELEASE_KV_SLOT);
    read_metrics.kv_read_dest         = (KV_NUM_READ'(1) << KV_DEST_IDX_DMA_DATA);
    check("Sanity: DMA-only read of release slot");

    // Sanity: pure HMAC-only (non-DMA) read of the release slot -> blocked both ways.
    read_metrics = '0;
    read_metrics.ocp_lock_in_progress = 1;
    read_metrics.kv_key_entry         = KV_ENTRY_ADDR_W'(OCP_LOCK_KEY_RELEASE_KV_SLOT);
    read_metrics.kv_read_dest         = (KV_NUM_READ'(1) << KV_DEST_IDX_HMAC_KEY);
    check("Sanity: HMAC-only read of release slot");

    // ---------------------------------------------------------------
    // THE BUG: concurrent DMA + HMAC read of the release slot. Spec
    // requires the mask to be exactly DMA-only -> must be BLOCKED.
    // Patched RTL only checks "does the DMA bit overlap" -> ALLOWED.
    // ---------------------------------------------------------------
    read_metrics = '0;
    read_metrics.ocp_lock_in_progress = 1;
    read_metrics.kv_key_entry         = KV_ENTRY_ADDR_W'(OCP_LOCK_KEY_RELEASE_KV_SLOT);
    read_metrics.kv_read_dest         = (KV_NUM_READ'(1) << KV_DEST_IDX_DMA_DATA) |
                                         (KV_NUM_READ'(1) << KV_DEST_IDX_HMAC_KEY);
    check("BUG: concurrent DMA+HMAC read of release slot (mixed one-hot mask)");

    // Same idea with AES_KEY instead of HMAC, to show it's not HMAC-specific.
    read_metrics = '0;
    read_metrics.ocp_lock_in_progress = 1;
    read_metrics.kv_key_entry         = KV_ENTRY_ADDR_W'(OCP_LOCK_KEY_RELEASE_KV_SLOT);
    read_metrics.kv_read_dest         = (KV_NUM_READ'(1) << KV_DEST_IDX_DMA_DATA) |
                                         (KV_NUM_READ'(1) << KV_DEST_IDX_ECC_SEED);
    check("BUG: concurrent DMA+ECC_SEED read of release slot (mixed one-hot mask)");

    $display("--------------------------------------------------------------");
    $display("Total DUT-vs-spec mismatches: %0d  (of which security bypasses: %0d)", mismatches, bypass_mismatches);
    $finish;
  end
endmodule
