`timescale 1ns/1ps
// PoC for Bug 13 (doe_fsm.sv UDS Key-Vault destination-valid widening).
//
// doe_fsm.sv is a large multi-state FSM wired deep into the DOE/KV/AES
// subsystem; driving it through a full UDS-derivation sequence end-to-end
// requires the surrounding chip harness. The bug itself, however, is a
// single combinational mux -- reproduced verbatim below from the real
// file -- so it can be dynamically exercised directly.
//
// ---- exact code from doe_fsm.sv ----
//   always_comb kv_write.write_dest_valid = running_hek ? OCP_LOCK_HEK_SEED_DEST_VALID :
//                                            (running_uds ? 9'h023 : 'd3);
// OCP_LOCK_HEK_SEED_DEST_VALID = (1 << KV_DEST_IDX_HMAC_BLOCK) = 9'h002 (from kv_defines_pkg.sv)
//
// KV_DEST_IDX_* bit assignments (kv_defines_pkg.sv):
//   0 = HMAC_KEY   1 = HMAC_BLOCK   2 = MLDSA_SEED   3 = ECC_PKEY
//   4 = ECC_SEED   5 = AES_KEY      6 = MLKEM_SEED   7 = MLKEM_MSG   8 = DMA_DATA
module tb;
  localparam OCP_LOCK_HEK_SEED_DEST_VALID = 9'h002;
  localparam KV_DEST_IDX_AES_KEY = 5;

  logic running_hek, running_uds;
  logic [8:0] write_dest_valid;

  // exact patched line
  always_comb
    write_dest_valid = running_hek ? OCP_LOCK_HEK_SEED_DEST_VALID :
                        (running_uds ? 9'h023 : 'd3);

  initial begin
    logic [8:0] uds_mask, fe_mask; // FE (field entropy) takes the "else" path, same as any
                                     // non-UDS, non-HEK derivation

    running_hek = 0; running_uds = 0; // "FE" or any other non-UDS derivation
    #1; fe_mask = write_dest_valid;
    $display("Non-UDS derivation (e.g. Field Entropy)  -> write_dest_valid = 9'b%09b (0x%0h)", fe_mask, fe_mask);

    running_hek = 0; running_uds = 1; // UDS derivation
    #1; uds_mask = write_dest_valid;
    $display("UDS derivation                            -> write_dest_valid = 9'b%09b (0x%0h)", uds_mask, uds_mask);

    $display("--------------------------------------------------------------");
    if (uds_mask[KV_DEST_IDX_AES_KEY] && !fe_mask[KV_DEST_IDX_AES_KEY]) begin
      $display("BUG CONFIRMED: the UDS-derived key's Key-Vault destination-valid mask sets bit %0d (KV_DEST_IDX_AES_KEY)", KV_DEST_IDX_AES_KEY);
      $display("which the non-UDS derivation path does NOT set. The AES engine's Key-Vault read port");
      $display("gains direct access to the Unique Device Secret-derived key that was not granted to it");
      $display("for other, structurally-identical derivations.");
    end else begin
      $display("Bug not observed in this run.");
    end
    $finish;
  end
endmodule
