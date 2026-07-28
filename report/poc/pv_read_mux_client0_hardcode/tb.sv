`timescale 1ns/1ps
// PoC / status check for Bug 8 candidate (src/pcrvault/rtl/pv.sv read mux).
//
// pv.sv's read-mux loop hardcodes pv_read[0].read_entry/read_offset for
// EVERY client's pv_rd_resp[client], instead of pv_read[client] (the
// exact line is reproduced verbatim below from the real file):
//
//   pv_rd_resp[client].read_data |= ((pv_read[0].read_entry == entry) &
//                                     (pv_read[0].read_offset == dword)) ?
//                                     pcr_value : '0;
//
// IMPORTANT CAVEAT discovered during this dynamic check: this same source
// drop also changed pv_defines_pkg.sv's PV_NUM_READ from the upstream
// v2.1.2 value of 2 down to 1 (verified separately via diff), and the
// only real read client wired up anywhere in the design is sha512.sv's
// PCR-hash-generation port. With PV_NUM_READ=1 the `client` loop variable
// can only ever be 0, so `pv_read[0]` and `pv_read[client]` are the exact
// same expression -- the hardcoded index has NO observable effect in the
// design AS CURRENTLY SHIPPED. It only becomes a live cross-client leak
// if/when a second PCR read client is wired up (which is upstream's own
// default configuration, and is exactly the situation the surrounding
// code -- the `for (client...)` loop, per-client pv_rd_resp array -- is
// structured to support). This test demonstrates both states.
module tb #(parameter int NUM_READ = 1, parameter int NUM_PCR = 4, parameter int NUM_DWORDS = 2);

  typedef struct packed {
    logic [$clog2(NUM_PCR)-1:0]     read_entry;
    logic [$clog2(NUM_DWORDS)-1:0]  read_offset;
  } pv_read_t;

  typedef struct packed {
    logic [31:0] read_data;
    logic        last;
    logic        error;
  } pv_rd_resp_t;

  logic [31:0] pcr_mem [NUM_PCR][NUM_DWORDS]; // stand-in for PCR_ENTRY storage

  pv_read_t    pv_read [NUM_READ];
  pv_rd_resp_t pv_rd_resp [NUM_READ];

  // exact buggy mux, reproduced verbatim (index 0 hardcoded) parameterized
  // over NUM_READ so both the shipped (NUM_READ=1) and latent
  // (NUM_READ=2, matching upstream v2.1.2) configurations can be tested
  // against the identical logic.
  always_comb begin : keyvault_readmux
    for (int client = 0; client < NUM_READ; client++) begin
      pv_rd_resp[client].read_data = '0;
      pv_rd_resp[client].last      = '0;
      pv_rd_resp[client].error     = '0;
      for (int entry = 0; entry < NUM_PCR; entry++) begin
        for (int dword = 0; dword < NUM_DWORDS; dword++) begin
          pv_rd_resp[client].read_data |= ((pv_read[0].read_entry == entry) &
                                            (pv_read[0].read_offset == dword)) ?
                                            pcr_mem[entry][dword] : '0;
        end
      end
    end
  end

  initial begin
    // Load distinct "PCR" values so we can tell which entry got returned.
    for (int e = 0; e < NUM_PCR; e++)
      for (int d = 0; d < NUM_DWORDS; d++)
        pcr_mem[e][d] = 32'hA000_0000 + e*16 + d;

    if (NUM_READ == 1) begin
      pv_read[0] = '{read_entry: 3, read_offset: 0};
      #1;
      $display("[NUM_READ=1, matches this drop's shipped pv_defines_pkg.sv] client 0 requests PCR entry 3 -> pv_rd_resp[0].read_data = 0x%08h (expected 0x%08h)",
                pv_rd_resp[0].read_data, pcr_mem[3][0]);
      if (pv_rd_resp[0].read_data == pcr_mem[3][0])
        $display("STATUS: with only one read client wired up, pv_read[0]==pv_read[client] trivially -- the hardcoded index is DORMANT / not exploitable in this configuration.");
    end else begin
      pv_read[0] = '{read_entry: 3, read_offset: 0}; // client 0: reading its own PCR entry 3
      pv_read[1] = '{read_entry: 1, read_offset: 0}; // client 1: reading its own, DIFFERENT, PCR entry 1
      #1;
      $display("[NUM_READ=2, matching upstream v2.1.2's own default] client 0 requested entry %0d, client 1 requested entry %0d",
                pv_read[0].read_entry, pv_read[1].read_entry);
      $display("  pv_rd_resp[0].read_data = 0x%08h (expected own entry 3 = 0x%08h)", pv_rd_resp[0].read_data, pcr_mem[3][0]);
      $display("  pv_rd_resp[1].read_data = 0x%08h (expected own entry 1 = 0x%08h, but got client 0's entry instead?)", pv_rd_resp[1].read_data, pcr_mem[1][0]);
      if (pv_rd_resp[1].read_data == pcr_mem[3][0] && pv_rd_resp[1].read_data != pcr_mem[1][0])
        $display("BUG CONFIRMED (latent): client 1 receives client 0's PCR entry instead of its own -- this is exactly what would happen if a second PCR read client were wired up.");
    end
    $finish;
  end
endmodule
