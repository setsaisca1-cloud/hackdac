`timescale 1ns/1ps
// PoC for Bug 9 (sha256.sv digest-clear polarity bug).
//
// Correct (upstream v2.1.2) expression:
//   zeroize_reg = ZEROIZE | debugUnlock_or_scan_mode_switch     (= Z | D)
//   DIGEST.hwclr = zeroize_reg
// The patched code instead drives DIGEST.hwclr from a second signal:
//   zeroize_reg2 = ZEROIZE | ~debugUnlock_or_scan_mode_switch   (= Z | ~D)
//   DIGEST.hwclr = zeroize_reg2
// i.e. the D term feeding the register file's hardware-clear is INVERTED
// relative to the D term still correctly used elsewhere in the same file
// to gate the *core's own* internal digest_reg/ready_flag_reg/valid_flag_reg
// (that internal reset still uses the original, un-inverted zeroize_reg).
//
// Dynamically confirmed net effect (see the two scenarios below): with D=0
// (normal, debug-locked operation -- the case used for essentially all
// production hashing), zeroize_reg2 = Z | 1 = 1 UNCONDITIONALLY, so the
// software-visible SHA256_DIGEST register is hardware-cleared every single
// cycle regardless of the software ZEROIZE bit, even though the core's own
// internal digest_reg computes and latches the correct result just fine.
// The digest can never be read back. With D=1 (debug/scan open), the
// *separate, correctly-signed* zeroize_reg additionally holds the whole
// core (digest_reg, ready_flag_reg, valid_flag_reg) in permanent reset, so
// no computation can complete at all while debug is open either. The
// result: SHA256_DIGEST is unconditionally stuck at 0 in every reachable
// state -- a complete, always-on denial-of-service of the digest read-back
// path, not a "stale secret retained" leak as a static read of the single
// changed line might suggest.
module tb;
  localparam SHA256_CTRL_OFFSET   = 12'h010;
  localparam SHA256_BLOCK_OFFSET  = 12'h080;
  localparam SHA256_DIGEST_OFFSET = 12'h100;

  logic clk = 0, reset_n = 0, cptra_pwrgood = 1;
  logic cs = 0, we = 0;
  logic [31:0] address = 0, write_data = 0;
  logic [31:0] read_data;
  logic err, error_intr, notif_intr;
  logic debugUnlock_or_scan_mode_switch = 0;

  sha256 dut (
    .clk, .reset_n, .cptra_pwrgood,
    .cs, .we, .address, .write_data, .read_data, .err,
    .error_intr, .notif_intr,
    .debugUnlock_or_scan_mode_switch
  );

  always #5 clk = ~clk;

  task automatic reg_write(logic [31:0] addr, logic [31:0] data);
    cs = 1; we = 1; address = addr; write_data = data;
    @(posedge clk); #1;
    cs = 0; we = 0;
  endtask

  task automatic reg_read(logic [31:0] addr, output logic [31:0] data);
    cs = 1; we = 0; address = addr;
    @(posedge clk); #1;
    data = read_data;
    cs = 0;
  endtask

  task automatic run_hash(logic [31:0] pattern_base);
    for (int i = 0; i < 16; i++)
      reg_write(SHA256_BLOCK_OFFSET + 4*i, pattern_base + i);
    reg_write(SHA256_CTRL_OFFSET, 32'h0000_0005); // MODE=1 (SHA256), INIT=1
    for (int i = 0; i < 200 && !dut.digest_valid_reg; i++) @(posedge clk);
    #1;
    repeat(2) @(posedge clk); #1; // let field_storage settle
  endtask

  task automatic read_digest(output logic [31:0] d[8], output logic nonzero);
    nonzero = 0;
    for (int i = 0; i < 8; i++) begin
      reg_read(SHA256_DIGEST_OFFSET + 4*i, d[i]);
      if (d[i] != 32'h0) nonzero = 1;
    end
  endtask

  initial begin
    logic [31:0] digest_normal[8];
    logic [31:0] digest_during_debug[8];
    logic [31:0] digest_after_debug_closes[8];
    logic nz_normal, nz_debug, nz_after;

    reset_n = 0; repeat(3) @(posedge clk); reset_n = 1; repeat(2) @(posedge clk);

    // -----------------------------------------------------------------
    // Scenario A: hash performed with debugUnlock_or_scan_mode_switch=0
    // throughout (normal/debug-locked operation) and SW ZEROIZE never
    // asserted.
    // -----------------------------------------------------------------
    debugUnlock_or_scan_mode_switch = 0;
    run_hash(32'hA5A5_0000);
    $display("Internal digest_reg right after Scenario A's hash op (probed directly, pre-register-file): 0x%0h", dut.digest_reg);
    read_digest(digest_normal, nz_normal);
    $display("Scenario A (debug LOCKED, D=0): SHA256_DIGEST readback:");
    for (int i = 0; i < 8; i++) $display("  DIGEST[%0d] = 0x%08h", i, digest_normal[i]);
    $display("  -> %s", nz_normal ? "digest is readable (as expected in normal operation)"
                                    : "digest reads back as ALL-ZERO (hwclr permanently asserted)");

    // -----------------------------------------------------------------
    // Scenario B: SAME hash, but with a debug/scan session OPEN
    // (debugUnlock_or_scan_mode_switch=1) throughout the operation and
    // the read.
    // -----------------------------------------------------------------
    debugUnlock_or_scan_mode_switch = 1;
    run_hash(32'hA5A5_0000);
    read_digest(digest_during_debug, nz_debug);
    $display("Scenario B (debug OPEN, D=1): SHA256_DIGEST readback:");
    for (int i = 0; i < 8; i++) $display("  DIGEST[%0d] = 0x%08h", i, digest_during_debug[i]);
    $display("  -> %s", nz_debug ? "digest IS readable while debug is open"
                                   : "digest is zero even with debug open");

    // Close the debug session and re-read without doing anything else.
    debugUnlock_or_scan_mode_switch = 0;
    repeat(2) @(posedge clk); #1;
    read_digest(digest_after_debug_closes, nz_after);
    $display("After closing debug session (D back to 0), same digest re-read:");
    for (int i = 0; i < 8; i++) $display("  DIGEST[%0d] = 0x%08h", i, digest_after_debug_closes[i]);

    $display("--------------------------------------------------------------");
    if (!nz_normal && !nz_debug) begin
      $display("BUG CONFIRMED: SHA256_DIGEST reads back as all-zero in BOTH scenarios, even though");
      $display("the core's internal digest_reg holds a real, nonzero computed digest. The DIGEST.hwclr");
      $display("polarity bug (zeroize_reg2 = Z | ~D instead of Z | D) permanently hardware-clears the");
      $display("software-visible register whenever debug is locked (D=0, the normal/production case),");
      $display("while a debug session (D=1) separately holds the whole core in reset via the still-");
      $display("correct zeroize_reg. Net result: the digest read-back path is completely non-functional");
      $display("in every reachable state -- a permanent denial-of-service of SHA256_DIGEST readback.");
    end else begin
      $display("Result did not match the expected buggy pattern in this run -- see readbacks above.");
    end
    $finish;
  end
endmodule
