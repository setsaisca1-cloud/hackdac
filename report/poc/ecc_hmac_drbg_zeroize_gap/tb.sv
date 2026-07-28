`timescale 1ns/1ps
// PoC for Bug 15 (ecc_hmac_drbg_interface.sv SCA mask-seed not cleared on zeroize).
//
// The register-update block below is reproduced verbatim from the real
// file (comments included, notably the challenge author's own
// "// without zeroize to make it more complex" left in place). Every
// other DRBG-derived register (lambda_reg, scalar_rnd_reg,
// masking_rnd_reg, drbg_reg) is cleared on `zeroize`; lfsr_seed_reg is
// not.
module dut (
  input logic clk,
  input logic reset_n,
  input logic zeroize,
  input logic hmac_done_edge,
  input logic [2:0] state_reg, // 0=LFSR_ST, 1=LAMBDA_ST, 2=SCALAR_RND_ST, 3=MASKING_RND_ST, 4=other
  input logic [31:0] hmac_drbg_result,
  output logic [31:0] lambda_reg,
  output logic [31:0] scalar_rnd_reg,
  output logic [31:0] masking_rnd_reg,
  output logic [31:0] drbg_reg,
  output logic [31:0] lfsr_seed_reg
);
  localparam LFSR_ST = 0, LAMBDA_ST = 1, SCALAR_RND_ST = 2, MASKING_RND_ST = 3;

  // ---- exact reg_update block from ecc_hmac_drbg_interface.sv ----
  always_ff @(posedge clk or negedge reset_n)
  begin //reg_update
      if (!reset_n) begin
          lambda_reg <= '0;
          scalar_rnd_reg <= '0;
          masking_rnd_reg <= '0;
          drbg_reg <= '0;
          lfsr_seed_reg <= '0;
      end
      else if (zeroize) begin
          lambda_reg <= '0;
          scalar_rnd_reg <= '0;
          masking_rnd_reg <= '0;
          drbg_reg <= '0;
          //lfsr_seed_reg <= '0; // without zeroize to make it more complex
      end
      else
          if (hmac_done_edge) begin
              unique case (state_reg) inside
                  LFSR_ST:        lfsr_seed_reg   <= hmac_drbg_result;
                  LAMBDA_ST:      lambda_reg      <= hmac_drbg_result;
                  SCALAR_RND_ST:  scalar_rnd_reg  <= hmac_drbg_result;
                  MASKING_RND_ST: masking_rnd_reg <= hmac_drbg_result;
                  default: begin
                      lambda_reg <= '0;
                      scalar_rnd_reg <= '0;
                      masking_rnd_reg <= '0;
                      drbg_reg <= '0;
                  end
              endcase
          end
  end //reg_update
endmodule

module tb;
  logic clk = 0, reset_n = 0, zeroize = 0, hmac_done_edge = 0;
  logic [2:0] state_reg = 0;
  logic [31:0] hmac_drbg_result = 0;
  logic [31:0] lambda_reg, scalar_rnd_reg, masking_rnd_reg, drbg_reg, lfsr_seed_reg;

  dut u_dut (.*);
  always #5 clk = ~clk;

  initial begin
    reset_n = 0; repeat(2) @(posedge clk); reset_n = 1; @(posedge clk);

    // Load a "secret" masking seed via the normal LFSR_ST capture path.
    state_reg = 0; // LFSR_ST
    hmac_drbg_result = 32'hDEAD_BEEF;
    hmac_done_edge = 1;
    @(posedge clk); #1;
    hmac_done_edge = 0;
    // Also give the other registers nonzero "secret" values via LAMBDA_ST etc.
    state_reg = 1; hmac_drbg_result = 32'h1111_1111; hmac_done_edge = 1; @(posedge clk); #1; hmac_done_edge = 0;

    $display("Before zeroize: lfsr_seed_reg=0x%08h lambda_reg=0x%08h", lfsr_seed_reg, lambda_reg);

    // Zeroize the ECC/HMAC-DRBG interface (as would happen between ECDSA operations).
    zeroize = 1;
    @(posedge clk); #1;
    zeroize = 0;

    $display("After zeroize:  lfsr_seed_reg=0x%08h lambda_reg=0x%08h", lfsr_seed_reg, lambda_reg);

    $display("--------------------------------------------------------------");
    if (lambda_reg == 32'h0 && lfsr_seed_reg == 32'hDEAD_BEEF) begin
      $display("BUG CONFIRMED: lambda_reg (and scalar_rnd_reg/masking_rnd_reg/drbg_reg, same pattern)");
      $display("were correctly cleared by zeroize, but lfsr_seed_reg -- the SCA masking-LFSR seed --");
      $display("retained its pre-zeroize value 0x%08h. Masking randomness state survives across the", lfsr_seed_reg);
      $display("zeroize boundary that is supposed to scrub it between ECDSA operations.");
    end else begin
      $display("Bug not observed in this run.");
    end
    $finish;
  end
endmodule
