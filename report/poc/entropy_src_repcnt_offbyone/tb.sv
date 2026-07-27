`timescale 1ns/1ps
module tb;
  logic clk_i = 0;
  logic rst_ni = 0;
  logic [3:0] entropy_bit_i = 0;
  logic entropy_bit_vld_i = 0;
  logic clear_i = 0;
  logic active_i = 1;
  logic [15:0] thresh_i = 16'd5; // health-test cutoff: fail must trigger once rep_cntr reaches 5
  logic [15:0] test_cnt_o;
  logic test_fail_pulse_o;
  logic count_err_o;

  entropy_src_repcnts_ht #(
    .RegWidth(16),
    .RngBusWidth(4)
  ) dut (
    .clk_i, .rst_ni,
    .entropy_bit_i, .entropy_bit_vld_i, .clear_i, .active_i, .thresh_i,
    .test_cnt_o, .test_fail_pulse_o, .count_err_o
  );

  always #5 clk_i = ~clk_i;

  int fail_seen_at_cnt;
  initial fail_seen_at_cnt = -1;

  always @(posedge clk_i) begin
    if (test_fail_pulse_o && fail_seen_at_cnt == -1)
      fail_seen_at_cnt = test_cnt_o;
  end

  initial begin
    rst_ni = 0;
    repeat(3) @(posedge clk_i);
    rst_ni = 1;
    @(posedge clk_i);

    // Feed a "stuck bit" attack: same symbol (0) repeated forever.
    // A correct repetition-count test must assert test_fail_pulse_o
    // as soon as rep_cntr reaches thresh_i (5), i.e. on the 5th matching sample.
    for (int i = 0; i < 12; i++) begin
      entropy_bit_i = 4'h0;
      entropy_bit_vld_i = 1;
      @(posedge clk_i);
      entropy_bit_vld_i = 0;
      @(posedge clk_i);
      $display("[%0t] sample #%0d  test_cnt_o=%0d  test_fail_pulse_o=%0b", $time, i, test_cnt_o, test_fail_pulse_o);
    end

    $display("--------------------------------------------------------");
    if (fail_seen_at_cnt == -1) begin
      $display("BUG CONFIRMED: threshold=%0d was reached/exceeded but test_fail_pulse_o NEVER fired", thresh_i);
    end else if (fail_seen_at_cnt == thresh_i) begin
      $display("OK: health test correctly fired exactly AT threshold (rep_cntr=%0d)", fail_seen_at_cnt);
    end else begin
      $display("BUG CONFIRMED: health test fired late, at rep_cntr=%0d instead of at threshold=%0d (off-by-one, '>' used instead of '>=')", fail_seen_at_cnt, thresh_i);
    end
    $finish;
  end
endmodule
