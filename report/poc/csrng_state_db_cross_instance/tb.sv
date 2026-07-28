`timescale 1ns/1ps
// PoC for Bug 12 (csrng_state_db.sv cross-instance internal-state leak).
//
// int_st_dump_qualified = int_st_dump_sel & {NApps{int_state_read_enable_i[0]}}
// broadcasts APPLICATION 0's own debug-read-enable bit to every application
// index, instead of gating each app `rd`'s dump visibility with its own
// int_state_read_enable_i[rd]. This lets application 0's enable bit expose
// any OTHER application's internal DRBG state.
import csrng_pkg::*;

module tb;
  localparam NAPPS = 4;
  localparam STATEID = 4;
  localparam BLKLEN = 128;
  localparam KEYLEN = 256;
  localparam CTRLEN = 32;
  localparam CMD = 3;

  logic clk_i = 0, rst_ni = 0;
  logic state_db_enable_i = 1;
  logic [STATEID-1:0] state_db_rd_inst_id_i = 0;
  logic [KEYLEN-1:0]  state_db_rd_key_o;
  logic [BLKLEN-1:0]  state_db_rd_v_o;
  logic [CTRLEN-1:0]  state_db_rd_res_ctr_o;
  logic state_db_rd_inst_st_o, state_db_rd_fips_o;

  logic state_db_wr_req_i = 0;
  logic state_db_wr_req_rdy_o;
  logic [STATEID-1:0] state_db_wr_inst_id_i = 0;
  logic state_db_wr_fips_i = 0;
  logic [CMD-1:0] state_db_wr_ccmd_i = INS;
  logic [KEYLEN-1:0] state_db_wr_key_i = '0;
  logic [BLKLEN-1:0] state_db_wr_v_i = '0;
  logic [CTRLEN-1:0] state_db_wr_res_ctr_i = '0;
  csrng_cmd_sts_e state_db_wr_sts_i = CMD_STS_SUCCESS;

  logic state_db_is_dump_en_i = 1;
  logic state_db_reg_rd_sel_i = 0;
  logic state_db_reg_rd_id_pulse_i = 0;
  logic [STATEID-1:0] state_db_reg_rd_id_i = 0;
  logic [31:0] state_db_reg_rd_val_o;
  logic state_db_sts_ack_o;
  csrng_cmd_sts_e state_db_sts_sts_o;
  logic [STATEID-1:0] state_db_sts_id_o;
  logic [NAPPS-1:0] int_state_read_enable_i = '0;
  logic [NAPPS-1:0][31:0] reseed_counter_o;

  csrng_state_db #(
    .NApps(NAPPS), .StateId(STATEID), .BlkLen(BLKLEN), .KeyLen(KEYLEN), .CtrLen(CTRLEN), .Cmd(CMD)
  ) dut (.*);

  always #5 clk_i = ~clk_i;

  task automatic write_app(int idx, logic [KEYLEN-1:0] key, logic [BLKLEN-1:0] v, logic [CTRLEN-1:0] rc);
    state_db_wr_req_i     = 1;
    state_db_wr_inst_id_i = idx[STATEID-1:0];
    state_db_wr_key_i     = key;
    state_db_wr_v_i       = v;
    state_db_wr_res_ctr_i = rc;
    state_db_wr_ccmd_i    = INS;
    @(posedge clk_i); #1;
    state_db_wr_req_i = 0;
  endtask

  initial begin
    rst_ni = 0; repeat(2) @(posedge clk_i); rst_ni = 1; @(posedge clk_i);

    // App 0's own (legitimately its own) secret state.
    write_app(0, {KEYLEN{1'b1}} & 256'hA0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0_A0A0,
                  128'hA1A1_A1A1_A1A1_A1A1_A1A1_A1A1_A1A1_A1A1, 32'hA2A2A2A2);

    // App 2's own SEPARATE secret DRBG state -- a different CSRNG
    // application instance entirely (e.g. a different privilege domain /
    // firmware component using its own CSRNG app id).
    write_app(2, 256'hDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF,
                 128'hDEAD_BEEF_DEAD_BEEF_DEAD_BEEF_DEAD_BEEF, 32'hDEADBEEF);

    // Attacker/observer controls ONLY application 0's own debug-state-read
    // enable bit. Application 2's own bit is explicitly left DISABLED.
    int_state_read_enable_i = '0;
    int_state_read_enable_i[0] = 1'b1;   // app 0's own enable: ON
    // int_state_read_enable_i[2] stays 0                       -- app 2's own enable: OFF

    // Select application 2 as the dump target via the normal register-read pointer path.
    state_db_reg_rd_id_i = 4'd2;
    state_db_reg_rd_id_pulse_i = 1'b1;
    @(posedge clk_i); #1;
    state_db_reg_rd_id_pulse_i = 1'b0;
    @(posedge clk_i); #1;

    $display("int_state_read_enable_i = %04b (app0=1, app2=0)", int_state_read_enable_i);
    $display("selected dump target app index = %0d", dut.int_st_dump_id_q);
    $display("internal_states_dump[2] = 0x%0h", dut.internal_states_dump[2]);
    $display("internal_states_q[2] (app 2's real secret state) = 0x%0h", dut.internal_states_q[2]);

    if (dut.internal_states_dump[2] == dut.internal_states_q[2] && dut.internal_states_q[2] != '0) begin
      $display("BUG CONFIRMED: application 2's internal DRBG state is exposed via internal_states_dump even though int_state_read_enable_i[2]==0 -- only app 0's own enable bit (int_state_read_enable_i[0]) was set.");
    end else begin
      $display("No leak observed in this run.");
    end
    $finish;
  end
endmodule
