`timescale 1ns/1ps
// PoC for Bug 14 (axi_sub_arb.sv `user` sideband desync).
//
// Sequence: (1) complete a write burst to flip read-priority (r_pri) to 1;
// (2) on the next cycle, assert a read (r_dv) AND a write (w_dv)
// simultaneously with r_pri=1. Under this condition r_win becomes 1
// (the read wins: addr==r_addr, write==0), yet `user_from_read` (=
// r_win & ~w_dv) evaluates to 0 because w_dv is also 1 -- so the
// arbiter reports the WRITE request's `user` tag on what is, by every
// other output signal, a READ transaction.
module tb;
  localparam AW=32, DW=32, UW=32, IW=4;

  logic clk = 0, rst_n = 0;
  logic r_dv, w_dv, r_last, w_last, hld;
  logic [AW-1:0] r_addr, w_addr;
  logic [UW-1:0] r_user, w_user;
  logic [IW-1:0] r_id, w_id;
  logic [2:0] r_size, w_size;
  logic [DW-1:0] w_wdata, wdata, rdata;
  logic [DW/8-1:0] w_wstrb, wstrb;
  logic r_hld, w_hld, r_err, w_err;
  logic dv, write, last;
  logic [AW-1:0] addr;
  logic [UW-1:0] user;
  logic [IW-1:0] id;
  logic [2:0] size;
  logic [DW-1:0] r_rdata;
  logic rd_err = 0, wr_err = 0;

  axi_sub_arb #(.AW(AW), .DW(DW), .UW(UW), .IW(IW)) dut (
    .clk, .rst_n,
    .r_dv, .r_addr, .r_user, .r_id, .r_size, .r_last, .r_hld, .r_err, .r_rdata,
    .w_dv, .w_addr, .w_user, .w_id, .w_wdata, .w_wstrb, .w_size, .w_last, .w_hld, .w_err,
    .dv, .addr, .write, .user, .id, .wdata, .wstrb, .size, .last,
    .hld(hld), .rd_err, .wr_err, .rdata
  );

  always #5 clk = ~clk;

  initial begin
    r_dv=0; w_dv=0; r_addr=0; w_addr=0; r_user=0; w_user=0; r_id=0; w_id=0;
    r_size=0; w_size=0; r_last=0; w_last=0; w_wdata=0; w_wstrb=0; hld=0;
    rdata = 0;

    rst_n = 0; repeat(2) @(posedge clk); rst_n = 1; @(posedge clk);

    // Step 1: complete a single-beat write burst so r_pri flips to 1
    // (see axi_sub_arb.sv: "else if (w_dv && !w_hld && w_last) r_pri <= 1'b1;")
    w_dv = 1; w_last = 1; w_addr = 32'hAAAA_0000; w_user = 32'hDEAD_0001; w_id = 4'h1;
    @(posedge clk); #1;
    w_dv = 0; w_last = 0;

    // Step 2: on the very next cycle, assert a READ for a DIFFERENT,
    // security-sensitive address, carrying the real (unprivileged)
    // requester's own user/context id, while ALSO keeping an unrelated
    // WRITE pending (any address) whose user id we control.
    r_dv = 1; r_addr = 32'h1234_5678; r_user = 32'h0000_00AA /* real requester id */; r_id = 4'h2; r_last = 0;
    w_dv = 1; w_addr = 32'hBBBB_0000; w_user = 32'hFFFF_FFFF /* attacker-chosen id to inject */; w_id = 4'h3; w_last = 1;

    @(posedge clk); #1;

    $display("dv=%0b write=%0b addr=0x%08h  user=0x%08h  (r_user=0x%08h w_user=0x%08h)",
              dv, write, addr, user, r_user, w_user);

    if (dv && write == 1'b0 && addr == r_addr) begin
      if (user == w_user) begin
        $display("BUG CONFIRMED: transaction is a READ of addr=0x%08h (write=0, addr==r_addr) but user=0x%08h == the WRITE request's user id, not the read requester's own id (0x%08h)", addr, user, r_user);
      end else if (user == r_user) begin
        $display("No bug observed: user correctly matches the read requester's own id");
      end
    end else begin
      $display("Arbitration did not land on the expected read-wins state (write=%0b) -- re-check r_pri sequencing", write);
    end

    $finish;
  end
endmodule
