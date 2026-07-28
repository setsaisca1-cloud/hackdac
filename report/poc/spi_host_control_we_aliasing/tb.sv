`timescale 1ns/1ps
// PoC for Bug 4 (spi_host_reg_top.sv control_we address-decode aliasing).
//
// control_we = (~&{~addr_hit[4], ~addr_hit[5]}) & reg_we & !reg_error
//            = (addr_hit[4] | addr_hit[5]) & reg_we & !reg_error   (De Morgan)
// addr_hit[4] = CONTROL (0x10, read-write), addr_hit[5] = STATUS (0x14,
// hardware read-only -- it has no software-writable fields at all). A
// write to STATUS should be a no-op; instead it also asserts CONTROL's
// write-enable, loading CONTROL's fields from the SAME write's data.
import spi_host_reg_pkg::*;

module tb;
  localparam AHB_DW = 64;
  localparam AHB_AW = 32;
  localparam SPI_HOST_CONTROL_OFFSET = 32'h10;
  localparam SPI_HOST_STATUS_OFFSET  = 32'h14;

  logic clk_i = 0, rst_ni = 0;
  logic [AHB_AW-1:0] haddr_i = 0;
  logic [AHB_DW-1:0] hwdata_i = 0;
  logic hsel_i = 0, hwrite_i = 0, hready_i = 1;
  logic [1:0] htrans_i = 2'b00;
  logic [2:0] hsize_i = 3'b010; // word
  logic hresp_o, hreadyout_o;
  logic [AHB_DW-1:0] hrdata_o;
  logic fifo_rx_re;
  spi_host_reg_pkg::spi_host_reg2hw_t reg2hw;
  spi_host_reg_pkg::spi_host_hw2reg_t hw2reg;
  logic intg_err_o;
  logic devmode_i = 1;

  spi_host_reg_top #(.AHBDataWidth(AHB_DW), .AHBAddrWidth(AHB_AW)) dut (
    .clk_i, .rst_ni,
    .haddr_i, .hwdata_i, .hsel_i, .hwrite_i, .hready_i, .htrans_i, .hsize_i,
    .hresp_o, .hreadyout_o, .hrdata_o,
    .fifo_rx_re,
    .reg2hw, .hw2reg,
    .intg_err_o,
    .devmode_i
  );

  always #5 clk_i = ~clk_i;

  // hw2reg defaults: everything read-only/status-driven tied off so the
  // register file has something well-defined to present on STATUS reads.
  initial hw2reg = '0;

  task automatic ahb_write32(logic [AHB_AW-1:0] addr, logic [31:0] data);
    // Address phase
    hsel_i = 1; hwrite_i = 1; htrans_i = 2'b10 /*NONSEQ*/; haddr_i = addr; hsize_i = 3'b010;
    @(posedge clk_i); #1;
    // Data phase: present data on the correct 32-bit half of the 64b AHB bus.
    hwdata_i = addr[2] ? {data, 32'h0} : {32'h0, data};
    hsel_i = 0; htrans_i = 2'b00;
    @(posedge clk_i); #1;
    hwdata_i = 0;
  endtask

  task automatic ahb_read32(logic [AHB_AW-1:0] addr, output logic [31:0] data);
    hsel_i = 1; hwrite_i = 0; htrans_i = 2'b10; haddr_i = addr; hsize_i = 3'b010;
    @(posedge clk_i); #1;
    hsel_i = 0; htrans_i = 2'b00;
    @(posedge clk_i); #1;
    data = addr[2] ? hrdata_o[63:32] : hrdata_o[31:0];
  endtask

  initial begin
    logic [31:0] control_before, control_after, readback;

    rst_ni = 0; repeat(3) @(posedge clk_i); rst_ni = 1; repeat(2) @(posedge clk_i);

    // Program CONTROL with a known, benign baseline: SPIEN=1 (bit31),
    // SW_RST=0 (bit30), watermarks = 0x11_22.
    ahb_write32(SPI_HOST_CONTROL_OFFSET, 32'h8000_1122);
    ahb_read32(SPI_HOST_CONTROL_OFFSET, control_before);
    $display("CONTROL after legitimate write (0x8000_1122): 0x%08h", control_before);

    // Now write to STATUS (0x14) -- a register with NO software-writable
    // fields at all. This should be a complete no-op for CONTROL.
    // wdata bit31=0 (would clear SPIEN), bit30=1 (would assert SW_RST).
    ahb_write32(SPI_HOST_STATUS_OFFSET, 32'h4000_0000);

    ahb_read32(SPI_HOST_CONTROL_OFFSET, control_after);
    $display("CONTROL after writing STATUS (0x14) with 0x4000_0000: 0x%08h", control_after);

    $display("--------------------------------------------------------------");
    if (control_after != control_before) begin
      $display("BUG CONFIRMED: writing the read-only STATUS register changed CONTROL");
      $display("  CONTROL before: 0x%08h  (SPIEN=%0b SW_RST=%0b)", control_before, control_before[31], control_before[30]);
      $display("  CONTROL after : 0x%08h  (SPIEN=%0b SW_RST=%0b)", control_after,  control_after[31],  control_after[30]);
      $display("  A write aimed at STATUS silently disabled SPIEN and/or asserted SW_RST on CONTROL.");
    end else begin
      $display("No bug observed: CONTROL unchanged by the STATUS write.");
    end
    $finish;
  end
endmodule
