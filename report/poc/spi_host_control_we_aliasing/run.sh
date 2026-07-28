#!/usr/bin/env bash
set -euo pipefail
: "${CALIPTRA_ROOT:?set CALIPTRA_ROOT to the caliptra src checkout root}"
SB="$CALIPTRA_ROOT/src"
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal \
  +incdir+"$SB/caliptra_prim/rtl" +incdir+"$SB/libs/rtl" \
  "$SB/caliptra_prim/rtl/caliptra_prim_assert.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_pkg.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_mubi_pkg.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_util_pkg.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_onehot_check.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_subreg_pkg.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_subreg.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_subreg_ext.sv" \
  "$SB/caliptra_prim_generic/rtl/caliptra_prim_generic_buf.sv" \
  "$SB/libs/rtl/ahb_defines_pkg.sv" \
  "$SB/libs/rtl/ahb_slv_sif.sv" \
  "$SB/libs/rtl/ahb_to_reg_adapter.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_reg_we_check.sv" \
  "$SB/spi_host/rtl/spi_host_reg_pkg.sv" \
  "$SB/spi_host/rtl/spi_host_reg_top.sv" \
  tb.sv -o tb_sim
./obj_dir/tb_sim
