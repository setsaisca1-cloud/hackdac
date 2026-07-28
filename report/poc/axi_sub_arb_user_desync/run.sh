#!/usr/bin/env bash
set -euo pipefail
: "${CALIPTRA_ROOT:?set CALIPTRA_ROOT to the caliptra src checkout root}"
SB="$CALIPTRA_ROOT/src"
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal \
  +incdir+"$SB/libs/rtl" +incdir+"$SB/caliptra_prim/rtl" \
  "$SB/axi/rtl/axi_pkg.sv" \
  "$SB/axi/rtl/axi_sub_arb.sv" \
  tb.sv -o tb_sim
./obj_dir/tb_sim
