#!/usr/bin/env bash
set -euo pipefail
: "${CALIPTRA_ROOT:?set CALIPTRA_ROOT to the caliptra src checkout root}"
SB="$CALIPTRA_ROOT/src"
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal \
  +incdir+"$SB/caliptra_prim/rtl" +incdir+"$SB/libs/rtl" \
  "$SB/caliptra_prim/rtl/caliptra_prim_assert.sv" \
  "$SB/hmac/rtl/hmac_reg_pkg.sv" \
  "$SB/hmac/rtl/hmac_reg.sv" \
  tb.sv -o tb_sim
./obj_dir/tb_sim
