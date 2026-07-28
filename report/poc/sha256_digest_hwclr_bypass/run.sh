#!/usr/bin/env bash
set -euo pipefail
: "${CALIPTRA_ROOT:?set CALIPTRA_ROOT to the caliptra src checkout root}"
SB="$CALIPTRA_ROOT/src"
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal \
  +incdir+"$SB/caliptra_prim/rtl" +incdir+"$SB/libs/rtl" \
  "$SB/caliptra_prim/rtl/caliptra_prim_assert.sv" \
  "$SB/sha256/rtl/sha256_params_pkg.sv" \
  "$SB/sha256/rtl/sha256_reg_pkg.sv" \
  "$SB/sha256/rtl/sha256_reg.sv" \
  "$SB/sha256/rtl/sha256_k_constants.v" \
  "$SB/sha256/rtl/sha256_w_mem.v" \
  "$SB/sha256/rtl/sha256_core.v" \
  "$SB/sha256/rtl/sha256.sv" \
  tb.sv -o tb_sim
./obj_dir/tb_sim
