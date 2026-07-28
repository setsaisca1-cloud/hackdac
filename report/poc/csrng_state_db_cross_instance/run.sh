#!/usr/bin/env bash
set -euo pipefail
: "${CALIPTRA_ROOT:?set CALIPTRA_ROOT to the caliptra src checkout root}"
SB="$CALIPTRA_ROOT/src"
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal \
  +incdir+"$SB/libs/rtl" +incdir+"$SB/caliptra_prim/rtl" \
  "$SB/entropy_src/rtl/entropy_src_pkg.sv" \
  "$SB/csrng/rtl/csrng_pkg.sv" \
  "$SB/csrng/rtl/csrng_state_db.sv" \
  tb.sv -o tb_sim
./obj_dir/tb_sim
