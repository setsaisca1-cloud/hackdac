#!/usr/bin/env bash
# PoC for: entropy_src_repcnts_ht.sv -- repetition-count health-test off-by-one
#
# Usage: CALIPTRA_ROOT=/path/to/caliptra-rtl-src ./run.sh
#   (CALIPTRA_ROOT must point at the checkout's top-level dir containing src/)
set -euo pipefail
: "${CALIPTRA_ROOT:?set CALIPTRA_ROOT to the caliptra src checkout root}"
SB="$CALIPTRA_ROOT/src"
cd "$(dirname "$0")"

verilator --binary --timing --top-module tb -Wno-fatal \
  +incdir+"$SB/caliptra_prim/rtl" +incdir+"$SB/libs/rtl" \
  "$SB/caliptra_prim/rtl/caliptra_prim_pkg.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_count_pkg.sv" \
  "$SB/caliptra_prim/rtl/caliptra_prim_count.sv" \
  "$SB/caliptra_prim_generic/rtl/caliptra_prim_generic_flop.sv" \
  "$SB/entropy_src/rtl/entropy_src_repcnts_ht.sv" \
  tb.sv -o tb_sim

./obj_dir/tb_sim
