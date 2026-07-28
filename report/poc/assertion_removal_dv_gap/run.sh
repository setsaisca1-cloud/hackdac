#!/usr/bin/env bash
set -euo pipefail
: "${CALIPTRA_ROOT:?set CALIPTRA_ROOT to the caliptra src checkout root}"
SB="$CALIPTRA_ROOT/src"
cd "$(dirname "$0")"

echo "=== Build 1: as-shipped (assertion removed) ==="
verilator --binary --timing --top-module tb -Wno-fatal +incdir+"$SB/libs/rtl" tb.sv -o tb_sim_noassert
./obj_dir/tb_sim_noassert || true

echo
echo "=== Build 2: with the upstream CALIPTRA_ASSERT_STABLE restored (-DWITH_ASSERTION) ==="
verilator --binary --timing --assert --top-module tb -Wno-fatal -DWITH_ASSERTION -DCLP_ASSERT_ON +incdir+"$SB/libs/rtl" --Mdir obj_dir2 tb.sv -o tb_sim_withassert
./obj_dir2/tb_sim_withassert || echo "(non-zero exit above is expected -- the assertion correctly aborted the sim)"
