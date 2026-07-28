#!/usr/bin/env bash
set -euo pipefail
: "${CALIPTRA_ROOT:?set CALIPTRA_ROOT to the caliptra src checkout root}"
SB="$CALIPTRA_ROOT/src"
cd "$(dirname "$0")"
verilator --binary --timing --top-module tb -Wno-fatal \
  "$SB/keyvault/rtl/kv_defines_pkg.sv" \
  "$SB/keyvault/rtl/kv_write_rule_check.sv" \
  tb.sv -o tb_sim
./obj_dir/tb_sim
